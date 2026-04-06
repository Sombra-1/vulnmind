"""
tools/merge_kb.py — Merge staging files into services.json with validation.

Merge order (later sources override earlier for descriptions):
  1. Current services.json  (baseline)
  2. nse_extracted.json     (auto-generated from nmap scripts)
  3. manual_additions.json  (hand-curated, highest trust)

Rules enforced before writing:
  - description >= 30 chars
  - CVE IDs match CVE-YYYY-NNNN format
  - priority must be critical/high/medium/low
  - suggested_commands must contain {host} if non-empty
  - No duplicate (service, product, version_match, version_before) tuples
  - Max one generic fallback entry per service (product=null, version_match=null, version_before=null)
  - _source tracking fields are stripped from final output

Run:
    python3 tools/merge_kb.py
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

BASE_FILE    = Path(__file__).parent.parent / "vulnmind" / "knowledge" / "services.json"
NSE_FILE     = Path(__file__).parent / "staging" / "nse_extracted.json"
MANUAL_FILE  = Path(__file__).parent / "staging" / "manual_additions.json"
OUT_FILE     = BASE_FILE

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
VALID_PRIORITIES = {"critical", "high", "medium", "low"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_entry(entry: dict, service: str) -> list:
    """Return list of error strings. Empty list = valid."""
    errors = []

    desc = entry.get("description", "")
    if not desc or len(desc) < 30:
        errors.append(f"description too short ({len(desc)} chars)")

    priority = entry.get("priority", "")
    if priority not in VALID_PRIORITIES:
        errors.append(f"invalid priority '{priority}'")

    for cve in entry.get("cves", []):
        if not CVE_RE.match(cve):
            errors.append(f"invalid CVE format '{cve}'")

    for cmd in entry.get("suggested_commands", []):
        if cmd and "{host}" not in cmd:
            errors.append(f"command missing {{host}} placeholder: '{cmd[:50]}'")

    return errors


def make_key(entry: dict) -> tuple:
    """Deduplication key for an entry."""
    return (
        entry.get("product") or "",
        entry.get("version_match") or "",
        entry.get("version_before") or "",
    )


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def merge_service_entries(existing: list, incoming: list) -> list:
    """
    Merge incoming entries into existing, deduplicating by key.
    Incoming entries override existing ones with the same key.
    Manual entries (no _source or _source=manual) always win.
    """
    # Index existing by dedup key
    index = {}
    order = []
    for entry in existing:
        k = make_key(entry)
        if k not in index:
            order.append(k)
        index[k] = entry

    for entry in incoming:
        k = make_key(entry)
        source = entry.get("_source", "")
        if k not in index:
            order.append(k)
            index[k] = entry
        else:
            # Incoming overrides if it's manual or has better description
            existing_entry = index[k]
            existing_source = existing_entry.get("_source", "")
            incoming_is_manual = not source or source == "manual"
            existing_is_manual = not existing_source or existing_source == "manual"

            if incoming_is_manual and not existing_is_manual:
                index[k] = entry  # manual always wins
            elif len(entry.get("description", "")) > len(existing_entry.get("description", "")):
                # Keep better description, merge CVEs and commands
                merged = dict(existing_entry)
                merged["description"] = entry["description"]
                merged["priority"] = entry.get("priority") or existing_entry.get("priority")
                # Merge CVEs
                all_cves = list(dict.fromkeys(
                    (existing_entry.get("cves") or []) + (entry.get("cves") or [])
                ))
                merged["cves"] = all_cves
                # Prefer NSE commands (more specific) over generic
                if entry.get("suggested_commands"):
                    merged["suggested_commands"] = entry["suggested_commands"]
                # Merge Metasploit modules
                all_msf = list(dict.fromkeys(
                    (existing_entry.get("metasploit_modules") or []) +
                    (entry.get("metasploit_modules") or [])
                ))
                merged["metasploit_modules"] = all_msf
                index[k] = merged

    return [index[k] for k in order]


def strip_source_fields(data: dict) -> dict:
    """Remove _source tracking fields before writing final output."""
    result = {}
    for service, entries in data.items():
        result[service] = []
        for entry in entries:
            clean = {k: v for k, v in entry.items() if k != "_source"}
            result[service].append(clean)
    return result


def enforce_single_fallback(entries: list, service: str) -> list:
    """
    Each service may have at most one generic fallback entry
    (product=null, version_match=null, version_before=null).
    Keep the one with the longest description.
    """
    fallbacks = [e for e in entries if not e.get("product") and
                 not e.get("version_match") and not e.get("version_before")]
    non_fallbacks = [e for e in entries if e not in fallbacks]

    if len(fallbacks) <= 1:
        return entries

    # Keep best fallback
    best = max(fallbacks, key=lambda e: len(e.get("description", "")))
    return non_fallbacks + [best]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("VulnMind Knowledge Base Merger")
    print("=" * 40)

    # Load all sources
    print(f"\nLoading sources...")
    base   = load_json(BASE_FILE)
    nse    = load_json(NSE_FILE)
    manual = load_json(MANUAL_FILE)

    base_count   = sum(len(v) for v in base.values())
    nse_count    = sum(len(v) for v in nse.values())
    manual_count = sum(len(v) for v in manual.values())

    print(f"  Base (services.json):      {base_count} entries")
    print(f"  NSE extracted:             {nse_count} entries")
    print(f"  Manual additions:          {manual_count} entries")

    # Collect all service keys
    all_services = set(base) | set(nse) | set(manual)

    # Merge
    merged = {}
    for service in sorted(all_services):
        entries = base.get(service, [])
        entries = merge_service_entries(entries, nse.get(service, []))
        entries = merge_service_entries(entries, manual.get(service, []))
        entries = enforce_single_fallback(entries, service)
        merged[service] = entries

    # Validate
    print(f"\nValidating entries...")
    errors = []
    warnings = []
    for service, entries in merged.items():
        for i, entry in enumerate(entries):
            errs = validate_entry(entry, service)
            for err in errs:
                product = entry.get("product") or "generic"
                source  = entry.get("_source", "unknown")
                errors.append(f"  [{service}/{product}] ({source}): {err}")

    if errors:
        print(f"\n{len(errors)} validation errors found:")
        for err in errors[:20]:
            print(err)
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more")
        print("\nFix errors before merging. Aborting.")
        sys.exit(1)

    # Strip tracking fields
    merged = strip_source_fields(merged)

    # Write output
    merged_count = sum(len(v) for v in merged.values())
    print(f"\nMerge complete:")
    print(f"  Services: {len(merged)}")
    print(f"  Entries:  {merged_count}  (+{merged_count - base_count} new)")

    total_cves = sum(
        len(e.get("cves", []))
        for entries in merged.values()
        for e in entries
    )
    print(f"  CVE IDs:  {total_cves}")

    with open(OUT_FILE, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"\nWritten to: {OUT_FILE}")

    # Summary by service
    print(f"\nEntries by service:")
    for service in sorted(merged):
        count = len(merged[service])
        print(f"  {service:<20} {count}")


if __name__ == "__main__":
    main()
