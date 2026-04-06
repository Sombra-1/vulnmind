"""
matcher.py — Offline knowledge base matcher.

Enriches Finding objects using a built-in database of known vulnerable
services, versions, and CVEs. No API, no internet, no AI — instant.

How it works:
  1. Takes a Finding with host, port, service, and description
  2. Looks up the service name in services.json
  3. Matches the product and version against known vulnerable entries
  4. Returns the Finding enriched with priority, CVEs, commands, modules

Matching logic (in order of specificity):
  1. Exact version match   — e.g. vsftpd 2.3.4 exactly
  2. Version before X      — e.g. OpenSSH < 8.0
  3. Product only          — e.g. any TP-LINK device
  4. Service fallback      — e.g. any HTTP server

Version comparison:
  Versions like "2.4.49", "7.2p2", "2012.55" are normalised to numeric
  tuples for comparison. Non-numeric parts are stripped.
"""

import json
import re
from dataclasses import replace
from pathlib import Path

_KNOWLEDGE_FILE = Path(__file__).parent / "knowledge" / "services.json"
_knowledge: dict | None = None


def _load_knowledge() -> dict:
    global _knowledge
    if _knowledge is None:
        with open(_KNOWLEDGE_FILE) as f:
            _knowledge = json.load(f)
    return _knowledge


def match_finding(finding) -> object:
    """
    Enrich a Finding from the offline knowledge base.

    Returns an enriched copy of the finding, or the original if no match.
    """
    knowledge = _load_knowledge()

    service = (finding.service or "").lower().strip()
    if not service:
        return finding

    # Normalise service aliases
    service = _normalise_service(service)

    entries = knowledge.get(service)
    if not entries:
        return finding

    # Extract product and version from the finding description/title
    product, version = _extract_product_version(finding)

    # Find the best matching entry
    match = _find_best_match(entries, product, version)
    if not match:
        return finding

    # Merge CVEs — keep any already found by the parser
    existing_cves = set(finding.cve_ids or [])
    new_cves = set(match.get("cves", []))
    merged_cves = list(existing_cves | new_cves)

    # Build commands with host/port substituted in
    host = finding.host
    port = str(finding.port) if finding.port else ""
    commands = [
        cmd.replace("{host}", host).replace("{port}", port)
        for cmd in match.get("suggested_commands", [])
    ]

    return replace(
        finding,
        priority=finding.priority or match.get("priority"),
        cve_ids=merged_cves,
        description=match.get("description") or finding.description,
        suggested_commands=finding.suggested_commands or commands,
        metasploit_modules=finding.metasploit_modules or match.get("metasploit_modules", []),
    )


def match_findings(findings: list) -> list:
    """Enrich a list of findings from the knowledge base."""
    return [match_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_service(service: str) -> str:
    """Map service name variations to the key used in services.json."""
    aliases = {
        "ssh":          "ssh",
        "ftp":          "ftp",
        "http":         "http",
        "http-proxy":   "http",
        "https":        "http",
        "ssl/http":     "http",
        "upnp":         "upnp",
        "ssdp":         "upnp",
        "mysql":        "mysql",
        "microsoft-ds": "microsoft-ds",
        "netbios-ssn":  "microsoft-ds",
        "smb":          "microsoft-ds",
        "domain":       "domain",
        "dns":          "domain",
        "telnet":       "telnet",
        "ms-wbt-server":"rdp",
        "rdp":          "rdp",
        "redis":        "redis",
        "mongodb":      "mongodb",
        "mongod":       "mongodb",
        "tomcat":       "tomcat",
        "http-tomcat":  "tomcat",
        "weblogic":     "weblogic",
        "samba":        "microsoft-ds",
        "ms-sql-s":     "mssql",
        "mssql":        "mssql",
        "docker":       "docker",
        "postgresql":   "postgresql",
        "postgres":     "postgresql",
    }
    return aliases.get(service, service)


def _extract_product_version(finding) -> tuple:
    """
    Extract product name and version string from a finding.

    Looks in: title, description, raw_evidence
    Returns: (product_str, version_str) — both lowercase, may be empty string
    """
    text = " ".join([
        finding.title or "",
        finding.description or "",
        finding.raw_evidence or "",
    ]).lower()

    # Common patterns:
    #   "dropbear sshd 2012.55"
    #   "openssh 7.2p2"
    #   "apache httpd 2.4.49"
    #   "tp-link wap"
    #   "mysql 5.7.32"

    product = ""
    version = ""

    # Product detection
    product_patterns = [
        (r"dropbear",           "dropbear"),
        (r"openssh",            "openssh"),
        (r"apache",             "apache"),
        (r"nginx",              "nginx"),
        (r"iis",                "iis"),
        (r"tp.?link",           "tp-link"),
        (r"vsftpd",             "vsftpd"),
        (r"proftpd",            "proftpd"),
        (r"portable sdk.*upnp", "portable sdk for upnp"),
        (r"mysql",              "mysql"),
        (r"mariadb",            "mysql"),
        (r"redis",              "redis"),
        (r"mongodb",            "mongodb"),
        (r"tomcat",             "tomcat"),
        (r"weblogic",           "weblogic"),
        (r"samba",              "samba"),
        (r"microsoft sql server", "mssql"),
        (r"mssql",              "mssql"),
        (r"docker",             "docker"),
        (r"postgresql",         "postgresql"),
    ]
    for pattern, name in product_patterns:
        if re.search(pattern, text):
            product = name
            break

    # Version extraction — grab the first version-like string after the product
    version_match = re.search(r"(\d+[\.\d]+(?:p\d+)?(?:\.\w+)?)", text)
    if version_match:
        version = version_match.group(1)

    return product, version


def _find_best_match(entries: list, product: str, version: str) -> dict | None:
    """
    Find the best matching entry from the knowledge base.

    Priority order:
      1. Exact version match for the detected product
      2. Version-before match for the detected product
      3. Product-only match (no version constraint)
      4. Service-level fallback (product=None entry)
    """
    fallback = None

    for entry in entries:
        entry_product = (entry.get("product") or "").lower()
        version_match = entry.get("version_match")
        version_before = entry.get("version_before")

        # Track the fallback (entry with no product constraint)
        if not entry_product:
            if fallback is None:
                fallback = entry
            continue

        # Skip if product doesn't match
        if product and entry_product and entry_product not in product and product not in entry_product:
            continue

        # Exact version match
        if version_match and version:
            if version.startswith(version_match):
                return entry

        # Version-before match
        if version_before and version:
            if _version_less_than(version, version_before):
                return entry

        # Product matched, no version constraint
        if not version_match and not version_before:
            return entry

    return fallback


def _version_less_than(v1: str, v2: str) -> bool:
    """
    Return True if version v1 is less than v2.

    Handles versions like: "7.2p2", "2012.55", "2.4.49", "1.6.19"
    Non-numeric parts (like 'p2') are stripped for comparison.
    """
    def normalise(v: str) -> tuple:
        # Extract only numeric parts separated by dots
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts)

    try:
        return normalise(v1) < normalise(v2)
    except (ValueError, TypeError):
        return False
