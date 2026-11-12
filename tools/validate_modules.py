"""Validate bundled module paths using a local metadata file or an explicit download.

Offline: python tools/validate_modules.py --metadata metadata.json
Online:  python tools/validate_modules.py --online --revision <Rapid7 commit SHA>
An optional --output writes provenance JSON; normal analysis never runs this tool.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

import requests

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 25 * 1024 * 1024


def validate(knowledge, metadata):
    if not isinstance(metadata, dict):
        raise ValueError("expected Rapid7 metadata object")
    available = {record["fullname"] for record in metadata.values()
                 if isinstance(record, dict) and isinstance(record.get("fullname"), str)}
    if not available:
        raise ValueError("metadata has no canonical module fullnames")
    modules = set()
    for entries in knowledge.values():
        for entry in entries:
            modules.update(entry.get("metasploit_modules", []))
    return {"checked": len(modules), "valid": sorted(modules & available),
            "missing": sorted(modules - available)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--metadata", type=Path, help="Local Rapid7 metadata JSON; no network")
    mode.add_argument("--online", action="store_true", help="Download official pinned metadata")
    parser.add_argument("--revision", help="Full 40-character Rapid7 commit SHA; required online")
    parser.add_argument("--output", type=Path, help="Write validation/provenance JSON")
    args = parser.parse_args(argv)
    source = str(args.metadata) if args.metadata else None
    try:
        if args.online:
            if not re.fullmatch(r"[0-9a-fA-F]{40}", args.revision or ""):
                parser.error("--online requires --revision with a full commit SHA")
            source = ("https://raw.githubusercontent.com/rapid7/metasploit-framework/"
                      f"{args.revision}/db/modules_metadata_base.json")
            with requests.get(source, timeout=30, stream=True) as response:
                response.raise_for_status()
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise ValueError("metadata exceeds size limit")
                    chunks.append(chunk)
                raw = b"".join(chunks)
        else:
            if args.metadata.stat().st_size > MAX_BYTES:
                raise ValueError("metadata exceeds size limit")
            raw = args.metadata.read_bytes()
        knowledge = json.loads((ROOT / "vulnmind/knowledge/services.json").read_text())
        result = validate(knowledge, json.loads(raw))
        result.update(source=source, revision=args.revision,
                      sha256=hashlib.sha256(raw).hexdigest(),
                      validated_at=datetime.now(timezone.utc).isoformat())
        encoded = json.dumps(result, indent=2) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return int(bool(result["missing"]))
    except (OSError, ValueError, requests.RequestException) as exc:
        print(f"Module validation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
