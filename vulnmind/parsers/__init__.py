"""
parsers/__init__.py — Auto-detector and dispatcher.

This module is the front door to all parsing.
The load_files() function is the only thing cli.py needs to call.

How auto-detection works:
  1. Read the first 200 bytes of each file (the "content preview")
  2. Ask each registered parser: can_parse(path, preview)?
  3. The first parser that says yes parses the full file
  4. Deduplicate findings across files using Finding.id

Why content-signature detection instead of file extensions?
  On Kali and Parrot, it's common to:
    - Run `nmap 192.168.1.0/24 > scan.txt`  (text output named .txt)
    - Run `nmap -oA basename` then pass all 3 files
    - Rename files to generic names like "output.log"
  Extensions are hints, not guarantees. Always trust content over name.

Adding a new parser:
  1. Create vulnmind/parsers/yourparser.py
  2. Subclass BaseParser, implement can_parse() and parse()
  3. Add it to REGISTERED_PARSERS below
  That's the entire integration. Nothing else changes.
"""

from pathlib import Path

from vulnmind.parsers.base import ParseError
from vulnmind.parsers.nmap import NmapParser
from vulnmind.parsers.nikto import NiktoParser
from vulnmind.parsers.metasploit import MetasploitParser

# All registered parsers, in priority order.
# If two parsers both claim can_parse() = True, the first one wins.
# Put more specific parsers before more general ones.
REGISTERED_PARSERS = [
    NmapParser(),
    NiktoParser(),
    MetasploitParser(),
]


def detect_and_parse(file_path: Path) -> list:
    """
    Read a file, detect its format, and return a list of Finding objects.

    Args:
        file_path: Path to the scanner output file

    Returns:
        List[Finding] — may be empty if the file had no relevant findings

    Raises:
        ParseError: if no parser recognises the file format
        OSError: if the file can't be read
    """
    # Read file content. Use errors='replace' to handle non-UTF8 bytes
    # (some nmap output can contain binary data in service version strings)
    content = file_path.read_text(encoding="utf-8", errors="replace")
    content_preview = content[:200]

    for parser in REGISTERED_PARSERS:
        if parser.can_parse(file_path, content_preview):
            return parser.parse(file_path, content)

    # No parser matched — give the user a helpful error message
    supported = "nmap XML (-oX), nmap text (-oN), Nikto text output"
    raise ParseError(
        f"Could not detect file format for '{file_path.name}'.\n"
        f"Supported formats: {supported}.\n"
        f"Tip: for nmap, use '-oX scan.xml' to save structured XML output."
    )


def load_files(file_paths: list) -> list:
    """
    Parse multiple files and return deduplicated findings.

    Why deduplicate?
      nmap -oA saves scan.xml, scan.nmap, and scan.gnmap simultaneously.
      If the user passes all three, the same finding would appear three times.
      Finding.id is a deterministic hash, so identical findings produce
      identical IDs — we skip any ID we've already seen.

    Args:
        file_paths: List of Path objects to parse

    Returns:
        List[Finding] deduplicated across all input files
    """
    all_findings = []
    seen_ids = set()

    for path in file_paths:
        findings = detect_and_parse(path)
        for finding in findings:
            if finding.id not in seen_ids:
                all_findings.append(finding)
                seen_ids.add(finding.id)

    return all_findings
