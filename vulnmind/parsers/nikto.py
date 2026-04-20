"""
parsers/nikto.py — Parse nikto web scanner output into Finding objects.

Nikto is a web server scanner. It checks for:
  - Dangerous files and CGIs
  - Outdated software versions
  - Server misconfigurations
  - Security headers (or their absence)
  - Known vulnerabilities (with CVE or OSVDB references)

Output format:
  nikto output (text mode) looks like this:

    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          192.168.1.10
    + Target Hostname:    target.local
    + Target Port:        80
    + Start Time:         2024-01-15 10:30:00 (GMT0)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.49 (Ubuntu)
    + /: The anti-clickjacking X-Frame-Options header is not present.
    + OSVDB-3092: /admin/: This might be interesting...
    + /: CVE-2021-41773 - Apache HTTP Server Path Traversal.
    + 7915 requests: 0 error(s) and 4 item(s) reported

State machine:
  State 0 (HEADER): Looking for Target IP and Port lines
  State 1 (FINDINGS): Processing + lines as findings

OSVDB IDs:
  OSVDB (Open Source Vulnerability Database) shut down in 2016. IDs like
  OSVDB-3092 still appear in nikto output but the database no longer exists.
  We keep the OSVDB ID in the title (for reference) but don't try to look it up.
  If the line also contains a CVE ID, we extract that instead.
"""

import re
from pathlib import Path
from typing import Optional

from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
OSVDB_PATTERN = re.compile(r"OSVDB-(\d+):\s*")


class NiktoParser(BaseParser):
    """Parses nikto text output into Finding objects."""

    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        """Return True if this looks like nikto output."""
        return "- Nikto v" in content_preview or "+ Target IP:" in content_preview

    def parse(self, file_path: Path, content: str) -> list:
        """
        Parse nikto text output.

        Uses a simple state machine:
          HEADER state → extract host and port metadata
          FINDINGS state → extract one Finding per + line
        """
        lines = content.splitlines()

        # State
        target_host: Optional[str] = None
        target_port: Optional[int] = None
        in_findings = False
        findings = []
        seen_ids = set()

        # Known header-only keys — lines with these prefixes are metadata, not findings
        _HEADER_PREFIXES = (
            "+ Target IP:",
            "+ Target Hostname:",
            "+ Target Port:",
            "+ Start Time:",
            "+ End Time:",
        )

        for line in lines:
            line = line.strip()

            # Separator lines (---) mark the end of the header block
            if line.startswith("-----"):
                if target_host and target_port:
                    in_findings = True
                continue

            # --- HEADER state ---
            if not in_findings:
                if line.startswith("+ Target IP:"):
                    target_host = line.split(":", 1)[1].strip()
                    continue

                if line.startswith("+ Target Hostname:") and not target_host:
                    # Use hostname only if we didn't get an IP
                    target_host = line.split(":", 1)[1].strip()
                    continue

                if line.startswith("+ Target Port:"):
                    try:
                        target_port = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                    continue

                # Skip any other known header-only lines
                if any(line.startswith(p) for p in _HEADER_PREFIXES):
                    continue

                # Transition to FINDINGS state when we see the first non-header + line
                if line.startswith("+ ") and target_host:
                    in_findings = True
                    # Fall through to findings processing below

            # --- FINDINGS state ---
            if in_findings and line.startswith("+ "):
                content_part = line[2:].strip()  # Strip the leading "+"

                if not content_part:
                    continue

                # Skip summary/closing lines
                if re.match(r"^\d+ requests?:", content_part):
                    continue
                if re.match(r"^\d+ host\(s\) tested", content_part):
                    continue
                if content_part.startswith("End Time:"):
                    continue

                finding = self._parse_finding_line(
                    content_part, target_host, target_port, file_path
                )
                if finding and finding.id not in seen_ids:
                    findings.append(finding)
                    seen_ids.add(finding.id)

        return findings

    def _parse_finding_line(
        self,
        content: str,
        host: Optional[str],
        port: Optional[int],
        file_path: Path,
    ) -> Optional[Finding]:
        """
        Parse a single nikto finding line into a Finding object.

        Examples:
          "Server: Apache/2.4.49 (Ubuntu)"
          "OSVDB-3092: /admin/: This might be interesting..."
          "/: CVE-2021-41773 - Apache HTTP Server Path Traversal."
          "The anti-clickjacking X-Frame-Options header is not present."
        """
        if not host:
            return None

        # Extract CVE IDs from anywhere in the line
        cve_ids = sorted({c.upper() for c in CVE_PATTERN.findall(content)})

        # Extract OSVDB ID if present, then strip it from the content
        osvdb_match = OSVDB_PATTERN.match(content)
        osvdb_id = None
        description = content
        if osvdb_match:
            osvdb_id = f"OSVDB-{osvdb_match.group(1)}"
            description = content[osvdb_match.end():].strip()

        # Build a clean title
        # If the line has a URL path prefix like "/admin/: description", extract it
        path = None
        path_match = re.match(r"^(\/[^\s:]*): (.+)$", description)
        if path_match:
            path = path_match.group(1)
            description = path_match.group(2).strip()

        # Build title
        if osvdb_id:
            title = f"{osvdb_id}: {description[:60]}"
        elif cve_ids:
            title = f"{cve_ids[0]}: {description[:60]}"
        else:
            title = description[:70]

        # Make the title unique enough to generate a stable ID
        # Include the path if we have it, to differentiate /admin/ from /backup/
        id_key = f"{title}{path or ''}"

        return Finding(
            id=make_finding_id(host, port, id_key),
            source_tool="nikto",
            source_file=str(file_path),
            timestamp=make_timestamp(),
            host=host,
            port=port,
            protocol="tcp",
            service="http",
            title=title,
            description=description,
            raw_evidence=content,
            cve_ids=[c.upper() for c in cve_ids],
        )
