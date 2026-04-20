"""
parsers/metasploit.py — Parse Metasploit console output into Finding objects.

Metasploit's `spool` command or just piping msfconsole output to a file
gives text like:

    msf6 > use auxiliary/scanner/smb/smb_ms17_010
    msf6 auxiliary(scanner/smb/smb_ms17_010) > run

    [+] 192.168.1.10:445       - Host is likely VULNERABLE to MS17-010!
    [+] 192.168.1.10:445       - Login Successful: ADMIN:password
    [*] 192.168.1.10:22        - SSH - Starting bruteforce
    [-] 192.168.1.10:21        - FTP - Login failed
    [*] Scanned 1 of 1 hosts (100% complete)

We extract:
  [+] lines → findings with high priority (a success / confirmed vuln)
  [*] lines → only if they mention a CVE, vulnerability, or confirmed fact
  [-] lines → ignored (failed attempts)

We also capture the `use <module>` lines seen before findings so we can
attach the attacking module to the finding's metasploit_modules list.

Result: cleaner, higher-signal findings from msfconsole logs.
"""

import re
from pathlib import Path
from typing import Optional

from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# [+] host:port - message  OR  [+] host - message  OR [*] host:port - message
LINE_RE = re.compile(
    r"^\[(?P<marker>[+*!])\]\s+(?P<host>[\d.]+|[a-zA-Z][\w.-]*)"
    r"(?::(?P<port>\d+))?\s*-?\s*(?P<message>.+)$"
)

# Lines like: msf6 > use auxiliary/scanner/smb/smb_ms17_010
USE_RE = re.compile(r"(?:^|\s)use\s+(\S+/\S+)")

# Lines like: msf6 auxiliary(scanner/smb/smb_ms17_010) > run
MODULE_CONTEXT_RE = re.compile(r"msf\d?\s+\w+\(([^)]+)\)\s*>")

# Vulnerability / noteworthy keywords — tell us [*] lines that matter
VULN_KEYWORDS = [
    "vulnerable", "vulnerability", "backdoor", "rce",
    "ms17-010", "eternalblue", "meterpreter session", "login successful",
    "credentials", "default creds", "information disclosure",
    "traversal", "injection",
]

# Noise keywords — skip lines that match these even with [+] marker
NOISE_PATTERNS = [
    "connecting to target",
    "sending smb fragments",
    "started reverse",
    "executing automatic check",
    "connection established",
    "starting bruteforce",
    "scanned ",
]


class MetasploitParser(BaseParser):
    """Parses msfconsole text output into Finding objects."""

    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        """Return True if this looks like metasploit output."""
        signals = (
            "msf6 >",
            "msf5 >",
            "msf>",
            "msf >",
            "Metasploit Framework",
            "=[ metasploit",
        )
        return any(s.lower() in content_preview.lower() for s in signals)

    def parse(self, file_path: Path, content: str) -> list:
        findings = []
        seen_ids = set()
        current_module: Optional[str] = None

        for line in content.splitlines():
            line = line.rstrip()

            # Track the current active module — used to attribute findings
            use_match = USE_RE.search(line)
            if use_match:
                current_module = use_match.group(1)
                continue

            ctx_match = MODULE_CONTEXT_RE.search(line)
            if ctx_match:
                current_module = ctx_match.group(1)
                continue

            match = LINE_RE.match(line.strip())
            if not match:
                continue

            marker = match.group("marker")
            host = match.group("host")
            port_str = match.group("port")
            message = match.group("message").strip()

            low = message.lower()
            cves = [c.upper() for c in CVE_PATTERN.findall(message)]

            # Skip scan progress and failed attempts
            if marker == "*" and not _is_noteworthy(message) and not cves:
                continue
            if marker == "!":  # warning — usually noise
                continue

            # Skip progress lines even when marked [+]
            if re.search(r"\bof\s+\d+\s+hosts", message):
                continue

            # Skip noise even when marked [+]
            if any(p in low for p in NOISE_PATTERNS):
                continue

            try:
                port = int(port_str) if port_str else None
            except ValueError:
                port = None

            priority = _priority_from_message(marker, message, cves)

            title = message[:70] + ("..." if len(message) > 70 else "")
            finding_id = make_finding_id(host, port, title)
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)

            # Attach the active module if we saw a `use` / context line
            modules = [current_module] if current_module else []

            findings.append(Finding(
                id=finding_id,
                source_tool="metasploit",
                source_file=str(file_path),
                timestamp=make_timestamp(),
                host=host,
                port=port,
                protocol="tcp" if port else None,
                service=_service_from_port(port),
                title=title,
                description=message,
                raw_evidence=line,
                cve_ids=cves,
                priority=priority,
                metasploit_modules=modules,
            ))

        return findings


def _is_noteworthy(message: str) -> bool:
    """Return True if a [*] status line carries useful info."""
    low = message.lower()
    return any(kw in low for kw in VULN_KEYWORDS)


def _priority_from_message(marker: str, message: str, cves: list) -> str:
    """Derive a default priority from the marker, message keywords, and CVEs."""
    low = message.lower()
    if "vulnerable" in low or "successful" in low or "login successful" in low:
        return "high"
    if "shell" in low or "meterpreter" in low or "rce" in low or "backdoor" in low:
        return "critical"
    if cves:
        return "high"
    if marker == "+":
        return "high"
    return "medium"


def _service_from_port(port: Optional[int]) -> Optional[str]:
    """Best-effort service name from well-known port numbers."""
    if port is None:
        return None
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "domain", 80: "http", 110: "pop3", 111: "rpcbind",
        143: "imap", 443: "http", 445: "microsoft-ds",
        993: "imap", 995: "pop3", 1433: "mssql", 1521: "oracle",
        2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http", 8443: "http",
        9200: "elasticsearch", 27017: "mongodb",
    }
    return common.get(port)
