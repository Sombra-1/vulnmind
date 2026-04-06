"""
parsers/metasploit.py — Parse Metasploit console output into Finding objects.
"""
import re
from pathlib import Path
from typing import Optional

from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp

class MetasploitParser(BaseParser):
    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        # Require msf prompt or specific Metasploit markers — not just [+]/[*]
        # which appear in many unrelated files (markdown, logs, etc.)
        return (
            "msf6 >" in content_preview
            or "msf5 >" in content_preview
            or "msf>" in content_preview
            or "Metasploit Framework" in content_preview
        )

    def parse(self, file_path: Path, content: str) -> list:
        findings = []
        seen_ids = set()
        
        # Match lines like: [+] 192.168.1.10:445 - Login Successful: admin:admin
        # Or: [*] 192.168.1.10:80 - Apache 2.4.49 Server Found
        pattern = re.compile(r"^\[(\+|\*)\]\s+([\d\.]+)(?::(\d+))?\s+-\s+(.+)$")
        
        for line in content.splitlines():
            line = line.strip()
            match = pattern.match(line)
            if not match:
                continue
                
            status_char, host, port_str, message = match.groups()
            port = int(port_str) if port_str else None
            
            # [+] usually means a positive finding (success/vuln)
            priority = "high" if status_char == "+" else "low"
            
            # Extract CVE if present in message
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", message, re.IGNORECASE)
            cves = [c.upper() for c in cves]
            
            title = message[:50] + ("..." if len(message) > 50 else "")
            finding_id = make_finding_id(host, port, title)
            
            if finding_id not in seen_ids:
                finding = Finding(
                    id=finding_id,
                    source_tool="metasploit",
                    source_file=str(file_path),
                    timestamp=make_timestamp(),
                    host=host,
                    port=port,
                    protocol="tcp" if port else None,
                    service=None,
                    title=title,
                    description=message,
                    raw_evidence=line,
                    cve_ids=cves,
                    priority=priority
                )
                findings.append(finding)
                seen_ids.add(finding_id)
                
        return findings
