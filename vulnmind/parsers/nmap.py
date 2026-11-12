"""
parsers/nmap.py — Parse nmap scan output into Finding objects.

Supports two formats:
  XML  (-oX or -oA): structured, unambiguous, preferred
  Text (-oN or -oA): regex-based, human-readable output

Why support both?
  Many pentesters run:  nmap 192.168.1.1 > scan.txt
  The XML flag (-oX) is the "right" way but not everyone uses it.
  Supporting text output means VulnMind works with whatever the user has.

Which should users prefer?
  Always use -oX or -oA if you can. XML gives us:
    - Service versions (for CVE matching)
    - NSE script names and output (where CVE IDs often appear)
    - Accurate port state (open/closed/filtered)
  Text output can lose information depending on terminal width and nmap version.

The NmapParser class detects which format was passed and routes to the
correct parsing method internally.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from typing import Optional

from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp

# Pattern to find CVE IDs anywhere in text: CVE-2021-44228, CVE-2023-1234
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapParser(BaseParser):
    """
    Parses nmap XML and text output into Finding objects.

    The can_parse() method checks for nmap content signatures.
    The parse() method detects XML vs text and routes accordingly.
    """

    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        """Return True if this looks like nmap output."""
        # nmap XML always starts with an XML declaration and has 'nmaprun'
        if "nmaprun" in content_preview:
            return True
        # nmap text output always contains this header line
        if "Nmap scan report for" in content_preview:
            return True
        # nmap text output alternative header (when no hosts found)
        if "Starting Nmap" in content_preview and "Nmap done" in content_preview:
            return True
        return False

    def parse(self, file_path: Path, content: str) -> list:
        """Parse nmap output. Auto-detects XML vs text format."""
        # XML detection: look for the XML declaration or the nmaprun root element
        if content.lstrip().startswith("<?xml") or "<nmaprun" in content[:500]:
            return self._parse_xml(file_path, content)
        else:
            return self._parse_text(file_path, content)

    # ------------------------------------------------------------------
    # XML Parsing
    # ------------------------------------------------------------------

    def _parse_xml(self, file_path: Path, content: str) -> list:
        """
        Parse nmap XML output (-oX or -oA).

        The nmap XML structure is:
          <nmaprun>
            <host>
              <address addr="192.168.1.1" addrtype="ipv4"/>
              <ports>
                <port portid="80" protocol="tcp">
                  <state state="open"/>
                  <service name="http" product="Apache" version="2.4.49"/>
                  <script id="http-vuln-cve2021-41773" output="..."/>
                </port>
              </ports>
            </host>
          </nmaprun>

        We only create Finding objects for OPEN ports. Closed and filtered
        ports are not actionable for a pentester.
        """
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid nmap XML: {e}") from e

        findings = []
        seen_ids = set()  # for deduplication

        for host_elem in root.findall("host"):
            # Get the host's IP address
            host_ip = self._get_host_address(host_elem)
            if not host_ip:
                continue

            # Get hostname if available (more descriptive than raw IP)
            hostname = self._get_hostname(host_elem)
            display_host = hostname if hostname else host_ip

            # Process each port
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue  # Skip closed/filtered ports

                try:
                    port_num = int(port_elem.get("portid", ""))
                except ValueError:
                    continue
                if not 1 <= port_num <= 65535:
                    continue
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_info = self._parse_service(service_elem)

                # Collect all NSE script output for this port
                scripts = port_elem.findall("script")
                blocked_script_evidence = [
                    f"{script.get('id', 'unknown')}: "
                    f"{script.get('output', '').strip()[:500]}"
                    for script in scripts
                    if _script_blocks_kb_inference(
                        script.get("id", ""),
                        script.get("output", ""),
                    )
                ]
                negated_cves = {
                    cve_id
                    for script in scripts
                    for cve_id in _explicitly_negated_cves(
                        script.get("id", ""),
                        script.get("output", ""),
                    )
                }
                script_findings = self._parse_scripts(
                    scripts, display_host, port_num, protocol,
                    service_info, file_path, seen_ids
                )

                if script_findings:
                    if blocked_script_evidence:
                        script_findings = [
                            _attach_blocked_script_evidence(
                                finding,
                                blocked_script_evidence,
                                negated_cves,
                            )
                            for finding in script_findings
                        ]
                    # Scripts found vulnerabilities — use those as findings
                    findings.extend(script_findings)
                    seen_ids.update(f.id for f in script_findings)
                else:
                    # No scripts — create a basic "open port" finding
                    finding = self._make_open_port_finding(
                        display_host,
                        port_num,
                        protocol,
                        service_info,
                        file_path,
                        blocked_script_evidence=blocked_script_evidence,
                    )
                    if finding.id not in seen_ids:
                        findings.append(finding)
                        seen_ids.add(finding.id)

        return findings

    def _get_host_address(self, host_elem) -> Optional[str]:
        """Extract IPv4 address from a <host> element."""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                return addr.get("addr")
        # Fallback: try IPv6
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv6":
                return addr.get("addr")
        return None

    def _get_hostname(self, host_elem) -> Optional[str]:
        """Extract the first hostname from a <host> element, if any."""
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                return hostname_elem.get("name")
        return None

    def _parse_service(self, service_elem) -> dict:
        """Extract service info from a <service> element."""
        if service_elem is None:
            return {"name": "unknown", "product": "", "version": "", "display": "unknown"}

        name = service_elem.get("name", "unknown")
        product = service_elem.get("product", "")
        version = service_elem.get("version", "")

        parts = [p for p in [product, version] if p]
        display = f"{name} ({' '.join(parts)})" if parts else name

        return {
            "name": name,
            "product": product,
            "version": version,
            "display": display,
        }

    def _parse_scripts(
        self, scripts, host, port, protocol, service_info, file_path, seen_ids
    ) -> list:
        """
        Convert NSE script results into Finding objects.

        NSE scripts like vulners, smb-vuln-*, http-shellshock etc. embed
        vulnerability information in their output. If a script name contains
        'vuln' or its output contains CVE IDs, it's worth making a Finding for it.

        The 'vulners' script is special — it outputs multiple CVEs, one per line.
        We create one Finding per CVE group from that script.
        """
        findings = []

        for script in scripts:
            script_id = script.get("id", "")
            output = script.get("output", "").strip()

            if not output:
                continue

            if not _script_reports_vulnerability(script_id, output):
                continue

            cve_ids = sorted({c.upper() for c in CVE_PATTERN.findall(output)})

            title = f"{script_id} on {host}:{port}"
            description = f"NSE script '{script_id}' flagged {host}:{port}/{protocol}."
            if cve_ids:
                description += f" Associated CVEs: {', '.join(cve_ids)}"

            finding_id = make_finding_id(host, port, script_id if protocol == "tcp" else f"{protocol}:{script_id}")
            if finding_id in seen_ids:
                continue

            # Attach service context (product, version) to evidence so the
            # matcher sees them even if the NSE output doesn't mention them.
            ev_parts = [f"Script: {script_id}"]
            product = service_info.get("product", "")
            version = service_info.get("version", "")
            if product:
                ev_parts.append(f"product: {product}")
            if version:
                ev_parts.append(f"version: {version}")
            ev_parts.append(f"Output:\n{output[:800]}")

            findings.append(Finding(
                id=finding_id,
                source_tool="nmap",
                source_file=str(file_path),
                timestamp=make_timestamp(),
                host=host,
                port=port,
                protocol=protocol,
                service=service_info["name"],
                title=title,
                description=description,
                raw_evidence="\n".join(ev_parts),
                cve_ids=list(dict.fromkeys(cve_ids)),  # deduplicated, order-preserved
                confidence="scanner-reported",
            ))

        return findings

    def _make_open_port_finding(
        self,
        host,
        port,
        protocol,
        service_info,
        file_path,
        blocked_script_evidence=None,
    ) -> Finding:
        """Create a basic Finding for an open port with no NSE vuln scripts."""
        product = service_info.get("product", "")
        version = service_info.get("version", "")
        display = service_info["display"]

        # Build a descriptive title that includes product+version when available
        if product and version:
            title = f"Open port {port}/{protocol} — {product} {version}"
        elif product:
            title = f"Open port {port}/{protocol} — {product}"
        else:
            title = f"Open port {port}/{protocol} ({display})"

        description = (
            f"Port {port}/{protocol} is open on {host}, "
            f"running {display}."
        )

        # Include product and version explicitly in raw_evidence so the matcher
        # can reliably extract them for CVE lookups.
        evidence_parts = [f"host: {host}  port: {port}/{protocol}  state: open"]
        evidence_parts.append(f"service: {service_info['name']}")
        if product:
            evidence_parts.append(f"product: {product}")
        if version:
            evidence_parts.append(f"version: {version}")
        evidence_parts.append(display)
        if blocked_script_evidence:
            evidence_parts.append(
                "kb-vulnerability-inference: blocked "
                "(explicit negative or inconclusive NSE result)"
            )
            evidence_parts.extend(
                f"NSE result: {evidence}" for evidence in blocked_script_evidence
            )

        return Finding(
            # Basic open-port IDs deliberately ignore presentation differences
            # between nmap XML and text output from the same -oA scan.
            id=make_finding_id(host, port, f"open-port:{protocol}"),
            source_tool="nmap",
            source_file=str(file_path),
            timestamp=make_timestamp(),
            host=host,
            port=port,
            protocol=protocol,
            service=service_info["name"],
            title=title,
            description=description,
            raw_evidence="\n".join(evidence_parts),
            cve_ids=[],
        )

    # ------------------------------------------------------------------
    # Text Parsing
    # ------------------------------------------------------------------

    def _parse_text(self, file_path: Path, content: str) -> list:
        """
        Parse nmap text output (-oN or stdout redirect).

        nmap text output looks like:

          Nmap scan report for 192.168.1.1
          Host is up (0.0012s latency).
          PORT     STATE  SERVICE  VERSION
          22/tcp   open   ssh      OpenSSH 7.2p2
          80/tcp   open   http     Apache httpd 2.4.49
          | http-vuln-cve2021-41773:
          |   VULNERABLE:
          |   CVE-2021-41773

        We use a state machine:
          - When we see "Nmap scan report for", set current host
          - When we see a PORT line (number/proto  open), record it
          - When we see a script block (lines starting with |), collect it
          - When we see a blank line or new host, flush the current port
        """
        findings = []
        seen_ids = set()

        lines = content.splitlines()
        current_host = None
        current_port = None
        current_protocol = None
        current_service = None
        current_service_version = ""  # full version string for context
        current_script_name = None
        script_buffer = []
        blocked_script_evidence = {}
        negated_cves_by_port = {}

        # Regex patterns for the text format
        # Matches: "22/tcp   open   ssh      OpenSSH 7.2p2 Ubuntu..."
        port_line_re = re.compile(
            r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)?$"
        )
        # Matches: "Nmap scan report for 192.168.1.1" or "...for example.com (192.168.1.1)"
        host_re = re.compile(
            r"^Nmap scan report for (\S+)(?:\s+\(([^)]+)\))?$"
        )
        # Matches NSE script output: "| script-name:" or "|_script-name:"
        script_start_re = re.compile(r"^\| ([a-zA-Z0-9_-]+):\s*$")
        script_line_re = re.compile(r"^\|[_ ]?\s?(.*)")

        def flush_script():
            """Create a Finding from buffered script output."""
            nonlocal current_script_name, script_buffer
            if not current_script_name or not script_buffer or not current_host:
                current_script_name = None
                script_buffer = []
                return

            output = "\n".join(script_buffer).strip()
            cve_ids = sorted({c.upper() for c in CVE_PATTERN.findall(output)})
            is_vuln = _script_reports_vulnerability(
                current_script_name,
                output,
            )

            if (
                current_port is not None
                and _script_blocks_kb_inference(current_script_name, output)
            ):
                key = (current_host, current_port, current_protocol)
                blocked_script_evidence.setdefault(key, []).append(
                    f"{current_script_name}: {output[:500]}"
                )
                negated_cves_by_port.setdefault(key, set()).update(
                    _explicitly_negated_cves(current_script_name, output)
                )

            if is_vuln and current_port is not None:
                finding_id = make_finding_id(
                    current_host, current_port, current_script_name if current_protocol == "tcp"
                    else f"{current_protocol}:{current_script_name}",
                )
                if finding_id not in seen_ids:
                    title = f"{current_script_name} on {current_host}:{current_port}"
                    # Include service context in evidence so matcher can detect
                    # the product (e.g. "Apache httpd 2.4.41") even when the
                    # NSE output itself doesn't name the product.
                    evidence_lines = [f"Script: {current_script_name}"]
                    if current_service_version:
                        evidence_lines.append(f"service: {current_service_version}")
                    evidence_lines.append(output[:800])
                    findings.append(Finding(
                        id=finding_id,
                        source_tool="nmap",
                        source_file=str(file_path),
                        timestamp=make_timestamp(),
                        host=current_host,
                        port=current_port,
                        protocol=current_protocol,
                        service=current_service,
                        title=title,
                        description=f"NSE script '{current_script_name}' flagged this port.",
                        raw_evidence="\n".join(evidence_lines),
                        cve_ids=list(dict.fromkeys(cve_ids)),
                        confidence="scanner-reported",
                    ))
                    seen_ids.add(finding_id)

            current_script_name = None
            script_buffer = []

        pending_open_ports = []  # (host, port, proto, service) — add at end if no script findings

        for line in lines:
            # New host
            m = host_re.match(line)
            if m:
                flush_script()
                # If the previous port had no script findings, record it as a basic finding
                for h, p, pr, svc in pending_open_ports:
                    f = self._make_open_port_finding(
                        h,
                        p,
                        pr,
                        {"name": svc, "display": svc},
                        file_path,
                        blocked_script_evidence=blocked_script_evidence.get((h, p, pr)),
                    )
                    if f.id not in seen_ids:
                        findings.append(f)
                        seen_ids.add(f.id)
                pending_open_ports.clear()

                hostname_part = m.group(1)
                ip_part = m.group(2)
                # Match XML behavior: prefer the displayed hostname when nmap
                # emits "hostname (IP)" so -oA XML/text IDs deduplicate.
                current_host = hostname_part if ip_part else hostname_part
                current_port = None
                continue

            # Open port line
            m = port_line_re.match(line)
            if m and current_host:
                flush_script()
                current_port = int(m.group(1))
                if not 1 <= current_port <= 65535:
                    current_port = None
                    continue
                current_protocol = m.group(2)
                current_service = m.group(4)
                version = m.group(5).strip() if m.group(5) else ""
                current_service_version = version
                svc_display = f"{current_service} {version}".strip()
                pending_open_ports.append((current_host, current_port, current_protocol, svc_display))
                continue

            # NSE script start: "| script-name:"
            m = script_start_re.match(line)
            if m and current_port is not None:
                flush_script()
                current_script_name = m.group(1)
                script_buffer = []
                continue

            # NSE script content line: starts with "| " or "|_"
            m = script_line_re.match(line)
            if m and current_script_name:
                script_buffer.append(m.group(1))
                continue

            # Blank line — flush current script
            if not line.strip() and current_script_name:
                flush_script()

        # End of file — flush remaining state
        flush_script()
        for h, p, pr, svc in pending_open_ports:
            f = self._make_open_port_finding(
                h,
                p,
                pr,
                {
                    "name": svc.split()[0] if svc else "unknown",
                    "display": svc,
                },
                file_path,
                blocked_script_evidence=blocked_script_evidence.get((h, p, pr)),
            )
            if f.id not in seen_ids:
                findings.append(f)
                seen_ids.add(f.id)

        # Text output can report several NSE scripts on one port in either
        # order. Propagate a negative/inconclusive sibling to every positive
        # script finding on that port so version-only matching cannot reverse
        # the dedicated check after parsing.
        for index, finding in enumerate(findings):
            evidence = blocked_script_evidence.get((finding.host, finding.port, finding.protocol))
            if evidence and not finding.title.startswith("Open port "):
                findings[index] = _attach_blocked_script_evidence(
                    finding,
                    evidence,
                    negated_cves_by_port.get(
                        (finding.host, finding.port, finding.protocol),
                        set(),
                    ),
                )

        return findings


def _is_explicit_negative_result(output: str) -> bool:
    """Return true when NSE explicitly reports that the target is unaffected."""
    if not isinstance(output, str):
        return False
    return bool(re.search(
        r"\bNOT\s+VULNERABLE\b|\bNOT\s+AFFECTED\b|"
        r"\bVULNERABLE\s*:\s*(?:FALSE|NO)\b|"
        r"\b(?:NO|ZERO|0)\s+(?:KNOWN\s+)?VULNERABILIT(?:Y|IES)"
        r"(?:\s+(?:WAS|WERE))?\s+(?:FOUND|DETECTED|IDENTIFIED)\b",
        output,
        re.IGNORECASE,
    ))


def _script_reports_vulnerability(script_id: str, output: str) -> bool:
    """Require positive NSE evidence, not merely a vulnerability script name."""
    if (
        not isinstance(output, str)
        or _is_explicit_negative_result(output)
        or _is_inconclusive_result(output)
    ):
        return False

    positive_status = re.search(
        r"(?:^|\n)\s*(?:STATE\s*:\s*)?(?:LIKELY\s+)?VULNERABLE\b|"
        r"\b(?:TARGET|HOST)\s+IS\s+(?:LIKELY\s+)?VULNERABLE\b|"
        r"(?:^|\n)\s*(?:STATE\s*:\s*)?EXPLOITABLE\b|"
        r"(?:^|\n)\s*BACKDOOR\b",
        output,
        re.IGNORECASE,
    )
    if positive_status:
        return True

    # Scripts such as `vulners` emit CVE rows rather than a VULNERABLE state.
    # Exact scanner-reported CVEs remain valid positive evidence.
    return CVE_PATTERN.search(output) is not None


def _is_inconclusive_result(output: str) -> bool:
    """Return true when NSE could not determine vulnerability status."""
    if not isinstance(output, str):
        return False
    return bool(re.search(
        r"(?:^|\n)\s*(?:ERROR|FAILED)\s*:|"
        r"SCRIPT\s+EXECUTION\s+FAILED|"
        r"COULD\s+NOT\s+DETERMINE|CAN(?:NO|')?T\s+DETERMINE|"
        r"UNABLE\s+TO\s+DETERMINE|INCONCLUSIVE|"
        r"\bTIMED?\s*OUT\b|\bTIMEOUT\b|"
        r"COULD\s+NOT\s+CONNECT|CONNECTION\s+(?:FAILED|REFUSED)|"
        r"CHECK\s+FAILED",
        output,
        re.IGNORECASE,
    ))


def _script_blocks_kb_inference(script_id: str, output: str) -> bool:
    """Protect a dedicated negative/inconclusive NSE result from KB reversal."""
    if not isinstance(script_id, str) or not isinstance(output, str):
        return False
    vulnerability_script = (
        "vuln" in script_id.lower()
        or CVE_PATTERN.search(script_id) is not None
        or CVE_PATTERN.search(output) is not None
    )
    return vulnerability_script and (
        _is_explicit_negative_result(output)
        or _is_inconclusive_result(output)
    )


def _attach_blocked_script_evidence(
    finding: Finding,
    evidence: list[str],
    negated_cves: set[str] | None = None,
) -> Finding:
    """Carry port-level contradictory NSE evidence into a positive sibling."""
    marker = (
        "kb-vulnerability-inference: blocked "
        "(explicit negative or inconclusive NSE result)"
    )
    if marker in (finding.raw_evidence or ""):
        return finding
    raw_evidence = "\n".join([
        finding.raw_evidence,
        marker,
        *(f"NSE result: {item}" for item in evidence),
    ])
    excluded = {cve.upper() for cve in (negated_cves or set())}
    cve_ids = [
        cve_id
        for cve_id in finding.cve_ids
        if not isinstance(cve_id, str) or cve_id.upper() not in excluded
    ]
    description = finding.description
    if cve_ids != finding.cve_ids:
        description = (
            f"NSE script '{finding.title.split(' on ', 1)[0]}' reported a "
            "positive result; CVEs contradicted by a dedicated negative "
            "check on the same port were omitted."
        )
    return replace(
        finding,
        raw_evidence=raw_evidence,
        cve_ids=cve_ids,
        description=description,
        priority=finding.priority or "medium",
        priority_reason=(
            finding.priority_reason
            or "NSE reported a positive result; a separate negative or "
            "inconclusive check prevented version-only CVE inference."
        ),
    )


def _explicitly_negated_cves(script_id: str, output: str) -> set[str]:
    """Extract CVEs covered by a dedicated explicit-negative NSE result."""
    if not _is_explicit_negative_result(output):
        return set()
    cves = {match.upper() for match in CVE_PATTERN.findall(output)}
    for year, number in re.findall(
        r"CVE[-_]?([0-9]{4})[-_]?([0-9]{4,7})",
        script_id,
        re.IGNORECASE,
    ):
        cves.add(f"CVE-{year}-{number}")
    return cves
