"""
parsers/nuclei.py — Parse Nuclei JSONL output into Finding objects.

Nuclei's JSONL output emits one JSON object per result. Typical fields include:
  template-id, info.severity, info.classification.cve-id, host, matched-at,
  matcher-name, extracted-results, and curl-command.

Accuracy rules:
  - Trust CVEs only when Nuclei reports them in info.classification.cve-id.
  - Do not infer CVEs from template IDs or template names.
  - Skip malformed JSONL lines and matcher-status=false events.
"""

from __future__ import annotations

import json
import ipaddress
import math
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from vulnmind.parsers.base import BaseParser, Finding, make_finding_id, make_timestamp

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NucleiParser(BaseParser):
    """Parses Nuclei JSONL output into Finding objects."""

    def can_parse(self, file_path: Path, content_preview: str) -> bool:
        """Return True if this looks like Nuclei JSONL output."""
        # Detection must tolerate the same leading bad records and key aliases
        # as parsing. Stay within the dispatcher's bounded content preview.
        for line in content_preview.lstrip("\ufeff").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # A long record may be cut off by the preview boundary.
                lower = line.lower()
                if (
                    ('"template-id"' in lower or '"templateid"' in lower)
                    and '"info"' in lower
                    and any(f'"{key}"' in lower for key in ("matched-at", "matchedat", "host", "matched"))
                ):
                    return True
                continue

            if isinstance(event, dict):
                keys = set(event)
                if keys & {"template-id", "templateID", "TemplateID"} and keys & {
                    "info", "Info", "matched-at", "matchedAt", "matched", "Matched",
                }:
                    return True
        return False

    def parse(self, file_path: Path, content: str) -> list:
        """Parse Nuclei JSONL. Bad lines are ignored instead of aborting."""
        findings = []
        seen_ids = set()

        for line in content.lstrip("\ufeff").splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            # Nuclei can emit failed matcher-status rows when explicitly asked.
            if _get(event, "matcher-status", "matcherStatus", "MatcherStatus") is False:
                continue

            finding = self._event_to_finding(file_path, event)
            if finding and finding.id not in seen_ids:
                findings.append(finding)
                seen_ids.add(finding.id)

        return findings

    def _event_to_finding(self, file_path: Path, event: dict) -> Optional[Finding]:
        info = _dict(_get(event, "info", "Info"))
        template_id = _string(_get(event, "template-id", "templateID", "TemplateID"))
        template_path = _string(_get(event, "template-path", "templatePath", "TemplatePath"))
        name = _string(_get(info, "name", "Name"))
        severity = _string(_get(info, "severity", "Severity")).lower()
        priority = _priority_from_severity(severity)

        target = _extract_target(event)
        host = target["host"] or "unknown"
        port = target["port"]
        protocol = target["protocol"]
        service = target["service"]
        matched_at = target["matched_at"]

        classification = _dict(_get(info, "classification", "Classification"))
        cve_ids = _extract_classification_cves(classification)
        cvss_score = _parse_cvss(_get(
            classification,
            "cvss-score",
            "cvssScore",
            "CVSSScore",
        ))

        title_base = name or template_id or "Nuclei finding"
        title = title_base[:100]
        description = _string(_get(info, "description", "Description"))
        if not description:
            template_label = template_id or template_path or "a Nuclei template"
            target_label = matched_at or host
            description = f"{template_label} matched {target_label}."

        matcher_name = _string(_get(event, "matcher-name", "matcherName", "MatcherName"))
        extractor_name = _string(_get(event, "extractor-name", "extractorName", "ExtractorName"))
        extracted_results = _strings(_get(
            event,
            "extracted-results",
            "extractedResults",
            "ExtractedResults",
        ))
        curl_command = _string(_get(event, "curl-command", "curlCommand", "CURLCommand"))

        evidence = _build_evidence(
            template_id=template_id,
            template_path=template_path,
            severity=severity,
            matched_at=matched_at,
            matcher_name=matcher_name,
            extractor_name=extractor_name,
            extracted_results=extracted_results,
            cve_ids=cve_ids,
            curl_command=curl_command,
        )

        id_key = template_id or title
        if matched_at:
            id_key = f"{id_key}:{matched_at}"

        priority_reason = _priority_reason(severity, cve_ids, template_id)
        fp_likelihood = "low" if cve_ids else "medium"
        fp_reason = (
            "Nuclei reported CVE classification metadata for this template."
            if cve_ids else
            "Nuclei matched the template, but no CVE classification metadata was present."
        )

        return Finding(
            id=make_finding_id(host, port, id_key),
            source_tool="nuclei",
            source_file=str(file_path),
            timestamp=make_timestamp(),
            host=host,
            port=port,
            protocol=protocol,
            service=service,
            title=title,
            description=description,
            raw_evidence=evidence,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            priority=priority,
            confidence="scanner-reported",
            suggested_commands=[curl_command] if curl_command else [],
            false_positive_likelihood=fp_likelihood,
            false_positive_reason=fp_reason,
            priority_reason=priority_reason,
        )


def _get(data: dict, *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_string(v) for v in value if _string(v)]
    text = _string(value)
    return [text] if text else []


def _extract_classification_cves(classification: dict) -> list[str]:
    raw = _get(classification, "cve-id", "cveId", "CVEID", "cves", "Cves")
    values = raw if isinstance(raw, list) else [raw]
    cves: list[str] = []
    for value in values:
        cves.extend(c.upper() for c in CVE_PATTERN.findall(_string(value)))
    return list(dict.fromkeys(cves))


def _parse_cvss(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    if math.isfinite(score) and 0.0 <= score <= 10.0:
        return score
    return None


def _priority_from_severity(severity: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "unknown": "low",
    }
    return mapping.get((severity or "").lower(), "low")


def _priority_reason(severity: str, cve_ids: list[str], template_id: str) -> str:
    source = f"template {template_id}" if template_id else "a Nuclei template"
    if cve_ids:
        return (
            f"Nuclei reported {len(cve_ids)} CVE classification(s) from {source}; "
            f"severity mapped from '{severity or 'unknown'}'."
        )
    return f"Nuclei severity mapped from '{severity or 'unknown'}' without CVE metadata."


def _extract_target(event: dict) -> dict:
    matched_at = _string(_get(
        event,
        "matched-at",
        "matchedAt",
        "Matched",
        "matched",
        "url",
        "URL",
        "host",
        "Host",
    ))
    host_hint = _string(_get(event, "host", "Host", "ip", "IP"))
    port_hint = _string(_get(event, "port", "Port"))
    scheme_hint = _string(_get(event, "scheme", "Scheme")).lower()
    type_hint = _string(_get(event, "type", "Type")).lower()

    parsed = _parse_target_string(matched_at)
    host = parsed["host"] or _parse_target_string(host_hint)["host"] or host_hint
    port = parsed["port"] or _parse_port(port_hint)
    scheme = parsed["scheme"] or scheme_hint

    if port is None and scheme == "http":
        port = 80
    elif port is None and scheme == "https":
        port = 443

    service = scheme or type_hint or _service_from_port(port)
    if service == "https":
        service = "http"
    protocol = "udp" if type_hint == "dns" else "tcp"

    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "service": service or None,
        "matched_at": matched_at,
    }


def _parse_target_string(value: str) -> dict:
    if not value:
        return {"host": "", "port": None, "scheme": ""}

    try:
        host = str(ipaddress.ip_address(value))
        return {"host": host, "port": None, "scheme": ""}
    except ValueError:
        pass

    try:
        parsed = urlparse(value)
        if not parsed.netloc and "://" not in value:
            parsed = urlparse(f"//{value}")
        host = parsed.hostname or ""
        if parsed.netloc.startswith("["):
            host = str(ipaddress.IPv6Address(host))
        port = parsed.port
    except (ipaddress.AddressValueError, ValueError):
        return {"host": "", "port": None, "scheme": ""}

    return {"host": host, "port": port, "scheme": (parsed.scheme or "").lower()}


def _parse_port(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    if 0 < port <= 65535:
        return port
    return None


def _service_from_port(port: Optional[int]) -> Optional[str]:
    if port == 80:
        return "http"
    if port == 443:
        return "http"
    if port == 53:
        return "domain"
    if port == 22:
        return "ssh"
    if port == 445:
        return "microsoft-ds"
    return None


def _build_evidence(
    template_id: str,
    template_path: str,
    severity: str,
    matched_at: str,
    matcher_name: str,
    extractor_name: str,
    extracted_results: list[str],
    cve_ids: list[str],
    curl_command: str,
) -> str:
    lines = []
    if template_id:
        lines.append(f"template-id: {template_id}")
    if template_path:
        lines.append(f"template-path: {template_path}")
    if severity:
        lines.append(f"severity: {severity}")
    if matched_at:
        lines.append(f"matched-at: {matched_at}")
    if matcher_name:
        lines.append(f"matcher-name: {matcher_name}")
    if extractor_name:
        lines.append(f"extractor-name: {extractor_name}")
    if cve_ids:
        lines.append(f"classification.cve-id: {', '.join(cve_ids)}")
    if extracted_results:
        lines.append("extracted-results:")
        lines.extend(f"  - {result[:300]}" for result in extracted_results[:10])
    if curl_command:
        lines.append(f"curl-command: {curl_command}")
    return "\n".join(lines)
