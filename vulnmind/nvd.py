"""
nvd.py — Live CVE lookups against the NVD API 2.0.

What this does:
  For each CVE ID found in a finding, fetch the official NVD record and
  populate:
    - cvss_score  (preferring v3.1 base score, falling back to v3.0, v2.0)
    - description (if the finding has none)
  Used by `--deep` mode in the CLI.

Why NVD?
  Official, authoritative, free, no API key required (though one increases
  your rate limit from 5/30s to 50/30s). URL: https://nvd.nist.gov/

Accuracy vs speed tradeoffs:
  - We cache every CVE response in ~/.vulnmind/cache/nvd/<CVE>.json
  - Cache TTL: 30 days (CVEs rarely change, but severity updates do happen)
  - We respect the 5 requests per 30 seconds public rate limit
  - We parallelise only within the rate-limit budget

Reliability:
  - All network failures are silent — the CLI continues with whatever data
    we have. A CVE lookup missing is much better than the whole tool crashing.
  - We never trust the network-returned data blindly: CVSS scores are
    clamped 0.0-10.0, descriptions are truncated to 1000 chars.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import replace
from pathlib import Path
from typing import Optional

import requests

from vulnmind._atomic import write_text
from vulnmind import __version__
from vulnmind.config import CACHE_DIR

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_DIR = CACHE_DIR / "nvd"
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days
MAX_CACHE_FILE_BYTES = 2 * 1024 * 1024
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.IGNORECASE)

# NVD public rate limit: 5 requests per 30 seconds.
# Stay comfortably under by sleeping 6.5s between requests.
DELAY_BETWEEN_REQUESTS = 6.5
REQUEST_TIMEOUT = 30  # per-request timeout — NVD can be slow under load


def enrich_with_nvd(findings: list, progress_callback=None) -> list:
    """
    Enrich findings with CVSS scores and descriptions from NVD.

    Iterates all CVEs across all findings (deduplicated), fetches each one
    from NVD (or cache), and applies the highest CVSS score per finding.

    Args:
        findings: list of Finding objects
        progress_callback: optional (current, total, cve_id) -> None

    Returns:
        New list of Finding objects with cvss_score populated where possible.
    """
    # Collect unique CVE IDs across all findings
    cve_set: set[str] = set()
    for f in findings:
        for cve in (f.cve_ids or []):
            if isinstance(cve, str) and _CVE_RE.fullmatch(cve):
                cve_set.add(cve.upper())

    if not cve_set:
        return findings

    # Fetch each CVE (respecting cache + rate limit)
    cve_data: dict[str, dict] = {}
    cve_list = sorted(cve_set)
    last_request_time = 0.0

    for i, cve_id in enumerate(cve_list):
        if progress_callback:
            progress_callback(i, len(cve_list), cve_id)

        cached = _read_cache(cve_id)
        if cached is not None:
            cve_data[cve_id] = cached
            continue

        # Rate limit: ensure at least DELAY_BETWEEN_REQUESTS since last network call
        elapsed = time.time() - last_request_time
        if elapsed < DELAY_BETWEEN_REQUESTS and last_request_time > 0:
            time.sleep(DELAY_BETWEEN_REQUESTS - elapsed)

        data = _fetch_cve(cve_id)
        last_request_time = time.time()
        if data is not None:
            cve_data[cve_id] = data
            _write_cache(cve_id, data)

    if progress_callback:
        progress_callback(len(cve_list), len(cve_list), None)

    # Apply the enrichment to each finding
    enriched = []
    for f in findings:
        enriched.append(_apply_to_finding(f, cve_data))
    return enriched


def lookup_cve(cve_id: str) -> Optional[dict]:
    """
    Look up a single CVE. Returns the normalized dict or None on failure.

    Useful for one-off lookups and testing.
    """
    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        return None
    cve_id = cve_id.upper()
    cached = _read_cache(cve_id)
    if cached is not None:
        return cached
    data = _fetch_cve(cve_id)
    if data is not None:
        _write_cache(cve_id, data)
    return data


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _fetch_cve(cve_id: str, max_retries: int = 3) -> Optional[dict]:
    """
    Fetch one CVE from NVD. Returns normalized dict, or None on failure.

    Retries on transient errors (timeout, 429, 5xx) with exponential backoff.
    A 404 is cached as "not found" to avoid re-requesting.
    """
    backoff = 5.0
    for attempt in range(max_retries):
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers={
                    "Accept": "application/json",
                    "User-Agent": (
                        f"vulnmind/{__version__} "
                        "(+https://github.com/Sombra-1/vulnmind)"
                    ),
                },
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                return {"cve_id": cve_id, "found": False}
            if resp.status_code == 429 or resp.status_code >= 500:
                # Transient — back off and retry
                time.sleep(backoff)
                backoff *= 2
                continue
            resp.raise_for_status()
            payload = resp.json()
        except requests.Timeout:
            time.sleep(backoff)
            backoff *= 2
            continue
        except (requests.RequestException, ValueError):
            return None

        if not isinstance(payload, dict):
            return None

        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return None
        if not vulnerabilities:
            return {"cve_id": cve_id, "found": False}

        first = vulnerabilities[0]
        if not isinstance(first, dict):
            return None
        cve = first.get("cve")
        if not isinstance(cve, dict):
            return None
        if not isinstance(cve.get("id"), str) or cve["id"].upper() != cve_id.upper():
            return None
        return _normalize_cve(cve_id, cve)

    # All retries exhausted
    return None


def _normalize_cve(cve_id: str, cve: dict) -> dict:
    """
    Extract the fields we care about from NVD's verbose CVE payload.

    NVD returns nested, inconsistent structures — older CVEs have v2 scores,
    newer ones have v3.0 or v3.1. Always prefer v3.1 > v3.0 > v2.0.
    """
    # Description — English preferred
    description = ""
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        descriptions = []
    for d in descriptions:
        if not isinstance(d, dict) or d.get("lang") != "en":
            continue
        value = d.get("value", "")
        if isinstance(value, str):
            description = value[:1000]
            break

    # CVSS — walk through metrics in order of preference
    metrics = cve.get("metrics", {}) or {}
    if not isinstance(metrics, dict):
        metrics = {}
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_entries = metrics.get(key)
        if not isinstance(metric_entries, list) or not metric_entries:
            continue
        primary = metric_entries[0]
        if not isinstance(primary, dict):
            continue
        data = primary.get("cvssData", {}) or {}
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        if not _is_finite_number(score):
            continue
        cvss_score = _clamp(float(score), 0.0, 10.0)
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        cvss_severity = severity if isinstance(severity, str) else _severity_from_score(cvss_score)
        vector = data.get("vectorString")
        cvss_vector = vector if isinstance(vector, str) else None
        break

    # References — grab a couple of canonical URLs
    references = []
    raw_references = cve.get("references", [])
    if not isinstance(raw_references, list):
        raw_references = []
    for ref in raw_references:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if isinstance(url, str) and url:
            references.append(url)
            if len(references) == 3:
                break

    published = cve.get("published")
    if not isinstance(published, str):
        published = None

    return {
        "cve_id": cve_id,
        "found": True,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": (cvss_severity or "").lower() or None,
        "cvss_vector": cvss_vector,
        "published": published,
        "references": references,
    }


def _apply_to_finding(finding, cve_data: dict):
    """Apply NVD data to a single finding, picking the HIGHEST CVSS score."""
    if not finding.cve_ids:
        return finding

    current_score = finding.cvss_score
    max_score: Optional[float] = (
        float(current_score)
        if _valid_cvss_score(current_score)
        else None
    )

    for cve_id in finding.cve_ids:
        if not isinstance(cve_id, str):
            continue
        cid = cve_id.upper()
        data = cve_data.get(cid)
        if not isinstance(data, dict) or data.get("found") is not True:
            continue
        score = data.get("cvss_score")
        if _valid_cvss_score(score):
            if max_score is None or score > max_score:
                max_score = float(score)

    if max_score is None:
        return finding

    # Lift priority if NVD score suggests a more severe rating than the
    # current one (e.g. no priority → medium, or low → critical).
    priority_from_score = _priority_from_score(max_score)
    new_priority = _lift_priority(finding.priority, priority_from_score)

    # If priority changed, add a reason
    priority_reason = finding.priority_reason
    if new_priority != finding.priority:
        priority_reason = (
            f"Elevated by NVD: highest associated CVSS is {max_score:.1f}"
            f" ({priority_from_score})."
        )

    return replace(
        finding,
        cvss_score=max_score,
        priority=new_priority,
        priority_reason=priority_reason or finding.priority_reason,
    )


def _priority_from_score(score: float) -> str:
    """CVSS base score → VulnMind priority label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _severity_from_score(score: float) -> str:
    """CVSS base score → NVD-style severity label (uppercase)."""
    return _priority_from_score(score).upper()


_PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _lift_priority(current: Optional[str], candidate: str) -> str:
    """Return the higher of two priorities."""
    cr = _PRIORITY_RANK.get((current or "").lower(), 0)
    ca = _PRIORITY_RANK.get(candidate, 0)
    return candidate if ca > cr else (current or candidate)


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _is_finite_number(value) -> bool:
    """Return True for finite JSON numbers, excluding booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _valid_cvss_score(value) -> bool:
    """Return True only for a finite CVSS base score in its defined range."""
    return _is_finite_number(value) and 0.0 <= value <= 10.0


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_path(cve_id: str) -> Path:
    return NVD_CACHE_DIR / f"{cve_id}.json"


def _read_cache(cve_id: str) -> Optional[dict]:
    """Return cached CVE data if fresh; None otherwise."""
    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        return None
    path = _cache_path(cve_id)
    try:
        if not path.exists():
            return None
        if path.stat().st_size > MAX_CACHE_FILE_BYTES:
            return None
        with open(path, encoding="utf-8") as f:
            raw = f.read(MAX_CACHE_FILE_BYTES + 1)
        if len(raw) > MAX_CACHE_FILE_BYTES:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None

        # TTL check — stale cache returns None, triggering a re-fetch
        cached_at = data.get("_cached_at")
        if not _is_finite_number(cached_at):
            return None
        now = time.time()
        if cached_at > now or now - cached_at > CACHE_TTL_SECONDS:
            return None
        payload = data.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("found"), bool):
            return None
        if "cve_id" in payload and payload["cve_id"] != cve_id:
            return None
        return payload
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None


def _write_cache(cve_id: str, payload: dict) -> None:
    """Write CVE data to cache. Silent on failure."""
    if not isinstance(payload, dict):
        return

    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        return
    try:
        write_text(_cache_path(cve_id), json.dumps(
            {"_cached_at": time.time(), "payload": payload}, allow_nan=False,
        ))
    except (OSError, TypeError, ValueError):
        pass
