"""CISA Known Exploited Vulnerabilities catalog lookup.

The cache is deliberately used before the network.  A fresh cache requires
no request; a stale cache is refreshed when possible and remains the fallback
when the network or the newly downloaded payload is unusable.  Callers may
disable network access completely with ``allow_network=False``.

Only an exact CVE entry in this official catalog is returned as known
exploited.  This module does not infer exploitation from products, versions,
or free-form text.
"""

from __future__ import annotations

import json
import math
import re
import time
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional

import requests

from vulnmind._atomic import write_text
from vulnmind import __version__
from vulnmind.config import CACHE_DIR

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EXPLOIT_CACHE_DIR = CACHE_DIR / "exploit"
KEV_CACHE_PATH = EXPLOIT_CACHE_DIR / "cisa_kev.json"

CACHE_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT = 20
MAX_REFERENCES = 5
MAX_CATALOG_BYTES = 20 * 1024 * 1024
MAX_CATALOG_ENTRIES = 25_000

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)
_Warn = Optional[Callable[[str], None]]


def load_catalog(
    *,
    allow_network: bool = False,
    cache_path: Path | str = KEV_CACHE_PATH,
    http_get: Optional[Callable] = None,
    now: Optional[Callable[[], float]] = None,
    warn: _Warn = None,
) -> dict[str, dict]:
    """Load a normalized ``CVE -> KEV record`` mapping.

    Cache and network failures return stale data (when available) or an empty
    mapping.  They never make normal analysis fail.  ``http_get`` and ``now``
    are injectable to keep callers and tests independent from real I/O.
    """
    path = Path(cache_path)
    clock = now or time.time
    cached, is_fresh = _read_cache(path, clock())

    if cached and (is_fresh or not allow_network):
        return cached
    if not allow_network:
        return cached

    payload = _download_catalog(http_get=http_get, warn=warn)
    downloaded = parse_catalog(payload) if payload is not None else {}
    if downloaded:
        _write_cache(path, payload, clock())
        return downloaded

    if payload is not None:
        _emit_warning(warn, "CISA KEV download did not contain a usable catalog")
    return cached


def lookup_cves(
    cve_ids: Iterable[str],
    *,
    allow_network: bool = False,
    cache_path: Path | str = KEV_CACHE_PATH,
    http_get: Optional[Callable] = None,
    now: Optional[Callable[[], float]] = None,
    warn: _Warn = None,
) -> dict[str, dict]:
    """Return exact CISA KEV matches for the requested CVE IDs."""
    requested = _normalize_cve_ids(cve_ids)
    if not requested:
        return {}

    catalog = load_catalog(
        allow_network=allow_network,
        cache_path=cache_path,
        http_get=http_get,
        now=now,
        warn=warn,
    )
    return {cve_id: catalog[cve_id] for cve_id in requested if cve_id in catalog}


def lookup_cve(cve_id: str, **kwargs) -> Optional[dict]:
    """Return one normalized KEV record, or ``None`` when it is not listed."""
    normalized = _normalize_cve_id(cve_id)
    if normalized is None:
        return None
    return lookup_cves([normalized], **kwargs).get(normalized)


def is_known_exploited(cve_id: str, **kwargs) -> bool:
    """Return true only when ``cve_id`` is an exact CISA KEV match."""
    return lookup_cve(cve_id, **kwargs) is not None


def parse_catalog(payload: object) -> dict[str, dict]:
    """Normalize a CISA catalog payload, skipping malformed records.

    Duplicate CVE entries are collapsed.  The first valid record wins so a
    later malformed or surprising duplicate cannot silently replace it.
    """
    if not isinstance(payload, Mapping):
        return {}
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return {}

    catalog: dict[str, dict] = {}
    for raw in vulnerabilities[:MAX_CATALOG_ENTRIES]:
        record = _normalize_record(raw)
        if record is not None:
            catalog.setdefault(record["cve_id"], record)
    return catalog


def _normalize_record(raw: object) -> Optional[dict]:
    if not isinstance(raw, Mapping):
        return None
    cve_id = _normalize_cve_id(raw.get("cveID"))
    if cve_id is None:
        return None

    ransomware_status = _clean_text(raw.get("knownRansomwareCampaignUse"), 32)
    return {
        "cve_id": cve_id,
        "actively_exploited": True,
        "source": "cisa-kev",
        "source_url": CISA_KEV_CATALOG_URL,
        "vendor_project": _clean_text(raw.get("vendorProject"), 200),
        "product": _clean_text(raw.get("product"), 200),
        "vulnerability_name": _clean_text(raw.get("vulnerabilityName"), 500),
        "date_added": _clean_text(raw.get("dateAdded"), 32),
        "due_date": _clean_text(raw.get("dueDate"), 32),
        "required_action": _clean_text(raw.get("requiredAction"), 1000),
        "known_ransomware_campaign_use": ransomware_status.lower() == "known",
        "ransomware_campaign_status": ransomware_status,
        "notes": _clean_text(raw.get("notes"), 1000),
        "references": [CISA_KEV_CATALOG_URL][:MAX_REFERENCES],
    }


def _download_catalog(*, http_get: Optional[Callable], warn: _Warn) -> Optional[object]:
    getter = http_get or requests.get
    response = None
    try:
        response = getter(
            CISA_KEV_URL,
            headers={
                "Accept": "application/json",
                "User-Agent": (
                    f"vulnmind/{__version__} "
                    "(+https://github.com/Sombra-1/vulnmind)"
                ),
            },
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        response.raise_for_status()
        content_length = _content_length(response)
        if content_length is not None and content_length > MAX_CATALOG_BYTES:
            _emit_warning(warn, "CISA KEV download was unexpectedly large")
            return None
        content = _read_bounded_content(response, MAX_CATALOG_BYTES)
        if content is None:
            _emit_warning(warn, "CISA KEV download was unexpectedly large or unreadable")
            return None
        return json.loads(content)
    except (requests.RequestException, OSError, TypeError, ValueError) as exc:
        _emit_warning(warn, f"Could not refresh CISA KEV data: {exc}")
        return None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _read_cache(path: Path, current_time: float) -> tuple[dict[str, dict], bool]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CATALOG_BYTES:
            return {}, False
        with path.open(encoding="utf-8") as handle:
            cached = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return {}, False

    # Accept both VulnMind's envelope and a raw official catalog.  Supporting
    # the raw form makes manually seeded offline caches useful.
    if isinstance(cached, Mapping) and "payload" in cached:
        payload = cached.get("payload")
        cached_at = cached.get("_cached_at")
    else:
        payload = cached
        try:
            cached_at = path.stat().st_mtime
        except OSError:
            cached_at = 0

    catalog = parse_catalog(payload)
    if not catalog:
        return {}, False

    if not _is_finite_number(cached_at) or not _is_finite_number(current_time):
        return catalog, False
    age = float(current_time) - float(cached_at)
    return catalog, 0.0 <= age <= CACHE_TTL_SECONDS


def _write_cache(path: Path, payload: object, cached_at: float) -> None:
    try:
        write_text(path, json.dumps({"_cached_at": cached_at, "payload": payload}, allow_nan=False))
    except (OSError, TypeError, ValueError):
        pass


def _normalize_cve_ids(cve_ids: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    try:
        iterator = iter(cve_ids)
    except TypeError:
        return normalized
    for value in iterator:
        cve_id = _normalize_cve_id(value)
        if cve_id is not None and cve_id not in seen:
            seen.add(cve_id)
            normalized.append(cve_id)
    return normalized


def _normalize_cve_id(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cve_id = value.strip().upper()
    if len(cve_id) > 32:
        return None
    return cve_id if _CVE_RE.fullmatch(cve_id) else None


def _clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("\x00", "").split())[:limit]


def _is_finite_number(value: object) -> bool:
    """Validate cache timestamps without overflowing on huge JSON integers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _content_length(response: object) -> Optional[int]:
    headers = getattr(response, "headers", None)
    if not isinstance(headers, Mapping):
        return None
    try:
        value = int(headers.get("Content-Length", ""))
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _read_bounded_content(response: object, limit: int) -> Optional[bytes]:
    iterator = getattr(response, "iter_content", None)
    if not callable(iterator):
        content = getattr(response, "content", None)
        if not isinstance(content, (bytes, bytearray)) or len(content) > limit:
            return None
        return bytes(content)

    body = bytearray()
    for chunk in iterator(chunk_size=64 * 1024):
        if not chunk:
            continue
        if not isinstance(chunk, (bytes, bytearray)):
            return None
        if len(body) + len(chunk) > limit:
            return None
        body.extend(chunk)
    return bytes(body)


def _emit_warning(warn: _Warn, message: str) -> None:
    if warn is None:
        return
    try:
        warn(message)
    except Exception:
        # Enrichment diagnostics must never break the analysis pipeline.
        pass
