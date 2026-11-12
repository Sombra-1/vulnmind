"""Read-only cache diagnostics. Never reads config secrets or contacts a server."""

import json
import time

from vulnmind import nvd, updater
from vulnmind.enrichers import kev, exploitdb


def _inspect(source, path, limit, ttl, now, decode):
    row = {"source": source, "path": str(path), "status": "missing", "entries": 0}
    try:
        stat = path.stat()
        if not path.is_file() or stat.st_size > limit:
            raise ValueError("invalid cache file or size limit exceeded")
        content = path.read_text(encoding="utf-8-sig")
        count, timestamp, failed = decode(content, stat.st_mtime)
        if not count or not updater._is_finite_timestamp(timestamp):
            raise ValueError("invalid cache payload or timestamp")
        age = now - timestamp
        row.update(entries=count, status="fresh" if 0 <= age <= ttl else "stale")
        if failed:
            row["status"] = "refresh-failed"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        row["status"] = "corrupt"
    return row


def cache_status():
    """Describe bounded cache contents without changing them or their timestamps."""
    now = time.time()

    def nvd_data(text, mtime):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("expected an NVD cache object")
        payload = data.get("payload")
        return (int(isinstance(payload, dict) and isinstance(payload.get("found"), bool)),
                data.get("_cached_at"), False)

    def kev_data(text, mtime):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("expected a catalog object")
        return (len(kev.parse_catalog(data.get("payload", data))),
                data.get("_cached_at", mtime), False)

    def update_data(text, mtime):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("expected release cache object")
        failed = data.get("failed") is True
        valid = failed or updater._parse_version(data.get("latest")) is not None
        return int(valid), data.get("checked_at"), failed

    rows = []
    try:
        # Iterate at most 1001 entries; leave large caches to explicit tooling.
        paths = []
        for path in nvd.NVD_CACHE_DIR.glob("*.json"):
            paths.append(path)
            if len(paths) > 1000:
                break
    except OSError:
        paths = []
    for path in sorted(paths[:1000]):
        rows.append(_inspect("nvd", path, nvd.MAX_CACHE_FILE_BYTES,
                             nvd.CACHE_TTL_SECONDS, now, nvd_data))
    if not paths:
        rows.append({"source": "nvd", "path": str(nvd.NVD_CACHE_DIR),
                     "status": "missing", "entries": 0})
    rows.append(_inspect("cisa-kev", kev.KEV_CACHE_PATH, kev.MAX_CATALOG_BYTES,
                         kev.CACHE_TTL_SECONDS, now, kev_data))
    rows.append(_inspect("exploitdb", exploitdb.EXPLOITDB_CACHE_PATH,
                         exploitdb.MAX_CSV_BYTES, exploitdb.CACHE_TTL_SECONDS,
                         now, lambda text, mtime: (len(exploitdb.parse_csv(text)), mtime, False)))
    rows.append(_inspect("updates", updater.CACHE_FILE, 64 * 1024,
                         updater.CACHE_TTL_SECONDS, now, update_data))
    return {"schema_version": 1, "truncated": len(paths) > 1000, "caches": rows}
