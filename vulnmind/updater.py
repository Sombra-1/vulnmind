"""
updater.py — Check for new VulnMind releases on GitHub.

How it works:
  1. On first run (or after 24h), hits the GitHub releases API
  2. Compares the latest tag to the installed version
  3. If newer, shows a one-line notice at the end of output
  4. Result is cached in ~/.vulnmind/cache/update_check.json

Design goals:
  - Zero latency: runs in a background thread while findings are displayed
  - Zero noise: completely silent on network errors, timeouts, or bad responses
  - Non-intrusive: one dim line at the very end, never interrupts the workflow
  - Respectful: 24h cache means at most one API call per day
"""

import json
import threading
import time
from pathlib import Path

import requests

from vulnmind import __version__
from vulnmind.config import CACHE_DIR

RELEASES_API = "https://api.github.com/repos/Sombra-1/vulnmind/releases/latest"
CACHE_FILE = CACHE_DIR / "update_check.json"
CACHE_TTL_SECONDS = 86400  # 24 hours
CHECK_TIMEOUT = 3  # seconds — fast enough to not annoy anyone

# Thread result is stored here after the background check completes
_result: dict | None = None
_thread: threading.Thread | None = None


def start_check() -> None:
    """
    Kick off the update check in a background thread.

    Call this early in the analyze command (before parsing begins),
    so the network request overlaps with the local work.
    """
    global _thread
    _thread = threading.Thread(target=_check, daemon=True)
    _thread.start()


def get_notice() -> str | None:
    """
    Wait for the background check to finish and return a notice string,
    or None if no update is available or the check failed.

    Call this after findings are displayed — by then the thread is
    almost certainly done and there's no wait.
    """
    global _thread
    if _thread is not None:
        _thread.join(timeout=CHECK_TIMEOUT + 1)
        _thread = None

    if _result and _result.get("newer"):
        latest = _result["latest"]
        return (
            f"[dim]  Update available: [bold]{latest}[/bold] — "
            f"github.com/Sombra-1/vulnmind/releases[/dim]"
        )
    return None


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _check() -> None:
    """Background thread: fetch latest release, compare, cache result."""
    global _result
    try:
        _result = _fetch_or_cached()
    except Exception:
        # Never crash the tool over an update check
        _result = None


def _fetch_or_cached() -> dict | None:
    """Return cached result if fresh, otherwise hit the API."""
    # Try cache first
    cached = _read_cache()
    if cached:
        return cached

    # Hit GitHub API
    try:
        resp = requests.get(
            RELEASES_API,
            headers={"Accept": "application/vnd.github+json"},
            timeout=CHECK_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    latest_tag = data.get("tag_name", "").lstrip("v")
    if not latest_tag:
        return None

    result = {
        "latest": data.get("tag_name", ""),
        "newer": _is_newer(latest_tag, __version__),
        "checked_at": time.time(),
    }

    _write_cache(result)
    return result


def _read_cache() -> dict | None:
    """Return cached result if it exists and is less than 24h old."""
    try:
        if not CACHE_FILE.exists():
            return None
        with open(CACHE_FILE) as f:
            data = json.load(f)
        if time.time() - data.get("checked_at", 0) > CACHE_TTL_SECONDS:
            return None
        return data
    except Exception:
        return None


def _write_cache(result: dict) -> None:
    """Write result to cache file. Silent on failure."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(result, f)
    except Exception:
        pass


def _is_newer(latest: str, current: str) -> bool:
    """Return True if latest version is greater than current version."""
    def to_tuple(v: str) -> tuple:
        try:
            return tuple(int(x) for x in v.split("."))
        except ValueError:
            return (0,)

    return to_tuple(latest) > to_tuple(current)
