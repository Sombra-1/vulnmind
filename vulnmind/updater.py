"""
updater.py — Check for and explicitly install VulnMind releases.

Normal analysis only checks for releases.  It never installs anything:
  1. On first run (or after 24h), query the GitHub releases API
  2. Compare the latest tag to the installed version
  3. Cache the result in ~/.vulnmind/cache/update_check.json
  4. Wait briefly for that background check and show a one-line notice

An explicit CLI update command can use ``get_update_plan`` and
``perform_update``.  Automatic installation is intentionally limited to pip
and pipx installs; source checkouts and unknown package managers receive
manual, actionable instructions instead.
"""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

import requests

from vulnmind._atomic import write_text
from vulnmind import __version__
from vulnmind.config import CACHE_DIR

RELEASES_API = "https://api.github.com/repos/Sombra-1/vulnmind/releases/latest"
RELEASES_URL = "https://github.com/Sombra-1/vulnmind/releases"
RELEASE_ARCHIVE_URL = (
    "https://github.com/Sombra-1/vulnmind/archive/refs/tags/{tag}.tar.gz"
)
CACHE_FILE = CACHE_DIR / "update_check.json"
CACHE_TTL_SECONDS = 86400  # 24 hours
CHECK_TIMEOUT = 2  # seconds
NOTICE_WAIT_SECONDS = CHECK_TIMEOUT + 0.5

INSTALL_PIP = "pip"
INSTALL_PIPX = "pipx"
INSTALL_SOURCE = "source"
INSTALL_UNKNOWN = "unknown"
PACKAGE_NAME = "vulnmind"
MAX_VERSION_TAG_LENGTH = 128

_SEMVER_RE = re.compile(
    r"^[vV]?"
    r"(?P<major>0|[1-9]\d*)\."
    r"(?P<minor>0|[1-9]\d*)\."
    r"(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclass(frozen=True)
class UpdatePlan:
    """A safe update action for the detected installation method."""

    installation_method: str
    command: tuple[str, ...] | None
    instructions: str

    @property
    def can_auto_update(self) -> bool:
        return self.command is not None


@dataclass(frozen=True)
class UpdateResult:
    """Result returned by :func:`perform_update` without printing output."""

    success: bool
    installation_method: str
    command: tuple[str, ...] | None
    message: str
    returncode: int | None = None


# Background-check state.  The lock prevents duplicate checks and stale reads
# when a command invokes the pipeline more than once in the same process.
_result: dict | None = None
_thread: threading.Thread | None = None
_state_lock = threading.Lock()


def start_check() -> None:
    """Start a release check in the background, unless one is already active."""
    global _result, _thread

    with _state_lock:
        if _thread is not None and _thread.is_alive():
            return

    # A local cache read is fast and guarantees that short/empty analyses can
    # still show a known update. Only stale/missing status needs a thread.
    cached = _read_cache()

    with _state_lock:
        if _thread is not None and _thread.is_alive():
            return
        if cached is not None:
            _result = cached
            _thread = None
            return
        _result = None
        # Reserve this automatic attempt before launching the daemon. Even if
        # parsing exits early or the process is interrupted, the next normal
        # run will respect the 24-hour backoff. The worker bypasses this marker.
        _write_cache({"failed": True, "checked_at": time.time()})
        try:
            _thread = threading.Thread(target=_check, daemon=True)
            _thread.start()
        except (OSError, RuntimeError):
            # Update discovery is best-effort and must never break analysis if
            # this process cannot allocate/start another thread.
            _thread = None


def get_notice() -> str | None:
    """Return an update notice, waiting only briefly for an active check.

    Parsing and matching overlap the request. At the end of a text-mode run,
    this function gives a still-active request a bounded grace period so short
    and empty analyses can reliably surface a release. If the request remains
    stuck, a failure timestamp prevents another automatic attempt for 24 hours.
    """
    global _result, _thread

    with _state_lock:
        thread = _thread

    if thread is not None and thread.is_alive():
        thread.join(timeout=NOTICE_WAIT_SECONDS)
        if thread.is_alive():
            _write_cache({"failed": True, "checked_at": time.time()})
            return None

    with _state_lock:
        _thread = None
        result = _result
        _result = None

    if result and result.get("newer"):
        latest = result.get("latest")
        if isinstance(latest, str):
            return (
                f"[dim]  Update available: [bold]{latest}[/bold] — "
                "run [bold]vulnmind update[/bold] or visit "
                f"{RELEASES_URL}[/dim]"
            )
    return None


def check_for_update(*, force: bool = False) -> dict | None:
    """Synchronously return release status, or ``None`` on any failure.

    The function never prints and never raises for network/cache failures, so
    callers can keep JSON output machine-readable.  ``force=True`` bypasses a
    fresh cache but retains the same short timeout and silent failure policy.
    """
    try:
        return _fetch_or_cached(force=force)
    except Exception:
        return None


def detect_install_method() -> str:
    """Detect pipx, pip, an editable source checkout, or an unknown method."""
    if _looks_like_pipx_environment():
        return INSTALL_PIPX

    if _find_source_root() is not None:
        return INSTALL_SOURCE

    try:
        distribution = metadata.distribution(PACKAGE_NAME)
        installer = (distribution.read_text("INSTALLER") or "").strip().lower()
    except (metadata.PackageNotFoundError, OSError, ValueError):
        return INSTALL_UNKNOWN

    if installer == "pip":
        return INSTALL_PIP
    return INSTALL_UNKNOWN


def get_update_plan(
    installation_method: str | None = None,
    *,
    latest_version: str | None = None,
) -> UpdatePlan:
    """Build an update plan without changing the environment.

    Automatic plans install the validated GitHub release tag directly.  The
    project is not currently published on PyPI, so a bare ``pip install
    --upgrade vulnmind`` could misleadingly succeed without installing the
    release reported by GitHub.
    """
    method = installation_method or detect_install_method()
    release_spec = _release_spec(latest_version)

    if method == INSTALL_PIP:
        if release_spec is None:
            return UpdatePlan(
                installation_method=method,
                command=None,
                instructions=(
                    "A valid GitHub release could not be determined. Check "
                    f"{RELEASES_URL} and install the desired release manually."
                ),
            )
        command = (
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            release_spec,
        )
        return UpdatePlan(
            installation_method=method,
            command=command,
            instructions=f"Run: {shlex.join(command)}",
        )

    if method == INSTALL_PIPX:
        if release_spec is None:
            return UpdatePlan(
                installation_method=method,
                command=None,
                instructions=(
                    "A valid GitHub release could not be determined. Check "
                    f"{RELEASES_URL} and install the desired release manually."
                ),
            )
        command = ("pipx", "install", "--force", release_spec)
        return UpdatePlan(
            installation_method=method,
            command=command,
            instructions=f"Run: {shlex.join(command)}",
        )

    if method == INSTALL_SOURCE:
        source_root = _find_source_root()
        if source_root is not None:
            pull_command = ("git", "-C", str(source_root), "pull", "--ff-only")
            install_command = (
                sys.executable,
                "-m",
                "pip",
                "install",
                "-e",
                str(source_root),
            )
            instructions = (
                "Source checkout detected. Review local changes, then run: "
                f"{shlex.join(pull_command)}\n"
                f"Refresh dependencies and package metadata with: "
                f"{shlex.join(install_command)}"
            )
        else:
            instructions = (
                "Source installation detected. Pull the latest release in the "
                "checkout, then reinstall it with python -m pip install -e ."
            )
        return UpdatePlan(method, None, instructions)

    pip_command = get_update_plan(
        INSTALL_PIP,
        latest_version=latest_version,
    )
    pip_instructions = (
        pip_command.instructions
        if pip_command.command is not None
        else f"See {RELEASES_URL} for release-specific installation instructions."
    )
    return UpdatePlan(
        installation_method=INSTALL_UNKNOWN,
        command=None,
        instructions=(
            "VulnMind's installation method could not be identified. Update it "
            "with the same package manager used to install it. If it was pip, "
            f"{pip_instructions}"
        ),
    )


def perform_update(
    installation_method: str | None = None,
    *,
    latest_version: str | None = None,
) -> UpdateResult:
    """Run the pip/pipx update command for an explicit update request.

    No shell is involved and subprocess output is captured, allowing the CLI to
    decide how to render the result.  Source and unknown installations are
    never mutated automatically.
    """
    plan = get_update_plan(
        installation_method,
        latest_version=latest_version,
    )
    if plan.command is None:
        return UpdateResult(
            success=False,
            installation_method=plan.installation_method,
            command=None,
            message=plan.instructions,
        )

    command = plan.command
    if plan.installation_method == INSTALL_PIPX:
        pipx_executable = shutil.which("pipx")
        if pipx_executable is None:
            return UpdateResult(
                success=False,
                installation_method=plan.installation_method,
                command=command,
                message=(
                    "This installation appears to be managed by pipx, but the "
                    "pipx command is not available. Add pipx to PATH, then run: "
                    f"{shlex.join(command)}"
                ),
            )
        command = (pipx_executable, *command[1:])

    try:
        run_options = {}
        if plan.installation_method == INSTALL_PIPX:
            prefix = Path(sys.prefix).resolve()
            if prefix.parent.name == "venvs":
                # Update the active pipx home even when its environment variable
                # is unset or points at another installation.
                run_options["env"] = {**os.environ, "PIPX_HOME": str(prefix.parent.parent)}
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            **run_options,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return UpdateResult(
            success=False,
            installation_method=plan.installation_method,
            command=command,
            message=(
                f"Update could not be started: {exc}. "
                f"Try manually: {shlex.join(command)}"
            ),
        )

    if completed.returncode == 0:
        installed_version = _installed_version()
        target_key = _parse_version(latest_version or "")
        installed_key = _parse_version(installed_version or "")
        if target_key is not None and installed_key is None:
            return UpdateResult(
                success=False,
                installation_method=plan.installation_method,
                command=command,
                returncode=0,
                message=(
                    "The installer exited successfully, but the installed "
                    "VulnMind version could not be verified. Try manually: "
                    f"{shlex.join(command)}"
                ),
            )
        if (
            target_key is not None
            and installed_key < target_key
        ):
            return UpdateResult(
                success=False,
                installation_method=plan.installation_method,
                command=command,
                returncode=0,
                message=(
                    "The installer exited successfully, but VulnMind still "
                    f"reports version {installed_version}; expected "
                    f"{latest_version}. Try manually: {shlex.join(command)}"
                ),
            )
        return UpdateResult(
            success=True,
            installation_method=plan.installation_method,
            command=command,
            returncode=0,
            message="VulnMind updated successfully. Restart it to use the new version.",
        )

    return UpdateResult(
        success=False,
        installation_method=plan.installation_method,
        command=command,
        returncode=completed.returncode,
        message=(
            f"Update failed with exit code {completed.returncode}. "
            f"Try manually: {shlex.join(command)}"
        ),
    )


# ---------------------------------------------------------------------------
# Internal release-check helpers
# ---------------------------------------------------------------------------

def _check() -> None:
    """Background thread: fetch latest release, compare, and cache it."""
    global _result
    result = check_for_update(force=True)
    with _state_lock:
        _result = result


def _fetch_or_cached(*, force: bool = False) -> dict | None:
    """Return a fresh cached result or query the GitHub releases API."""
    if not force:
        cached = _read_cache()
        if cached is not None:
            if cached.get("failed") is True:
                return None
            return cached

    try:
        response = requests.get(
            RELEASES_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"vulnmind/{__version__}",
            },
            timeout=CHECK_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except Exception:
        _write_cache({"failed": True, "checked_at": time.time()})
        return None

    if not isinstance(data, dict):
        _write_cache({"failed": True, "checked_at": time.time()})
        return None

    latest = data.get("tag_name")
    if not isinstance(latest, str) or _parse_version(latest) is None:
        _write_cache({"failed": True, "checked_at": time.time()})
        return None

    result = {
        "latest": latest,
        "newer": _is_newer(latest, __version__),
        "checked_at": time.time(),
    }
    _write_cache(result)
    return result


def _read_cache() -> dict | None:
    """Return a valid cached result if it is less than 24 hours old."""
    try:
        if not CACHE_FILE.exists():
            return None
        if CACHE_FILE.stat().st_size > 64 * 1024:
            return None
        with open(CACHE_FILE, encoding="utf-8") as cache_file:
            data = json.load(cache_file)
    except (OSError, ValueError, TypeError, RecursionError):
        return None

    if not isinstance(data, dict):
        return None

    checked_at = data.get("checked_at")
    if not _is_finite_timestamp(checked_at):
        return None

    age = time.time() - checked_at
    if age < 0 or age > CACHE_TTL_SECONDS:
        return None

    if data.get("failed") is True:
        return {"failed": True, "checked_at": checked_at}

    latest = data.get("latest")
    if not isinstance(latest, str) or _parse_version(latest) is None:
        return None

    # Recompute against the running version.  Trusting a cached ``newer`` flag
    # would show a stale update notice for 24 hours after a successful upgrade.
    return {
        "latest": latest,
        "newer": _is_newer(latest, __version__),
        "checked_at": checked_at,
    }


def _write_cache(result: dict) -> None:
    """Atomically write release-check state, silently on failure."""
    try:
        write_text(CACHE_FILE, json.dumps(result, allow_nan=False))
    except (OSError, TypeError, ValueError):
        pass


def _is_finite_timestamp(value) -> bool:
    """Validate JSON timestamps without overflowing on huge integers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _parse_version(version: str) -> tuple | None:
    """Parse a SemVer tag into a key that follows prerelease ordering."""
    if not isinstance(version, str):
        return None

    normalized = version.strip()
    if not normalized or len(normalized) > MAX_VERSION_TAG_LENGTH:
        return None

    match = _SEMVER_RE.fullmatch(normalized)
    if match is None:
        return None

    try:
        core = (
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
        )
    except (ValueError, OverflowError):
        return None
    prerelease = match.group("prerelease")
    if prerelease is None:
        return core, 1, ()

    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            if len(identifier) > 1 and identifier.startswith("0"):
                return None
            try:
                identifiers.append((0, int(identifier)))
            except (ValueError, OverflowError):
                return None
        else:
            identifiers.append((1, identifier))
    return core, 0, tuple(identifiers)


def _is_newer(latest: str, current: str) -> bool:
    """Return whether a valid latest SemVer is greater than the current one."""
    latest_key = _parse_version(latest)
    current_key = _parse_version(current)
    if latest_key is None or current_key is None:
        return False
    return latest_key > current_key


def _release_spec(version: str | None) -> str | None:
    """Return a PEP 508 spec for an exact SemVer GitHub release tag."""
    if not isinstance(version, str) or _parse_version(version) is None:
        return None
    tag = version.strip()
    archive_url = RELEASE_ARCHIVE_URL.format(tag=tag)
    return f"{PACKAGE_NAME} @ {archive_url}"


def _installed_version() -> str | None:
    """Read installed distribution metadata after an updater subprocess exits."""
    try:
        return metadata.version(PACKAGE_NAME)
    except (metadata.PackageNotFoundError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Internal installation-detection helpers
# ---------------------------------------------------------------------------

def _looks_like_pipx_environment() -> bool:
    """Return whether the active Python prefix is inside a pipx venv tree."""
    try:
        prefix = Path(sys.prefix).expanduser().resolve()
    except OSError:
        prefix = Path(sys.prefix).expanduser()

    parts = tuple(part.lower() for part in prefix.parts)
    if "pipx" in parts and "venvs" in parts:
        return True
    if (prefix / "pipx_metadata.json").is_file():
        return True

    pipx_home_value = os.environ.get("PIPX_HOME")
    if not pipx_home_value:
        return False

    try:
        pipx_venvs = (Path(pipx_home_value).expanduser() / "venvs").resolve()
        prefix.relative_to(pipx_venvs)
        return True
    except (OSError, ValueError):
        return False


def _find_source_root() -> Path | None:
    """Find a source checkout containing the imported updater module."""
    module_path = Path(__file__).resolve()
    for parent in module_path.parents:
        source_module = (parent / "vulnmind" / "updater.py").resolve()
        if (parent / "setup.py").is_file() and module_path == source_module:
            return parent
    return None
