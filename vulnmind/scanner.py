"""
scanner.py — Run nmap against a live target and produce XML for the pipeline.

This is what turns VulnMind from a parser into a full scanner. Instead of:

    nmap -sV -sC -oX scan.xml 192.168.1.1
    vulnmind analyze scan.xml

the user runs:

    vulnmind scan 192.168.1.1

Design:
  - Shell out to the system `nmap` binary. Do not reimplement scanning.
  - Write to a temp XML file, not stdin/stdout. Lets nmap stream progress to
    the terminal on stderr without corrupting the data stream, and gives the
    user a real file path in error messages.
  - Default flags are `-sV -sC --top-ports 1000`: the minimum useful scan
    for pentest triage. Version detection + default NSE scripts on the top
    1000 ports covers most real-world services without taking forever.
  - If the user specifies `-p/--ports`, we drop `--top-ports` automatically
    (nmap rejects both at once).
  - Extra pass-through args (e.g. `-T4 -Pn`) go via a single `--nmap-args`
    string that is shlex-split — keeps the flag surface small and lets power
    users escape into the full nmap CLI when needed.
  - Never swallow nmap's stderr. Pentesters watch scan progress live.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


DEFAULT_SCAN_ARGS: list[str] = ["-sV", "-sC"]
DEFAULT_PORT_ARGS: list[str] = ["--top-ports", "1000"]


class ScannerError(RuntimeError):
    """Raised when we can't run nmap or it exits non-zero."""


def nmap_available() -> bool:
    """Return True if the nmap binary is on PATH."""
    return shutil.which("nmap") is not None


def nmap_version() -> Optional[str]:
    """Return a short 'Nmap version 7.99' style string, or None if nmap is missing."""
    if not nmap_available():
        return None
    try:
        out = subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    first_line = (out.stdout or "").splitlines()[0:1]
    return first_line[0].strip() if first_line else None


def build_nmap_args(
    target: str,
    xml_path: Path,
    ports: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
) -> list[str]:
    """
    Build the argv for the nmap subprocess.

    -p and --top-ports are mutually exclusive in nmap; if the user passed a
    port spec, we drop the default --top-ports.
    """
    args: list[str] = ["nmap", "-oX", str(xml_path)]
    args.extend(DEFAULT_SCAN_ARGS)
    if ports:
        args.extend(["-p", ports])
    else:
        args.extend(DEFAULT_PORT_ARGS)
    if extra_args:
        args.extend(extra_args)
    args.append(target)
    return args


def run_nmap(
    target: str,
    ports: Optional[str] = None,
    extra_args_str: str = "",
    quiet: bool = False,
) -> Path:
    """
    Run nmap against `target` and return the path to the XML output file.

    The caller owns the returned temp file and should unlink it when done.

    Args:
        target: IP, hostname, or CIDR range to scan.
        ports: Optional port spec (e.g. "22,80,443" or "1-65535").
        extra_args_str: Extra flags, shell-split (e.g. "-T4 -Pn").
        quiet: If True, suppress nmap's own stdout/stderr. Used for JSON mode
               where any text on stderr would confuse a downstream pipe.

    Raises:
        ScannerError: if nmap is missing, invalid arguments, or non-zero exit.
    """
    if not nmap_available():
        raise ScannerError(
            "nmap binary not found on PATH.\n"
            "Install with:\n"
            "  Arch:        sudo pacman -S nmap\n"
            "  Debian/Kali: sudo apt install nmap\n"
            "  macOS:       brew install nmap"
        )

    try:
        extra_args = shlex.split(extra_args_str) if extra_args_str else []
    except ValueError as e:
        raise ScannerError(f"Could not parse --nmap-args: {e}") from e

    # Temp XML file — NamedTemporaryFile with delete=False so the file survives
    # this function returning. The caller is responsible for unlinking.
    tmp = tempfile.NamedTemporaryFile(
        prefix="vulnmind_", suffix=".xml", delete=False
    )
    tmp.close()
    xml_path = Path(tmp.name)

    argv = build_nmap_args(target, xml_path, ports=ports, extra_args=extra_args)

    if quiet:
        stdout = subprocess.DEVNULL
        stderr = subprocess.PIPE  # capture so we can include it in errors
    else:
        stdout = None  # inherit — nmap's progress goes straight to terminal
        stderr = None

    try:
        result = subprocess.run(
            argv,
            stdout=stdout,
            stderr=stderr,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        xml_path.unlink(missing_ok=True)
        raise ScannerError(f"Failed to launch nmap: {e}") from e
    except KeyboardInterrupt:
        xml_path.unlink(missing_ok=True)
        raise

    if result.returncode != 0:
        err_tail = (result.stderr or "").strip()
        xml_path.unlink(missing_ok=True)
        msg = f"nmap exited with status {result.returncode}"
        if err_tail:
            msg += f":\n{err_tail}"
        raise ScannerError(msg)

    if not xml_path.exists() or xml_path.stat().st_size == 0:
        xml_path.unlink(missing_ok=True)
        raise ScannerError("nmap completed but produced no XML output.")

    return xml_path
