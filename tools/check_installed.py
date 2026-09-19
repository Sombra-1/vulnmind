"""Exercise a non-editable installation from outside the source checkout.

Usage: /path/to/venv/bin/python tools/check_installed.py tests --version 0.6.1
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import vulnmind


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    fixtures = args.fixtures.resolve()
    # Fail if an editable checkout accidentally masks the installed artifact.
    Path(vulnmind.__file__).resolve().relative_to(Path(sys.prefix).resolve())
    assert vulnmind.__version__ == args.version
    cli = Path(sys.executable).parent / "vulnmind"
    env = {**os.environ, "VULNMIND_UPDATE_CHECKS": "off"}

    with tempfile.TemporaryDirectory(prefix="vulnmind-smoke-") as directory:
        def run(*arguments):
            return subprocess.run(
                [str(cli), *arguments], cwd=directory, env=env,
                check=True, capture_output=True, text=True, timeout=30,
            ).stdout

        assert run("--version").strip() == f"VulnMind, version {args.version}"
        for fixture, expected_count in (
            ("sample_nmap.xml", 5), ("sample_nmap.txt", 4),
            ("sample_nuclei.jsonl", 3), ("sample_nikto.txt", 8),
            ("sample_metasploit.txt", 5),
        ):
            payload = json.loads(run("analyze", str(fixtures / fixture), "--format", "json"))
            assert len(payload) == expected_count, (fixture, len(payload))
            for finding in payload:
                assert finding["confidence"] in {"confirmed", "scanner-reported", "strong", "weak"}
                for key in ("actively_exploited", "exploit_available", "metasploit_available"):
                    assert isinstance(finding[key], bool)
                assert isinstance(finding["exploit_confidence"], str)
                assert isinstance(finding["exploit_references"], list)
            print(f"{fixture}: {len(payload)} findings, valid JSON")

        pdf = Path(directory) / "report.pdf"
        run("analyze", str(fixtures / "sample_nmap.xml"), "--report", "pdf", "--output", str(pdf))
        assert pdf.read_bytes().startswith(b"%PDF-")
        print(f"VulnMind {args.version}: installed CLI, bundled KB, JSON and PDF smoke checks passed")


if __name__ == "__main__":
    main()
