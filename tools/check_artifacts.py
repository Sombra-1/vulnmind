"""Verify release contents, including source-package test completeness and exclusions."""

import argparse
from pathlib import Path
import tarfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wheel = args.directory / f"vulnmind-{args.version}-py3-none-any.whl"
    sdist = args.directory / f"vulnmind-{args.version}.tar.gz"
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
        for source in (root / "vulnmind").rglob("*"):
            if source.is_file() and source.suffix in {".py", ".json"} and "__pycache__" not in source.parts:
                name = source.relative_to(root).as_posix()
                assert name in wheel_names, f"missing wheel source: {name}"
                assert archive.read(name) == source.read_bytes(), f"stale wheel source: {name}"
    with tarfile.open(sdist) as archive:
        prefix = f"vulnmind-{args.version}/"
        source_names = {name.removeprefix(prefix) for name in archive.getnames()}
        for path in (root / "tests").rglob("*"):
            if path.is_file() and path.suffix in {".py", ".txt", ".xml", ".jsonl", ".json"} and "__pycache__" not in path.parts:
                assert path.relative_to(root).as_posix() in source_names, f"missing source fixture: {path.name}"
        for name in ("tools/check_installed.py", "tools/check_artifacts.py", "tools/validate_modules.py", "tools/module-validation.json"):
            assert name in source_names, f"missing developer tool: {name}"
    for name in wheel_names | source_names:
        path = Path(name)
        assert not set(path.parts) & {".git", ".venv", ".vulnmind", "output", "__pycache__"}, f"private/artifact path: {name}"
        assert path.name not in {"CLAUDE.md", "AGENTS.md", "config.json"}, f"local-only file: {name}"
        assert not path.name.startswith(".env"), f"environment file: {name}"
        assert path.suffix.lower() not in {".pem", ".key"}, f"key file: {name}"
        assert path.suffix.lower() != ".md" or path.name == "README.md", f"unexpected Markdown file: {name}"
    print(f"VulnMind {args.version}: wheel matches source; source tests/tools complete; private files excluded")


if __name__ == "__main__":
    main()
