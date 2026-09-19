from pathlib import Path

import pytest

from vulnmind import scanner


@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("launch failed")])
def test_nmap_launch_errors_clean_up_temporary_xml(tmp_path, monkeypatch, error):
    monkeypatch.setattr(scanner, "nmap_available", lambda: True)
    monkeypatch.setattr(scanner.tempfile, "tempdir", str(tmp_path))

    def fail_launch(argv, **kwargs):
        assert Path(argv[2]).exists()
        raise error

    monkeypatch.setattr(scanner.subprocess, "run", fail_launch)

    with pytest.raises(scanner.ScannerError, match="Failed to launch nmap"):
        scanner.run_nmap("127.0.0.1", quiet=True)

    assert list(tmp_path.iterdir()) == []
