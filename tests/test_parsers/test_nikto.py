from pathlib import Path

import pytest

from vulnmind.parsers import detect_and_parse

FIXTURES = Path(__file__).resolve().parents[1]


def test_nikto_fixture_parses_findings_and_cves():
    findings = detect_and_parse(FIXTURES / "sample_nikto.txt")

    assert len(findings) == 8
    assert {finding.host for finding in findings} == {"192.168.1.10"}
    assert {finding.port for finding in findings} == {80}
    assert {finding.service for finding in findings} == {"http"}
    assert any(f.title.startswith("OSVDB-3092") for f in findings)
    assert any(f.cve_ids == ["CVE-2021-41773"] for f in findings)
    assert any(f.cve_ids == ["CVE-2014-6271"] for f in findings)
    assert not any("requests:" in f.title for f in findings)


@pytest.mark.parametrize("second_port, expected_port", [("443", 443), ("bad", None), ("70000", None)])
def test_nikto_multi_target_keeps_findings_with_their_target(tmp_path, second_port, expected_port):
    scan = tmp_path / "nikto.txt"
    scan.write_text(
        "- Nikto v2.5.0\n"
        "+ Target IP: 192.0.2.1\n+ Target Hostname: first.example\n"
        "+ Target Port: 80\n-------\n+ /first: First finding\n"
        "+ End Time: done\n-------\n"
        "+ Target IP: 192.0.2.2\n+ Target Hostname: second.example\n"
        f"+ Target Port: {second_port}\n+ Start Time: now\n-------\n"
        "+ /second: Second finding\n+ End Time: done\n"
    )

    findings = detect_and_parse(scan)

    assert [(f.host, f.port, f.description) for f in findings] == [
        ("192.0.2.1", 80, "First finding"),
        ("192.0.2.2", expected_port, "Second finding"),
    ]


def test_nikto_repeated_hostname_only_reports_reset_target(tmp_path):
    scan = tmp_path / "nikto.txt"
    scan.write_text(
        "- Nikto v2.5.0\n+ Target Hostname: first.example\n"
        "+ Target Port: 80\n+ /: First finding\n"
        "- Nikto v2.5.0\n+ Target Hostname: second.example\n"
        "+ /: Second finding\n"
    )

    findings = detect_and_parse(scan)

    assert [(f.host, f.port) for f in findings] == [
        ("first.example", 80), ("second.example", None),
    ]
