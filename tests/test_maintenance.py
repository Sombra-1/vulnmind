"""Regression checks for v0.6.2 reliability and maintenance tooling."""

import json
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner
import pytest

from vulnmind import _atomic, nvd, updater
from vulnmind.cli import cli
from vulnmind.enrichers import kev, exploitdb
from vulnmind.parsers.nmap import NmapParser
from tools.validate_modules import validate, main as validate_main

FIXTURES = Path(__file__).parent


def test_json_and_pdf_can_be_requested_together(tmp_path):
    output = tmp_path / "report.pdf"
    result = CliRunner().invoke(cli, ["analyze", str(FIXTURES / "sample_nmap.xml"),
                                     "--format", "json", "--report", "pdf",
                                     "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 5
    assert output.read_bytes().startswith(b"%PDF-")
    assert not result.stderr


def test_pdf_write_failure_has_clean_json_stdout(tmp_path):
    output = tmp_path / "missing" / "report.pdf"
    result = CliRunner().invoke(cli, ["analyze", str(FIXTURES / "sample_nmap.xml"),
                                     "--format", "json", "--report", "pdf",
                                     "--output", str(output)])
    assert result.exit_code == 1
    assert not result.stdout
    assert "Could not generate PDF report" in result.stderr
    assert "Traceback" not in result.stderr


def test_terminal_renders_scanner_markup_literally(tmp_path, monkeypatch):
    scan = tmp_path / "nuclei.jsonl"
    scan.write_text(json.dumps({"template-id": "markup", "host": "http://127.0.0.1",
                                "info": {"name": "[/bold] [link=https://bad.test]title[/link]",
                                         "description": "Evidence [/dim] [red]literal[/red]"}}))
    monkeypatch.setenv("VULNMIND_UPDATE_CHECKS", "off")
    result = CliRunner().invoke(cli, ["analyze", str(scan)])
    assert result.exit_code == 0, result.output
    assert "[red]literal[/red]" in result.output
    assert "[link=https://bad.test]" in result.output


@pytest.mark.parametrize("bad_port", ["", "not-a-port", "0", "-1", "65536"])
def test_malformed_nmap_xml_port_does_not_discard_valid_ports(bad_port):
    xml = f'''<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>
    <port portid="{bad_port}" protocol="tcp"><state state="open"/></port>
    <port portid="443" protocol="tcp"><state state="open"/></port>
    </ports></host></nmaprun>'''
    findings = NmapParser().parse(Path("input.xml"), xml)
    assert [f.port for f in findings] == [443]


@pytest.mark.parametrize("cve", ["../../outside", None, 42, "CVE-2024-1234/extra", "CVE-２０２４-１２３４"])
def test_invalid_cve_ids_never_reach_network_or_cache(cve, monkeypatch, tmp_path):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path)
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: pytest.fail("unexpected network"))
    assert nvd.lookup_cve(cve) is None
    nvd._write_cache(cve, {"found": True})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("identity", [None, 42, "CVE-2024-9999"])
def test_nvd_rejects_mismatched_response_identity(identity, monkeypatch):
    response = SimpleNamespace(status_code=200, raise_for_status=lambda: None,
                               json=lambda: {"vulnerabilities": [{"cve": {"id": identity}}]})
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: response)
    assert nvd._fetch_cve("CVE-2024-1234") is None


@pytest.mark.parametrize("source", ["nvd", "kev", "exploitdb", "updates"])
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("stage", ["replace", "fsync"])
def test_failed_cache_writes_preserve_previous_file_and_clean_temps(
    tmp_path, monkeypatch, source, failure, stage,
):
    path = tmp_path / "cache.json"
    path.write_text("previous contents")
    def fail(*args):
        raise failure("interrupted write")
    monkeypatch.setattr(_atomic.os, stage, fail)
    if source == "nvd":
        monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path)
        path.rename(tmp_path / "CVE-2024-1234.json")
        path = tmp_path / "CVE-2024-1234.json"
        write = lambda: nvd._write_cache("CVE-2024-1234", {"found": True})
    elif source == "kev":
        write = lambda: kev._write_cache(path, {"vulnerabilities": []}, 100)
    elif source == "exploitdb":
        write = lambda: exploitdb._write_cache(path, "id,codes\n1,CVE-2024-1234\n")
    else:
        monkeypatch.setattr(updater, "CACHE_FILE", path)
        write = lambda: updater._write_cache({"failed": True, "checked_at": 100})
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            write()
    else:
        write()
    assert path.read_text() == "previous contents"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("env_home", [None, "another-home"])
def test_pipx_update_uses_active_custom_home(tmp_path, monkeypatch, env_home):
    active_home = tmp_path / "custom apps"
    prefix = active_home / "venvs" / "vulnmind"
    prefix.mkdir(parents=True)
    (prefix / "pipx_metadata.json").write_text("{}")
    monkeypatch.setattr(updater.sys, "prefix", str(prefix))
    if env_home:
        monkeypatch.setenv("PIPX_HOME", str(tmp_path / env_home))
    else:
        monkeypatch.delenv("PIPX_HOME", raising=False)
    assert updater.detect_install_method() == updater.INSTALL_PIPX
    monkeypatch.setattr(updater.shutil, "which", lambda name: "/usr/bin/pipx")
    monkeypatch.setattr(updater, "_installed_version", lambda: "0.6.2")
    captured = {}
    def run(command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(updater.subprocess, "run", run)
    assert updater.perform_update(latest_version="v0.6.2").success
    assert captured["env"]["PIPX_HOME"] == str(active_home)
    assert captured["shell"] is False


def test_failed_update_reports_failure_without_claiming_rollback(monkeypatch):
    monkeypatch.setattr(updater.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    result = updater.perform_update(updater.INSTALL_PIP, latest_version="v0.6.2")
    assert not result.success
    assert result.returncode == 1
    assert "failed" in result.message
    assert "rollback" not in result.message


def test_semver_prerelease_order_is_case_sensitive():
    assert updater._is_newer("0.6.2-alpha", "0.6.2-ZETA")


@pytest.mark.parametrize("content", ["not json", "[]", "null", "{\"payload\": []}"])
def test_cache_diagnostics_tolerate_corruption_and_stay_offline(tmp_path, monkeypatch, content):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path / "nvd")
    monkeypatch.setattr(kev, "KEV_CACHE_PATH", tmp_path / "kev.json")
    monkeypatch.setattr(exploitdb, "EXPLOITDB_CACHE_PATH", tmp_path / "exploits.csv")
    monkeypatch.setattr(updater, "CACHE_FILE", tmp_path / "updates.json")
    nvd.NVD_CACHE_DIR.mkdir()
    (nvd.NVD_CACHE_DIR / "CVE-2024-1234.json").write_text(content)
    kev.KEV_CACHE_PATH.write_text(content)
    updater.CACHE_FILE.write_text(content)
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: pytest.fail("diagnostics must be offline"))
    result = CliRunner().invoke(cli, ["cache", "status", "--format", "json"])
    assert result.exit_code == 0, result.output
    caches = json.loads(result.stdout)["caches"]
    assert [c["status"] for c in caches] == ["corrupt", "corrupt", "missing", "corrupt"]
    assert kev.KEV_CACHE_PATH.read_text() == content


def test_cache_diagnostics_fresh_stale_and_failed(tmp_path, monkeypatch):
    from vulnmind.diagnostics import _inspect
    path = tmp_path / "cache.json"
    path.write_text("{}")
    decode = lambda content, mtime: (1, 100, False)
    assert _inspect("test", path, 100, 10, 105, decode)["status"] == "fresh"
    assert _inspect("test", path, 100, 10, 111, decode)["status"] == "stale"
    assert _inspect("test", path, 100, 10, 90, decode)["status"] == "stale"
    assert _inspect("test", path, 100, 10, 105, lambda *a: (1, 100, True))["status"] == "refresh-failed"


def test_module_validator_uses_fullname_and_reports_missing():
    knowledge = {"http": [{"metasploit_modules": ["exploit/test/valid", "exploit/test/missing"]}]}
    metadata = {"misleading-key": {"fullname": "exploit/test/valid"}}
    result = validate(knowledge, metadata)
    assert result["valid"] == ["exploit/test/valid"]
    assert result["missing"] == ["exploit/test/missing"]
    with pytest.raises(ValueError):
        validate(knowledge, [])


def test_module_validator_offline_fixture_and_online_pin_requirement(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: pytest.fail("offline validation contacted network"))
    result = validate_main(["--metadata", str(FIXTURES / "fixtures" / "rapid7-metadata.json")])
    assert result == 0
    with pytest.raises(SystemExit) as error:
        validate_main(["--online", "--revision", "master"])
    assert error.value.code == 2


@pytest.mark.parametrize("format", ["xml", "text"])
def test_nmap_same_script_on_tcp_and_udp_preserves_both_findings(format):
    if format == "xml":
        ports = ''.join(f'''<port portid="53" protocol="{proto}"><state state="open"/>
            <script id="dns-vuln-test" output="CVE-2024-1234 VULNERABLE"/></port>'''
                        for proto in ("tcp", "udp"))
        content = f'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>{ports}</ports></host></nmaprun>'
    else:
        content = 'Nmap scan report for 127.0.0.1\n' + ''.join(
            f'{proto_port}/' + proto + ' open domain\n| dns-vuln-test:\n|_ CVE-2024-1234 VULNERABLE\n'
            for proto_port, proto in [(53, "tcp"), (53, "udp")])
    findings = NmapParser().parse(Path('scan.' + format), content)
    scripts = [f for f in findings if not f.title.startswith('Open port')]
    assert {f.protocol for f in scripts} == {"tcp", "udp"}
    assert len({f.id for f in scripts}) == 2


def test_nmap_negative_tcp_check_does_not_suppress_udp_evidence():
    content = '''Nmap scan report for 127.0.0.1
53/tcp open domain
| dns-vuln-test:
|_ CVE-2024-1234 NOT VULNERABLE
53/udp open domain
| dns-vuln-test:
|_ CVE-2024-1234 VULNERABLE
'''
    findings = NmapParser().parse(Path('scan.txt'), content)
    udp = [f for f in findings if f.protocol == "udp" and not f.title.startswith('Open port')]
    assert len(udp) == 1
    assert udp[0].cve_ids == ["CVE-2024-1234"]


@pytest.mark.parametrize("payload", [{"found": "false"}, {"found": True, "cve_id": "CVE-2024-9999"}])
def test_nvd_ignores_bad_cached_identity_or_found_flag(tmp_path, monkeypatch, payload):
    monkeypatch.setattr(nvd, "NVD_CACHE_DIR", tmp_path)
    nvd._write_cache("CVE-2024-1234", payload)
    assert nvd._read_cache("CVE-2024-1234") is None


def test_empty_findings_still_generate_requested_report(tmp_path):
    scan = tmp_path / "empty.xml"
    scan.write_text("<nmaprun/>")
    report = tmp_path / "empty.pdf"
    result = CliRunner().invoke(cli, ["analyze", str(scan), "--format", "json",
                                     "--report", "pdf", "--output", str(report)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == []
    assert report.read_bytes().startswith(b"%PDF-")


def test_nvd_unexpected_response_is_not_cached_as_not_found(monkeypatch):
    response = SimpleNamespace(status_code=200, raise_for_status=lambda: None, json=lambda: {})
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: response)
    assert nvd._fetch_cve("CVE-2024-1234") is None


def test_module_validator_online_download_is_pinned_and_records_hash(tmp_path, monkeypatch):
    import hashlib
    raw = (FIXTURES / "fixtures" / "rapid7-metadata.json").read_bytes()
    requests_seen = []
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def raise_for_status(self):
            pass
        def iter_content(self, size):
            yield raw[:100]
            yield raw[100:]
    def get(url, **options):
        requests_seen.append((url, options))
        return Response()
    monkeypatch.setattr(nvd.requests, "get", get)
    output = tmp_path / "validation.json"
    revision = "a" * 40
    assert validate_main(["--online", "--revision", revision, "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["revision"] == revision
    assert f"/{revision}/" in requests_seen[0][0]
    assert requests_seen[0][1] == {"timeout": 30, "stream": True}


def test_pinned_metadata_fixture_matches_recorded_validation():
    import hashlib
    report = json.loads((FIXTURES.parent / "tools/module-validation.json").read_text())
    fixture = (FIXTURES / "fixtures/rapid7-metadata.json").read_bytes()
    fullnames = {entry["fullname"] for entry in json.loads(fixture).values()}
    assert fullnames == set(report["valid"])
    assert report["missing"] == []
    assert len(fullnames) == report["checked"] == 31
    assert hashlib.sha256(fixture).hexdigest() == report["fixture_sha256"]
