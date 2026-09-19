import json

import pytest
from click.testing import CliRunner

from vulnmind import config as config_module
from vulnmind.cli import cli
from vulnmind.config import Config


def test_update_check_preference_parses_boolean_and_environment(monkeypatch):
    assert Config({}).update_checks_enabled is True
    assert Config({"update_checks": False}).update_checks_enabled is False
    assert Config({"update_checks": "off"}).update_checks_enabled is False

    monkeypatch.setenv("VULNMIND_UPDATE_CHECKS", "no")
    assert Config({"update_checks": True}).update_checks_enabled is False


def test_valid_non_object_config_falls_back_to_defaults(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text("[]")
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)

    config = Config.load()

    assert config.display_dict() == {}
    assert config.update_checks_enabled is True


def test_invalid_config_encoding_falls_back_to_defaults(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_bytes(b"\xff")
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)

    assert Config.load().display_dict() == {}


@pytest.mark.parametrize("value", [123456789, True, {"secret": "do-not-display"}, ["do-not-display"]])
def test_config_display_masks_non_string_secrets(value):
    assert Config({"groq_api_key": value}).display_dict() == {"groq_api_key": "***"}


def test_config_command_persists_update_check_opt_out(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)

    result = CliRunner().invoke(cli, ["config", "set-update-checks", "off"])

    assert result.exit_code == 0, result.output
    assert json.loads(config_file.read_text())["update_checks"] is False


def test_config_save_is_atomic_and_owner_only(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"old": true}')
    config_file.chmod(0o644)
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)

    Config({"groq_api_key": "secret"}).save()

    assert json.loads(config_file.read_text()) == {"groq_api_key": "secret"}
    assert config_file.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


def test_config_save_preserves_previous_file_when_replace_fails(
    tmp_path,
    monkeypatch,
):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"old": true}')
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)
    monkeypatch.setattr(
        config_module.os,
        "replace",
        lambda *_: (_ for _ in ()).throw(OSError("interrupted")),
    )

    with pytest.raises(OSError, match="interrupted"):
        Config({"new": True}).save()

    assert json.loads(config_file.read_text()) == {"old": True}
    assert list(tmp_path.glob(".config.json.*.tmp")) == []
