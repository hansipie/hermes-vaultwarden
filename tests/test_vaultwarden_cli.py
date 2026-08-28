"""Hermetic regressions for the Vaultwarden plugin CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest import mock

import pytest
from agent.secret_sources import registry
from agent.secret_sources.base import FetchResult, SecretSource

import vw_cli as cli
import vw_source as vw

_SESSION = "test-session-token"


def _proc(*, stdout: str = "", stderr: str = "", returncode: int = 0):
    proc = mock.MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _setup_args(**overrides) -> argparse.Namespace:
    values = {
        "binary_path": None,
        "auto_unlock": False,
        "item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "item_name": None,
        "server_url": None,
        "username_env": None,
        "password_env": None,
        "notes_env": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture(autouse=True)
def _registered_vaultwarden_source():
    vw._CACHE.clear()
    registry._reset_registry_for_tests()
    registry.register_source(vw.VaultwardenSource())
    yield
    registry._reset_registry_for_tests()


def test_setup_reuses_configured_binary_pin(monkeypatch):
    configured = "/usr/local/bin/bw"
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: {"secrets": {"vaultwarden": {"binary_path": configured}}},
    )
    find_bw = mock.Mock(return_value=None)
    monkeypatch.setattr(vw, "find_bw", find_bw)

    assert cli.cmd_setup(_setup_args()) == 1
    find_bw.assert_called_once_with(configured)


def test_interactive_setup_rejects_server_mismatch_before_fetch(monkeypatch):
    config = {"secrets": {"vaultwarden": {}}}
    monkeypatch.setenv("BW_SESSION", _SESSION)
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/usr/local/bin/bw"))
    monkeypatch.setattr(cli, "_bw_version", lambda *_: "2026.8.0")
    monkeypatch.setattr(cli, "_bw_current_server", lambda *_: "https://old.example")
    monkeypatch.setattr(cli.sys, "stdin", mock.MagicMock(isatty=lambda: False))
    fetch = mock.Mock()
    save = mock.Mock()
    monkeypatch.setattr(vw, "fetch_vaultwarden_secrets", fetch)
    monkeypatch.setattr(cli, "save_config", save)

    result = cli.cmd_setup(_setup_args(server_url="https://vault.example/"))

    assert result == 1
    fetch.assert_not_called()
    save.assert_not_called()


def _configure_sync(monkeypatch, tmp_path, config, item):
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/usr/local/bin/bw"))
    monkeypatch.setattr(cli, "run_secret_cli", lambda *a, **k: _proc())
    monkeypatch.setattr(
        vw,
        "run_secret_cli",
        lambda *a, **k: _proc(stdout=json.dumps(item)),
    )


def test_sync_apply_does_not_force_override_or_replace_bootstrap(monkeypatch, tmp_path):
    config = {
        "secrets": {
            "vaultwarden": {
                "enabled": True,
                "item_name": "Hermes",
                "override_existing": False,
                "binary_path": "/usr/local/bin/bw",
            }
        }
    }
    item = {
        "fields": [
            {"name": "EXISTING_KEY", "value": "vault-value", "type": 1},
            {"name": "NEW_KEY", "value": "new-value", "type": 1},
            {
                "name": "BW_MASTER_PASSWORD",
                "value": "must-not-win",
                "type": 1,
            },
        ]
    }
    _configure_sync(monkeypatch, tmp_path, config, item)
    monkeypatch.setenv("BW_SESSION", _SESSION)
    monkeypatch.setenv("EXISTING_KEY", "working-value")
    monkeypatch.setenv("BW_MASTER_PASSWORD", "bootstrap-value")
    monkeypatch.delenv("NEW_KEY", raising=False)
    real_apply = registry.apply_all

    with mock.patch.object(
        cli.secret_registry, "apply_all", wraps=real_apply
    ) as apply_all:
        result = cli.cmd_sync(argparse.Namespace(apply=True))

    assert result == 0
    apply_all.assert_called_once()
    assert cli.os.environ["EXISTING_KEY"] == "working-value"
    assert cli.os.environ["BW_MASTER_PASSWORD"] == "bootstrap-value"
    assert cli.os.environ["NEW_KEY"] == "new-value"


class _MappedSource(SecretSource):
    name = "mapped_test"
    label = "Mapped test source"
    shape = "mapped"
    scheme = "mapped-test"

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        return FetchResult(secrets={"SHARED_KEY": "mapped-value"})


def test_sync_apply_respects_preserve_and_cross_source_precedence(
    monkeypatch, tmp_path
):
    registry.register_source(_MappedSource())
    config = {
        "secrets": {
            "sources": ["mapped_test", "vaultwarden"],
            "preserve_existing": ["PRESERVE_KEY"],
            "mapped_test": {"enabled": True},
            "vaultwarden": {
                "enabled": True,
                "item_name": "Hermes",
                "override_existing": True,
                "binary_path": "/usr/local/bin/bw",
            },
        }
    }
    item = {
        "fields": [
            {"name": "SHARED_KEY", "value": "vault-value", "type": 1},
            {"name": "PRESERVE_KEY", "value": "vault-value", "type": 1},
            {"name": "VAULT_ONLY", "value": "vault-value", "type": 1},
        ]
    }
    _configure_sync(monkeypatch, tmp_path, config, item)
    monkeypatch.setenv("BW_SESSION", _SESSION)
    monkeypatch.setenv("PRESERVE_KEY", "working-value")
    monkeypatch.delenv("SHARED_KEY", raising=False)
    monkeypatch.delenv("VAULT_ONLY", raising=False)

    result = cli.cmd_sync(argparse.Namespace(apply=True))

    assert result == 0
    assert cli.os.environ["PRESERVE_KEY"] == "working-value"
    assert "SHARED_KEY" not in cli.os.environ
    assert cli.os.environ["VAULT_ONLY"] == "vault-value"
