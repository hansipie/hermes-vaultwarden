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
        "session": None,
        "item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "item_name": None,
        "server_url": None,
        "username_env": None,
        "password_env": None,
        "notes_env": None,
        "credentials_command": None,
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


def _configure_setup(monkeypatch, config):
    monkeypatch.setattr(cli, "load_config", lambda: config)
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/usr/local/bin/bw"))
    monkeypatch.setattr(cli, "_bw_version", lambda *_: "2026.8.0")
    monkeypatch.setattr(cli, "_bw_current_server", lambda *_a, **_k: "")
    monkeypatch.setattr(cli.sys, "stdin", mock.MagicMock(isatty=lambda: False))
    monkeypatch.setattr(
        vw, "fetch_vaultwarden_secrets", mock.Mock(return_value=({}, []))
    )
    save_env = mock.Mock()
    monkeypatch.setattr(cli, "save_env_value", save_env)
    monkeypatch.setattr(cli, "get_env_path", lambda: Path("/tmp/.env"))
    monkeypatch.setattr(cli, "save_config", mock.Mock())
    return save_env


def test_setup_session_flag_is_saved_to_env(monkeypatch):
    config = {"secrets": {"vaultwarden": {}}}
    # setenv first so monkeypatch restores BW_SESSION after setup writes it
    monkeypatch.setenv("BW_SESSION", "")
    monkeypatch.delenv("BW_SESSION")
    save_env = _configure_setup(monkeypatch, config)

    assert cli.cmd_setup(_setup_args(session=_SESSION)) == 0

    save_env.assert_called_once_with("BW_SESSION", _SESSION)
    assert cli.os.environ["BW_SESSION"] == _SESSION
    vw_cfg = config["secrets"]["vaultwarden"]
    assert vw_cfg["override_existing"] is True
    assert vw_cfg["auto_unlock"] is False


def test_setup_prompts_for_session_when_missing(monkeypatch):
    config = {"secrets": {"vaultwarden": {}}}
    # setenv first so monkeypatch restores BW_SESSION after setup writes it
    monkeypatch.setenv("BW_SESSION", "")
    monkeypatch.delenv("BW_SESSION")
    save_env = _configure_setup(monkeypatch, config)
    monkeypatch.setattr(cli.sys, "stdin", mock.MagicMock(isatty=lambda: True))
    prompt = mock.Mock(return_value=f"  {_SESSION}  ")
    monkeypatch.setattr(cli, "masked_secret_prompt", prompt)
    # later binding prompts: answer blank (skip)
    monkeypatch.setattr(cli.Console, "input", lambda *_a, **_k: "")

    assert cli.cmd_setup(_setup_args()) == 0

    prompt.assert_called_once()
    save_env.assert_called_once_with("BW_SESSION", _SESSION)


def test_setup_auto_unlock_does_not_persist_session(monkeypatch, tmp_path):
    config = {"secrets": {"vaultwarden": {}}}
    save_env = _configure_setup(monkeypatch, config)
    monkeypatch.setattr(cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(vw, "mint_session", mock.Mock(return_value="minted"))

    result = cli.cmd_setup(
        _setup_args(auto_unlock=True, server_url="https://vault.example.com")
    )

    assert result == 0
    save_env.assert_not_called()
    vw_cfg = config["secrets"]["vaultwarden"]
    assert vw_cfg["override_existing"] is False
    assert vw_cfg["auto_unlock"] is True
    # declared explicitly so Hermes strips them from spawned children
    assert vw_cfg["client_id_env"] == "BW_CLIENTID"
    assert vw_cfg["client_secret_env"] == "BW_CLIENTSECRET"
    assert vw_cfg["master_password_env"] == "BW_MASTER_PASSWORD"


def test_setup_item_name_clears_stale_item_id(monkeypatch):
    config = {
        "secrets": {
            "vaultwarden": {"item_id": "old-id-0000", "override_existing": False}
        }
    }
    monkeypatch.setenv("BW_SESSION", _SESSION)
    _configure_setup(monkeypatch, config)

    assert cli.cmd_setup(_setup_args(item_id=None, item_name="Hermes")) == 0

    vw_cfg = config["secrets"]["vaultwarden"]
    assert vw_cfg["item_name"] == "Hermes"
    assert "item_id" not in vw_cfg
    # an existing explicit choice is preserved
    assert vw_cfg["override_existing"] is False


def test_setup_item_id_clears_item_name(monkeypatch):
    config = {"secrets": {"vaultwarden": {"item_name": "Old"}}}
    monkeypatch.setenv("BW_SESSION", _SESSION)
    _configure_setup(monkeypatch, config)

    assert cli.cmd_setup(_setup_args(item_id="new-id-1111")) == 0

    vw_cfg = config["secrets"]["vaultwarden"]
    assert vw_cfg["item_id"] == "new-id-1111"
    assert "item_name" not in vw_cfg


def test_sync_auto_unlock_mints_once_and_ignores_env_session(monkeypatch, tmp_path):
    config = {
        "secrets": {
            "vaultwarden": {
                "enabled": True,
                "item_name": "Hermes",
                "auto_unlock": True,
                "server_url": "https://vault.example.com",
                "binary_path": "/usr/local/bin/bw",
            }
        }
    }
    item = {"fields": [{"name": "NEW_KEY", "value": "new-value", "type": 1}]}
    _configure_sync(monkeypatch, tmp_path, config, item)
    monkeypatch.setenv("BW_SESSION", "stale-env-session")
    monkeypatch.delenv("NEW_KEY", raising=False)
    mint = mock.Mock(return_value="minted-session")
    monkeypatch.setattr(vw, "mint_session", mint)

    result = cli.cmd_sync(argparse.Namespace(apply=False))

    assert result == 0
    mint.assert_called_once()
    assert "NEW_KEY" not in cli.os.environ  # dry-run writes nothing


def test_sync_expands_item_name_ref(monkeypatch, tmp_path):
    config = {
        "secrets": {
            "vaultwarden": {
                "enabled": True,
                "item_name": "${BW_ITEM_NAME}",
                "binary_path": "/usr/local/bin/bw",
            }
        }
    }
    item = {"fields": [{"name": "NEW_KEY", "value": "new-value", "type": 1}]}
    _configure_sync(monkeypatch, tmp_path, config, item)
    calls = []
    monkeypatch.setattr(
        vw,
        "run_secret_cli",
        lambda argv, **k: calls.append(list(argv)) or _proc(stdout=json.dumps(item)),
    )
    monkeypatch.setenv("BW_SESSION", _SESSION)
    monkeypatch.setenv("BW_ITEM_NAME", "Hermes")
    monkeypatch.delenv("NEW_KEY", raising=False)

    assert cli.cmd_sync(argparse.Namespace(apply=False)) == 0
    get_item = [argv for argv in calls if argv[1:3] == ["get", "item"]]
    assert get_item and get_item[0][3] == "Hermes"


def test_sync_reports_unset_item_ref(monkeypatch, tmp_path, capsys):
    config = {
        "secrets": {
            "vaultwarden": {
                "enabled": True,
                "item_name": "${BW_ITEM_NAME}",
                "binary_path": "/usr/local/bin/bw",
            }
        }
    }
    _configure_sync(monkeypatch, tmp_path, config, {})
    monkeypatch.setenv("BW_SESSION", _SESSION)
    monkeypatch.delenv("BW_ITEM_NAME", raising=False)

    assert cli.cmd_sync(argparse.Namespace(apply=False)) == 1
    assert "BW_ITEM_NAME" in capsys.readouterr().out


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


# --- bw output shown by the CLI is redacted, bounded and markup-safe ---


def _recording_console():
    from rich.console import Console
    return Console(record=True, force_terminal=False, width=400)


def test_list_items_failure_redacts_session_and_escapes_markup(monkeypatch):
    stdout = f"[/bold] boom {_SESSION} " + "z" * 1000
    monkeypatch.setattr(
        cli, "run_secret_cli",
        lambda *a, **k: _proc(stdout=stdout, stderr="", returncode=1),
    )
    console = _recording_console()
    assert cli._list_items(Path("/bin/bw"), _SESSION, console) is None
    out = console.export_text()
    assert _SESSION not in out
    assert "[/bold] boom [REDACTED]" in out
    assert "z" * 400 not in out


def test_list_items_failure_with_no_output_does_not_crash(monkeypatch):
    monkeypatch.setattr(
        cli, "run_secret_cli",
        lambda *a, **k: _proc(stdout=None, stderr=None, returncode=1),
    )
    console = _recording_console()
    assert cli._list_items(Path("/bin/bw"), _SESSION, console) is None


def test_reset_auth_failure_redacts_and_escapes(monkeypatch, tmp_path):
    monkeypatch.setenv("BW_CLIENTSECRET", "client-secret-value")
    monkeypatch.setattr(cli, "load_config", lambda: {})
    monkeypatch.setattr(cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/bin/bw"))
    monkeypatch.setattr(
        vw, "_run_bw",
        lambda *a, **k: _proc(stderr="[/x] client-secret-value", returncode=1),
    )
    console = _recording_console()
    monkeypatch.setattr(cli, "Console", lambda: console)
    assert cli.cmd_reset_auth(argparse.Namespace()) == 1
    out = console.export_text()
    assert "client-secret-value" not in out
    assert "bw logout failed: [/x] [REDACTED]" in out


# --- setup --auto-unlock resolves credentials like fetch() (credentials_command) ---

import sys as _sys

_HELPER = (
    f"{_sys.executable} -c \"print('BW_CLIENTID=cid-h'); "
    "print('BW_CLIENTSECRET=sec-h'); print('BW_MASTER_PASSWORD=pw-h')\""
)


def _auto_setup(monkeypatch, tmp_path, config, env=None):
    _configure_setup(monkeypatch, config)
    monkeypatch.setattr(cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(vw, "get_source_environment", lambda: dict(env or {}))
    mint = mock.Mock(return_value="minted")
    monkeypatch.setattr(vw, "mint_session", mint)
    console = _recording_console()
    monkeypatch.setattr(cli, "Console", lambda: console)
    return mint, console


def test_setup_uses_configured_credentials_command(monkeypatch, tmp_path):
    config = {"secrets": {"vaultwarden": {"credentials_command": _HELPER}}}
    mint, console = _auto_setup(monkeypatch, tmp_path, config)
    assert cli.cmd_setup(_setup_args(auto_unlock=True, server_url="https://vault.example.com")) == 0
    assert mint.call_args.kwargs["credentials_env"] == {
        "BW_CLIENTID": "cid-h", "BW_CLIENTSECRET": "sec-h", "BW_MASTER_PASSWORD": "pw-h"}
    out = console.export_text()
    assert "credentials from credentials_command: BW_CLIENTID, BW_CLIENTSECRET, BW_MASTER_PASSWORD" in out
    assert not any(v in out for v in ("cid-h", "sec-h", "pw-h"))
    assert config["secrets"]["vaultwarden"]["credentials_command"] == _HELPER


def test_setup_flag_is_used_and_saved(monkeypatch, tmp_path):
    config = {"secrets": {"vaultwarden": {}}}
    mint, _ = _auto_setup(monkeypatch, tmp_path, config)
    args = _setup_args(auto_unlock=True, server_url="https://vault.example.com",
                       credentials_command=_HELPER)
    assert cli.cmd_setup(args) == 0
    assert mint.call_args.kwargs["credentials_env"]["BW_MASTER_PASSWORD"] == "pw-h"
    assert config["secrets"]["vaultwarden"]["credentials_command"] == _HELPER


def test_setup_empty_flag_removes_configured_helper(monkeypatch, tmp_path):
    config = {"secrets": {"vaultwarden": {"credentials_command": _HELPER}}}
    env = {"BW_CLIENTID": "e1", "BW_CLIENTSECRET": "e2", "BW_MASTER_PASSWORD": "e3"}
    _auto_setup(monkeypatch, tmp_path, config, env)
    args = _setup_args(auto_unlock=True, server_url="https://vault.example.com",
                       credentials_command="")
    assert cli.cmd_setup(args) == 0
    assert "credentials_command" not in config["secrets"]["vaultwarden"]


def test_setup_environment_wins_and_helper_not_run(monkeypatch, tmp_path):
    config = {"secrets": {"vaultwarden": {"credentials_command": _HELPER}}}
    env = {"BW_CLIENTID": "e1", "BW_CLIENTSECRET": "e2", "BW_MASTER_PASSWORD": "e3"}
    mint, console = _auto_setup(monkeypatch, tmp_path, config, env)
    runner = mock.Mock()
    monkeypatch.setattr(vw, "run_credentials_command", runner)
    assert cli.cmd_setup(_setup_args(auto_unlock=True, server_url="https://vault.example.com")) == 0
    runner.assert_not_called()
    assert mint.call_args.kwargs["credentials_env"] == env
    assert "credentials from credentials_command" not in console.export_text()


def test_setup_helper_failure_aborts_without_saving(monkeypatch, tmp_path):
    failing = f"{_sys.executable} -c \"import sys; sys.stderr.write('pw-h'); sys.exit(2)\""
    config = {"secrets": {"vaultwarden": {"credentials_command": failing}}}
    mint, console = _auto_setup(monkeypatch, tmp_path, config)
    assert cli.cmd_setup(_setup_args(auto_unlock=True, server_url="https://vault.example.com")) == 1
    mint.assert_not_called()
    cli.save_config.assert_not_called()
    out = console.export_text()
    assert "credentials_command failed: exit code 2" in out and "pw-h" not in out


def test_setup_honors_configured_credential_names(monkeypatch, tmp_path):
    helper = f"{_sys.executable} -c \"print('MY_ID=i'); print('MY_SECRET=s'); print('MY_PW=p')\""
    config = {"secrets": {"vaultwarden": {
        "credentials_command": helper, "client_id_env": "MY_ID",
        "client_secret_env": "MY_SECRET", "master_password_env": "MY_PW"}}}
    mint, _ = _auto_setup(monkeypatch, tmp_path, config)
    assert cli.cmd_setup(_setup_args(auto_unlock=True, server_url="https://vault.example.com")) == 0
    kw = mint.call_args.kwargs
    assert (kw["client_id_env"], kw["client_secret_env"], kw["master_password_env"]) == (
        "MY_ID", "MY_SECRET", "MY_PW")
    assert kw["credentials_env"] == {"MY_ID": "i", "MY_SECRET": "s", "MY_PW": "p"}
