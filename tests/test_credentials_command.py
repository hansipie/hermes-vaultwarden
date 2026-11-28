"""credentials_command: auto-unlock credentials from a helper (secret-tool, ...)
instead of .env. Values must stay in process memory and out of diagnostics."""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from agent.secret_sources.base import ErrorKind

import vw_source as vw

NAMES = ("BW_CLIENTID", "BW_CLIENTSECRET", "BW_MASTER_PASSWORD")


def _printf(*lines: str) -> str:
    # A helper that prints exactly the given lines (no shell interpolation).
    script = "import sys; sys.stdout.write(%r)" % ("".join(l + "\n" for l in lines))
    return f"{sys.executable} -c {json.dumps(script)}"


# --- run_credentials_command ------------------------------------------------

def test_parses_requested_names_only_and_keeps_spaces():
    out = vw.run_credentials_command(
        _printf("BW_CLIENTID=user.abc", "export BW_CLIENTSECRET='s3cr et'",
                "BW_MASTER_PASSWORD=  pass word  ", "OTHER=ignored", "# comment", "junk"),
        NAMES,
    )
    assert out == {"BW_CLIENTID": "user.abc", "BW_CLIENTSECRET": "s3cr et",
                   "BW_MASTER_PASSWORD": "  pass word  "}


def test_failure_reports_exit_code_only():
    cmd = f"{sys.executable} -c \"import sys; sys.stderr.write('leak-me'); print('BW_CLIENTID=leak-me'); sys.exit(3)\""
    with pytest.raises(RuntimeError) as exc:
        vw.run_credentials_command(cmd, NAMES)
    assert str(exc.value) == "credentials_command failed: exit code 3"


def test_timeout_is_bounded():
    with pytest.raises(RuntimeError, match="timed out after 0.5s"):
        vw.run_credentials_command(f"{sys.executable} -c 'import time; time.sleep(10)'",
                                   NAMES, timeout=0.5)


def test_output_cap(monkeypatch):
    monkeypatch.setattr(vw, "_CRED_CMD_MAX_OUTPUT", 10)
    with pytest.raises(RuntimeError, match="size cap"):
        vw.run_credentials_command(_printf("BW_CLIENTID=" + "x" * 50), NAMES)


# --- fetch() integration ----------------------------------------------------

@pytest.fixture
def rig(tmp_path, monkeypatch):
    vw._reset_cache_for_tests(tmp_path)
    env = {}
    monkeypatch.setattr(vw, "get_source_environment", lambda: env)
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/bin/bw"))
    mint = Mock(return_value="minted-session")
    read = Mock(return_value=({"A": "b"}, []))
    monkeypatch.setattr(vw, "mint_session", mint)
    monkeypatch.setattr(vw, "fetch_vaultwarden_secrets", read)
    cfg = {"auto_unlock": True, "item_name": "x", "server_url": "https://example.test",
           "credentials_command": _printf("BW_CLIENTID=cid-from-cmd",
                                          "BW_CLIENTSECRET=secret-from-cmd",
                                          "BW_MASTER_PASSWORD=pw-from-cmd")}
    yield SimpleNamespace(env=env, cfg=cfg, mint=mint, read=read, home=tmp_path,
                          source=vw.VaultwardenSource())
    vw._AUTH_SESSIONS.clear()


def test_fetch_uses_command_values_in_memory_only(rig):
    before = dict(os.environ)
    result = rig.source.fetch(rig.cfg, rig.home)
    assert not result.error and result.secrets == {"A": "b"}
    assert rig.mint.call_args.kwargs["credentials_env"] == {
        "BW_CLIENTID": "cid-from-cmd", "BW_CLIENTSECRET": "secret-from-cmd",
        "BW_MASTER_PASSWORD": "pw-from-cmd"}
    assert dict(os.environ) == before and rig.env == {}
    assert not any("from-cmd" in p.read_text(errors="ignore")
                   for p in rig.home.rglob("*") if p.is_file())


def test_environment_value_keeps_precedence(rig):
    rig.env["BW_CLIENTSECRET"] = "secret-from-env"
    rig.source.fetch(rig.cfg, rig.home)
    creds = rig.mint.call_args.kwargs["credentials_env"]
    assert creds["BW_CLIENTSECRET"] == "secret-from-env"
    assert creds["BW_CLIENTID"] == "cid-from-cmd"


def test_command_not_run_when_environment_is_complete(rig, monkeypatch):
    rig.env.update({n: "env-" + n for n in NAMES})
    runner = Mock()
    monkeypatch.setattr(vw, "run_credentials_command", runner)
    assert not rig.source.fetch(rig.cfg, rig.home).error
    runner.assert_not_called()


def test_rotation_in_helper_triggers_new_mint(rig):
    rig.source.fetch(rig.cfg, rig.home)
    rig.source.fetch(rig.cfg, rig.home)
    assert rig.mint.call_count == 1
    rig.cfg["credentials_command"] = _printf("BW_CLIENTID=cid-from-cmd",
                                             "BW_CLIENTSECRET=rotated-secret",
                                             "BW_MASTER_PASSWORD=pw-from-cmd")
    rig.source.fetch(rig.cfg, rig.home)
    assert rig.mint.call_count == 2


def test_command_failure_is_reported_without_output(rig):
    rig.cfg["credentials_command"] = (
        f"{sys.executable} -c \"import sys; sys.stderr.write('pw-from-cmd'); sys.exit(1)\"")
    result = rig.source.fetch(rig.cfg, rig.home)
    assert result.error == "credentials_command failed: exit code 1"
    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    rig.mint.assert_not_called()


def test_values_are_redacted_from_diagnostics(rig):
    rig.mint.side_effect = RuntimeError("bw unlock failed: echo pw-from-cmd secret-from-cmd")
    result = rig.source.fetch(rig.cfg, rig.home)
    assert result.error and "from-cmd" not in result.error


def test_ignored_outside_auto_unlock(rig, monkeypatch):
    rig.cfg["auto_unlock"] = False
    rig.env["BW_SESSION"] = "ambient"
    runner = Mock()
    monkeypatch.setattr(vw, "run_credentials_command", runner)
    rig.source.fetch(rig.cfg, rig.home)
    runner.assert_not_called()


def test_master_password_reaches_bw_unlock_child_only(tmp_path, monkeypatch):
    # Real mint_session: the helper's password is handed to `bw unlock` via the
    # child env, never through argv or os.environ.
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, "get_source_environment", lambda: {})
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/bin/bw"))
    proc = lambda out="", code=0: SimpleNamespace(stdout=out, stderr="", returncode=code)
    run = Mock(side_effect=[
        proc(json.dumps({"status": "locked", "serverUrl": "https://example.test"})),
        proc("session-token"), proc(), proc(json.dumps({"fields": []})),
    ])
    monkeypatch.setattr(vw, "run_secret_cli", run)
    cfg = {"auto_unlock": True, "server_url": "https://example.test", "item_name": "item",
           "sync_interval_seconds": 0,
           "credentials_command": _printf("BW_CLIENTID=cid", "BW_CLIENTSECRET=csec",
                                          "BW_MASTER_PASSWORD=helper-password")}
    result = vw.VaultwardenSource().fetch(cfg, tmp_path)
    assert not result.error
    unlock = run.call_args_list[1]
    assert unlock.args[0][1:] == ["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"]
    assert unlock.kwargs["extra_env"]["BW_MASTER_PASSWORD"] == "helper-password"
    assert all("helper-password" not in repr(c.args) for c in run.call_args_list)
    assert "BW_MASTER_PASSWORD" not in os.environ
