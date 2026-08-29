"""Hermetic tests for the Vaultwarden secret-source plugin.

We never hit a real vault — subprocess is mocked so the suite stays
fast and offline-safe.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest
from agent.secret_sources import registry
from agent.secret_sources.base import ErrorKind

import vw_source as vw

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_ITEM = {
    "object": "item",
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "name": "Hermes",
    "type": 1,
    "fields": [
        {"name": "OPENROUTER_API_KEY", "value": "sk-or-test", "type": 1},
        {"name": "ANTHROPIC_API_KEY", "value": "sk-ant-test", "type": 1},
        {"name": "123INVALID", "value": "should-be-skipped", "type": 0},
        {"name": "", "value": "also-skipped", "type": 0},
    ],
}

_FAKE_LOGIN_ITEM = {
    **_FAKE_ITEM,
    "login": {"username": "svc-hermes", "password": "hunter2"},
    "notes": "rotate quarterly",
}

_FAKE_SESSION = "fake-session-token-abc123"


def _make_ok_proc(payload=None) -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.returncode = 0
    proc.stdout = json.dumps(payload if payload is not None else _FAKE_ITEM)
    proc.stderr = ""
    return proc


def _make_fail_proc(returncode=1, stderr="error msg") -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.returncode = returncode
    proc.stdout = ""
    proc.stderr = stderr
    return proc


def _make_status(status="unauthenticated", server_url=None) -> mock.MagicMock:
    return _make_ok_proc(
        {"serverUrl": server_url, "lastSync": None, "status": status}
    )


# ---------------------------------------------------------------------------
# find_bw
# ---------------------------------------------------------------------------


class TestFindBw:
    def test_finds_system_bw(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        result = vw.find_bw()
        assert result == Path("/usr/bin/bw")

    def test_managed_bin_wins_over_system(self, tmp_path, monkeypatch):
        managed = tmp_path / "bin" / "bw"
        managed.parent.mkdir(parents=True)
        managed.write_text("#!/bin/sh\necho fake")
        managed.chmod(0o755)
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        result = vw.find_bw()
        assert result == managed

    def test_returns_none_when_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw, "_hermes_bin_dir", lambda: tmp_path / "bin")
        monkeypatch.setattr(vw.shutil, "which", lambda _: None)
        assert vw.find_bw() is None

    def test_pinned_path_wins(self, tmp_path, monkeypatch):
        pinned = tmp_path / "custom-bw"
        pinned.write_text("#!/bin/sh\necho fake")
        pinned.chmod(0o755)
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        assert vw.find_bw(str(pinned)) == pinned

    def test_broken_pin_returns_none_without_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vw.shutil, "which", lambda _: "/usr/bin/bw")
        assert vw.find_bw(str(tmp_path / "does-not-exist")) is None


# ---------------------------------------------------------------------------
# is_valid_env_name (shared helper from base — regression sanity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("OPENROUTER_API_KEY", True),
        ("_PRIVATE", True),
        ("MY_VAR_123", True),
        ("123INVALID", False),
        ("", False),
        ("has space", False),
        ("has-dash", False),
    ],
)
def test_is_valid_env_name(name, expected):
    assert vw.is_valid_env_name(name) is expected


# ---------------------------------------------------------------------------
# resolve_login_bindings
# ---------------------------------------------------------------------------


class TestResolveLoginBindings:
    def test_all_unset_by_default(self):
        bindings, warnings = vw.resolve_login_bindings({})
        assert bindings == {
            "username_env": None,
            "password_env": None,
            "notes_env": None,
        }
        assert warnings == []

    def test_valid_names_pass_through(self):
        cfg = {
            "username_env": "VW_USER",
            "password_env": "VW_PASS",
            "notes_env": "VW_NOTES",
        }
        bindings, warnings = vw.resolve_login_bindings(cfg)
        assert bindings == cfg
        assert warnings == []

    def test_invalid_name_warns_and_resolves_to_none(self):
        bindings, warnings = vw.resolve_login_bindings({"username_env": "bad name!"})
        assert bindings["username_env"] is None
        assert len(warnings) == 1
        assert "username_env" in warnings[0]

    def test_blank_and_whitespace_treated_as_unset(self):
        bindings, warnings = vw.resolve_login_bindings({"password_env": "   "})
        assert bindings["password_env"] is None
        assert warnings == []


# ---------------------------------------------------------------------------
# fetch_vaultwarden_secrets
# ---------------------------------------------------------------------------


class TestFetchVaultwardenSecrets:
    def setup_method(self):
        vw._CACHE.clear()

    def test_returns_parsed_fields(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert secrets["ANTHROPIC_API_KEY"] == "sk-ant-test"
        assert "123INVALID" not in secrets
        assert any("123INVALID" in w for w in warnings)

    def test_child_env_is_minimal_and_session_not_in_argv(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        argv = mock_run.call_args.args[0]
        assert "--session" not in argv
        assert _FAKE_SESSION not in argv
        assert argv[-1] == "Hermes"
        assert "--" not in argv
        child_env = mock_run.call_args.kwargs["env"]
        assert child_env["BW_SESSION"] == _FAKE_SESSION
        # allowlisted env only — no wholesale os.environ copy
        assert "HERMES_TEST_CANARY" not in child_env

    def test_raises_on_empty_session(self):
        with pytest.raises(RuntimeError, match="session token is empty"):
            vw.fetch_vaultwarden_secrets(
                session="",
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
            )

    def test_raises_on_empty_item_name(self):
        with pytest.raises(RuntimeError, match="item_name is empty"):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
            )

    @pytest.mark.parametrize("item_reference", ["-h", "--help"])
    def test_rejects_option_shaped_item_reference(self, item_reference):
        with (
            mock.patch.object(vw, "run_secret_cli") as mock_run,
            pytest.raises(RuntimeError, match="cannot begin with '-'"),
        ):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name=item_reference,
                binary=Path("/usr/bin/bw"),
                use_cache=False,
            )
        mock_run.assert_not_called()

    def test_raises_when_bw_fails(self, tmp_path):
        with (
            mock.patch(
                "subprocess.run",
                side_effect=[_make_ok_proc({}), _make_fail_proc(1, "Not logged in")],
            ),
            pytest.raises(RuntimeError, match="bw exited 1"),
        ):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )

    def test_sync_failure_refuses_stale_local_item(self, tmp_path):
        with (
            mock.patch(
                "subprocess.run", return_value=_make_fail_proc(1, "Network unavailable")
            ) as mock_run,
            pytest.raises(RuntimeError, match="bw sync failed"),
        ):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 1
        assert mock_run.call_args.args[0] == ["/usr/bin/bw", "sync"]

    def test_raises_when_bw_not_found(self, monkeypatch):
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: None)
        with pytest.raises(RuntimeError, match="bw binary not found"):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=None,
                use_cache=False,
            )

    def test_in_process_cache_prevents_second_subprocess_call(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            for _ in range(2):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=True,
                    cache_ttl_seconds=300,
                    home_path=tmp_path,
                )
        assert mock_run.call_count == 2

    def test_disk_cache_survives_process_cache_clear(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
            vw._CACHE.clear()
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 2
        assert "OPENROUTER_API_KEY" in secrets

    def test_expired_disk_cache_triggers_refetch(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=1,
                use_cache=True,
                home_path=tmp_path,
            )
            vw._CACHE.clear()
            cache_file = vw._disk_cache_path(tmp_path)
            payload = json.loads(cache_file.read_text())
            payload["fetched_at"] = time.time() - 10
            cache_file.write_text(json.dumps(payload))

            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=1,
                use_cache=True,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 4

    def test_item_with_no_fields_returns_empty_with_warning(self, tmp_path):
        item = {**_FAKE_ITEM, "fields": []}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert secrets == {}
        assert any("fields" in w for w in warnings)

    def test_raises_on_non_json_output(self, tmp_path):
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.stdout = "not json"
        proc.stderr = ""
        with mock.patch("subprocess.run", return_value=proc):
            with pytest.raises(RuntimeError, match="non-JSON"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )

    def test_login_bindings_opt_in(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
                password_env="SVC_PASSWORD",
                notes_env="SVC_NOTES",
            )
        assert secrets["SVC_USER"] == "svc-hermes"
        assert secrets["SVC_PASSWORD"] == "hunter2"
        assert secrets["SVC_NOTES"] == "rotate quarterly"
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert not any("SVC_" in w for w in warnings)

    def test_login_bindings_default_off(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
            )
        assert "SVC_USER" not in secrets
        assert "hunter2" not in secrets.values()

    def test_login_binding_missing_value_warns(self, tmp_path):
        item = {**_FAKE_ITEM, "login": {}, "notes": ""}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
                notes_env="SVC_NOTES",
            )
        assert "SVC_USER" not in secrets
        assert any("login.username" in w for w in warnings)
        assert any("notes" in w for w in warnings)

    def test_login_binding_collision_with_custom_field_warns(self, tmp_path):
        item = {
            **_FAKE_ITEM,
            "fields": [{"name": "SVC_USER", "value": "from-field", "type": 1}],
            "login": {"username": "from-login"},
        }
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                username_env="SVC_USER",
            )
        assert secrets["SVC_USER"] == "from-login"
        assert any("both a custom field" in w for w in warnings)

    def test_cache_key_distinguishes_login_bindings(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
            )
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
                username_env="SVC_USER",
            )
        assert mock_run.call_count == 4
        assert secrets["SVC_USER"] == "svc-hermes"

    def test_timeout_raises_runtime_error(self, tmp_path):
        with mock.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("bw", 30)
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )


# ---------------------------------------------------------------------------
# VaultwardenSource.fetch — the SecretSource contract surface
# ---------------------------------------------------------------------------


class TestVaultwardenSourceFetch:
    def setup_method(self):
        vw._CACHE.clear()
        self.source = vw.VaultwardenSource()

    def test_disabled_by_default(self):
        assert self.source.is_enabled({}) is False
        assert self.source.is_enabled({"enabled": False}) is False

    def test_missing_session_env_reports_not_configured(self, monkeypatch):
        monkeypatch.delenv("BW_SESSION", raising=False)
        result = self.source.fetch({"enabled": True, "item_name": "Hermes"}, Path("/tmp"))
        assert not result.ok
        assert "BW_SESSION" in result.error
        assert result.error_kind is ErrorKind.NOT_CONFIGURED
        assert result.secrets == {}

    def test_missing_item_name_reports_not_configured(self, monkeypatch):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        result = self.source.fetch({"enabled": True}, Path("/tmp"))
        assert not result.ok
        assert "item_name" in result.error
        assert result.error_kind is ErrorKind.NOT_CONFIGURED

    def test_missing_binary_reports_binary_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: None)
        result = self.source.fetch(
            {"enabled": True, "item_name": "Hermes"}, tmp_path
        )
        assert not result.ok
        assert "not found" in result.error
        assert result.error_kind is ErrorKind.BINARY_MISSING

    def test_fetch_error_classified(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch(
            "subprocess.run", return_value=_make_fail_proc(1, "Session expired")
        ):
            result = self.source.fetch(
                {"enabled": True, "item_name": "Hermes"}, tmp_path
            )
        assert not result.ok
        assert "Session expired" in result.error
        assert result.error_kind is ErrorKind.AUTH_EXPIRED

    def test_fetch_returns_secrets_without_touching_environ(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            result = self.source.fetch(
                {"enabled": True, "item_name": "Hermes"}, tmp_path
            )
        assert result.ok
        assert result.secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        import os

        assert "OPENROUTER_API_KEY" not in os.environ

    def test_login_bindings_exported_via_config(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "username_env": "SVC_USER",
                    "password_env": "SVC_PASSWORD",
                },
                tmp_path,
            )
        assert result.ok
        assert result.secrets["SVC_USER"] == "svc-hermes"
        assert result.secrets["SVC_PASSWORD"] == "hunter2"
        assert "SVC_NOTES" not in result.secrets

    def test_invalid_login_binding_name_warns_and_is_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch("subprocess.run", return_value=_make_ok_proc(_FAKE_LOGIN_ITEM)):
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "username_env": "not a name",
                },
                tmp_path,
            )
        assert result.ok
        assert "not a name" not in result.secrets
        assert any("not a valid" in w for w in result.warnings)

    def test_protected_env_vars_follows_config(self):
        defaults = {
            "BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_MASTER_PASSWORD"
        }
        assert self.source.protected_env_vars({}) == frozenset(defaults)
        protected = self.source.protected_env_vars({"session_env": "MY_BW_TOKEN"})
        assert protected == frozenset((defaults - {"BW_SESSION"}) | {"MY_BW_TOKEN"})
        protected = self.source.protected_env_vars({"session_env": "not a name"})
        assert "not a name" not in protected

    def test_override_existing_defaults_false(self):
        assert self.source.override_existing({}) is False
        assert self.source.override_existing({"override_existing": True}) is True


@pytest.mark.parametrize(
    "message, expected",
    [
        ("bw timed out after 30s", ErrorKind.TIMEOUT),
        ("failed to invoke bw: No such file", ErrorKind.BINARY_MISSING),
        ("bw exited 1: Session expired", ErrorKind.AUTH_EXPIRED),
        ("bw exited 1: Vault is locked.", ErrorKind.AUTH_EXPIRED),
        ("bw exited 1: You are not logged in.", ErrorKind.AUTH_EXPIRED),
        ("bw API-key login failed: Invalid client_id", ErrorKind.AUTH_FAILED),
        ("bw unlock failed: Invalid master password", ErrorKind.AUTH_FAILED),
        ("auto_unlock requires an explicit secrets.vaultwarden.server_url", ErrorKind.NOT_CONFIGURED),
        ("bw exited 1: Not found.", ErrorKind.REF_INVALID),
        ("bw exited 1: connection refused", ErrorKind.NETWORK),
        ("bw returned non-JSON output: x", ErrorKind.INTERNAL),
    ],
)
def test_classify_bw_error(message, expected):
    assert vw._classify_bw_error(message) is expected


# ---------------------------------------------------------------------------
# mint_session — unattended API-key login and memory-only unlock
# ---------------------------------------------------------------------------


class TestMintSession:
    def _set_credentials(self, monkeypatch):
        monkeypatch.setenv("BW_CLIENTID", "user.test-client")
        monkeypatch.setenv("BW_CLIENTSECRET", "client-secret")
        monkeypatch.setenv("BW_MASTER_PASSWORD", "master-secret")

    def test_missing_env_raises(self, monkeypatch, tmp_path):
        for name in ("BW_CLIENTID", "BW_CLIENTSECRET", "BW_MASTER_PASSWORD"):
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(RuntimeError, match="auto_unlock requires"):
            vw.mint_session(Path("/usr/bin/bw"), home_path=tmp_path)

    def test_unauthenticated_login_then_unlock_keeps_secrets_out_of_argv(
        self, monkeypatch, tmp_path
    ):
        self._set_credentials(monkeypatch)
        login_proc = _make_ok_proc({})
        unlock_proc = _make_ok_proc("unused")
        unlock_proc.stdout = "fresh-session-token\n"
        with mock.patch(
            "subprocess.run",
            side_effect=[
                _make_status(),
                _make_ok_proc({}),
                _make_status("unauthenticated", "https://vault.example.com"),
                login_proc,
                unlock_proc,
            ],
        ) as mock_run:
            session = vw.mint_session(
                Path("/usr/bin/bw"),
                home_path=tmp_path,
                server_url="https://vault.example.com",
            )

        assert session == "fresh-session-token"
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert calls[1] == ["/usr/bin/bw", "config", "server", "https://vault.example.com"]
        assert calls[3] == ["/usr/bin/bw", "login", "--apikey"]
        assert calls[4] == [
            "/usr/bin/bw", "unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"
        ]
        argv_text = " ".join(" ".join(call) for call in calls)
        assert "client-secret" not in argv_text
        assert "master-secret" not in argv_text
        appdata = str(tmp_path / "plugin-data" / "vaultwarden" / "bw-cli")
        assert all(c.kwargs["env"]["BITWARDENCLI_APPDATA_DIR"] == appdata for c in mock_run.call_args_list)

    def test_locked_state_skips_login(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        unlock_proc = _make_ok_proc()
        unlock_proc.stdout = "fresh-session-token\n"
        with mock.patch(
            "subprocess.run",
            side_effect=[_make_status("locked", "https://vault.example.com"), unlock_proc],
        ) as mock_run:
            session = vw.mint_session(
                Path("/usr/bin/bw"), home_path=tmp_path,
                server_url="https://vault.example.com"
            )
        assert session == "fresh-session-token"
        assert all("login" not in c.args[0] for c in mock_run.call_args_list)

    def test_api_login_failure_raises(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        with mock.patch(
            "subprocess.run",
            side_effect=[
                _make_status("unauthenticated", "https://vault.example.com"),
                _make_fail_proc(1, "API key rejected"),
            ],
        ):
            with pytest.raises(RuntimeError, match="API-key login failed"):
                vw.mint_session(
                    Path("/usr/bin/bw"), home_path=tmp_path,
                    server_url="https://vault.example.com"
                )

    def test_empty_unlock_output_raises(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        empty_proc = mock.MagicMock()
        empty_proc.returncode = 0
        empty_proc.stdout = ""
        empty_proc.stderr = ""
        with mock.patch(
            "subprocess.run",
            side_effect=[_make_status("locked", "https://vault.example.com"), empty_proc],
        ):
            with pytest.raises(RuntimeError, match="empty session token"):
                vw.mint_session(
                    Path("/usr/bin/bw"), home_path=tmp_path,
                    server_url="https://vault.example.com"
                )

    def test_server_mismatch_refuses_implicit_account_switch(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        with mock.patch(
            "subprocess.run",
            return_value=_make_status("locked", "https://old.example.com"),
        ):
            with pytest.raises(RuntimeError, match="does not match"):
                vw.mint_session(
                    Path("/usr/bin/bw"), home_path=tmp_path,
                    server_url="https://new.example.com"
                )

    def test_auto_unlock_requires_explicit_https_server(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        with mock.patch("subprocess.run", return_value=_make_status()):
            with pytest.raises(RuntimeError, match="explicit.*server_url"):
                vw.mint_session(Path("/usr/bin/bw"), home_path=tmp_path)
        with mock.patch("subprocess.run", return_value=_make_status()):
            with pytest.raises(RuntimeError, match="must use HTTPS"):
                vw.mint_session(
                    Path("/usr/bin/bw"), home_path=tmp_path,
                    server_url="http://vault.example.com"
                )

    def test_nonpersistent_sandboxed_cli_fails_before_login(self, monkeypatch, tmp_path):
        self._set_credentials(monkeypatch)
        with mock.patch(
            "subprocess.run",
            side_effect=[_make_status(), _make_ok_proc({}), _make_status()],
        ) as mock_run:
            with pytest.raises(RuntimeError, match="did not persist"):
                vw.mint_session(
                    Path("/usr/bin/bw"), home_path=tmp_path,
                    server_url="https://vault.example.com"
                )
        assert all("login" not in call.args[0] for call in mock_run.call_args_list)


class TestVaultwardenSourceAutoUnlock:
    def setup_method(self):
        vw._CACHE.clear()
        self.source = vw.VaultwardenSource()

    def test_auto_unlock_mints_session_and_fetches(self, monkeypatch, tmp_path):
        monkeypatch.delenv("BW_SESSION", raising=False)
        monkeypatch.setenv("BW_CLIENTID", "user.test-client")
        monkeypatch.setenv("BW_CLIENTSECRET", "client-secret")
        monkeypatch.setenv("BW_MASTER_PASSWORD", "master-secret")
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))

        unlock_proc = _make_ok_proc()
        unlock_proc.stdout = "auto-minted-session\n"

        with mock.patch(
            "subprocess.run",
            side_effect=[
                _make_status(),       # status
                _make_ok_proc({}),    # config server
                _make_status("unauthenticated", "https://vault.example.com"),
                _make_ok_proc({}),    # login --apikey
                unlock_proc,          # unlock --passwordenv
                _make_ok_proc({}),    # sync
                _make_ok_proc(),      # get item
            ],
        ) as mock_run:
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "auto_unlock": True,
                    "server_url": "https://vault.example.com",
                },
                tmp_path,
            )

        assert result.ok
        assert result.secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        argv_text = " ".join(" ".join(c.args[0]) for c in mock_run.call_args_list)
        assert "auto-minted-session" not in argv_text
        assert "master-secret" not in argv_text
        sync_env = mock_run.call_args_list[5].kwargs["env"]
        get_item_env = mock_run.call_args_list[6].kwargs["env"]
        assert sync_env["BW_SESSION"] == "auto-minted-session"
        assert get_item_env["BW_SESSION"] == "auto-minted-session"
        assert "BW_CLIENTSECRET" not in get_item_env

    def test_auto_unlock_disabled_still_requires_session(self, monkeypatch):
        monkeypatch.delenv("BW_SESSION", raising=False)
        result = self.source.fetch(
            {"enabled": True, "item_name": "Hermes"}, Path("/tmp")
        )
        assert not result.ok
        assert result.error_kind is ErrorKind.NOT_CONFIGURED
        assert "auto_unlock" in result.error

    def test_existing_session_with_auto_unlock_uses_profile_appdata(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("BW_SESSION", "existing-session")
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))

        with mock.patch(
            "subprocess.run",
            side_effect=[_make_ok_proc({}), _make_ok_proc()],
        ) as mock_run:
            result = self.source.fetch(
                {
                    "enabled": True,
                    "item_name": "Hermes",
                    "auto_unlock": True,
                    "server_url": "https://vault.example.com",
                },
                tmp_path,
            )

        assert result.ok
        appdata = str(tmp_path / "plugin-data" / "vaultwarden" / "bw-cli")
        assert all(
            call.kwargs["env"]["BITWARDENCLI_APPDATA_DIR"] == appdata
            for call in mock_run.call_args_list
        )

    def test_auto_unlock_missing_bootstrap_env_reports_clean_error(self, monkeypatch, tmp_path):
        monkeypatch.delenv("BW_SESSION", raising=False)
        monkeypatch.delenv("BW_CLIENTID", raising=False)
        monkeypatch.delenv("BW_CLIENTSECRET", raising=False)
        monkeypatch.delenv("BW_MASTER_PASSWORD", raising=False)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        result = self.source.fetch(
            {"enabled": True, "item_name": "Hermes", "auto_unlock": True},
            tmp_path,
        )
        assert not result.ok
        assert "auto_unlock requires" in result.error


# ---------------------------------------------------------------------------
# Orchestrator round-trip — apply semantics now live in registry.apply_all
# ---------------------------------------------------------------------------


class TestOrchestratedApply:
    def setup_method(self):
        vw._CACHE.clear()
        registry._reset_registry_for_tests()
        registry.register_source(vw.VaultwardenSource())

    def teardown_method(self):
        registry._reset_registry_for_tests()

    def _apply(self, tmp_path, environ, cfg_extra=None):
        environ.setdefault("BW_SESSION", _FAKE_SESSION)
        cfg = {"enabled": True, "item_name": "Hermes", **(cfg_extra or {})}
        return registry.apply_all({"vaultwarden": cfg}, tmp_path, environ=environ)

    def test_applies_new_secrets(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(tmp_path, environ)
        assert environ["OPENROUTER_API_KEY"] == "sk-or-test"
        assert report.provenance["OPENROUTER_API_KEY"].source == "vaultwarden"
        assert report.provenance["OPENROUTER_API_KEY"].shape == "bulk"

    def test_skips_existing_when_override_false(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {"OPENROUTER_API_KEY": "existing-value"}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(tmp_path, environ)
        assert environ["OPENROUTER_API_KEY"] == "existing-value"
        sr = report.sources[0]
        assert "OPENROUTER_API_KEY" in sr.skipped_existing
        assert "ANTHROPIC_API_KEY" in sr.applied

    def test_overrides_existing_when_flag_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        environ = {"OPENROUTER_API_KEY": "old-value"}
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            report = self._apply(
                tmp_path, environ, cfg_extra={"override_existing": True}
            )
        assert environ["OPENROUTER_API_KEY"] == "sk-or-test"
        assert report.provenance["OPENROUTER_API_KEY"].overrode_env is True

    def test_session_env_itself_never_overwritten(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        item = {
            **_FAKE_ITEM,
            "fields": [
                {"name": "BW_SESSION", "value": "should-not-apply", "type": 1},
                {"name": "SOME_KEY", "value": "val", "type": 1},
            ],
        }
        environ = {"BW_SESSION": _FAKE_SESSION}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            report = self._apply(
                tmp_path, environ, cfg_extra={"override_existing": True}
            )
        assert environ["BW_SESSION"] == _FAKE_SESSION
        sr = report.sources[0]
        assert "BW_SESSION" in sr.skipped_protected
        assert "SOME_KEY" in sr.applied

    def test_empty_field_never_overwrites_existing_value(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        item = {
            **_FAKE_ITEM,
            "fields": [
                {"name": "OPENROUTER_API_KEY", "value": "", "type": 1},
                {"name": "SOME_KEY", "value": "val", "type": 1},
            ],
        }
        environ = {"OPENROUTER_API_KEY": "working-value"}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)):
            report = self._apply(
                tmp_path, environ, cfg_extra={"override_existing": True}
            )
        assert environ["OPENROUTER_API_KEY"] == "working-value"
        assert "OPENROUTER_API_KEY" not in report.provenance
        assert "SOME_KEY" in report.provenance
        assert any(
            "OPENROUTER_API_KEY" in warning and "empty" in warning
            for warning in report.sources[0].result.warnings
        )

    def test_fetch_error_does_not_break_pass(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BW_SESSION", _FAKE_SESSION)
        monkeypatch.setattr(vw, "find_bw", lambda *a, **k: Path("/usr/bin/bw"))
        with mock.patch(
            "subprocess.run", return_value=_make_fail_proc(1, "Session expired")
        ):
            report = self._apply(tmp_path, {})
        assert not report.applied_any
        assert not report.sources[0].result.ok


# ---------------------------------------------------------------------------
# Disk cache format
# ---------------------------------------------------------------------------


class TestDiskCache:
    def setup_method(self):
        vw._CACHE.clear()

    def test_disk_cache_written_with_mode_0600(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        cache_path = vw._disk_cache_path(tmp_path)
        assert cache_path.exists()
        mode = cache_path.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_cache_key_prefixed_with_vw(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        payload = json.loads(vw._disk_cache_path(tmp_path).read_text())
        assert payload["key"].startswith("vw|")
        assert _FAKE_SESSION not in payload["key"]

    def test_zero_ttl_writes_no_cache_file(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                cache_ttl_seconds=0,
                use_cache=True,
                home_path=tmp_path,
            )
        assert not vw._disk_cache_path(tmp_path).exists()
        assert not vw._CACHE

    def test_reset_cache_for_tests_clears_both_layers(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                cache_ttl_seconds=300,
                home_path=tmp_path,
            )
        assert vw._CACHE
        vw._reset_cache_for_tests(tmp_path)
        assert not vw._CACHE
        assert not vw._disk_cache_path(tmp_path).exists()
