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

from agent.secret_sources.base import ErrorKind
from agent.secret_sources import registry

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
        assert argv[-2:] == ["--", "Hermes"]
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

    def test_raises_when_bw_fails(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_fail_proc(1, "Not logged in")):
            with pytest.raises(RuntimeError, match="bw exited 1"):
                vw.fetch_vaultwarden_secrets(
                    session=_FAKE_SESSION,
                    item_name="Hermes",
                    binary=Path("/usr/bin/bw"),
                    use_cache=False,
                    home_path=tmp_path,
                )

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
                    home_path=tmp_path,
                )
        assert mock_run.call_count == 1

    def test_disk_cache_survives_process_cache_clear(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
            )
            vw._CACHE.clear()
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
            )
        assert mock_run.call_count == 1
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
        assert mock_run.call_count == 2

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
        assert mock_run.call_count == 2
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
        assert self.source.protected_env_vars({}) == frozenset({"BW_SESSION"})
        assert self.source.protected_env_vars(
            {"session_env": "MY_BW_TOKEN"}
        ) == frozenset({"MY_BW_TOKEN"})
        # invalid name falls back to the default rather than exporting junk
        assert self.source.protected_env_vars(
            {"session_env": "not a name"}
        ) == frozenset({"BW_SESSION"})

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
        ("bw exited 1: Not found.", ErrorKind.REF_INVALID),
        ("bw exited 1: connection refused", ErrorKind.NETWORK),
        ("bw returned non-JSON output: x", ErrorKind.INTERNAL),
    ],
)
def test_classify_bw_error(message, expected):
    assert vw._classify_bw_error(message) is expected


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

    def test_reset_cache_for_tests_clears_both_layers(self, tmp_path):
        with mock.patch("subprocess.run", return_value=_make_ok_proc()):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
            )
        assert vw._CACHE
        vw._reset_cache_for_tests(tmp_path)
        assert not vw._CACHE
        assert not vw._disk_cache_path(tmp_path).exists()


# ---------------------------------------------------------------------------
# Self-heal: re-derive the session when the stored token is dead
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Self-heal: re-derive the session when the stored token is dead
# ---------------------------------------------------------------------------


def _tok(ch: str) -> str:
    """A stand-in for a real 88-char base64 session token (kept out of
    literal form so tool-side secret redaction can never mask it)."""
    return ch * 88


class TestSelfHeal:
    def setup_method(self):
        vw._CACHE.clear()
        vw._HEAL_ATTEMPTED = False

    _HEAL_PW_FILE_CONTENT = (
        "# heal credentials for the vaultwarden secret source\n"
        "BW_SERVER_URL=https://vw.example.test\n"
        "BW_CLIENT_ID=user.aaaa-1111\n"
        "BW_CLIENT_SECRET=sec-2222\n"
        "BW_PASSWORD=hunter2\n"
    )

    def _write_pw_file(self, tmp_path, content=None):
        pw_file = tmp_path / "bw.env"
        pw_file.write_text(content if content is not None else self._HEAL_PW_FILE_CONTENT)
        return pw_file

    def _dead_item_proc(self):
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.stdout = ""  # dead session: bw prompts, prints nothing
        proc.stderr = ""
        return proc

    def _unlock_proc(self, token):
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.stdout = token + "\n"
        proc.stderr = ""
        return proc

    def _side_effect(self, unlock_token):
        """First call: get item with dead session -> empty. Then login,
        unlock (token), and a successful get item with the fresh token."""
        return [
            self._dead_item_proc(),
            _make_ok_proc(),  # apikey login (stdout may be empty)
            self._unlock_proc(unlock_token),
            _make_ok_proc(),  # retry with healed session
        ]

    def test_dead_session_triggers_heal_and_refreshes_env_file(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("TELEGRAM_BOT_TOKEN=123\nBW_SESSION=deadtok0")
        unlock_token = _tok("b")

        with mock.patch("subprocess.run", side_effect=self._side_effect(unlock_token)) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert any("self-heal ok" in w for w in warnings)
        # .env refreshed in place, other lines untouched, 0600
        text = env_file.read_text()
        assert ("BW_SESSION=" + unlock_token) in text
        assert "TELEGRAM_BOT_TOKEN=123" in text
        assert "dead-token-000" not in text
        assert env_file.stat().st_mode & 0o777 == 0o600
        # argv check: get item (dead) -> login --apikey -> unlock --passwordenv -> get item (fresh)
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert calls[0][-2:] == ["--", "Hermes"]
        assert calls[1][1:4] == ["login", "--apikey", "--raw"]
        assert calls[2][1:5] == ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"]
        assert calls[3][-2:] == ["--", "Hermes"]
        # secret hygiene: password never in argv; client creds only on login
        for argv in calls:
            assert "hunter2" not in argv
            assert "sec-2222" not in argv
        envs = [c.kwargs["env"] for c in mock_run.call_args_list]
        assert envs[1]["BW_CLIENTID"] == "user.aaaa-1111"
        assert envs[1]["BW_CLIENTSECRET"] == "sec-2222"
        assert envs[1]["NODE_OPTIONS"] == "--no-deprecation"
        assert "BW_PASSWORD" not in envs[1]
        assert envs[2]["BW_PASSWORD"] == "hunter2"
        assert envs[3]["BW_SESSION"] == unlock_token
        # NODE_OPTIONS rides along on the item fetch too
        assert envs[0]["NODE_OPTIONS"] == "--no-deprecation"

    def test_no_apikey_pair_skips_login_step(self, tmp_path):
        pw_file = self._write_pw_file(
            tmp_path, "BW_PASSWORD=hunter2\n"
        )
        with mock.patch(
            "subprocess.run",
            side_effect=[
                self._dead_item_proc(),
                self._unlock_proc(_tok("c")),
                _make_ok_proc(),
            ],
        ) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert len(calls) == 3  # no login step
        assert calls[1][1:5] == ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"]

    def test_password_with_space_uses_passwordfile(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path, "BW_PASSWORD=hunter2 badger\n")
        with mock.patch(
            "subprocess.run",
            side_effect=[
                self._dead_item_proc(),
                self._unlock_proc(_tok("d")),
                _make_ok_proc(),
            ],
        ) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        unlock_argv = mock_run.call_args_list[1].args[0]
        assert unlock_argv[1:3] == ["unlock", "--passwordfile"]
        assert not unlock_argv[3].startswith("-")
        assert not Path(unlock_argv[3]).exists()  # temp file removed
        assert "BW_PASSWORD" not in mock_run.call_args_list[1].kwargs["env"]

    def test_heal_disabled_keeps_original_result(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        with mock.patch("subprocess.run", return_value=self._dead_item_proc()) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=False,
                heal_password_file=str(pw_file),
            )
        assert secrets == {}
        assert "bw returned no output" in warnings
        assert mock_run.call_count == 1

    def test_missing_password_file_no_crash(self, tmp_path):
        with mock.patch("subprocess.run", return_value=self._dead_item_proc()) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(tmp_path / "absent.env"),
            )
        assert secrets == {}
        assert any("self-heal skipped" in w for w in warnings)
        assert mock_run.call_count == 1

    def test_unlock_without_token_falls_back_to_original(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        with mock.patch(
            "subprocess.run",
            side_effect=[
                self._dead_item_proc(),
                _make_ok_proc(),
                self._unlock_proc("no-token-here"),
            ],
        ) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets == {}
        assert any("self-heal failed" in w for w in warnings)
        assert mock_run.call_count == 3  # no retry after failed heal

    def test_one_heal_attempt_per_process(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        dead = self._dead_item_proc()
        with mock.patch(
            "subprocess.run",
            # attempt 1: get item (dead) + login + unlock (no token);
            # then endless dead item fetches for the second call
            side_effect=[dead, _make_ok_proc(), self._unlock_proc("no-token-here")]
            + [dead] * 10,
        ) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
            # flag consumed: second fetch must not re-derive
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets == {}
        assert mock_run.call_count == 4  # (get+login+unlock) + get

    def test_healthy_session_does_not_heal(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        with mock.patch("subprocess.run", return_value=_make_ok_proc()) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert not any("self-heal" in w for w in warnings)
        assert mock_run.call_count == 1

    def test_item_with_no_fields_does_not_heal(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        item = {**_FAKE_ITEM, "fields": []}
        with mock.patch("subprocess.run", return_value=_make_ok_proc(item)) as mock_run:
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets == {}
        assert any("no custom fields" in w for w in warnings)
        assert mock_run.call_count == 1

    def test_token_extraction_last_matching_line(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        token = "e" * 80 + "=="
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.stdout = f"You are now unlocked.\n{token}\n"
        proc.stderr = ""
        with mock.patch(
            "subprocess.run",
            side_effect=[self._dead_item_proc(), _make_ok_proc(), proc, _make_ok_proc()],
        ):
            secrets, _ = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"

    def test_env_file_absent_is_not_an_error(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        with mock.patch(
            "subprocess.run",
            side_effect=[
                self._dead_item_proc(),
                _make_ok_proc(),
                self._unlock_proc(_tok("f")),
                _make_ok_proc(),
            ],
        ):
            secrets, warnings = vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        assert secrets["OPENROUTER_API_KEY"] == "sk-or-test"
        assert any("in-memory only" in w for w in warnings)

    def test_env_file_without_session_line_appends(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("OTHER=1\n")
        token = _tok("g")
        with mock.patch(
            "subprocess.run",
            side_effect=[
                self._dead_item_proc(),
                _make_ok_proc(),
                self._unlock_proc(token),
                _make_ok_proc(),
            ],
        ):
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=False,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        text = env_file.read_text()
        assert "OTHER=1" in text
        assert ("BW_SESSION=" + token) in text

    def test_failed_heal_result_not_cached(self, tmp_path):
        pw_file = self._write_pw_file(tmp_path)
        with mock.patch("subprocess.run", return_value=self._dead_item_proc()) as mock_run:
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
            vw._HEAL_ATTEMPTED = False  # second process-like attempt
            vw._CACHE.clear()
            vw.fetch_vaultwarden_secrets(
                session=_FAKE_SESSION,
                item_name="Hermes",
                binary=Path("/usr/bin/bw"),
                use_cache=True,
                home_path=tmp_path,
                self_heal=True,
                heal_password_file=str(pw_file),
            )
        # each attempt: get item + login + unlock (no cache hit in between)
        assert mock_run.call_count == 6
