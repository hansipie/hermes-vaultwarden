from pathlib import Path
from unittest.mock import Mock

import pytest
import hermes_cli.config as core
import vw_source as vw


@pytest.fixture
def rig(tmp_path, monkeypatch):
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(core, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(core, "ensure_hermes_home", lambda: None)
    monkeypatch.setattr(core, "is_managed", lambda: False)
    monkeypatch.setattr(core.managed_scope, "is_env_managed", lambda key: False)
    monkeypatch.setattr(vw, "get_source_environment", lambda: {})
    monkeypatch.setattr(vw, "find_bw", lambda *_: Path("/bin/bw"))
    mint = Mock(side_effect=["fresh token#one", "fresh-token-two"])
    read = Mock(return_value=({"A": "value"}, []))
    monkeypatch.setattr(vw, "mint_session", mint)
    monkeypatch.setattr(vw, "fetch_vaultwarden_secrets", read)
    cfg = {"auto_unlock": True, "item_name": "x", "persist_session_file": True}
    yield tmp_path, cfg, vw.VaultwardenSource(), mint, read
    vw._AUTH_SESSIONS.clear()


def test_write_only_fresh_proven_and_not_cache_hits(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    (home / ".env").write_text("OTHER=yes\n")
    save = Mock()
    monkeypatch.setattr(core, "save_env_value", save)
    assert source.fetch(cfg, home).secrets == {"A": "value"}
    assert source.fetch(cfg, home).secrets == {"A": "value"}
    save.assert_called_once_with("BW_SESSION", "fresh token#one")


def test_recovery_persists_new_token(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    (home / ".env").write_text("OTHER=yes\n")
    save = Mock()
    monkeypatch.setattr(core, "save_env_value", save)
    source.fetch(cfg, home)
    read.side_effect = [RuntimeError("session expired"), ({"A": "value"}, [])]
    result = source.fetch(cfg, home)
    assert not result.error
    assert save.call_count == 2
    save.assert_called_with("BW_SESSION", "fresh-token-two")


@pytest.mark.parametrize("mode", ["disabled", "session", "failed_read", "missing"])
def test_no_write_in_ineligible_cases(rig, monkeypatch, mode):
    home, cfg, source, mint, read = rig
    if mode != "missing":
        (home / ".env").write_text("OTHER=yes\n")
    if mode == "disabled": cfg["persist_session_file"] = False
    if mode == "session":
        cfg["auto_unlock"] = False
        monkeypatch.setattr(vw, "get_source_environment", lambda: {"BW_SESSION": "ambient"})
    if mode == "failed_read": read.side_effect = RuntimeError("session expired")
    save = Mock()
    monkeypatch.setattr(core, "save_env_value", save)
    source.fetch(cfg, home)
    save.assert_not_called()
    if mode == "missing": assert not (home / ".env").exists()


def test_real_helper_normalizes_and_publishes(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    monkeypatch.delenv("BW_SESSION", raising=False)
    env = home / ".env"
    env.write_bytes(b"\xef\xbb\xbfexport BW_SESSION=old\r\nBW_SESSION=duplicate\r\n OTHER=yes \r\n")
    result = source.fetch(cfg, home)
    assert not result.error
    assert env.read_bytes() == b'BW_SESSION="fresh token#one"\nBW_SESSION=duplicate\nOTHER=yes\n'
    import os
    assert os.environ["BW_SESSION"] == "fresh token#one"


def successful_baseline(rig):
    home, cfg, source, mint, read = rig
    baseline = source.fetch({**cfg, "persist_session_file": False}, home)
    assert baseline.ok and baseline.secrets == {"A": "value"}
    vw._reset_cache_for_tests(home)
    mint.side_effect = ["fresh token#one", "fresh-token-two"]
    mint.reset_mock()
    return baseline


def assert_preserved_and_redacted(result, baseline):
    assert (result.ok, result.secrets, result.error, result.error_kind) == (
        baseline.ok, baseline.secrets, baseline.error, baseline.error_kind
    )
    assert any("persist" in warning.lower() for warning in result.warnings)
    assert "fresh token#one" not in repr(result.warnings)


def test_duplicate_warns_and_real_reader_sees_shadow(rig, monkeypatch):
    from agent.secret_scope import load_env_file

    home, cfg, source, mint, read = rig
    monkeypatch.delenv("BW_SESSION", raising=False)
    env = home / ".env"
    env.write_text("export BW_SESSION=old-first\nOTHER=yes\n BW_SESSION = old-later\n")
    result = source.fetch(cfg, home)
    assert result.ok
    assert env.read_text().splitlines()[0] == 'BW_SESSION="fresh token#one"'
    assert load_env_file(env)["BW_SESSION"] == "old-later"
    assert any("line(s) 3 shadow" in w for w in result.warnings)
    assert "fresh token#one" not in repr(result.warnings)
    assert "old-later" not in repr(result.warnings)


def test_policy_changes_after_preflight_warns_and_preserves_result(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    env = home / ".env"
    env.write_text("BW_SESSION=old\n")
    baseline = successful_baseline(rig)
    blocked = Mock(return_value=True)
    monkeypatch.setattr(core, "_env_write_blocked", blocked)
    result = source.fetch(cfg, home)
    blocked.assert_called_once_with("BW_SESSION", "set")
    assert env.read_text() == "BW_SESSION=old\n"
    assert_preserved_and_redacted(result, baseline)
    assert any("not updated" in w.lower() for w in result.warnings)


def test_real_validation_refusal_warns_and_preserves_result(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    env = home / ".env"
    env.write_text("BW_SESSION=old\n")
    baseline = successful_baseline(rig)
    def reject(key):
        assert key == "BW_SESSION"
        raise ValueError("fresh token#one")
    monkeypatch.setattr(core, "validate_env_var_name_for_write", reject)
    result = source.fetch(cfg, home)
    assert env.read_text() == "BW_SESSION=old\n"
    assert_preserved_and_redacted(result, baseline)


def test_real_managed_refusal_warns_without_token(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    env = home / ".env"
    env.write_text("BW_SESSION=old\n")
    baseline = successful_baseline(rig)
    monkeypatch.setattr(core.managed_scope, "is_env_managed", lambda key: True)
    result = source.fetch(cfg, home)
    assert_preserved_and_redacted(result, baseline)
    assert env.read_text() == "BW_SESSION=old\n"
    assert any("persist" in w.lower() for w in result.warnings)
    assert "fresh token#one" not in repr(result.warnings)


def test_write_failure_warns_without_leaking_and_preserves_cache(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    (home / ".env").write_text("OTHER=yes\n")
    baseline = successful_baseline(rig)
    def fail(*args): raise OSError("fresh token#one secret")
    monkeypatch.setattr(core, "save_env_value", fail)
    result = source.fetch(cfg, home)
    assert_preserved_and_redacted(result, baseline)
    source.fetch(cfg, home)
    assert mint.call_count == 1


def test_mismatched_active_profile_refuses_write(rig, monkeypatch, tmp_path):
    home, cfg, source, mint, read = rig
    other = tmp_path / "other"
    other.mkdir()
    (other / ".env").write_text("OTHER=yes\n")
    baseline = successful_baseline(rig)
    monkeypatch.setattr(core, "get_hermes_home", lambda: other)
    result = source.fetch(cfg, home)
    assert_preserved_and_redacted(result, baseline)
    assert (other / ".env").read_text() == "OTHER=yes\n"


def test_missing_file_with_real_helper_is_not_created(rig):
    home, cfg, source, mint, read = rig
    result = source.fetch(cfg, home)
    assert result.secrets == {"A": "value"} and not result.error
    assert not (home / ".env").exists()


def test_custom_key_and_fresh_read_when_reuse_disabled(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    cfg.update(session_env="CUSTOM_SESSION", remint_on_auth_expired=False)
    (home / ".env").write_text("CUSTOM_SESSION=old\n")
    save = Mock()
    monkeypatch.setattr(core, "save_env_value", save)
    assert not source.fetch(cfg, home).error
    save.assert_called_once_with("CUSTOM_SESSION", "fresh token#one")
    assert read.call_args.kwargs["force_read"] is True


def test_failed_recovery_never_persists_unproven_session(rig, monkeypatch):
    home, cfg, source, mint, read = rig
    (home / ".env").write_text("OTHER=yes\n")
    save = Mock()
    monkeypatch.setattr(core, "save_env_value", save)
    source.fetch(cfg, home)
    read.side_effect = [RuntimeError("session expired"), RuntimeError("read failed")]
    result = source.fetch(cfg, home)
    assert result.error
    assert save.call_count == 1
