from unittest.mock import patch
from pathlib import Path
import vw_source as vw


def test_proven_session_is_reused(tmp_path):
    vw._reset_cache_for_tests(tmp_path)
    cfg = {"auto_unlock": True, "item_name": "x", "server_url": "https://example.test"}
    with patch.object(vw, "find_bw", return_value=Path("/bin/bw")), \
         patch.object(vw, "mint_session", return_value="session-one") as mint, \
         patch.object(vw, "fetch_vaultwarden_secrets", return_value=({"A": "b"}, [])) as read:
        source = vw.VaultwardenSource()
        assert not source.fetch(cfg, tmp_path).error
        assert not source.fetch(cfg, tmp_path).error
        assert mint.call_count == 1
        assert read.call_count == 2

import argparse
from types import SimpleNamespace
import pytest
import vw_cli as cli
from agent.secret_sources.base import ErrorKind


@pytest.fixture
def rig(tmp_path, monkeypatch):
    vw._reset_cache_for_tests(tmp_path)
    env = {"BW_SESSION": "ambient-token", "BW_CLIENTID": "client-id", "BW_CLIENTSECRET": "client-secret", "BW_MASTER_PASSWORD": " password "}
    monkeypatch.setattr(vw, "get_source_environment", lambda: env)
    find = patch.object(vw, "find_bw", return_value=Path("/bin/bw")).start()
    mint = patch.object(vw, "mint_session", side_effect=["mint-token-one", "mint-token-two", "mint-token-three"]).start()
    read = patch.object(vw, "fetch_vaultwarden_secrets", return_value=({"A": "b"}, [])).start()
    cfg = {"auto_unlock": True, "item_name": "x", "server_url": "https://example.test", "sync_interval_seconds": 0}
    yield SimpleNamespace(env=env, find=find, mint=mint, read=read, cfg=cfg, home=tmp_path, source=vw.VaultwardenSource())
    patch.stopall()
    vw._AUTH_SESSIONS.clear()


def test_ignore_env_reuse_and_pointer_warning(rig):
    a = rig.source.fetch(rig.cfg, rig.home)
    b = rig.source.fetch(rig.cfg, rig.home)
    assert rig.mint.call_count == 1
    assert [c.kwargs['session'] for c in rig.read.call_args_list] == ['mint-token-one'] * 2
    assert any('ignoring BW_SESSION' in w and 'used or minted' in w for w in b.warnings)
    assert any('client_secret_env' in w and 'master_password_env' in w for w in a.warnings)
    assert all('ambient-token' not in w for w in a.warnings + b.warnings)


@pytest.mark.parametrize('change', ['home', 'server', 'binary', 'name', 'id', 'secret', 'password'])
def test_context_change_requires_new_mint(rig, change):
    rig.source.fetch(rig.cfg, rig.home)
    cfg, home = dict(rig.cfg), rig.home
    if change == 'home': home = home / 'other'
    if change == 'server': cfg['server_url'] = 'https://other.test'
    if change == 'binary': rig.find.return_value = Path('/bin/other-bw')
    if change == 'name': cfg['client_secret_env'] = 'ANOTHER_SECRET'; rig.env['ANOTHER_SECRET'] = 'client-secret'
    if change == 'id': rig.env['BW_CLIENTID'] = 'rotated-client'
    if change == 'secret': rig.env['BW_CLIENTSECRET'] = 'rotated-secret'
    if change == 'password': rig.env['BW_MASTER_PASSWORD'] = 'password'
    assert not rig.source.fetch(cfg, home).error
    assert rig.mint.call_count == 2
    assert all('client-secret' not in repr(key) and 'password' not in repr(key) for key in vw._AUTH_SESSIONS)


def test_cached_expiry_mints_once_and_retries_with_resolved_item(rig):
    rig.env['ITEM'] = 'item-id'
    rig.cfg.update(item_id='${env:ITEM}', item_name='ignored', sync_interval_seconds=123)
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = [RuntimeError('session expired'), ({'A': 'b'}, [])]
    result = rig.source.fetch(rig.cfg, rig.home)
    assert not result.error
    assert rig.mint.call_count == 2
    assert [c.kwargs['session'] for c in rig.read.call_args_list] == ['mint-token-one', 'mint-token-one', 'mint-token-two']
    assert all(c.kwargs['item_name'] == 'item-id' and c.kwargs['sync_interval_seconds'] == 123 for c in rig.read.call_args_list)
    assert list(vw._AUTH_SESSIONS.values()) == ['mint-token-two']


def test_fresh_expiry_does_not_remint_or_publish(rig):
    rig.read.side_effect = RuntimeError('session expired')
    result = rig.source.fetch(rig.cfg, rig.home)
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert rig.mint.call_count == 1 and not vw._AUTH_SESSIONS


def test_recovery_failure_redacts_and_preserves_classification(rig):
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = RuntimeError('session expired mint-token-one')
    rig.mint.side_effect = RuntimeError('\x1b[31mnetwork client-secret password mint-token-one ' + 'A' * 70 + '\x1b[0m')
    result = rig.source.fetch(rig.cfg, rig.home)
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert 'recovery failed' in result.error and '[REDACTED]' in result.error
    assert all(v not in result.error for v in ['client-secret', 'password', 'mint-token-one', '\x1b', 'A' * 70])
    assert rig.mint.call_count == 2 and not vw._AUTH_SESSIONS
    assert any('client_secret_env' in w for w in result.warnings)


@pytest.mark.parametrize('error', ['network unavailable', 'not logged in', 'item not found', 'unknown failure'])
def test_nonrecoverable_errors_do_not_remint(rig, error):
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = RuntimeError(error)
    assert rig.source.fetch(rig.cfg, rig.home).error
    assert rig.mint.call_count == 1


def test_gate_off_mints_each_time_and_never_reads_or_writes_auth_cache(rig):
    rig.source.fetch(rig.cfg, rig.home)
    rig.cfg['remint_on_auth_expired'] = False
    rig.source.fetch(rig.cfg, rig.home)
    rig.source.fetch(rig.cfg, rig.home)
    assert rig.mint.call_count == 3
    assert list(vw._AUTH_SESSIONS.values()) == ['mint-token-one']


def test_session_mode_does_not_mint_or_use_isolated_appdata(rig):
    rig.cfg['auto_unlock'] = False
    rig.source.fetch(rig.cfg, rig.home)
    rig.mint.assert_not_called()
    assert rig.read.call_args.kwargs['session'] == 'ambient-token'
    assert rig.read.call_args.kwargs['appdata_dir'] is None
    assert not vw._AUTH_SESSIONS


@pytest.mark.parametrize('code,err,expected', [(0, '', 0), (1, 'not logged in', 0), (1, 'connection failure', 1)])
def test_reset_auth_evicts_only_target_even_on_failure(rig, monkeypatch, code, err, expected):
    rig.source.fetch(rig.cfg, rig.home)
    rig.source.fetch(rig.cfg, rig.home / 'other')
    monkeypatch.setattr(cli, 'get_hermes_home', lambda: rig.home)
    monkeypatch.setattr(cli, 'load_config', lambda: {})
    monkeypatch.setattr(vw, '_run_bw', lambda *a, **k: SimpleNamespace(returncode=code, stderr=err, stdout=''))
    assert cli.cmd_reset_auth(argparse.Namespace()) == expected
    assert list(vw._AUTH_SESSIONS.values()) == ['mint-token-two']



def test_real_subprocess_sequence_reuses_session_without_mint(tmp_path, monkeypatch):
    import json
    from unittest.mock import Mock
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {'BW_CLIENTID': 'id', 'BW_CLIENTSECRET': 'secret', 'BW_MASTER_PASSWORD': ' password ', 'BW_SESSION': 'old-env'})
    monkeypatch.setattr(vw, 'find_bw', lambda *_: Path('/bin/bw'))
    proc = lambda out='', code=0, err='': SimpleNamespace(stdout=out, stderr=err, returncode=code)
    run = Mock(side_effect=[proc(json.dumps({'status': 'locked', 'serverUrl': 'https://example.test'})), proc('mint-token-one'), proc(), proc(json.dumps({'fields': []})), proc(), proc(json.dumps({'fields': []}))])
    monkeypatch.setattr(vw, 'run_secret_cli', run)
    cfg = {'auto_unlock': True, 'server_url': 'https://example.test', 'item_name': 'item', 'sync_interval_seconds': 0}
    source = vw.VaultwardenSource()
    assert not source.fetch(cfg, tmp_path).error
    assert not source.fetch(cfg, tmp_path).error
    commands = [c.args[0][1:] for c in run.call_args_list]
    assert commands == [['status', '--raw'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['sync'], ['get', 'item', 'item'], ['sync'], ['get', 'item', 'item']]
    assert all('mint-token-one' not in repr(cmd) and 'old-env' not in repr(cmd) for cmd in commands)
    assert all('mint-token-one' not in p.read_text(errors='ignore') for p in tmp_path.rglob('*') if p.is_file())


def test_unlock_failure_stdout_never_exposed(tmp_path, monkeypatch):
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {'BW_CLIENTID': 'id', 'BW_CLIENTSECRET': 'secret', 'BW_MASTER_PASSWORD': 'password'})
    monkeypatch.setattr(vw, '_bw_status', lambda *a: {'status': 'locked', 'serverUrl': 'https://example.test'})
    monkeypatch.setattr(vw, '_run_bw', lambda *a, **k: SimpleNamespace(returncode=1, stdout='secret-session-token', stderr='bad unlock'))
    with pytest.raises(RuntimeError) as exc:
        vw.mint_session(Path('/bin/bw'), home_path=tmp_path, server_url='https://example.test')
    assert 'bad unlock' in str(exc.value) and 'secret-session-token' not in str(exc.value)


def test_retry_failure_preserves_auth_and_redacts_new_token(rig):
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = [RuntimeError('session expired'), RuntimeError('network mint-token-two client-secret')]
    result = rig.source.fetch(rig.cfg, rig.home)
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert 'mint-token-two' not in result.error and 'client-secret' not in result.error
    assert not vw._AUTH_SESSIONS
