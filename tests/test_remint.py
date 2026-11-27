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
    if change == 'password': rig.env['BW_MASTER_PASSWORD'] = 'rotated-passphrase'
    result = rig.source.fetch(cfg, home)
    assert not result.error
    assert rig.mint.call_count == 2
    assert [c.kwargs['session'] for c in rig.read.call_args_list] == ['mint-token-one', 'mint-token-two']
    assert all(value not in str(result.error or '') + repr(result.warnings) for value in rig.env.values() if value)
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


@pytest.mark.parametrize('error', ['network unavailable', 'item not found', 'unknown failure'])
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
    assert not rig.source.fetch(rig.cfg, rig.home).error
    assert rig.read.call_args.kwargs['session'] == 'mint-token-three'



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


@pytest.mark.parametrize("suffix", ["timed out", "invalid client"])
def test_late_diagnostics_do_not_override_expiry(rig, suffix):
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = [RuntimeError("session expired " + "x" * 210 + suffix), ({}, [])]
    result = rig.source.fetch(rig.cfg, rig.home)
    assert not result.error and result.error_kind is None
    assert rig.mint.call_count == 2

def test_unknown_segmented_session_redacted(rig):
    rig.read.side_effect = RuntimeError("failure session=abcd.efgh.ijkl")
    result = rig.source.fetch(rig.cfg, rig.home)
    assert "abcd.efgh.ijkl" not in result.error

def test_logged_out_cached_session_recovers(rig):
    rig.source.fetch(rig.cfg, rig.home)
    rig.read.side_effect = [RuntimeError("not logged in"), ({}, [])]
    result = rig.source.fetch(rig.cfg, rig.home)
    assert not result.error and result.error_kind is None
    assert rig.mint.call_count == 2


def test_reset_fences_inflight_read(rig):
    from threading import Event, Thread
    entered, release = Event(), Event()
    def read(**kwargs):
        entered.set()
        assert release.wait(5)
        return {}, []
    rig.read.side_effect = read
    results = []
    worker = Thread(target=lambda: results.append(rig.source.fetch(rig.cfg, rig.home)))
    worker.start()
    assert entered.wait(5)
    vw._clear_auth_sessions(vw._profile_bw_appdata(rig.home))
    release.set()
    worker.join(5)
    assert not worker.is_alive() and not results[0].error
    assert not vw._AUTH_SESSIONS

def test_failed_old_token_does_not_evict_newer_token(rig):
    from threading import Event, Thread
    rig.source.fetch(rig.cfg, rig.home)
    entered, release = Event(), Event()
    def read(**kwargs):
        if kwargs['session'] == 'mint-token-one':
            entered.set()
            assert release.wait(5)
            raise RuntimeError('session expired')
        return {}, []
    rig.read.side_effect = read
    results = []
    worker = Thread(target=lambda: results.append(rig.source.fetch(rig.cfg, rig.home)))
    worker.start()
    assert entered.wait(5)
    key = next(iter(vw._AUTH_SESSIONS))
    with vw._AUTH_LOCK:
        vw._AUTH_SESSIONS[key] = 'another-proven-token'
    release.set()
    worker.join(5)
    assert not worker.is_alive() and not results[0].error
    assert vw._AUTH_SESSIONS[key] == 'another-proven-token'

def test_concurrent_recoveries_publish_at_most_one_proven_token(rig):
    from threading import Barrier, Lock, Thread
    rig.source.fetch(rig.cfg, rig.home)
    barrier = Barrier(2)
    counter_lock = Lock()
    counter = iter(['fresh-one', 'fresh-two'])
    def mint(*args, **kwargs):
        with counter_lock:
            return next(counter)
    def read(**kwargs):
        if kwargs['session'] == 'mint-token-one':
            barrier.wait(timeout=5)
            raise RuntimeError('session expired')
        return {}, []
    rig.mint.side_effect = mint
    rig.read.side_effect = read
    results = []
    workers = [Thread(target=lambda: results.append(rig.source.fetch(rig.cfg, rig.home))) for _ in range(2)]
    for worker in workers: worker.start()
    for worker in workers: worker.join(5)
    assert all(not worker.is_alive() for worker in workers)
    assert len(results) == 2 and all(not result.error for result in results)
    assert list(vw._AUTH_SESSIONS.values()) in (['fresh-one'], ['fresh-two'])
    proven = next(iter(vw._AUTH_SESSIONS.values()))
    assert rig.mint.call_count == 3
    assert not rig.source.fetch(rig.cfg, rig.home).error
    assert rig.mint.call_count == 3
    assert rig.read.call_args.kwargs['session'] == proven


def test_logout_recovery_real_sequence(tmp_path, monkeypatch):
    import json
    from unittest.mock import Mock
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {'BW_CLIENTID': 'cid', 'BW_CLIENTSECRET': 'csecret', 'BW_MASTER_PASSWORD': 'passphrase'})
    monkeypatch.setattr(vw, 'find_bw', lambda *_: Path('/bin/bw'))
    proc = lambda out='', code=0, err='': SimpleNamespace(stdout=out, stderr=err, returncode=code)
    status = lambda state: proc(json.dumps({'status': state, 'serverUrl': 'https://example.test'}))
    item = proc(json.dumps({'fields': []}))
    run = Mock(side_effect=[status('locked'), proc('old-token'), proc(), item, proc(code=1, err='not logged in'), status('unauthenticated'), proc(), proc('new-token'), proc(), item])
    monkeypatch.setattr(vw, 'run_secret_cli', run)
    cfg = {'auto_unlock': True, 'server_url': 'https://example.test', 'item_name': 'item', 'sync_interval_seconds': 0}
    source = vw.VaultwardenSource()
    assert not source.fetch(cfg, tmp_path).error
    result = source.fetch(cfg, tmp_path)
    assert not result.error and result.error_kind is None
    assert list(vw._AUTH_SESSIONS.values()) == ['new-token']
    assert [c.args[0][1:] for c in run.call_args_list] == [['status', '--raw'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['sync'], ['get', 'item', 'item'], ['sync'], ['status', '--raw'], ['login', '--apikey'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['sync'], ['get', 'item', 'item']]

def test_recent_sync_sequence_skips_network(tmp_path, monkeypatch):
    import json
    from datetime import datetime, timezone
    from unittest.mock import Mock
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {'BW_CLIENTID': 'cid', 'BW_CLIENTSECRET': 'csecret', 'BW_MASTER_PASSWORD': 'passphrase'})
    monkeypatch.setattr(vw, 'find_bw', lambda *_: Path('/bin/bw'))
    proc = lambda out='': SimpleNamespace(stdout=out, stderr='', returncode=0)
    run = Mock(side_effect=[proc(json.dumps({'status': 'locked', 'serverUrl': 'https://example.test'})), proc('new-token'), proc(json.dumps({'lastSync': datetime.now(timezone.utc).isoformat()})), proc(json.dumps({'fields': []}))])
    monkeypatch.setattr(vw, 'run_secret_cli', run)
    result = vw.VaultwardenSource().fetch({'auto_unlock': True, 'server_url': 'https://example.test', 'item_name': 'item', 'sync_interval_seconds': 300}, tmp_path)
    assert not result.error
    assert [c.args[0][1:] for c in run.call_args_list] == [['status', '--raw'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['status', '--raw'], ['get', 'item', 'item']]


def test_gate_off_real_process_mints_each_time_and_never_retries(tmp_path, monkeypatch):
    import json
    from unittest.mock import Mock
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {'BW_CLIENTID': 'cid', 'BW_CLIENTSECRET': 'csecret', 'BW_MASTER_PASSWORD': 'passphrase'})
    monkeypatch.setattr(vw, 'find_bw', lambda *_: Path('/bin/bw'))
    proc = lambda out='', code=0, err='': SimpleNamespace(stdout=out, stderr=err, returncode=code)
    status = proc(json.dumps({'status': 'locked', 'serverUrl': 'https://example.test'}))
    run = Mock(side_effect=[status, proc('one-token'), proc(), proc(json.dumps({'fields': []})), status, proc('two-token'), proc(code=1, err='session expired')])
    monkeypatch.setattr(vw, 'run_secret_cli', run)
    cfg = {'auto_unlock': True, 'remint_on_auth_expired': False, 'server_url': 'https://example.test', 'item_name': 'item', 'sync_interval_seconds': 0}
    source = vw.VaultwardenSource()
    assert not source.fetch(cfg, tmp_path).error
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.AUTH_EXPIRED
    assert not vw._AUTH_SESSIONS
    assert [c.args[0][1:] for c in run.call_args_list] == [['status', '--raw'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['sync'], ['get', 'item', 'item'], ['status', '--raw'], ['unlock', '--passwordenv', 'BW_MASTER_PASSWORD', '--raw'], ['sync']]

@pytest.mark.parametrize('failure', ['exception', 'missing'])
def test_reset_failure_still_prevents_reuse(rig, monkeypatch, failure):
    rig.source.fetch(rig.cfg, rig.home)
    monkeypatch.setattr(cli, 'get_hermes_home', lambda: rig.home)
    monkeypatch.setattr(cli, 'load_config', lambda: {})
    if failure == 'missing':
        rig.find.return_value = None
    else:
        def fail(*args, **kwargs): raise RuntimeError('logout failed')
        monkeypatch.setattr(vw, '_run_bw', fail)
    assert cli.cmd_reset_auth(argparse.Namespace()) == 1
    rig.find.return_value = Path('/bin/bw')
    assert not rig.source.fetch(rig.cfg, rig.home).error
    assert rig.read.call_args.kwargs['session'] == 'mint-token-two'


@pytest.mark.parametrize('outcome', ['success', 'not_logged_in', 'failure', 'exception'])
def test_reset_fences_fetch_during_logout(rig, monkeypatch, outcome):
    from threading import Event, Thread
    assert not rig.source.fetch(rig.cfg, rig.home).error
    monkeypatch.setattr(cli, 'get_hermes_home', lambda: rig.home)
    monkeypatch.setattr(cli, 'load_config', lambda: {})
    entered, release = Event(), Event()
    def logout(*args, **kwargs):
        assert args[1] == 'logout'
        entered.set()
        assert release.wait(5)
        if outcome == 'exception':
            raise RuntimeError('logout failed')
        return SimpleNamespace(returncode=0 if outcome == 'success' else 1,
                               stderr={'not_logged_in': 'not logged in', 'failure': 'failed'}.get(outcome, ''), stdout='')
    monkeypatch.setattr(vw, '_run_bw', logout)
    results = []
    worker = Thread(target=lambda: results.append(cli.cmd_reset_auth(argparse.Namespace())))
    worker.start()
    try:
        assert entered.wait(5)
        assert not rig.source.fetch(rig.cfg, rig.home).error
        assert rig.read.call_args.kwargs['session'] == 'mint-token-two'
        assert not vw._AUTH_SESSIONS
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert results == [0 if outcome in ('success', 'not_logged_in') else 1]
    assert not vw._AUTH_SESSIONS
    assert not rig.source.fetch(rig.cfg, rig.home).error
    assert rig.read.call_args.kwargs['session'] == 'mint-token-three'

@pytest.mark.parametrize('label,session_env', [('BW_SESSION', 'BW_SESSION'), ('MY_SESSION', 'BW_SESSION'), ('CUSTOM_TOKEN', 'CUSTOM_TOKEN'), ('session', 'BW_SESSION'), ('--session ', 'BW_SESSION')])
def test_failed_get_stdout_redacts_unknown_session(tmp_path, monkeypatch, label, session_env):
    from unittest.mock import Mock
    vw._reset_cache_for_tests(tmp_path)
    monkeypatch.setattr(vw, 'get_source_environment', lambda: {session_env: 'known-session'})
    monkeypatch.setattr(vw, 'find_bw', lambda *_: Path('/bin/bw'))
    proc = lambda out='', code=0: SimpleNamespace(stdout=out, stderr='', returncode=code)
    sep = '' if label.endswith(' ') else '='
    run = Mock(side_effect=[proc(), proc('failure ' + label + sep + 'abcd.efgh.ijkl', 1)])
    monkeypatch.setattr(vw, 'run_secret_cli', run)
    result = vw.VaultwardenSource().fetch({'item_name': 'item', 'session_env': session_env, 'sync_interval_seconds': 0}, tmp_path)
    assert result.error
    assert 'abcd.efgh.ijkl' not in result.error + repr(result.warnings)
    assert [c.args[0][1:] for c in run.call_args_list] == [['sync'], ['get', 'item', 'item']]


def test_overlapping_resets_keep_publication_fenced(rig, monkeypatch):
    from threading import Event, Lock, Thread
    monkeypatch.setattr(cli, 'get_hermes_home', lambda: rig.home)
    monkeypatch.setattr(cli, 'load_config', lambda: {})
    entered = [Event(), Event()]
    release = [Event(), Event()]
    lock = Lock()
    indices = iter(range(2))
    def logout(*args, **kwargs):
        with lock:
            index = next(indices)
        entered[index].set()
        assert release[index].wait(5)
        return SimpleNamespace(returncode=0, stderr='', stdout='')
    monkeypatch.setattr(vw, '_run_bw', logout)
    results = []
    workers = [Thread(target=lambda: results.append(cli.cmd_reset_auth(argparse.Namespace()))) for _ in range(2)]
    try:
        workers[0].start()
        assert entered[0].wait(5)
        workers[1].start()
        assert entered[1].wait(5)
        release[0].set()
        workers[0].join(5)
        assert not workers[0].is_alive()
        assert not rig.source.fetch(rig.cfg, rig.home).error
        assert not vw._AUTH_SESSIONS
    finally:
        for event in release: event.set()
        for worker in workers:
            if worker.ident is not None: worker.join(5)
    assert results == [0, 0]
    assert not vw._AUTH_SESSIONS
    assert not rig.source.fetch(rig.cfg, rig.home).error
    assert rig.read.call_args.kwargs['session'] == 'mint-token-two'
