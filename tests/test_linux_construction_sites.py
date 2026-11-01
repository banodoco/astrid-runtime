"""Exercise production Linux custody construction through seal and child binding."""
import os
import signal
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from astrid_runtime import custody_broker as custody
from runtime_protocol import local_execution_supervisor as supervisor
from runtime_protocol import local_worker_composition as composition
from runtime_protocol import platform
from runtime_protocol import verified_host_launch
from test_local_execution_supervisor import _prepare_case
from test_local_worker import host_only_profile_case, profile_case

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux custody construction coverage')

SLEEPER = [sys.executable, '-I', '-c', 'import time; time.sleep(60)']


@pytest.fixture
def launch(tmp_path, monkeypatch):
    # Production uses a compact socket directory. Keep even that directory in
    # the task's pytest basetemp, while staying below Linux's AF_UNIX limit.
    socket_parent = Path(__file__).resolve().parents[2] / 'sockets'
    socket_parent.mkdir(mode=0o700, exist_ok=True)
    monkeypatch.setattr(platform, 'handoff_socket_parent', lambda: socket_parent)
    original_spawn = platform.spawn_tree
    children = []
    mode = {'early_exit': False}

    def spawn(argv, **kwargs):
        assert argv == custody.custody_wrapper_argv(sys.executable)
        if mode['early_exit']:
            # Run the real wrapper with an incomplete admission environment so
            # it exits before connecting. Wait here to make the race deterministic.
            kwargs['env'] = dict(kwargs['env'])
            kwargs['env'].pop('ASTRID_RUNTIME_CUSTODY_TARGET_B64')
        child = original_spawn(argv, **kwargs)
        children.append(child)
        if mode['early_exit']:
            assert child.wait(timeout=10) != 0
        return child

    monkeypatch.setattr(platform, 'spawn_tree', spawn)
    yield mode, children
    for child in children:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)


def _site(site, tmp_path, monkeypatch, launch, *, adapt_relay=True, create_relay_scope=True):
    """Return a callable and a way to obtain its published real broker/child."""
    if site == 'host_only':
        profile = replace(host_only_profile_case(), support_root=tmp_path,
                          realm_root=tmp_path, host_executable=Path(sys.executable))
        config = {**profile.host_launch, 'runtime_endpoint': 'http://127.0.0.1:1',
                  'runtime_instance_id': 'epoch', 'credential_file': str(tmp_path / 'cred'),
                  'ready_file': str(tmp_path / 'ready')}

        class Verifier:
            def __init__(self, **kwargs): pass
            def verify(self, **kwargs): return object()
            def claim(self, proof, **kwargs): return SLEEPER, b'binding'
            def bind_child(self, proof, **kwargs): pass
            def verify_child(self, proof, **kwargs): pass

        monkeypatch.setattr(verified_host_launch, 'TrustedLocalHostLaunchVerifier', Verifier)
        monkeypatch.setattr(composition, '_installed_host_release', lambda *args: {})
        request = {}
        monkeypatch.setattr(composition, '_frame_send', lambda channel, value: request.update(value))
        def receive(channel):
            handle = preparer._active
            return {'version': request['version'], 'status': 'prepared', 'operation_id': 'op',
                    'channel_id': 'channel', 'owner_epoch': 'epoch', 'execution_mode': 'host_only_cpu',
                    'processes': {'host': {'pid': handle.worker.pid, 'birth_id': handle.birth_id}},
                    'session_config_digest': profile.session_config_digest}
        monkeypatch.setattr(composition, '_frame_receive', receive)
        preparer = composition.CrossProcessWorkerPreparer(profile=profile, config=config, environment={}, timeout_seconds=2)
        # The test owns cleanup of the test workload, including failed admission.
        monkeypatch.setattr(preparer, 'abort', lambda handle: None)
        return (lambda: preparer._prepare_host_only(profile, operation_id='op', channel_id='channel'),
                lambda: preparer._active)

    if site == 'relay':
        profile = replace(profile_case(), support_root=tmp_path, worker_executable=Path(sys.executable),
                          worker_artifact_digest=composition._file_digest(Path(sys.executable)))
        # Match the actual resolved executable check while retaining the venv path
        # for the wrapper, as in the production site.
        profile = replace(profile, worker_executable=composition._actual_executable(os.getpid()))
        preparer = composition.CrossProcessWorkerPreparer(profile=profile,
            config={'runtime_instance_id': 'epoch'}, environment={}, timeout_seconds=2)
        # The Linux owner currently includes extra observation fields, which
        # the request validator rejects. Project the contract fields here so
        # the remaining production relay custody path can be exercised.
        original_request = supervisor.host_prepare_request
        def project_request(**kwargs):
            owner = kwargs['runtime_owner']
            kwargs['runtime_owner'] = {key: owner[key] for key in
                ('pid', 'uid', 'birth_id', 'runtime_instance_id', 'coordinator_epoch')}
            return original_request(**kwargs)
        if adapt_relay:
            monkeypatch.setattr(supervisor, 'host_prepare_request', project_request)
        if create_relay_scope:
            (tmp_path / 'local-execution-custody' / 'op').mkdir(parents=True, mode=0o700)
        monkeypatch.setattr(preparer, '_rpc', lambda handle, request: {'report': {}})
        monkeypatch.setattr(preparer, 'abort', lambda handle: None)
        return (lambda: preparer._prepare_relay(profile, operation_id='op', channel_id='channel'),
                lambda: preparer._active)

    preparation, _ = _prepare_case()
    preparation['custody_scope'] = str(tmp_path / 'scope')
    (tmp_path / 'scope').mkdir(mode=0o700)
    preparation['profile']['worker_executable'] = sys.executable
    config = {'support_root': str(tmp_path), 'source_checkout': None}
    monkeypatch.setattr(supervisor, 'selected_host_argv', lambda *args, **kwargs: SLEEPER)
    retained = []
    return (lambda: supervisor.NativeHostSession.create(preparation, config, retain=retained.append, timeout=2),
            lambda: retained[0] if retained else None)


def _close(site, owner):
    if owner is None:
        return
    for name in ('control', 'activation'):
        channel = getattr(owner, name, None)
        if channel is not None:
            channel.close()


@pytest.mark.parametrize('site', ['host_only', 'relay', 'supervisor'])
def test_real_site_seals_binds_and_signals(site, tmp_path, monkeypatch, launch):
    run, get_owner = _site(site, tmp_path, monkeypatch, launch)
    owner = None
    try:
        owner = run()
        broker, retained = owner.broker, owner.retained
        assert broker.state in {'sealed', 'ready-bound'}
        assert isinstance(retained.actor, custody.AuthenticatedCleanupActor)
        assert retained.actor.verify()['pid'] == retained.child.pid
        assert broker.role_authority.reference()['target'] == retained.actor.verify()
        broker.signal(signal.SIGTERM, expected_pid=retained.child.pid)
        with retained.guard:
            assert retained.child.wait(timeout=10) == -15
        assert retained.child.returncode == -15
    finally:
        _close(site, owner or get_owner())


@pytest.mark.parametrize('site', ['host_only', 'relay', 'supervisor'])
def test_real_site_refuses_child_exiting_before_seal(site, tmp_path, monkeypatch, launch):
    launch[0]['early_exit'] = True
    calls = []
    monkeypatch.setattr(custody.RoleCustodyAuthority, 'signal', lambda *args, **kwargs: calls.append((args, kwargs)))
    run, get_owner = _site(site, tmp_path, monkeypatch, launch)
    try:
        with pytest.raises(custody.CustodyError):
            run()
        owner = get_owner()
        assert owner is not None
        assert owner.retained.actor is None
        assert owner.broker.state not in {'sealed', 'ready-bound'}
        with pytest.raises(custody.CustodyError, match='not sealed'):
            owner.broker.signal(signal.SIGTERM, expected_pid=owner.retained.child.pid)
        assert calls == []
    finally:
        _close(site, get_owner())


def test_relay_rejects_real_linux_owner_before_construction(tmp_path, monkeypatch, launch):
    run, get_owner = _site('relay', tmp_path, monkeypatch, launch, adapt_relay=False)
    with pytest.raises(supervisor.RelayError, match='exact Runtime owner incarnation'):
        run()
    assert get_owner() is None
    assert launch[1] == []


def test_relay_without_precreated_scope_refuses_implicit_nonprivate_directory(tmp_path, monkeypatch, launch):
    run, get_owner = _site('relay', tmp_path, monkeypatch, launch, create_relay_scope=False)
    old_umask = os.umask(0o022)
    try:
        with pytest.raises(custody.CustodyError, match='scope is not owner-only'):
            run()
    finally:
        os.umask(old_umask)
    assert get_owner() is None
    assert launch[1] == []


def test_retained_wait_currently_cannot_reap_signalled_child(tmp_path, monkeypatch, launch):
    run, get_owner = _site('host_only', tmp_path, monkeypatch, launch)
    try:
        owner = run()
        retained = owner.retained
        owner.broker.signal(signal.SIGTERM, expected_pid=retained.child.pid)
        # Observe exit without consuming it, so the test proves the failure is
        # in retained.wait rather than in signal delivery or scheduling.
        deadline = time.monotonic() + 10
        while os.waitid(os.P_PID, retained.child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            assert time.monotonic() < deadline, 'child did not exit after TERM'
            time.sleep(0.01)
        with pytest.raises(supervisor.RelayError, match='exit remains unresolved'):
            retained.wait(0.25)
        with retained.guard:
            assert retained.child.wait(timeout=10) == -15
    finally:
        _close('host_only', get_owner())
