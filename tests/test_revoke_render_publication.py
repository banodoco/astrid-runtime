"""Opt-in real H027 render task qualification; no fake renderer or authority.

The absolute run-owned root supplies the admitted closure and disposable store.
This first positive is a prerequisite to an in-flight revoke/publication proof.
"""
import hashlib
import http.client
import importlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

import pytest


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _inventory(root):
    return {str(p.relative_to(root)): {
        'sha256': _sha(p), 'size': p.stat().st_size,
        'mode': stat.S_IMODE(p.stat().st_mode),
    } for p in root.rglob('*') if p.is_file()}


def test_qualified_real_render_task_positive(tmp_path):
    raw_root = os.environ.get('H_RENDER_PROOF_ROOT')
    if not raw_root:
        pytest.skip('requires the explicitly admitted H027 run-owned closure')
    out = Path(raw_root).resolve(strict=True)
    config = json.loads((out / 'config.json').read_text())
    source = Path(config['astrid'])
    prior = Path(config['prior'])
    project_dir = prior / 'project'
    assert tmp_path.is_relative_to(Path(config['proof_root']) / 'runtime')
    assert _sha(prior / 'HAND-BACK-027.md') == 'cf955f875639b7ae24b45df224e44caa8e76e4b25e4f1869acea7313582af741'

    # H032 uses the real admitted joined validator; no alternate module loader.
    validator_path = source / 'astrid/core/rendering/remotion_runtime.py'
    assert _sha(validator_path) == '7ec87517ce807557cb6672a6a5a4bf51648bf3283bae96083796a386d9f13dd2'
    validator_name = 'astrid.core.rendering.remotion_runtime'
    validator = importlib.import_module(validator_name)
    assert Path(validator.__file__) == validator_path
    st = Path(validator.__file__).stat()
    assert (st.st_dev, st.st_ino) == (config['validator_identity']['st_dev'],
                                    config['validator_identity']['st_ino'])
    (out / 'loaded-validator.json').write_text(json.dumps({
        'module': validator_name, 'path': validator.__file__,
        'sha256': _sha(validator_path), 'device': st.st_dev, 'inode': st.st_ino,
    }, indent=2) + '\n')

    from astrid.core.execution import generic_host as gh
    from astrid.core.execution.remotion_closure import RemotionClosureBinding
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.store import RealmStore
    from test_revoke_inflight_consumer import _request
    from test_task_authority_host_canary import SCOPES

    assert Path(gh.__file__).resolve().is_relative_to(source)
    expected = json.loads((out / 'worker-preflight.json').read_text())['loaded_source_expected']
    loaded = {}
    for relative, digest in expected.items():
        path = source / relative
        assert _sha(path) == digest
        if relative.startswith('astrid/core/'):
            module = importlib.import_module(relative[:-3].replace('/', '.'))
            assert Path(module.__file__).resolve() == path.resolve()
        st = path.stat()
        loaded[relative] = {'path': str(path.resolve()), 'sha256': _sha(path),
                            'device': st.st_dev, 'inode': st.st_ino,
                            'imported_in_host': relative.startswith('astrid/core/')}
    (out / 'loaded-source.json').write_text(json.dumps(loaded, indent=2) + '\n')
    events = []
    cli_processes = []
    ready = threading.Event()
    release = threading.Event()
    claim_done = threading.Event()

    def event(name, **fields):
        events.append({'sequence': len(events), 'event': name,
                       'monotonic_ns': time.monotonic_ns(), **fields})
        (out / 'positive-events.json').write_text(json.dumps(events, indent=2) + '\n')

    class ObservedHost(gh.GenericPackHost):
        # Observers only: no pause, replacement command, signal, or authority change.
        def _track_process(self, process):
            super()._track_process(process)
            tracked.append(process)
            event('host-owned-process-track', pid=process.pid,
                  args=process.args, claim=dict(self._confinement_policy.claim_binding))

        def _untrack_process(self, process):
            event('host-owned-process-untrack', pid=process.pid, exit=process.poll())
            super()._untrack_process(process)

    before = _inventory(project_dir)
    (out / 'positive-project-before.json').write_text(json.dumps(before, sort_keys=True) + '\n')
    admission = json.loads((prior / 'receipt-admission.json').read_text())
    binding = RemotionClosureBinding.admit(
        project=project_dir, installed_project=project_dir,
        verification_receipt=admission['path'], receipt_sha256=admission['sha256'],
        manifest_sha256=admission['manifest_sha256'], lock_sha256=admission['lock_sha256'])
    event('strict-binding-validated', cli=str(binding.validate(project_dir)), files=len(binding.files))
    # The isolated consumer was prepared once, before Host construction.
    env = json.loads((out / 'ready-environment.json').read_text())
    # pytest adds only these two diagnostics around the already installed mapping.
    assert {k: v for k, v in os.environ.items()
            if k not in {'PYTEST_CURRENT_TEST', 'PYTEST_VERSION'}} == env
    receipt = Path(env['ASTRID_REMOTION_VALIDATION_PATH'])
    assert receipt.is_relative_to(Path(config['proof_root']) / 'host-support')
    assert not receipt.is_symlink() and receipt.stat().st_uid == os.getuid()
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert _sha(receipt) == env['ASTRID_REMOTION_VALIDATION_SHA256']
    from astrid.core.rendering.remotion_runtime import _validated_runtime
    _validated_runtime(project_dir, environment=dict(os.environ))
    event('h032-readiness-consumed', launch=env['ASTRID_REMOTION_VALIDATION_LAUNCH'],
          environment_sha256=_sha(out / 'ready-environment.json'))
    RealmStore.initialize(tmp_path / 'realm').close()
    daemon = RuntimeDaemon(tmp_path / 'realm', support_root=tmp_path / 'support').start()
    tracked = []
    host = None
    lease_fd = None
    lease = {'identity': 'astrid-host-workload:v1', 'weight': 1,
             'mode': 'shared_nonblocking', 'owner': 'H-REVOKE-RENDER-PUBLICATION-032',
             'supervisor_pid': os.getpid(), 'acquired': False, 'released': False}
    result = {'producer': 'unmodified rendering.render', 'render_proof': False,
              'inflight_pause_available': False, 'acceptance_claimed': False}
    task_id = None
    thread = None
    try:
        client = gh.RuntimeProtocolClient(daemon.endpoint, daemon.worker_credential_path.read_text().strip())
        host = ObservedHost(pack_roots=[source / 'astrid/packs/rendering'], client=client,
                            executor_id='astrid-pack-host', attempt_base=tmp_path / 'attempts',
                            capability_matrix=source / 'config/astrid-beta-capabilities.json',
                            remotion_closure_binding=binding)
        def observer(observation, process, cancelled):
            event('render-command-observer', observation=observation,
                  original_popen_id=id(process), poll=process.poll())
            if observation['event'] == 'started':
                cli_processes.append(process)
                assert observation['pid'] == process.pid
                assert observation['parent_pid'] == os.getpid()
                assert observation['birth'] == process._astrid_process_birth
                assert observation['registration'] == process._astrid_custody._launch_broker.registration
                assert observation['identity']['pid'] == process.pid
                assert observation['executable'] == str(Path(env['ASTRID_NODE_EXECUTABLE']).resolve())
                assert Path(observation['command'][1]).resolve() == binding.validate(project_dir).resolve()
                assert process.poll() is None
                ready.set()
                release.wait()
            else:
                assert observation['event'] == 'exited'
                assert any(p is process for p in cli_processes)
                assert process.poll() == observation['returncode']

        host._render_command_observer = observer
        host.discover()
        host.register()
        record = host.capabilities['rendering.render']
        result['capability'] = record.manifest()
        service = daemon.service
        project = service.create_project({'slug': 'h032-synthetic', 'name': 'H032 Synthetic'},
                                         idempotency_key='h032-project')['id']
        actor = 'h032-synthetic-connector'
        service.select_project(actor, project)
        token, _ = daemon.credentials.provision_connector(
            actor, SCOPES, connector_id=actor, realm_id=service.realm['id'], expires_at=time.time()+1800)
        context = {'pair_id': 'h032-positive-pair', 'connector_id': actor,
                   'realm_id': service.realm['id'], 'generation': 1,
                   'expires_at': int((time.time()+1700)*1000)}
        # Supported file-mode snapshot, using no real media or canonical film.
        snapshot = {'config': {'theme': 'banodoco-default', 'clips': [],
                              'theme_overrides': {'visual': {'canvas': {'width': 16, 'height': 16, 'fps': 30}}}},
                    'registry': {'assets': {}}}
        body = {'project': project, 'capability_id': 'rendering.render',
                'capability_digest': record.capability_digest,
                'spec': {'inputs': {'timeline_snapshot': snapshot, 'selector': 'rendering.remotion',
                                    'output_name': 'h032-positive.mp4'}}}
        status, answer = _request(daemon, token, context, 'POST', '/v1/tasks', body, 'h032-positive')
        result.update(admission_status=status, admission=answer, actor=actor, pair=context,
                      project_id=project, endpoint=daemon.endpoint)
        assert status == 201, answer
        task_id = answer['data']['task_id']
        event('real-render-task-admitted', task_id=task_id, project=project)
        import fcntl
        lock = Path('/Users/peteromalley/.local/state/astrid/host-workload-v1.lock')
        lease_fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        st = os.fstat(lease_fd)
        assert stat.S_ISREG(st.st_mode)
        lease.update(path=str(lock), device=st.st_dev, inode=st.st_ino)
        fcntl.flock(lease_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        lease.update(acquired=True, acquired_unix=time.time(), projected_growth='bounded one-frame video plus temporary bundle; no install')
        (out / 'positive-lease.json').write_text(json.dumps(lease, indent=2) + '\n')
        event('host-workload-lease-acquired', device=st.st_dev, inode=st.st_ino)
        def durable_state(label):
            with service.store._mutex:
                state = {'task': service.task(task_id),
                         'attempts': [dict(row) for row in service.store.conn.execute(
                             'SELECT * FROM attempts WHERE task_id=?', (task_id,)).fetchall()],
                         'managed_outputs': service.store.list_managed_outputs(task_id),
                         'database_dump': '\n'.join(service.store.conn.iterdump()),
                         'cas': _inventory(service.store.cas_root),
                         'staging': _inventory(service.store.staging_root)}
            (out / ('positive-state-' + label + '.json')).write_text(json.dumps(state, indent=2, default=str) + '\n')
            return state

        durable_state('admitted')

        def claim():
            try:
                result['claim_result'] = host.claim_once()
            except Exception as exc:
                result['claim_error'] = {'type': type(exc).__name__, 'message': str(exc)}
            finally:
                claim_done.set()
                ready.set()

        thread = threading.Thread(target=claim)
        thread.start()
        ready.wait()
        result['live_observer_seen'] = bool(cli_processes)
        if cli_processes:
            result['original_claim'] = dict(host._confinement_policy.claim_binding)
            durable_state('live')
            assert not claim_done.is_set()
            assert all(p.poll() is None for p in cli_processes)
            result['inflight_pause_available'] = True
        release.set()
        thread.join()
        durable_state('terminal')
        result['task'] = service.task(task_id)
        result['attempts'] = [dict(row) for row in service.store.conn.execute(
            'SELECT * FROM attempts WHERE task_id=?', (task_id,)).fetchall()]
        result['managed_outputs'] = service.store.list_managed_outputs(task_id)
        result['output_readbacks'] = []
        for output in result['managed_outputs']:
            digest = output['object_id'].removeprefix('sha256:')
            payload = service.cas.path_for(digest).read_bytes()
            result['output_readbacks'].append({'receipt': output, 'digest': hashlib.sha256(payload).hexdigest(),
                                               'size': len(payload)})
            assert hashlib.sha256(payload).hexdigest() == digest
        result['public_readbacks'] = []
        endpoint = urlsplit(daemon.endpoint)
        for output in result['managed_outputs']:
            digest = output['object_id'].removeprefix('sha256:')
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
            try:
                connection.request('GET', '/v1/objects/' + digest, headers={
                    'Authorization': 'Bearer ' + token,
                    'X-Reigh-Paired-Session': json.dumps(context)})
                response = connection.getresponse()
                data = response.read()
                readback = {'status': response.status, 'sha256': hashlib.sha256(data).hexdigest(),
                            'size': len(data), 'expected_digest': digest}
                result['public_readbacks'].append(readback)
                assert response.status == 200 and readback['sha256'] == digest
            finally:
                connection.close()
        result['render_proof'] = result['task']['task']['status'] == 'completed'
        assert result['live_observer_seen'], result
        assert all(p.poll() == 0 for p in cli_processes), result
        assert result['render_proof'], result
        assert result['managed_outputs'], result
    finally:
        release.set()
        if thread is not None:
            thread.join()
        if host is not None:
            host.shutdown()
            result['cleanup'] = getattr(host, 'last_cleanup_receipt', None)
            result['active_processes_after_shutdown'] = len(host._active_processes)
            result['host_lifetime_processes_after_shutdown'] = len(host._host_lifetime_processes)
        result['processes'] = [{'pid': p.pid, 'exit': p.poll(), 'kind': 'cli' if p in cli_processes else 'executor'} for p in tracked + cli_processes]
        daemon.stop()
        event('owned-host-and-daemon-shutdown', processes=result['processes'])
        if lease_fd is not None:
            if lease['acquired']:
                assert all(p.poll() is not None for p in tracked + cli_processes)
                assert (os.stat(lock).st_dev, os.stat(lock).st_ino) == (lease['device'], lease['inode'])
                fcntl.flock(lease_fd, fcntl.LOCK_UN)
                lease.update(released=True, released_unix=time.time())
            os.close(lease_fd)
        (out / 'positive-lease.json').write_text(json.dumps(lease, indent=2) + '\n')
        result['project_changes'] = {k: {'before': before.get(k), 'after': value}
                                     for k, value in _inventory(project_dir).items() if before.get(k) != value}
        result['project_removed'] = sorted(set(before) - set(_inventory(project_dir)))
        binding.validate(project_dir)
        result['binding_valid_after'] = True
        (out / 'positive-result.json').write_text(json.dumps(result, indent=2, default=str) + '\n')
        assert not result['project_changes'] and not result['project_removed']
