"""Opt-in real H027 render task qualification; no fake renderer or authority.

The absolute run-owned root supplies the admitted closure and disposable store.
This first positive is a prerequisite to an in-flight revoke/publication proof.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import time

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
    assert tmp_path.is_relative_to(out)
    assert _sha(prior / 'HAND-BACK-027.md') == 'cf955f875639b7ae24b45df224e44caa8e76e4b25e4f1869acea7313582af741'

    from astrid.core.execution import generic_host as gh
    from astrid.core.execution.remotion_closure import RemotionClosureBinding
    from astrid.sdk.host_bootstrap import _host_render_environment, _prepare_render_validation
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.store import RealmStore
    from test_revoke_inflight_consumer import _request
    from test_task_authority_host_canary import SCOPES

    assert Path(gh.__file__).resolve().is_relative_to(source)
    events = []

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
    # Reuse only a context validated by the real host path in this proof root.
    # The unchanged validator checks the exact environment/source/closure.
    ready_path = out / 'positive-ready-environment.json'
    if ready_path.exists():
        from astrid.core.rendering.remotion_runtime import _validated_runtime
        env = json.loads(ready_path.read_text())
        _validated_runtime(project_dir, environment=env)
        launch = env['ASTRID_REMOTION_VALIDATION_LAUNCH']
    else:
        env = _host_render_environment(source)
        launch = _prepare_render_validation(source, env, out / 'host-support',
                                           os.environ['ASTRID_PACK_HOST_PYTHON'],
                                           pack_roots=(source / 'astrid/packs/rendering',))
    os.environ.update(env)
    (out / 'positive-ready-environment.json').write_text(json.dumps(env, indent=2) + '\n')
    binding.validate(project_dir)
    event('real-host-readiness-refreshed', launch=launch)
    RealmStore.initialize(tmp_path / 'realm').close()
    daemon = RuntimeDaemon(tmp_path / 'realm', support_root=tmp_path / 'support').start()
    tracked = []
    host = None
    lease_fd = None
    lease = {'identity': 'astrid-host-workload:v1', 'weight': 1,
             'mode': 'shared_nonblocking', 'owner': 'H-REVOKE-RENDER-PUBLICATION-028',
             'supervisor_pid': os.getpid(), 'acquired': False, 'released': False}
    result = {'producer': 'unmodified rendering.render', 'render_proof': False,
              'inflight_pause_available': False, 'acceptance_claimed': False}
    task_id = None
    try:
        client = gh.RuntimeProtocolClient(daemon.endpoint, daemon.worker_credential_path.read_text().strip())
        host = ObservedHost(pack_roots=[source / 'astrid/packs/rendering'], client=client,
                            executor_id='astrid-pack-host', attempt_base=tmp_path / 'attempts',
                            remotion_closure_binding=binding)
        host.discover()
        host.register()
        record = host.capabilities['rendering.render']
        result['capability'] = record.manifest()
        service = daemon.service
        project = service.create_project({'slug': 'h028-synthetic', 'name': 'H028 Synthetic'},
                                         idempotency_key='h028-project')['id']
        actor = 'h028-synthetic-connector'
        service.select_project(actor, project)
        token, _ = daemon.credentials.provision_connector(
            actor, SCOPES, connector_id=actor, realm_id=service.realm['id'], expires_at=time.time()+1800)
        context = {'pair_id': 'h028-positive-pair', 'connector_id': actor,
                   'realm_id': service.realm['id'], 'generation': 1,
                   'expires_at': int((time.time()+1700)*1000)}
        # Supported file-mode snapshot, using no real media or canonical film.
        snapshot = {'config': {'theme': 'banodoco-default', 'clips': [],
                              'theme_overrides': {'visual': {'canvas': {'width': 16, 'height': 16, 'fps': 30}}}},
                    'registry': {'assets': {}}}
        body = {'project': project, 'capability_id': 'rendering.render',
                'capability_digest': record.capability_digest,
                'spec': {'inputs': {'timeline_snapshot': snapshot, 'selector': 'rendering.remotion',
                                    'output_name': 'h028-positive.mp4'}}}
        status, answer = _request(daemon, token, context, 'POST', '/v1/tasks', body, 'h028-positive')
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
        try:
            result['claim_result'] = host.claim_once()
        except Exception as exc:
            result['claim_error'] = {'type': type(exc).__name__, 'message': str(exc)}
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
        result['render_proof'] = result['task']['task']['status'] == 'completed'
        assert result['render_proof'], result
        assert result['managed_outputs'], result
    finally:
        if host is not None:
            host.shutdown()
            result['cleanup'] = getattr(host, 'last_cleanup_receipt', None)
            result['active_processes_after_shutdown'] = len(host._active_processes)
            result['host_lifetime_processes_after_shutdown'] = len(host._host_lifetime_processes)
        result['processes'] = [{'pid': p.pid, 'exit': p.poll()} for p in tracked]
        daemon.stop()
        event('owned-host-and-daemon-shutdown', processes=result['processes'])
        if lease_fd is not None:
            if lease['acquired']:
                assert all(p.poll() is not None for p in tracked)
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
