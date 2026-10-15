"""Real Vite /api/astrid proxy to disposable Runtime HTTP acceptance.

Requires the exact App worktree and its lock-pinned isolated Vite tool closure.
No default checkout, live store, or production identity is ever selected.
"""
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

from test_timeline_accept import fixture, fixture_prepare, http_server, wire, acceptance, IDENTITY, valid, count


def test_actual_app_vite_proxy_to_runtime_commit(fixture, tmp_path):
    s, p = fixture
    app = Path(os.environ['ACCEPT_APP_ROOT'])
    vite_entry = Path(os.environ['ACCEPT_VITE_ENTRY'])
    assert app.is_dir() and vite_entry.is_file()
    fixture_prepare(s, p)
    runtime, thread, api = http_server(s, tmp_path)
    env = dict(os.environ, ACCEPT_FIXTURE_TOKEN=api.credential,
               ACCEPT_FIXTURE_RUNTIME_PORT=str(runtime.server_port), ACCEPT_VITE_CACHE=str(tmp_path / 'vite-cache'))
    proxy = subprocess.Popen([os.environ.get('ACCEPT_NODE', '/opt/homebrew/bin/node'), '--experimental-transform-types',
                              'scripts/security/timeline-commit-proxy.fixture.mjs'], cwd=app, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proxy.stdout.readline()
        assert line, proxy.stderr.read()
        observed = json.loads(line)
        assert observed['polling_ms'] == 30000
        endpoint = f"http://127.0.0.1:{observed['port']}"
        path = f'/api/astrid/astrid/v1/projects/{p}/timelines/main/commit'
        request = wire(p)
        def post(body):
            req = urllib.request.Request(endpoint + path, json.dumps(body).encode(), method='POST', headers={
                'Content-Type': 'application/json', 'Idempotency-Key': body['request_id'],
                'X-Astrid-Session': body['session_id'], 'Origin': endpoint,
                # A caller token must not override the configured fixture publisher.
                'Authorization': 'Bearer untrusted-browser-token',
            })
            try:
                with urllib.request.urlopen(req) as response:
                    return response.status, response.read(), {k.lower(): v for k, v in response.headers.items()}
            except urllib.error.HTTPError as error:
                return error.code, error.read(), {k.lower(): v for k, v in error.headers.items()}
        status, first_bytes, headers = post(request)
        first = json.loads(first_bytes)
        assert status == 200, first
        valid(first, 'CommitHttpSuccess')
        assert first['runtime_receipt']['publisher'] == IDENTITY['actor']
        assert s.lookup_request(p, 'main', request['request_id'])['result'] == first
        s.accept(acceptance(s, p, key='advance-through-direct-boundary'), identity=IDENTITY)
        status, replay_bytes, replay_headers = post(request)
        assert status == 200 and replay_bytes == first_bytes
        assert headers['x-request-id'] != replay_headers['x-request-id']
        status, changed, _ = post({**request, 'label': 'changed body'})
        changed = json.loads(changed)
        assert status == 400 and changed['error']['code'] == 'request_id_conflict'
        valid(changed, 'CommitHttpBadRequest')
        status, preview, _ = post(wire(p, key='proxy-dry-run', dry_run=True))
        assert status == 200 and json.loads(preview)['status'] == 'preview'
        assert s.lookup_request(p, 'main', 'proxy-dry-run') is None
        assert count(s, 'parent_composition_revisions') == 3
        print(json.dumps({'proxy': '/api/astrid/*', 'runtime_route': path.removeprefix('/api/astrid'),
                          'status': 200, 'replay_bytes_identical': True, 'changed_body_status': 400,
                          'authenticated_publisher': first['runtime_receipt']['publisher'], 'polling_ms': 30000,
                          'producer': 'synthetic COMMIT preparation; real Vite and Runtime acceptance'}))
    finally:
        proxy.terminate()
        stdout, stderr = proxy.communicate()
        runtime.shutdown(); runtime.server_close(); thread.join()
        assert proxy.returncode == 0, (stdout, stderr)
