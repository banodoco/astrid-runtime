"""Disposable stdin-owned fixture for the App's actual relay/connector test.

No control HTTP route. Requires explicit private HOME/TMPDIR/fixture paths.
"""
import json
import os
from pathlib import Path
import sys
import time

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ForbiddenError
from runtime_protocol.store import RealmStore

root = Path(sys.argv[1]).resolve()
if (not root.is_relative_to(Path(os.environ['TMPDIR']).resolve())
        or Path(os.environ['HOME']).resolve().parent != Path(os.environ['TMPDIR']).resolve().parent):
    raise SystemExit('private HOME and TMPDIR required')
root.mkdir(mode=0o700, parents=True)
RealmStore.initialize(root / 'realm').close()
d = RuntimeDaemon(root / 'realm', support_root=root / 'support').start()
scopes = ['handshake', 'projects:read', 'projects:write', 'tasks:read', 'tasks:write', 'objects:read', 'objects:write']
try:
    project = d.service.create_project({'slug': 'one', 'name': 'One'}, idempotency_key='p1')['id']
    second = d.service.create_project({'slug': 'two', 'name': 'Two'}, idempotency_key='p2')['id']
    d.service.select_project('connector-fixture', project)
    expiry = time.time() + 900
    _, credential = d.credentials.provision_connector('connector-fixture', scopes,
        connector_id='fixture-connector', realm_id=d.service.realm['id'], expires_at=expiry)
    _, ordinary = d.credentials.provision('ordinary-fixture', scopes)
    _, other = d.credentials.provision_connector('other-fixture', scopes,
        connector_id='fixture-connector', realm_id=d.service.realm['id'], expires_at=expiry)
    d.service.select_project('other-fixture', project)
    discovery = root / 'discovery.json'
    discovery.write_text(json.dumps({'endpoint': d.endpoint, 'credential_file': str(credential)}))
    print(json.dumps({'endpoint': d.endpoint, 'realm': d.service.realm['id'], 'project': project,
        'second': second, 'discovery': str(discovery), 'credential': str(credential),
        'ordinary': str(ordinary), 'other': str(other), 'credential_expiry': expiry}), flush=True)
    for line in sys.stdin:
        message = json.loads(line)
        command = message['command']
        if command == 'stop':
            break
        if command == 'select-second':
            d.service.select_project('connector-fixture', second)
            result = {'selected': second}
        elif command == 'exchange':
            a, b = (d.httpd.paired_sessions._sessions[p] for p in message['pairs'])
            try:
                d.httpd.paired_sessions.decision(b, project_id=project, operation='rendering.render', presented_grant=a.handle)
                raise AssertionError('foreign grant admitted')
            except ForbiddenError as exc:
                result = exc.details
        elif command == 'expire-credential':
            metadata = d.credentials.actor_metadata('connector-fixture')
            metadata['expires_at'] = time.time() - 1
            d.credentials._publish('connector-fixture', credential.read_text().strip(), metadata)
            result = {'expired': True}
        else:
            raise AssertionError(command)
        print(json.dumps(result), flush=True)
finally:
    d.stop()
