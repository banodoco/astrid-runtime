"""Run from the exact clean pre-updater checkout with an unused destination.

PYTHONPATH=. python /path/to/generate.py /path/to/new-realm
"""
from pathlib import Path
import subprocess
import sys

EXPECTED = '11443b0b5b34bd5b36725504fb083146192a759d'
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == EXPECTED
from runtime_protocol.store import RealmStore, SCHEMA_VERSION
from runtime_protocol.service import RuntimeService
assert SCHEMA_VERSION == 31
root = Path(sys.argv[1])
assert not root.exists()
RealmStore.initialize(root, realm_id='realm-authentic-pre-updater', display_name='Fixture realm').close()
service = RuntimeService(root)
try:
    project = service.create_project({'slug': 'film', 'name': 'Fixture film'}, idempotency_key='project')
    service.create_timeline_document(project['id'], {'timeline_id': 'main', 'name': 'Main', 'config': {'tracks': [], 'clips': [], 'metadata': {'note': 'keep timeline'}}, 'registry': {'assets': {}}}, idempotency_key='timeline')
    service.update_preferences('user', 'Prefer local editing.', 0, 'preferences', identity={'actor': 'fixture-user'})
    service.ingest_object(b'authentic fixture object\n', media_type='text/plain', original_name='fixture.txt', idempotency_key='object')
    service.store.create_task('fixture.render', {'prompt': 'keep task'}, project=project['id'], idempotency_key='task')
finally:
    service.close()
