"""Compare candidate migration with the exact pre-updater Runtime admission."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import zipfile

from runtime_protocol.upgrade import migrate_canonical_to_current

old = Path(sys.argv[1]).resolve()
assert subprocess.check_output(['git', '-C', str(old), 'rev-parse', 'HEAD'], text=True).strip() == '11443b0b5b34bd5b36725504fb083146192a759d'
archive = Path(__file__).with_name('realm.zip')
with tempfile.TemporaryDirectory(prefix='tst-d1-compat-') as temp:
    root = Path(temp) / 'realm'
    root.mkdir()
    with zipfile.ZipFile(archive) as fixture:
        for name in fixture.namelist():
            destination = root / name
            if name != 'realm.sqlite3' and not name.startswith('cas/sha256/'):
                raise ValueError('unexpected fixture member')
            if '..' in Path(name).parts or Path(name).is_absolute():
                raise ValueError('unsafe fixture member')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(fixture.read(name))
    (root / 'staging').mkdir()
    result = migrate_canonical_to_current(root, confirmation='MIGRATE CANONICAL realm-authentic-pre-updater', expected_realm_id='realm-authentic-pre-updater')
    print('candidate migration:', result, flush=True)
    code = ('from runtime_protocol.store import RealmStore, SCHEMA_VERSION; import sys; '
            's=RealmStore(sys.argv[1]); print("old admission: accepted, schema", SCHEMA_VERSION, '
            '"realm", s.realm["id"], "integrity", s.integrity_report()["ok"]); s.close()')
    subprocess.run([sys.executable, '-c', code, str(root)], cwd=old,
                   env=dict(os.environ, PYTHONPATH=str(old)), check=True)
