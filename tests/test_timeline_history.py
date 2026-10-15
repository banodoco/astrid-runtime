"""Bounded synthetic HISTORY checks; no named-film or production evidence."""
import hashlib
import sqlite3

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.upgrade import migrate_canonical_to_current
from test_shot_composition_runtime import _service, _publication
from test_timeline_accept import acceptance, IDENTITY


@pytest.fixture
def history(tmp_path):
    s, p = _service(tmp_path)
    s.publish_parent_composition(p, 'main', _publication(p), idempotency_key='initial')
    try:
        yield s, p
    finally:
        s.close()


def test_head_reads_no_inspection_and_observes_next_poll(history, monkeypatch):
    s, p = history
    monkeypatch.setattr(s, 'inspect_timeline', lambda *a, **k: pytest.fail('head must not inspect'))
    before = s.head(p, 'main')
    published = s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1', parent_revision_id='parent-2'), idempotency_key='second')
    head = s.head(p, 'main')  # The very next poll, with no cache delay.
    assert set(head) == {'revision_id', 'publication_id', 'updated_at'}
    assert head['revision_id'] == 'parent-2'
    assert head['publication_id'] == published['receipt']['receipt_id'] != before['publication_id']


def test_repeated_revision_publications_are_distinct_events(history):
    s, p = history
    first = s.head(p, 'main')
    second = s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1'), idempotency_key='repeat')
    rows = s.list_project_parent_composition_revisions(p, 'main')['items']
    assert len(rows) == 2
    assert rows[0]['revision_id'] == rows[1]['revision_id'] == 'parent-1'
    assert rows[0]['publication_id'] != rows[1]['publication_id']
    assert rows[0]['previous_revision_id'] == 'parent-1'
    assert rows[0]['previous_publication_id'] == first['publication_id']
    assert [r['is_current_head'] for r in rows] == [True, False]
    replay = s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1'), idempotency_key='repeat')
    assert replay == second
    assert len(s.list_project_parent_composition_revisions(p, 'main')['items']) == 2


def test_acceptance_and_restore_persist_separate_ancestry_and_provenance(history):
    s, p = history
    original = s.head(p, 'main')
    accepted = s.accept(acceptance(s, p), identity=IDENTITY)
    row = s.revisions(p, 'main', {'limit': 1})[0]
    assert row['previous_revision_id'] == original['revision_id']
    assert row['previous_publication_id'] == original['publication_id']
    assert row['publisher'] == IDENTITY['actor']
    assert s.list_project_parent_composition_revisions(p, 'main')['items'][0]['provenance']['publisher'] == IDENTITY['actor']
    restored = s.restore_project_parent_composition_revision(p, 'main', 'parent-1', {'expected_head': accepted['revision_id']}, idempotency_key='restore')
    row = s.list_project_parent_composition_revisions(p, 'main')['items'][0]
    assert row['previous_revision_id'] == accepted['revision_id']
    assert row['previous_publication_id'] == accepted['publication_id']
    assert row['restored_from_revision_id'] == 'parent-1'
    assert restored['data']['parent_revision_id'] == row['revision_id'] != row['previous_revision_id']
    assert row['provenance']['source'] == {'via': 'restore'}


@pytest.mark.parametrize('route', ['accept', 'publish', 'restore'])
def test_old_writer_refused_at_each_atomic_write_boundary(history, monkeypatch, route):
    s, p = history
    # Publish v1 using the current writer, then model the old v0 helper.
    s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1', parent_revision_id='feature', config={'app': {'astrid': {'v': 1}}}), idempotency_key='feature')
    prepared = acceptance(s, p)
    monkeypatch.setattr('astrid.core.timeline.compatibility.SUPPORTED_VERSIONS', frozenset({0}))
    before = s.head(p, 'main')
    with pytest.raises((ConflictError, ValidationError), match=r'app.astrid.v=1'):
        if route == 'accept':
            s.accept(prepared, identity=IDENTITY)
        elif route == 'publish':
            s.publish_parent_composition(p, 'main', _publication(p, expected_head='feature', parent_revision_id='lossy'), idempotency_key='old')
        else:
            s.restore_project_parent_composition_revision(p, 'main', 'parent-1', {'expected_head': 'feature'}, idempotency_key='old')
    assert s.head(p, 'main') == before
    assert s.lookup_request(p, 'main', 'save-1') is None


def test_old_writer_can_publish_compatible_legacy_head(history, monkeypatch):
    s, p = history
    monkeypatch.setattr('astrid.core.timeline.compatibility.SUPPORTED_VERSIONS', frozenset({0}))
    s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1', parent_revision_id='legacy'), idempotency_key='legacy')
    assert s.head(p, 'main')['revision_id'] == 'legacy'


def test_history_and_head_roll_back_with_acceptance_ledger(history, monkeypatch):
    s, p = history
    before = s.head(p, 'main')
    original = s._command_record
    def fail(kind, *args, **kwargs):
        if kind == 'timeline.commit':
            raise RuntimeError('history rollback')
        return original(kind, *args, **kwargs)
    monkeypatch.setattr(s, '_command_record', fail)
    with pytest.raises(RuntimeError, match='history rollback'):
        s.accept(acceptance(s, p), identity=IDENTITY)
    assert s.head(p, 'main') == before
    assert len(s.list_project_parent_composition_revisions(p, 'main')['items']) == 1


def test_synthetic_v27_migration_preserves_rows_events_and_is_byte_idempotent(history):
    s, p = history
    s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1'), idempotency_key='repeat')
    root = s.store.root
    realm_id = s.store.realm['id']
    revisions = [tuple(r) for r in s.store.conn.execute('SELECT * FROM parent_composition_revisions')]
    s.close()
    db = root / 'realm.sqlite3'
    with sqlite3.connect(db) as c:
        c.execute('DROP TABLE parent_composition_publications')
        c.execute('ALTER TABLE parent_composition_heads DROP COLUMN publication_id')
        c.execute('UPDATE runtime_schema SET version=27')
    first = migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm_id}')
    assert first['target_schema_version'] == 28
    digest = hashlib.sha256(db.read_bytes()).hexdigest()
    assert migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm_id}')['changed'] is False
    assert hashlib.sha256(db.read_bytes()).hexdigest() == digest
    with sqlite3.connect(db) as c:
        assert c.execute('SELECT * FROM parent_composition_revisions').fetchall() == revisions
        rows = c.execute('SELECT revision_id, previous_publication_id, restored_from_revision_id FROM parent_composition_publications').fetchall()
        assert rows == [('parent-1', None, None), ('parent-1', None, None)]
    reopened = RuntimeService(root)
    try:
        assert reopened.head(p, 'main')['revision_id'] == 'parent-1'
        assert len(reopened.list_project_parent_composition_revisions(p, 'main')['items']) == 2
    finally:
        reopened.close()


@pytest.mark.parametrize('route', ['accept', 'publish', 'restore'])
def test_declared_legacy_payload_cannot_downgrade_feature_head(history, route):
    s, p = history
    s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1', parent_revision_id='feature', config={'app': {'astrid': {'v': 1}}}), idempotency_key='feature')
    before = s.head(p, 'main')
    with pytest.raises(ConflictError, match='below pinned head'):
        if route == 'accept':
            s.accept(acceptance(s, p), identity=IDENTITY)
        elif route == 'publish':
            s.publish_parent_composition(p, 'main', _publication(p, expected_head='feature', parent_revision_id='lossy'), idempotency_key='lossy')
        else:
            s.restore_project_parent_composition_revision(p, 'main', 'parent-1', {'expected_head': 'feature'}, idempotency_key='lossy')
    assert s.head(p, 'main') == before


def test_binding_authority_set_show_list_rebind_survives_head_advancement(history):
    s, p = history
    first = s.set_project_shot_text_binding(p, {'shot_id': 'shot-1', 'kind': 'transcript', 'text': 'one', 'expected_head': 0}, idempotency_key='text-one')['data']
    second = s.set_project_shot_text_binding(p, {'binding_id': first['binding_id'], 'text': 'two', 'expected_head': 1}, idempotency_key='text-two')['data']
    s.accept(acceptance(s, p), identity=IDENTITY)
    assert s.get_project_shot_text_binding(p, first['binding_id']) == second
    assert s.list_project_shot_text_bindings(p, shot_id='shot-1')['items'] == [second]
    rebound = s.rebind_project_shot_text_binding(p, {'binding_id': first['binding_id'], 'media_id': first['media_id'], 'expected_head': 2}, idempotency_key='text-rebind')['data']
    assert rebound['head'] == 3
    assert s.get_project_shot_text_binding(p, first['binding_id']) == rebound


def test_history_migration_rolls_back_last_step_atomically(tmp_path, monkeypatch):
    import runtime_protocol.upgrade as upgrade
    from test_runtime_upgrade import _canonical_fixture
    root = tmp_path / 'old-realm'
    realm_id = _canonical_fixture(root, 24)
    original = upgrade._apply_v27_to_v28
    def fail(connection):
        original(connection)
        raise RuntimeError('history migration rollback')
    monkeypatch.setattr(upgrade, '_apply_v27_to_v28', fail)
    with pytest.raises(RuntimeError, match='history migration rollback'):
        migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm_id}')
    assert upgrade.inspect_canonical_schema(root)['version'] == 24



def test_unrecorded_revision_remains_listable_with_unknown_ancestry(history):
    s, p = history
    with s.store._transaction():
        s.store.conn.execute("INSERT INTO parent_composition_revisions SELECT 'unrecorded', project_id, timeline_id, payload_json, content_digest, created_at FROM parent_composition_revisions WHERE id='parent-1'")
    page = s.list_project_parent_composition_revisions(p, 'main', limit=1)
    assert page['items'][0]['revision_id'] == 'parent-1'
    old = s.list_project_parent_composition_revisions(p, 'main', cursor=page['next_cursor'], limit=1)['items'][0]
    assert old['revision_id'] == 'unrecorded'
    assert old['publication_id'] is old['previous_revision_id'] is old['provenance'] is None
    assert old['is_current_head'] is False


def test_migration_preserves_preexisting_acceptance_provenance_and_links(history):
    s, p = history
    accepted = s.accept(acceptance(s, p), identity=IDENTITY)
    expected = s.list_project_parent_composition_revisions(p, 'main')['items'][0]
    root = s.store.root
    realm_id = s.store.realm['id']
    s.close()
    with sqlite3.connect(root / 'realm.sqlite3') as c:
        ledger = c.execute('SELECT * FROM command_idempotency').fetchall()
        c.execute('DROP TABLE parent_composition_publications')
        c.execute('ALTER TABLE parent_composition_heads DROP COLUMN publication_id')
        c.execute('UPDATE runtime_schema SET version=27')
    migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm_id}')
    reopened = RuntimeService(root)
    try:
        actual = reopened.list_project_parent_composition_revisions(p, 'main')['items'][0]
        for key in ('publication_id', 'revision_id', 'previous_revision_id', 'previous_publication_id', 'restored_from_revision_id', 'provenance'):
            assert actual[key] == expected[key]
        assert [tuple(r) for r in reopened.store.conn.execute('SELECT * FROM command_idempotency')] == ledger
        assert reopened.accept(acceptance(reopened, p, key='next'), identity=IDENTITY)['previous_publication_id'] == accepted['publication_id']
    finally:
        reopened.close()



def test_no_change_acceptance_cannot_skip_head_compatibility(history, monkeypatch):
    s, p = history
    s.publish_parent_composition(p, 'main', _publication(p, expected_head='parent-1', parent_revision_id='feature', config={'app': {'astrid': {'v': 1}}}), idempotency_key='feature')
    prepared = acceptance(s, p, no_change=True)
    before = s.head(p, 'main')
    monkeypatch.setattr('astrid.core.timeline.compatibility.SUPPORTED_VERSIONS', frozenset({0}))
    with pytest.raises(ConflictError, match=r'app.astrid.v=1'):
        s.accept(prepared, identity=IDENTITY)
    assert s.head(p, 'main') == before
    assert s.lookup_request(p, 'main', 'save-1') is None
