"""Same-ID create repairs only an exact empty headless shell, atomically."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_baseline import empty_bootstrap_document, verify_baseline
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import canonical_json, now
from test_timeline_commit_acceptance import validate_prepared
from test_timeline_commit_port import PreparedProvider


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "shell", "name": "Shell"}, idempotency_key="project")["id"]
    # Created before a commit provider exists, so no publication is installed.
    runtime.create_timeline(project, "main", idempotency_key="create-main")
    runtime.register_timeline_commit_provider(PreparedProvider())
    try:
        yield runtime, project
    finally:
        runtime.close()


def _shell(service, project, *, parent="empty-parent", payload=None, key="shell"):
    """Leave a published parent revision with no publication: the headless shell.

    Mirrors the first half of the commit store's bootstrap (closure, head,
    publication event, receipt) with a caller-chosen revision, stopping before
    the head edge is installed.
    """
    document = empty_bootstrap_document(project, "main", parent)
    if payload is not None:
        document["parent_revision"] = {"revision_id": parent, "payload": payload,
                                       "content_digest": "sha256:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()}
    commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
    store = service.store
    with store._mutex, store._transaction():
        commits._validate_closure(document)
        commits._persist_closure(document)
        revision, timestamp = document["parent_revision"], now()
        store.conn.execute("INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, ?, ?)",
                           ("main", project, parent, timestamp))
        manifest = {k: v for k, v in document["dependency_manifest"].items() if k != "documents"}
        event = store._append_timeline_event("main", "parent.composition.published",
            {"project_id": project, "timeline_id": "main", "old_head": None, "new_head": parent,
             "content_digest": revision["content_digest"], "dependency_manifest": manifest})
        result = {"project_id": project, "timeline_id": "main", "revision_id": parent, "parent_revision_id": parent,
                  "content_digest": revision["content_digest"], "payload": revision["payload"], "old_head": None,
                  "new_head": parent, "dependency_manifest": manifest,
                  "content_digests": {"parent": revision["content_digest"]}, "event_id": event, "created_at": timestamp}
        seq = store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", ("main",)).fetchone()[0]
        store._record_command_receipt("parent_composition.publish", "main", key,
            hashlib.sha256(key.encode()).hexdigest(), result, project_id=project, event_ids=[event],
            primary_stream_id="main", resulting_stream_seq=seq, created_at=timestamp)


def _dump(service):
    return tuple(service.store.conn.iterdump())


def _cas_dump(service):
    return {
        str(path.relative_to(service.store.cas_root)): path.read_bytes()
        for path in service.store.cas_root.rglob("*") if path.is_file()
    }


def _retain_document(service, project, content):
    _retain_document_bytes(service, project, canonical_json(content))


def _retain_document_bytes(service, project, content):
    with service.store._mutex, service.store._transaction():
        service.store.conn.execute(
            "INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)",
            ("timeline:main", project, "timeline", content, "t", "t"),
        )


def _refused_untouched(service, call):
    before = _dump(service)
    with pytest.raises(ConflictError) as error:
        call()
    assert error.value.status == 409
    assert error.value.details == {"timeline_id": "main"}
    assert _dump(service) == before


def _head(service, project):
    return service.get_project_timeline(project, "main")


def test_empty_headless_shell_is_repaired_once_and_replays_identically(service):
    runtime, project = service
    _shell(runtime, project)
    assert _head(runtime, project)["head_publication_id"] is None

    first = runtime.create_timeline(project, "main", idempotency_key="adopt")
    head = _head(runtime, project)
    assert head["head_publication_id"] is not None
    assert head["head_revision_id"] == "empty-parent"
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)
    assert [entry["intent"] for entry in history["items"]] == ["bootstrap"]
    assert verify_baseline(runtime.store.conn, project, "main", read_object=runtime.cas.read)["canonical_document"] \
        == empty_bootstrap_document(project, "main", "empty-parent")

    before = _dump(runtime)
    assert runtime.create_timeline(project, "main", idempotency_key="adopt") == first
    assert _dump(runtime) == before


def test_replayed_adoption_never_reapplies_over_later_writes(service):
    runtime, project = service
    _shell(runtime, project)
    first = runtime.create_timeline(project, "main", idempotency_key="adopt")
    runtime.rename_timeline(project, "main", {"name": "Later"}, idempotency_key="rename")
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)

    assert runtime.create_timeline(project, "main", idempotency_key="adopt") == first
    assert runtime.list_timeline_commits(project, "main", authorize=lambda: None) == history
    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="second"))


def test_crash_before_commit_leaves_shell_and_retry_adopts_once(service, monkeypatch):
    runtime, project = service
    _shell(runtime, project)
    before = _dump(runtime)

    def crash(*args, **kwargs):
        raise RuntimeError("crash after adoption, before receipt")

    monkeypatch.setattr(runtime, "_command_record", crash)
    with pytest.raises(RuntimeError):
        runtime.create_timeline(project, "main", idempotency_key="adopt")
    monkeypatch.undo()
    assert _dump(runtime) == before
    assert _head(runtime, project)["head_publication_id"] is None

    first = runtime.create_timeline(project, "main", idempotency_key="adopt")
    assert runtime.create_timeline(project, "main", idempotency_key="adopt") == first
    assert len(runtime.list_timeline_commits(project, "main", authorize=lambda: None)["items"]) == 1


def test_original_create_replay_is_unchanged_by_adoption(service):
    runtime, project = service
    original = runtime.create_timeline(project, "main", idempotency_key="create-main")
    _shell(runtime, project)
    runtime.create_timeline(project, "main", idempotency_key="adopt")

    before = _dump(runtime)
    assert runtime.create_timeline(project, "main", idempotency_key="create-main") == original
    assert _dump(runtime) == before


def test_headed_timeline_is_refused_untouched(service):
    runtime, project = service
    _shell(runtime, project)
    runtime.create_timeline(project, "main", idempotency_key="adopt")
    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="other"))


def test_non_empty_headless_shell_is_refused_untouched(service):
    runtime, project = service
    payload = copy.deepcopy(empty_bootstrap_document(project, "main", "non-empty")["parent_revision"]["payload"])
    payload["config"] = {"clips": [], "tracks": [{"id": "picture", "kind": "visual", "role": "output", "opaque": [None, False]}]}
    _shell(runtime, project, parent="non-empty", payload=payload)
    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="adopt"))
    assert _head(runtime, project)["head_publication_id"] is None


@pytest.mark.parametrize("parent", ["unpublished", "absent", "null"])
def test_non_empty_legacy_document_is_refused_before_empty_shell_adoption(service, parent):
    runtime, project = service
    if parent == "unpublished":
        _shell(runtime, project)
    elif parent == "null":
        with runtime.store._mutex, runtime.store._transaction():
            runtime.store.conn.execute(
                "INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?)",
                ("main", project, "t"),
            )
    content = {
        "config": {"clips": [{"id": "unsaved", "at": 7, "hold": 3}]},
        "registry": {"assets": {}},
        "slug": "keep",
    }
    _retain_document(runtime, project, content)
    before, cas_before = _dump(runtime), _cas_dump(runtime)

    with pytest.raises(ConflictError) as error:
        runtime.create_timeline(project, "main", idempotency_key="adopt")

    assert error.value.details == {"timeline_id": "main"}
    assert _dump(runtime) == before
    assert _cas_dump(runtime) == cas_before
    assert json.loads(runtime.store.conn.execute(
        "SELECT content_json FROM project_documents WHERE id='timeline:main'"
    ).fetchone()[0]) == content
    assert _head(runtime, project)["head_publication_id"] is None
    assert runtime.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0


@pytest.mark.parametrize("raw", [
    '{"clips":[{"id":"keep"}],"clips":[]}',
    '{"opaque":{"clips":[{"id":"keep"}],"clips":[]},"clips":[]}',
    r'{"clips":[{"id":"keep"}],"\u0063lips":[]}',
    '{"clips":[],"clips":[]}',
])
@pytest.mark.parametrize("parent", ["absent", "null"])
def test_duplicate_legacy_json_is_refused_before_missing_head_bootstrap(service, parent, raw):
    runtime, project = service
    if parent == "null":
        with runtime.store._mutex, runtime.store._transaction():
            runtime.store.conn.execute(
                "INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?)",
                ("main", project, "t"),
            )
    _retain_document_bytes(runtime, project, raw)
    before, cas_before, changes = _dump(runtime), _cas_dump(runtime), runtime.store.conn.total_changes

    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="repair"))
    assert _dump(runtime) == before and _cas_dump(runtime) == cas_before
    assert runtime.store.conn.total_changes == changes
    assert runtime.store.conn.execute(
        "SELECT content_json FROM project_documents WHERE id='timeline:main'"
    ).fetchone()[0] == raw


@pytest.mark.parametrize("raw", [
    '{"clips":[],"opaque":{"first":[],"second":{}}}',
    '{"references":[],"shots":[]}',
])
@pytest.mark.parametrize("parent", ["absent", "null"])
def test_distinct_empty_legacy_json_still_repairs_missing_head(service, parent, raw):
    runtime, project = service
    if parent == "null":
        with runtime.store._mutex, runtime.store._transaction():
            runtime.store.conn.execute(
                "INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?)",
                ("main", project, "t"),
            )
    _retain_document_bytes(runtime, project, raw)

    repaired = runtime.create_timeline(project, "main", idempotency_key="repair")
    assert repaired["data"]["head_revision_id"]


@pytest.mark.parametrize("sql, args", [
    pytest.param("INSERT INTO composition_revision_dependencies(parent_revision_id, dependency_kind, dependency_id, content_digest, ordinal) VALUES (?,?,?,?,0)",
                 ("empty-parent", "media", "m", "0" * 64), id="dependency-row"),
    pytest.param("INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?,?,?,?)", ("ref", "main", "obj", None),
                 id="timeline-references"),
    pytest.param("INSERT INTO timeline_shots(id, timeline_id, start_ms, duration_ms, reference_ids_json) VALUES (?,?,?,?,?)",
                 ("shot", "main", 0, 1, "[]"), id="timeline-shots"),
    pytest.param("INSERT INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) VALUES (?,?,?,?,?)",
                 ("main", 99, '[{"id": "x"}]', "[]", "t"), id="timeline-revisions"),])
def test_empty_shell_with_dependency_row_or_scope_is_refused_untouched(service, sql, args):
    runtime, project = service
    _shell(runtime, project)
    with runtime.store._mutex, runtime.store._transaction():
        runtime.store.conn.execute(sql, args)
    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="adopt"))
    assert _head(runtime, project)["head_publication_id"] is None


def test_wrong_project_or_name_is_refused_untouched(service):
    runtime, project = service
    _shell(runtime, project)
    other = runtime.create_project({"slug": "other", "name": "Other"}, idempotency_key="other")["id"]
    _refused_untouched(runtime, lambda: runtime.create_timeline(other, "main", idempotency_key="foreign"))
    _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", name="Renamed", idempotency_key="renamed"))


@pytest.mark.parametrize("parent", ["absent", "null"])
@pytest.mark.parametrize("hidden", ["timeline_references", "timeline_shots", "snapshot", "dependency",
                                   "retained-parent", "internal", "internal-digest", "internal-project",
                                   "publication", "foreign-head", "archived"])
def test_no_parent_repair_refuses_retained_content_and_corruption(service, parent, hidden):
    from test_timeline_headless_overwrite_refused import _scoped_rows

    runtime, project = service
    conn = runtime.store.conn
    with runtime.store._mutex, runtime.store._transaction():
        if parent == "null":
            conn.execute("INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?)",
                         ("main", project, "t"))
        if hidden in {"timeline_references", "timeline_shots", "snapshot", "dependency"}:
            _scoped_rows(runtime, project, hidden)
        elif hidden == "retained-parent":
            _scoped_rows(runtime, project, "dependency")
            conn.execute("DELETE FROM composition_revision_dependencies WHERE parent_revision_id='orphan-rev'")
        elif hidden == "internal":
            conn.execute("INSERT INTO internal_timeline_revisions(id, project_id, timeline_id, payload_json, content_digest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                         ("hidden", project, "main", '{"clips":[],"tracks":[]}', "0" * 64, "t"))
        elif hidden == "internal-digest":
            conn.execute("UPDATE internal_timeline_revisions SET content_digest=? WHERE timeline_id='main'", ("0" * 64,))
        elif hidden == "internal-project":
            other = runtime.create_project({"slug": "other", "name": "Other"})["id"]
            conn.execute("UPDATE internal_timeline_revisions SET project_id=? WHERE timeline_id='main'", (other,))
        elif hidden == "publication":
            runtime.store._append_timeline_event("main", "parent.composition.published", {"project_id": project})
        elif hidden == "foreign-head":
            other = runtime.create_project({"slug": "other", "name": "Other"})["id"]
            conn.execute("INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?) "
                         "ON CONFLICT(timeline_id) DO UPDATE SET project_id=excluded.project_id", ("main", other, "t"))
        else:
            conn.execute("UPDATE timelines SET archived_at='t' WHERE id='main'")
    before, cas_before, changes = _dump(runtime), _cas_dump(runtime), conn.total_changes
    for _ in range(2):
        _refused_untouched(runtime, lambda: runtime.create_timeline(project, "main", idempotency_key="repair"))
        assert _dump(runtime) == before and _cas_dump(runtime) == cas_before
        assert conn.total_changes == changes
