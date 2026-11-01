"""Fresh bootstrap refuses corrupt orphan content before allocating authority."""
from __future__ import annotations

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_baseline import (
    bootstrap_install_plan, default_bootstrap_document, empty_bootstrap_document, verify_baseline,
)
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_port import PreparedProvider


@pytest.fixture
def realm(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "fresh", "name": "Fresh"}, idempotency_key="project")["id"]
    try:
        yield runtime, project
    finally:
        runtime.close()


def _tree(root):
    return {str(path.relative_to(root)): None if path.is_dir() else path.read_bytes()
            for path in root.rglob("*")}


def _state(runtime):
    return (tuple(runtime.store.conn.iterdump()), _tree(runtime.store.cas_root), _tree(runtime.store.staging_root))


def _orphan(runtime, project, raw):
    # Explicitly corrupt state: current document APIs reject reserved timeline IDs.
    assert runtime.store.conn.execute("SELECT 1 FROM timelines WHERE id='main'").fetchone() is None
    with runtime.store._mutex, runtime.store._transaction():
        runtime.store.conn.execute(
            "INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)",
            ("timeline:main", project, "timeline", raw, "t", "t"),
        )


def _assert_empty_bootstrap(runtime, project, created):
    head = created["data"]
    facts = verify_baseline(runtime.store.conn, project, "main", read_object=runtime.cas.read)
    assert head["head_publication_id"] == facts["head"]["publication_id"]
    assert facts["canonical_document"] == default_bootstrap_document(project, "main", head["head_revision_id"])
    config = facts["canonical_document"]["parent_revision"]["payload"]["config"]
    assert config["clips"] == []
    assert [(track["id"], track["label"], track["kind"]) for track in config["tracks"]] == [
        ("V1", "V1", "visual"), ("A1", "A1", "audio"),
    ]
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)
    assert [entry["intent"] for entry in history["items"]] == ["bootstrap"]


@pytest.mark.parametrize("raw", [
    '{"clips":[{"id":"keep"}]}',
    '{"clips":[{"id":"keep"}],"clips":[]}',
], ids=["plain-nonempty", "duplicate-hidden"])
def test_corrupt_orphan_refuses_before_any_write(realm, raw):
    runtime, project = realm
    runtime.register_timeline_commit_provider(PreparedProvider())
    _orphan(runtime, project, raw)
    before, changes = _state(runtime), runtime.store.conn.total_changes

    for _ in range(2):
        with pytest.raises(ConflictError) as error:
            runtime.create_timeline(project, "main", idempotency_key="create")
        assert "timeline:main" in str(error.value)
        assert error.value.details == {"status": "refused", "reason": "headless_content_not_empty"}
        assert _state(runtime) == before
        assert runtime.store.conn.total_changes == changes


@pytest.mark.parametrize("raw", [
    None,
    '{"config":{},"registry":{"assets":{}},"clips":[]}',
    r'{"opaque":{"a":[],"A":{},"\u00e9":[],"e\u0301":{}}}',
], ids=["fresh", "empty-orphan", "distinct-opaque-empty"])
def test_fresh_or_empty_scope_bootstraps_and_replays(realm, raw):
    runtime, project = realm
    runtime.register_timeline_commit_provider(PreparedProvider())
    if raw is not None:
        _orphan(runtime, project, raw)
    created = runtime.create_timeline(project, "main", idempotency_key="create")
    _assert_empty_bootstrap(runtime, project, created)
    before, changes = _state(runtime), runtime.store.conn.total_changes
    assert runtime.create_timeline(project, "main", idempotency_key="create") == created
    assert _state(runtime) == before and runtime.store.conn.total_changes == changes
    if raw is not None:
        assert runtime.store.conn.execute("SELECT content_json FROM project_documents WHERE id='timeline:main'").fetchone()[0] == raw


def test_unrelated_catalog_and_foreign_orphan_do_not_block_fresh_create(realm):
    runtime, project = realm
    foreign = runtime.create_project({"slug": "other", "name": "Other"}, idempotency_key="other")["id"]
    _orphan(runtime, foreign, '{"clips":[{"id":"foreign"}],"clips":[]}')
    runtime.create_document(project, {
        "document_id": "catalog-notes", "kind": "notes", "content": {"clips": [{"id": "catalog-only"}]},
    }, idempotency_key="notes")
    runtime.ingest(project, b"unrelated catalog media", idempotency_key="media")
    runtime.register_timeline_commit_provider(PreparedProvider())
    tables = ("project_documents", "objects", "project_objects")
    before = {table: [tuple(row) for row in runtime.store.conn.execute(f"SELECT * FROM {table}")] for table in tables}
    cas_before, staging_before = _tree(runtime.store.cas_root), _tree(runtime.store.staging_root)

    created = runtime.create_timeline(project, "main", idempotency_key="create")

    _assert_empty_bootstrap(runtime, project, created)
    assert {table: [tuple(row) for row in runtime.store.conn.execute(f"SELECT * FROM {table}")] for table in tables} == before
    assert _tree(runtime.store.cas_root) == cas_before and _tree(runtime.store.staging_root) == staging_before


def test_legacy_trackless_bootstrap_remains_adoptable(realm, monkeypatch):
    runtime, project = realm
    runtime.register_timeline_commit_provider(PreparedProvider())
    # Produce the former bootstrap through the same publication transaction.
    with monkeypatch.context() as legacy:
        legacy.setattr("runtime_protocol.timeline_commit_baseline.default_bootstrap_document", empty_bootstrap_document)
        created = runtime.create_timeline(project, "main", idempotency_key="create")
    before, changes = _state(runtime), runtime.store.conn.total_changes
    with runtime.store._transaction():
        plan = bootstrap_install_plan(runtime.store.conn, project, "main", read_object=runtime.cas.read)
    assert plan["head"]["revision_id"] == created["data"]["head_revision_id"]
    assert plan["entries"][0]["intent"] == "bootstrap"
    assert _state(runtime) == before and runtime.store.conn.total_changes == changes


def test_no_provider_main_creation_and_original_replay_stay_valid(realm, monkeypatch):
    runtime, project = realm
    created = runtime.create_timeline(project, "main", name="Main", idempotency_key="create")
    assert created["data"]["name"] == "Main"
    assert created["data"]["head_revision_id"] is None
    assert created["data"]["head_publication_id"] is None
    assert runtime.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
    runtime.rename_timeline(project, "main", {"name": "Later"}, idempotency_key="rename")
    runtime.register_timeline_commit_provider(PreparedProvider())
    before, changes = _state(runtime), runtime.store.conn.total_changes

    def forbidden(*args, **kwargs):
        raise AssertionError("original create replay reached scope/adoption/bootstrap")

    monkeypatch.setattr("runtime_protocol.service.timeline_scope_is_empty", forbidden)
    monkeypatch.setattr(runtime, "_adopt_empty_shell_create", forbidden)
    monkeypatch.setattr(TimelineCommitStore, "bootstrap", forbidden)
    assert runtime.create_timeline(project, "main", name="Main", idempotency_key="create") == created
    assert _state(runtime) == before and runtime.store.conn.total_changes == changes


@pytest.mark.integration
def test_real_provider_fresh_create_uses_normal_bootstrap(realm, astrid_importable):
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    runtime, project = realm
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    created = runtime.create_timeline(project, "main", name="Main", idempotency_key="create")
    _assert_empty_bootstrap(runtime, project, created)
    before, changes = _state(runtime), runtime.store.conn.total_changes
    assert runtime.create_timeline(project, "main", name="Main", idempotency_key="create") == created
    assert _state(runtime) == before and runtime.store.conn.total_changes == changes
