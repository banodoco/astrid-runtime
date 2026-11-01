"""Real-provider same-ID repair uses create/bootstrap without semantic defaults."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_baseline import empty_bootstrap_document, verify_baseline
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from test_timeline_empty_shell_repair import _cas_dump, _dump

pytestmark = pytest.mark.integration


@pytest.fixture(params=["absent", "null"])
def shell(tmp_path, astrid_importable, request):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "repair", "name": "Repair"})["id"]
    original = runtime.create_timeline(project, "main", name="Keep", idempotency_key="original")
    if request.param == "null":
        # Only the empty head representation is historical; no revision/history is seeded.
        with runtime.store._mutex, runtime.store._transaction():
            runtime.store.conn.execute(
                "INSERT INTO parent_composition_heads(timeline_id, project_id, revision_id, updated_at) VALUES (?, ?, NULL, ?)",
                ("main", project, "t"),
            )
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    try:
        yield runtime, project, original
    finally:
        runtime.close()


def test_repair_exact_bootstrap_retry_restart_and_edit_undo(shell, monkeypatch):
    runtime, project, original = shell
    repaired = runtime.create_timeline(project, "main", idempotency_key="repair")
    data = repaired["data"]
    assert data["name"] == "Keep"
    basis = verify_baseline(runtime.store.conn, project, "main", read_object=runtime.cas.read)
    assert basis["canonical_document"] == empty_bootstrap_document(project, "main", data["head_revision_id"])
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)
    assert [item["intent"] for item in history["items"]] == ["bootstrap"]
    assert history["head"] == basis["head"]

    def submit(calls, key):
        current = runtime.get_project_timeline(project, "main")
        return runtime.commit_timeline(project, "main", {
            "api_version": 1, "project_id": project, "timeline_id": "main",
            "base_revision_id": current["head_revision_id"], "base_publication_id": current["head_publication_id"],
            "commands": copy.deepcopy(calls), "source": {"via": "python"},
        }, idempotency_key=key, publisher="editor", invocation_path=route_path(project, "main"), authorize=lambda: None)

    edited = submit([{"schema_version": 1, "op": "track.create", "version": "1", "select": "parent",
                      "args": {"row": {"id": "later", "kind": "visual"}}}], "edit")
    before, cas_before = _dump(runtime), _cas_dump(runtime)
    assert runtime.create_timeline(project, "main", idempotency_key="repair") == repaired
    assert _dump(runtime) == before and _cas_dump(runtime) == cas_before
    submit([{"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
             "args": {"publications": [edited["receipt"]["receipt_id"]]}}], "undo")
    retired = runtime.get_project_timeline(project, "main")
    root = runtime.store.root
    runtime.close()
    reopened = RuntimeService(root)
    try:
        assert reopened.get_project_timeline(project, "main") == retired
        before, cas_before = _dump(reopened), _cas_dump(reopened)
        def forbidden(*args, **kwargs):
            raise AssertionError("exact create retry tried to bootstrap again")

        monkeypatch.setattr(reopened, "_adopt_empty_shell_create", forbidden)
        assert reopened.create_timeline(project, "main", name="Keep", idempotency_key="original") == original
        assert reopened.create_timeline(project, "main", idempotency_key="repair") == repaired
        with pytest.raises(ConflictError):
            reopened.create_timeline(project, "main", name="Changed", idempotency_key="repair")
        assert _dump(reopened) == before and _cas_dump(reopened) == cas_before
    finally:
        reopened.close()


def test_repair_rollback_before_receipt_and_exact_retry(shell, monkeypatch):
    runtime, project, _ = shell
    before, cas_before = _dump(runtime), _cas_dump(runtime)

    def crash(*args, **kwargs):
        raise RuntimeError("crash before repair receipt")

    with monkeypatch.context() as patch:
        patch.setattr(runtime, "_command_record", crash)
        with pytest.raises(RuntimeError, match="crash before repair receipt"):
            runtime.create_timeline(project, "main", idempotency_key="repair")
    assert _dump(runtime) == before and _cas_dump(runtime) == cas_before
    repaired = runtime.create_timeline(project, "main", idempotency_key="repair")
    assert runtime.create_timeline(project, "main", idempotency_key="repair") == repaired
    assert len(runtime.list_timeline_commits(project, "main", authorize=lambda: None)["items"]) == 1
