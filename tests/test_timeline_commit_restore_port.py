"""Restore admission/persistence with captured sources and a prepared fixture.

This provider tests Runtime's boundary, not Agent restore semantics/inverses;
those run in the companion actual-provider integration suite.
"""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import RequestCommitPort, digest, route_path
from runtime_protocol.util import canonical_json
from baseline_fixture import load_baseline_fixture
from test_timeline_commit_baseline import _disable_renderer
from test_timeline_commit_port import PreparedProvider, prepared, request, rows
from test_timeline_projection_occupancy import accept, proposal, refresh


def _source(tmp_path):
    service, project_id, (first,) = load_baseline_fixture(tmp_path, "explicit-media")
    service.test_project = project_id
    return service, first


def _seed(tmp_path):
    # Only setup uses host acceptance; measured restores use the registered port.
    service, first = _source(tmp_path)
    project_id = service.test_project
    commits, _ = service._timeline_commits()
    commits.install_verified_baseline(project_id, "main", authorize=lambda: None)
    pair = proposal(service, commits, project_id, "main", "current-B")
    document = pair[1]["canonical_document"]
    document["parent_revision"]["payload"]["config"] = {"opaque": {"current": True}}
    internal = document["internal_timeline_revisions"][0]
    internal["revision_id"] = "internal-B"
    internal["payload"]["opaque"] = {"current": "B"}
    internal["content_digest"] = digest(internal["payload"])
    shot = document["shot_revisions"][0]
    shot["revision_id"] = "shot-B"
    shot["internal_timeline_revision_id"] = "internal-B"
    shot["payload"]["internal_timeline_revision_id"] = "internal-B"
    shot["payload"]["metadata"] = {"title": "current B"}
    shot["content_digest"] = digest(shot["payload"])
    document["parent_revision"]["payload"]["occurrences"][0]["shot_revision_id"] = "shot-B"
    document["dependency_manifest"] = {
        "shots": [{key: shot[key] for key in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}],
        "internal_timelines": [{key: internal[key] for key in ("timeline_id", "revision_id", "content_digest")}],
        "media": [], "documents": [],
    }
    refresh(pair[1])
    second = accept(commits, pair)
    return service, first, second


@pytest.fixture
def selected(tmp_path, monkeypatch, request):
    if getattr(request, "param", None) == "history":
        service, project_id, (first, second) = load_baseline_fixture(tmp_path, "history")
        service.test_project = project_id
    else:
        service, first, second = _seed(tmp_path)
    _disable_renderer(monkeypatch, service)
    provider = PreparedProvider()
    service.register_timeline_commit_provider(provider)
    try:
        yield service, provider, first, second
    finally:
        service.close()


def _restore(service, source, *, direct=False, key="restore", content_digest=None, authorize=lambda: None):
    current = request(service)
    if direct:
        args = {"revision_id": source, "content_digest": content_digest}
        current["commands"] = [{"schema_version": 1, "op": "timeline.restore", "version": "1",
                                "select": None, "args": args}]
        return lambda: service.commit_timeline(service.test_project, "main", current, idempotency_key=key,
            publisher="editor", invocation_path=route_path(service.test_project, "main"), authorize=authorize)
    body = {"expected_head": current["base_revision_id"], "expected_publication_id": current["base_publication_id"]}
    return lambda: service.restore_project_parent_composition_revision(service.test_project, "main", source, body,
        idempotency_key=key, publisher="editor", authorize=authorize,
        invocation_path=route_path(service.test_project, "main", f"composition-revisions/{source}/restore"))


def _assert_source(service, first, document):
    parent = document["parent_revision"]
    stored = service.store.conn.execute("SELECT payload_json, content_digest FROM parent_composition_revisions WHERE id=?",
                                        (first["data"]["revision_id"],)).fetchone()
    assert canonical_json(parent["payload"]) == stored["payload_json"] == canonical_json(first["data"]["payload"])
    assert parent["content_digest"] == stored["content_digest"] == digest(parent["payload"])
    assert document["dependency_manifest"] == {**first["data"]["dependency_manifest"], "documents": []}
    assert document["shot_revisions"][0]["revision_id"] == "shot-rev-1"
    assert document["shot_revisions"][0]["payload"]["metadata"] == {"title": "opening"}
    assert document["internal_timeline_revisions"][0]["revision_id"] == "timeline-rev-1"
    assert "opaque" not in document["internal_timeline_revisions"][0]["payload"]


def test_old_main_null_manifest_read_verifies_exact_source_without_installation(tmp_path, monkeypatch):
    service, first = _source(tmp_path)
    try:
        _disable_renderer(monkeypatch, service)
        commits, _ = service._timeline_commits()
        assert service.store.conn.execute("SELECT commit_manifest_json FROM parent_composition_revisions WHERE id='parent-media'").fetchone()[0] is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
        before = rows(service)
        changes = service.store.conn.total_changes
        source = commits.revision_closure(service.test_project, "main", "parent-media")
        _assert_source(service, first, source)
        source["parent_revision"]["payload"]["config"]["mutated"] = True
        _assert_source(service, first, commits.revision_closure(service.test_project, "main", "parent-media"))
        assert rows(service) == before and service.store.conn.total_changes == changes
    finally:
        service.close()


@pytest.mark.parametrize("selected", ["history", "explicit-media"], indirect=True)
def test_selected_scoped_source_read_is_detached_and_does_not_require_source_accepted_edge(selected):
    service, provider, first, second = selected
    source_id = first["data"]["revision_id"]
    legacy = second["receipt"]["command_kind"] == "parent_composition.publish"
    current_id = second["data"]["new_head"] if legacy else second["data"]["accepted_revision_id"]
    # Preserve the old-main missing-edge case and the distinct media/child case.
    # Remove only legacy migration metadata, never source bytes, events or receipts.
    if legacy:
        service.store.conn.execute("UPDATE timeline_commit_history SET previous_publication_id=NULL, previous_revision_id=NULL WHERE revision_id=?", (current_id,))
        service.store.conn.execute("DELETE FROM timeline_commit_history WHERE revision_id=?", (source_id,))
        service.store.conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json=NULL WHERE id=?", (source_id,))
    body = request(service)
    body["commands"][0]["args"]["source"] = {"revision_id": source_id, "content_digest": first["data"]["content_digest"]}
    context = {"request": body, "invocation": {"operation": "commitTimeline"}}
    commits, _ = service._timeline_commits()
    before = rows(service)
    changes = service.store.conn.total_changes
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        source = port.revision_closure(source_id)
        assert source["parent_revision"]["revision_id"] == source_id
        _assert_source(service, first, source)
        source["shot_revisions"].clear()
        _assert_source(service, first, port.revision_closure(source_id))
    finally:
        port.close()
    assert rows(service) == before and service.store.conn.total_changes == changes
    assert provider.calls == 0
    result = _restore(service, source_id)()
    _assert_source(service, first, result["data"]["canonical_document"])
    history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    if legacy:
        assert [entry["intent"] for entry in history["items"]] == ["legacy_unknown", "recorded"]
    else:
        assert [entry["intent"] for entry in history["items"]] == ["legacy_unknown", "recorded", "recorded"]
    assert history["items"][-2]["revision_id"] == current_id
    assert history["items"][-1]["records"]["restored_from"] == {
        "revision_id": source_id, "content_digest": first["data"]["content_digest"],
    }


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("seconds", [5.0, 120.0])
def test_main_source_restore_uses_selected_budget_and_exact_closure(selected, monkeypatch, direct, seconds):
    service, provider, first, second = selected
    service.store.admission_timeout = seconds
    original = service.store.integrity_report
    observed = []
    def inspect(*, timeout_seconds):
        observed.append(timeout_seconds)
        assert provider.calls == 0
        return original(timeout_seconds=timeout_seconds)
    monkeypatch.setattr(service.store, "integrity_report", inspect)
    result = _restore(service, "parent-media", direct=direct, content_digest=first["data"]["content_digest"])()
    assert observed == [seconds] and provider.calls == 1
    _assert_source(service, first, result["data"]["canonical_document"])
    assert result["data"]["previous_revision_id"] == "current-B"
    assert result["data"]["previous_publication_id"] == second["receipt"]["receipt_id"]
    assert result["data"]["commands"][0]["args"] == result["receipt"]["result"]["commands"][0]["args"]
    assert result["data"]["rebased_onto"] is None


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("damage", ["parent", "shot", "internal", "missing_shot", "missing_internal", "dependency", "media", "missing_media", "ownership", "scope"])
def test_restore_rejects_damaged_exact_source_before_provider_or_writes(selected, direct, damage):
    service, provider, first, _ = selected
    call = _restore(service, "parent-media", direct=direct, content_digest=first["data"]["content_digest"])
    conn = service.store.conn
    if damage in {"parent", "shot", "internal"}:
        table, identity = {"parent": ("parent_composition_revisions", "parent-media"), "shot": ("shot_revisions", "shot-rev-1"),
                           "internal": ("internal_timeline_revisions", "timeline-rev-1")}[damage]
        conn.execute(f"UPDATE {table} SET payload_json='{{}}' WHERE id=?", (identity,))
    elif damage in {"missing_shot", "missing_internal"}:
        # Deliberately simulate a damaged database that ordinary FK enforcement prevents.
        conn.execute("PRAGMA foreign_keys=OFF")
        if damage == "missing_shot":
            conn.execute("DELETE FROM shot_revisions WHERE id='shot-rev-1'")
        else:
            conn.execute("DELETE FROM internal_timeline_revisions WHERE id='timeline-rev-1'")
        conn.execute("PRAGMA foreign_keys=ON")
    elif damage == "dependency":
        conn.execute("UPDATE composition_revision_dependencies SET content_digest=? WHERE parent_revision_id='parent-media'", ("sha256:" + "0" * 64,))
    elif damage in {"media", "missing_media"}:
        pin = first["data"]["dependency_manifest"]["media"][0]["media_id"]
        path = service.cas.path_for(pin[7:])
        path.write_bytes(b"corrupt") if damage == "media" else path.unlink()
    elif damage == "ownership":
        conn.execute("DELETE FROM project_objects WHERE digest=?", (first["data"]["dependency_manifest"]["media"][0]["media_id"][7:],))
    else:
        other = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")
        conn.execute("UPDATE internal_timeline_revisions SET project_id=? WHERE id='timeline-rev-1'", (other["id"],))
    before = rows(service)
    changes = conn.total_changes
    with pytest.raises(RuntimeErrorBase) as error:
        call()
    assert error.value.status in (409, 422)
    assert provider.calls == 0
    assert rows(service) == before and conn.total_changes == changes


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("report", [None, {}, {"checks": None}, RealmStore._integrity_not_checked(5),
    RealmStore._integrity_failure("timeout", "bounded inspection exhausted"),
    {"checks": {"revisions": {"ok": True, "errors": []}, "event_chain": {"ok": False, "errors": []}}}])
def test_incomplete_integrity_refuses_before_provider_or_writes(selected, monkeypatch, direct, report):
    service, provider, first, _ = selected
    call = _restore(service, "parent-media", direct=direct, content_digest=first["data"]["content_digest"])
    observed = []
    def incomplete(*, timeout_seconds):
        observed.append(timeout_seconds)
        return report
    monkeypatch.setattr(service.store, "integrity_report", incomplete)
    before = rows(service)
    with pytest.raises(RuntimeErrorBase, match="dependency closure failed immutable verification") as error:
        call()
    assert error.value.details["errors"] == [{"reason": "integrity_report_unavailable"}]
    assert observed == [service.store.admission_timeout] and provider.calls == 0
    assert rows(service) == before


@pytest.mark.parametrize("direct", [False, True])
def test_missing_or_foreign_source_refuses_without_provider_or_writes(selected, direct):
    service, provider, first, _ = selected
    other = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")
    commits, _ = service._timeline_commits()
    before = rows(service)
    with pytest.raises(CommitRejected):
        commits.revision_closure(other["id"], "main", "parent-media")
    with pytest.raises(RuntimeErrorBase):
        _restore(service, "missing", direct=direct, content_digest=first["data"]["content_digest"])()
    assert provider.calls == 0 and rows(service) == before


def test_direct_restore_wrong_digest_is_never_normalized(selected):
    service, provider, _, _ = selected
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        _restore(service, "parent-media", direct=True, content_digest="sha256:" + "0" * 64)()
    assert error.value.details["reason"] == "dependency_unavailable"
    assert provider.calls == 0 and rows(service) == before


@pytest.mark.parametrize("direct", [False, True])
def test_restart_exact_retry_is_ledger_only_but_authorized(selected, monkeypatch, direct):
    service, provider, first, _ = selected
    call = _restore(service, "parent-media", direct=direct, content_digest=first["data"]["content_digest"])
    accepted = call()
    root, project_id = service.store.root, service.test_project
    context = copy.deepcopy(provider.contexts[0])
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project_id
        def forbidden(*args, **kwargs):
            raise AssertionError("accepted retry must not reread provider, source, integrity, or media")
        restarted.register_timeline_commit_provider(PreparedProvider(forbidden))
        monkeypatch.setattr(restarted.store, "integrity_report", forbidden)
        commits, _ = restarted._timeline_commits()
        monkeypatch.setattr(commits, "revision_closure", forbidden)
        monkeypatch.setattr(restarted.cas, "read", forbidden)
        def replay(authorize=lambda: None):
            return restarted._execute_timeline_commit(project_id, "main", context["request"], context["invocation"]["body"],
                operation=context["invocation"]["operation"], idempotency_key=context["idempotency_key"], publisher=context["publisher"],
                invocation_path=context["invocation"]["path"], authorize=authorize)
        before = rows(restarted)
        assert canonical_json(replay()) == canonical_json(accepted)
        def revoked():
            raise AuthorizationError("credential revoked")
        with pytest.raises(AuthorizationError):
            replay(revoked)
        assert rows(restarted) == before
    finally:
        restarted.close()


@pytest.mark.parametrize("missing_proof", ["receipt", "event", "manifest"])
def test_null_manifest_source_requires_original_main_publication_proof(tmp_path, monkeypatch, missing_proof):
    service, first = _source(tmp_path)
    try:
        _disable_renderer(monkeypatch, service)
        conn = service.store.conn
        if missing_proof == "receipt":
            conn.execute("DELETE FROM command_idempotency WHERE txn_id=?", (first["receipt"]["receipt_id"],))
        elif missing_proof == "event":
            conn.execute("UPDATE timeline_events SET event_hash=? WHERE kind='parent.composition.published'", ("0" * 64,))
        else:
            conn.execute("DELETE FROM composition_revision_dependencies WHERE parent_revision_id='parent-media'")
        commits, _ = service._timeline_commits()
        before = rows(service)
        changes = conn.total_changes
        with pytest.raises(RuntimeErrorBase) as error:
            commits.revision_closure(service.test_project, "main", "parent-media")
        assert error.value.details["reason"] == "history_unavailable"
        assert rows(service) == before and conn.total_changes == changes
    finally:
        service.close()


@pytest.mark.parametrize("damage", [None, "content", "binding", "link"])
def test_restore_retains_exact_document_v1_after_mutable_producer_v2(selected, damage):
    service, provider, _, _ = selected
    resource = service.create_document(service.test_project, {
        "document_id": "restore-config", "kind": "pack.config", "content": {"schema": "pack.config/v1", "value": "v1"},
    }, idempotency_key="config-v1")["data"]
    pin = {"document_id": resource["document_id"], "version": resource["version"], "content_digest": digest(resource["content"])}
    captured = []
    def retain(context, port):
        candidate = prepared(context, port)
        document = candidate["canonical_document"]
        if context["idempotency_key"] == "input-A":
            document["dependency_manifest"]["documents"] = [pin]
        for declared in document["dependency_manifest"]["documents"]:
            captured.append(port.config_source(declared))
            candidate["records"]["commands"][0]["dependencies"].append({
                "key": "fixture.config", "kind": "source", "pin": declared, "policy": "exact",
            })
        candidate["document_digest"] = digest(document)
        return port.accept(candidate)
    provider.action = retain
    body = request(service)
    body["commands"] = [{"schema_version": 1, "op": "fixture.retain-input", "version": "1",
                         "select": None, "args": {"config": pin}}]
    first = service.commit_timeline(service.test_project, "main", body, idempotency_key="input-A", publisher="editor",
        invocation_path=route_path(service.test_project, "main"), authorize=lambda: None)
    service.commit_timeline(service.test_project, "main", request(service), idempotency_key="input-B", publisher="editor",
        invocation_path=route_path(service.test_project, "main"), authorize=lambda: None)
    service.update_document(service.test_project, resource["document_id"], {
        "expected_version": 1, "content": {"schema": "pack.config/v1", "value": "v2"},
    }, idempotency_key="config-v2")
    source = first["data"]["canonical_document"]
    call = _restore(service, source["parent_revision"]["revision_id"], direct=True,
                    content_digest=source["parent_revision"]["content_digest"])
    if damage == "content":
        service.store.conn.execute("UPDATE timeline_document_input_contents SET content_json='{}'")
    elif damage == "binding":
        # Simulate a missing retained binding despite its link foreign key.
        service.store.conn.execute("PRAGMA foreign_keys=OFF")
        service.store.conn.execute("DELETE FROM timeline_document_input_bindings")
        service.store.conn.execute("PRAGMA foreign_keys=ON")
    elif damage == "link":
        service.store.conn.execute("DELETE FROM timeline_document_input_links WHERE revision_id=?", (source["parent_revision"]["revision_id"],))
    before = rows(service)
    calls = provider.calls
    if damage:
        with pytest.raises(RuntimeErrorBase):
            call()
        assert provider.calls == calls and rows(service) == before
    else:
        result = call()
        assert result["data"]["canonical_document"] == source
        assert captured[-1] == {"pin": pin, "document": resource}
        assert result["data"]["canonical_document"]["dependency_manifest"]["documents"] == [pin]
        current = service.get_document(service.test_project, resource["document_id"])
        assert current["version"] == 2 and current["content"]["value"] == "v2"
