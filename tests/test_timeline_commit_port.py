"""Exercise the service adapter with prepared providers and real persistence."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from precut_realm_fixture import load_precut_realm_fixture
from test_timeline_commit_baseline import _disable_renderer

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_baseline import verify_baseline
from runtime_protocol.timeline_commit_port import digest, route_path
from runtime_protocol.util import canonical_json


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    runtime.test_provider = PreparedProvider()
    runtime.register_timeline_commit_provider(runtime.test_provider)
    project = runtime.create_project({"slug": "commit-port", "name": "Commit port"})["id"]
    runtime.test_created = runtime.create_timeline(project, "main", idempotency_key="create-main")
    runtime.test_project = project
    try:
        yield runtime
    finally:
        runtime.close()


def request(service, **changes):
    head = service.get_project_timeline(service.test_project, "main")
    return {"api_version": 1, "project_id": service.test_project, "timeline_id": "main",
            "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
            "commands": [{"schema_version": 1, "op": "clip.move", "version": "1",
                          "select": "parent/clip:clip-1", "args": {"on": 2}}], **changes}


def commit(service, body, *, key="edit-1", publisher="editor", authorize=lambda: None):
    return service.commit_timeline(service.test_project, "main", body, idempotency_key=key,
                                   publisher=publisher, invocation_path=route_path(service.test_project, "main"),
                                   authorize=authorize)


def _v2_request(request):
    return any(key in request for key in ("label", "steps", "merge", "reads")) or any(
        command.get("op") == "doc.patch" for command in request.get("commands", [])
    )


def _effective_merge_mode(request):
    if request.get("merge") == "atomic":
        return "atomic"
    if "reads" not in request and any(command.get("op") == "doc.patch"
                                      for command in request.get("commands", [])):
        return "atomic"
    return request.get("merge", "fields")


def _state(value, present):
    return {"state": "present", "value": copy.deepcopy(value)} if present else {"state": "absent"}


def _step_patches(source, document):
    patches = []
    source_parent = source["parent_revision"]["payload"]
    candidate_parent = document["parent_revision"]["payload"]
    for key in sorted(set(source_parent) | set(candidate_parent)):
        before_present, after_present = key in source_parent, key in candidate_parent
        before, after = source_parent.get(key), candidate_parent.get(key)
        if before_present == after_present and before == after:
            continue
        change = {"op": "set" if after_present else "remove", "ref": "parent", "path": [key],
                  "before": _state(before, before_present)}
        if after_present:
            change["value"] = copy.deepcopy(after)
        patches.append(change)

    def images(value):
        return {**{
            "shot-revision:" + row["revision_id"]: row for row in value["shot_revisions"]}, **{
            "internal-revision:" + row["revision_id"]: row
            for row in value["internal_timeline_revisions"]}}

    source_images, candidate_images = images(source), images(document)
    for ref in sorted(set(source_images) | set(candidate_images)):
        before_image, after_image = source_images.get(ref), candidate_images.get(ref)
        before_present, after_present = before_image is not None, after_image is not None
        before_payload = before_image.get("payload") if before_image else None
        after_payload = after_image.get("payload") if after_image else None
        if before_present == after_present and before_payload == after_payload:
            continue
        change = {"op": "set" if after_present else "remove", "ref": ref, "path": [],
                  "before": _state(before_payload, before_present)}
        if after_present:
            change["value"] = copy.deepcopy(after_payload)
        patches.append(change)
    return patches


def _validate_prepared_request(request):
    # Legacy callers specialize the candidate's command records themselves.
    if not _v2_request(request):
        return
    if len(request.get("commands", [])) != 1:
        raise ValueError("PreparedProvider fixture supports one command only")
    if "steps" in request:
        steps = request["steps"]
        if not isinstance(steps, list) or len(steps) != 1:
            raise ValueError("PreparedProvider fixture supports one v2 step only")
        if steps[0].get("command_ordinals") != [0]:
            raise ValueError("PreparedProvider fixture requires sole-step command_ordinals [0]")


def _complete_v2_metadata(context, port, document, expected_head, records):
    request = context["request"]
    _validate_prepared_request(request)
    if not _v2_request(request):
        return
    source = port.revision_closure(expected_head["revision_id"])
    patches = _step_patches(source, document)
    requested_steps = request.get("steps")
    if requested_steps:
        steps = [copy.deepcopy(step) for step in requested_steps]
        # This fixture has one provider execution boundary; retain the requested
        # step identity while attaching its complete authenticated effects.
        steps[0]["patch"] = patches
    else:
        steps = [{"id": "edit", "label": request.get("label", "Timeline edit"),
                  "intent": request["commands"][0]["op"], "tags": [],
                  "command_ordinals": list(range(len(request["commands"]))), "patch": patches}]
    inherited = copy.deepcopy(request.get("reads", []))
    if _effective_merge_mode(request) == "atomic":
        inherited.append({"kind": "scope", "ref": "parent", "path": []})
    for step in steps:
        dependencies = copy.deepcopy(inherited)
        dependencies.extend(copy.deepcopy(step.get("reads", [])))
        unique = []
        for dependency in dependencies:
            if dependency not in unique:
                unique.append(dependency)
        step["dependencies"] = unique
    records.update(label=request.get("label", "Timeline edit"),
                   merge_mode=_effective_merge_mode(request), steps=steps)


def prepared(context, port, *, same=False):
    _validate_prepared_request(context["request"])
    head = port.head()
    document = port.revision_closure(head["revision_id"])
    source = None
    command = context["request"]["commands"][0]
    if command["op"] == "timeline.restore":
        source = copy.deepcopy(command["args"])
        document = port.revision_closure(source["revision_id"])
    elif not same:
        document["parent_revision"]["revision_id"] = "candidate-" + context["idempotency_key"]
        document["parent_revision"]["payload"]["fixture_label"] = context["idempotency_key"]
        document["parent_revision"]["payload"]["config"].setdefault("clips", [])
        document["parent_revision"]["payload"]["config"].setdefault("tracks", [])
        document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
    records = {"schema_version": 1, "commands": [{"ordinal": 0, "command": copy.deepcopy(command),
                "writes": [{"ref": "parent", "path": ["fixture_label"],
                            "before": {"state": "absent"},
                            "after": {"state": "present", "value": context["idempotency_key"]}}],
                "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [],
                "derived_writes": []}], "undo_of": [], "restored_from": source}
    candidate = {"expected_head": head, "canonical_document": document, "document_digest": digest(document),
                 "records": records, "id_map": {}, "semantic_events": [],
                 "provider_version": "prepared-fixture-1", "compiler_version": "fixture-1"}
    _complete_v2_metadata(context, port, document, head, records)
    return candidate


class PreparedProvider:
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def __init__(self, action=None):
        self.action = action
        self.calls = 0
        self.contexts = []
        self.ports = []

    def commit(self, context, port):
        self.calls += 1
        self.contexts.append(copy.deepcopy(context))
        self.ports.append(port)
        if self.action:
            return self.action(context, port)
        candidate = prepared(context, port)
        return port.preview(candidate) if context["request"].get("dry_run", False) else port.accept(candidate)


def use_provider(service, provider):
    service.test_provider.__dict__.update(provider.__dict__)
    return service.test_provider


def rows(service):
    return {table: [tuple(row) for row in service.store.conn.execute(f"SELECT * FROM {table}")]
            for table in ("parent_composition_heads", "parent_composition_revisions", "timeline_commit_history",
                          "command_idempotency", "timeline_events", "project_sequences",
                          "timeline_document_input_contents", "timeline_document_input_bindings", "timeline_document_input_links")}


def test_create_has_real_atomic_empty_bootstrap(service):
    head = service.get_project_timeline(service.test_project, "main")
    history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    entry = history["items"][0]
    assert history["head"] == {"revision_id": head["head_revision_id"], "publication_id": head["head_publication_id"]}
    assert entry["publication_id"] == entry["receipt"]["receipt_id"]
    assert entry["receipt"]["command_kind"] == "parent_composition.publish"
    assert entry["intent"] == "bootstrap" and entry["records"] is None and entry["previous"] is None


def test_created_timeline_provenance_and_exact_retry_survive_restart(service):
    created = service.test_created
    project, root = service.test_project, service.store.root
    before = rows(service)
    facts = verify_baseline(service.store.conn, project, "main", read_object=service.cas.read)
    assert rows(service) == before
    head = facts["head"]
    assert created["data"]["head_revision_id"] == head["revision_id"]
    assert created["data"]["head_publication_id"] == head["publication_id"]
    assert created["receipt"]["result"] == created["data"]
    receipts = service.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE primary_stream_id=? ORDER BY resulting_stream_seq", ("main",)
    ).fetchall()
    events = service.store.conn.execute("SELECT * FROM timeline_events WHERE timeline_id=? ORDER BY id", ("main",)).fetchall()
    assert [row["command_kind"] for row in receipts] == ["timeline.create", "parent_composition.publish"]
    assert [row["kind"] for row in events] == ["timeline.created", "parent.composition.published"]
    assert [row["resulting_stream_seq"] for row in receipts] == [1, 2]
    assert [row["first_project_seq"] for row in receipts] == sorted({row["first_project_seq"] for row in receipts})
    for row, event in zip(receipts, events):
        assert json.loads(row["event_ids_json"]) == [str(event["id"])]
        assert row["first_project_seq"] == row["last_project_seq"]
    assert receipts[0]["txn_id"] == created["receipt"]["receipt_id"]
    assert receipts[1]["txn_id"] == head["publication_id"]
    assert len(facts["entries"]) == 1
    assert facts["entries"][0]["publication_id"] == head["publication_id"]
    assert facts["entries"][0]["receipt"]["event_ids"] == [str(events[1]["id"])]
    original = canonical_json(created).encode()
    assert canonical_json(service.create_timeline(project, "main", idempotency_key="create-main")).encode() == original
    service.close()
    restarted = RuntimeService(root)
    try:
        assert restarted.store.admission_report["ok"]
        restarted.register_timeline_commit_provider(PreparedProvider())
        before = rows(restarted)
        assert verify_baseline(restarted.store.conn, project, "main", read_object=restarted.cas.read) == facts
        assert canonical_json(restarted.create_timeline(project, "main", idempotency_key="create-main")).encode() == original
        assert rows(restarted) == before
        restarted.test_project = project
        commit(restarted, request(restarted))
        assert restarted.get_project_timeline(project, "main")["head_publication_id"] != head["publication_id"]
        before = rows(restarted)
        assert canonical_json(restarted.create_timeline(project, "main", idempotency_key="create-main")).encode() == original
        assert rows(restarted) == before
    finally:
        restarted.close()


def test_bootstrap_failure_rolls_back_creation_and_both_receipts(service, monkeypatch):
    commits, _ = service._timeline_commits()
    install = commits._install_entries
    def fail_after_install(project, timeline, plan):
        install(project, timeline, plan)
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM command_idempotency WHERE primary_stream_id=?", (timeline,)
        ).fetchone()[0] == 2
        raise RuntimeError("bootstrap installation failed")
    before = list(service.store.conn.iterdump())
    with monkeypatch.context() as patch:
        patch.setattr(commits, "_install_entries", fail_after_install)
        with pytest.raises(RuntimeError, match="bootstrap installation failed"):
            service.create_timeline(service.test_project, "failed", idempotency_key="failed-create")
    assert list(service.store.conn.iterdump()) == before
    created = service.create_timeline(service.test_project, "failed", idempotency_key="failed-create")
    facts = verify_baseline(service.store.conn, service.test_project, "failed", read_object=service.cas.read)
    assert created["data"]["head_publication_id"] == facts["head"]["publication_id"]


def test_history_remains_read_only_when_mutation_admission_revoked(service):
    before = list(service.store.conn.iterdump())
    service._verified = False
    history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    assert history["head"]["publication_id"] == service.test_created["data"]["head_publication_id"]
    assert list(service.store.conn.iterdump()) == before


@pytest.mark.parametrize("key", [None, "atomic-create"])
def test_editable_create_has_one_outer_commit(service, key):
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    try:
        created = service.create_timeline(service.test_project, "atomic", idempotency_key=key)
    finally:
        service.store.conn.set_trace_callback(None)
    assert sum(sql == "BEGIN IMMEDIATE" for sql in statements) == 1
    assert sum(sql == "COMMIT" for sql in statements) == 1
    resource = created if key is None else created["data"]
    facts = verify_baseline(service.store.conn, service.test_project, "atomic", read_object=service.cas.read)
    assert resource["head_revision_id"] == facts["head"]["revision_id"]
    assert resource["head_publication_id"] == facts["head"]["publication_id"]


def test_revoked_admission_prevents_startup_baseline_migration_and_history_writes(tmp_path, monkeypatch, request):
    # DESIGN rev 3 §8 (migration): retain this pre-activation U33 state on its owning binary.
    from runtime_protocol.store import SCHEMA_VERSION
    if SCHEMA_VERSION == 34:
        from custody_schema_fixtures import historical_case
        return historical_case(request.getfixturevalue('tmp_path'), request.node.nodeid, record_property=lambda name, value: request.node.user_properties.append((name, value)))
    captured = load_precut_realm_fixture(tmp_path)
    runtime = RuntimeService(captured.copy_roots[0])
    try:
        project, timeline = captured.pins["project_id"], captured.pins["timeline_id"]
        _disable_renderer(monkeypatch, runtime)
        assert runtime.get_project_timeline(project, timeline)["head_publication_id"] is None
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
        runtime._verified = False
        before = list(runtime.store.conn.iterdump())
        with pytest.raises(RuntimeErrorBase):
            runtime.list_timeline_commits(project, timeline, authorize=lambda: None)
        assert list(runtime.store.conn.iterdump()) == before
        runtime.register_timeline_commit_provider(PreparedProvider())
        assert list(runtime.store.conn.iterdump()) == before
        with pytest.raises(RuntimeErrorBase):
            runtime.list_timeline_commits(project, timeline, authorize=lambda: None)
        assert list(runtime.store.conn.iterdump()) == before
    finally:
        runtime.close()


def test_neutral_runtime_refuses_without_writes(tmp_path):
    root = tmp_path / "neutral"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        service.test_project = service.create_project({"slug": "neutral", "name": "Neutral"})["id"]
        service.create_timeline(service.test_project, "main", idempotency_key="neutral-main")
        before = rows(service)
        body = request(service, base_revision_id="unverified", base_publication_id="unverified")
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, body)
        assert (error.value.status, error.value.code, error.value.details["reason"]) == (503, "not_ready", "runtime_unavailable")
        assert rows(service) == before
    finally:
        service.close()


def test_provider_runs_without_store_mutex_and_port_closes(service):
    def action(context, port):
        assert not service.store._mutex._is_owned()
        return port.accept(prepared(context, port))
    provider = PreparedProvider(action)
    provider = use_provider(service, provider)
    result = commit(service, request(service))
    assert result["data"]["status"] == "accepted"
    assert result["receipt"]["result"] == result["data"]
    with pytest.raises(AuthorizationError):
        provider.ports[0].head()
    with pytest.raises(ValidationError):
        service.register_timeline_commit_provider(PreparedProvider())


def test_original_body_hash_does_not_insert_defaults(service):
    provider = PreparedProvider()
    provider = use_provider(service, provider)
    body = request(service)
    original = copy.deepcopy(body)
    result = commit(service, body)
    expected = hashlib.sha256(canonical_json({"operation": "commitTimeline", "path": route_path(service.test_project, "main"),
                                              "publisher": "editor", "request": original}).encode()).hexdigest()
    assert result["receipt"]["request_hash"] == expected
    assert body == original
    assert provider.contexts[0]["invocation"]["body"] == original
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, {**original, "dry_run": False})
    assert error.value.details["reason"] == "idempotency_mismatch"
    assert provider.calls == 1


def test_exact_retry_rechecks_authority_without_provider(service):
    provider = PreparedProvider()
    provider = use_provider(service, provider)
    body = request(service)
    accepted = commit(service, body)
    def revoked():
        raise AuthorizationError("credential revoked")
    with pytest.raises(AuthorizationError):
        commit(service, body, authorize=revoked)
    assert provider.calls == 1
    assert commit(service, body) == accepted
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, body, publisher="different-actor")
    assert error.value.details["reason"] == "idempotency_mismatch"


def test_authority_revoked_during_provider_rolls_back(service):
    admitted = True
    def authorize():
        if not admitted:
            raise AuthorizationError("credential revoked")
    def action(context, port):
        nonlocal admitted
        candidate = prepared(context, port)
        admitted = False
        return port.accept(candidate)
    use_provider(service, PreparedProvider(action))
    before = rows(service)
    with pytest.raises(AuthorizationError):
        commit(service, request(service), authorize=authorize)
    assert rows(service) == before


def test_preview_has_no_writes_or_key_reservation(service):
    provider = PreparedProvider()
    provider = use_provider(service, provider)
    before = rows(service)
    body = request(service, dry_run=True)
    preview = commit(service, body)
    assert preview["receipt"] is None and preview["data"]["status"] == "preview"
    assert rows(service) == before
    real = commit(service, {**body, "dry_run": False})
    assert real["receipt"]["command_kind"] == "timeline.commit"


def test_provider_cannot_forge_preview(service):
    def action(context, port):
        preview = port.preview(prepared(context, port))
        preview["data"]["commands"] = []
        return preview
    use_provider(service, PreparedProvider(action))
    before = rows(service)
    with pytest.raises((ValidationError, RuntimeErrorBase)):
        commit(service, request(service, dry_run=True))
    assert rows(service) == before


def test_same_revision_still_accepts_recorded_write_edge(service):
    use_provider(service, PreparedProvider(lambda ctx, port: port.accept(prepared(ctx, port, same=True))))
    body = request(service)
    first = commit(service, body)
    second = commit(service, request(service), key="edit-2")
    assert first["data"]["accepted_revision_id"] == second["data"]["accepted_revision_id"] == body["base_revision_id"]
    assert first["receipt"]["receipt_id"] != second["receipt"]["receipt_id"]
    history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    assert len(history["items"]) == 3
    assert history["items"][-1]["records"]["commands"][0]["writes"]


def test_opaque_foreign_looking_json_is_preserved(service):
    provider = PreparedProvider()
    provider = use_provider(service, provider)
    body = request(service)
    body["commands"][0]["op"] = "fixture.inspect"
    body["commands"][0]["args"]["extension"] = {"project_id": "opaque-other-project", "source": {"url": "opaque://example"}}
    accepted = commit(service, body)
    assert accepted["data"]["commands"][0]["args"] == body["commands"][0]["args"]


def test_foreign_revision_and_undeclared_shot_pins_refuse(service):
    foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
    service.create_timeline(foreign, "other", idempotency_key="other")
    foreign_revision = service.get_project_timeline(foreign, "other")["head_revision_id"]
    def action(context, port):
        port.head()
        with pytest.raises(CommitRejected):
            port.shot_closure("undeclared", "revision")
        port.revision_closure(foreign_revision)
    use_provider(service, PreparedProvider(action))
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, request(service))
    assert error.value.details["reason"] == "history_unavailable"
    assert rows(service) == before


def test_canonical_project_and_path_body_identity(service):
    body = request(service)
    with pytest.raises(ValidationError):
        service.commit_timeline(service.test_project, "main", {**body, "timeline_id": "elsewhere"},
                                idempotency_key="bad", publisher="editor", invocation_path=route_path(service.test_project, "main"),
                                authorize=lambda: None)
    with pytest.raises(AuthorizationError):
        service.commit_timeline("commit-port", "main", {**body, "project_id": "commit-port"},
                                idempotency_key="bad", publisher="editor", invocation_path=route_path("commit-port", "main"),
                                authorize=lambda: None)


def test_restore_maps_only_after_lookup_preserving_original_invocation(service):
    provider = PreparedProvider()
    provider = use_provider(service, provider)
    original = request(service)
    source = original["base_revision_id"]
    commit(service, original)
    current = service.get_project_timeline(service.test_project, "main")
    body = {"expected_head": current["head_revision_id"], "expected_publication_id": current["head_publication_id"]}
    path = route_path(service.test_project, "main", f"composition-revisions/{source}/restore")
    result = service.restore_project_parent_composition_revision(service.test_project, "main", source, body,
        idempotency_key="restore-1", publisher="editor", invocation_path=path, authorize=lambda: None)
    context = provider.contexts[-1]
    command = context["request"]["commands"]
    assert len(command) == 1 and command[0]["op"] == "timeline.restore" and command[0]["version"] == "1"
    assert set(command[0]["args"]) == {"revision_id", "content_digest"}
    assert context["invocation"] == {"operation": "restoreProjectParentCompositionRevision", "path": path, "body": body}
    expected = hashlib.sha256(canonical_json({"operation": context["invocation"]["operation"], "path": path,
                                             "publisher": "editor", "request": body}).encode()).hexdigest()
    assert result["receipt"]["request_hash"] == expected
    assert result["data"]["status"] == "accepted" and result["data"]["rebased_onto"] is None
    assert service.restore_project_parent_composition_revision(service.test_project, "main", source, body,
        idempotency_key="restore-1", publisher="editor", invocation_path=path, authorize=lambda: None) == result
    assert provider.calls == 2


def test_restore_does_not_rebase_on_same_revision_new_publication(service):
    provider = PreparedProvider(lambda ctx, port: port.accept(prepared(ctx, port, same=True)))
    provider = use_provider(service, provider)
    body = request(service)
    commit(service, body)
    restore_body = {"expected_head": body["base_revision_id"], "expected_publication_id": body["base_publication_id"]}
    with pytest.raises(RuntimeErrorBase) as error:
        service.restore_project_parent_composition_revision(service.test_project, "main", body["base_revision_id"], restore_body,
            idempotency_key="stale-restore", publisher="editor",
            invocation_path=route_path(service.test_project, "main", f"composition-revisions/{body['base_revision_id']}/restore"),
            authorize=lambda: None)
    assert error.value.details["reason"] == "stale_head"


def test_commit_receipt_replay_outlives_generic_window(service):
    use_provider(service, PreparedProvider())
    body = request(service)
    accepted = commit(service, body)
    row = service.store.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (accepted["receipt"]["receipt_id"],)).fetchone()
    old = dict(row)
    old["created_at"] = "2000-01-01T00:00:00.000Z"
    assert service._receipt_payload(old, project_id=service.test_project)["result"] == accepted["data"]
    service.store.conn.execute("UPDATE command_idempotency SET created_at=? WHERE txn_id=?", (old["created_at"], row["txn_id"]))
    found, replay = service._command_replay_state("timeline.commit", canonical_json([service.test_project, "main"]),
        "edit-1", row["request_hash"], project_id=service.test_project)
    assert found and replay["data"] == accepted["data"]


def test_history_pagination_keeps_original_head(service):
    use_provider(service, PreparedProvider())
    commit(service, request(service))
    first = service.list_timeline_commits(service.test_project, "main", limit=1, authorize=lambda: None)
    commit(service, request(service), key="edit-2")
    second = service.list_timeline_commits(service.test_project, "main", cursor=first["next_cursor"], limit=1, authorize=lambda: None)
    assert second["head"] == first["head"]
    assert second["next_cursor"] is None
    assert second["items"][0]["publication_id"] == first["head"]["publication_id"]


def test_retained_config_is_exact_after_live_kind_and_content_update(service):
    document = service.create_document(service.test_project, {
        "document_id": "pack-settings", "kind": "pack.config", "content": {"schema": "pack.config/v1", "fps": 24},
    }, idempotency_key="settings-v1")["data"]
    pin = {"document_id": document["document_id"], "version": document["version"], "content_digest": digest(document["content"])}
    seen = []
    def action(context, port):
        head = port.head()
        port.revision_closure(head["revision_id"])
        value = port.config_source(pin)
        seen.append(value)
        candidate = prepared(context, port)
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [pin]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "config:pack-settings", "kind": "source", "pin": pin, "policy": "exact"},
        ]
        return port.accept(candidate)
    provider = use_provider(service, PreparedProvider(action))
    body = request(service)
    body["commands"][0]["op"] = "fixture.inspect"
    body["commands"][0]["args"]["config"] = pin
    accepted = commit(service, body)
    service.update_document(service.test_project, document["document_id"], {
        "expected_version": document["version"], "kind": "other.config",
        "content": {"schema": "other.config/v2", "fps": 60},
    }, idempotency_key="settings-v2")
    assert commit(service, body) == accepted
    assert provider.calls == 1
    second = request(service)
    second["commands"][0]["op"] = "fixture.inspect"
    second["commands"][0]["args"]["config"] = pin
    commit(service, second, key="use-retained-config")
    assert seen == [{"pin": pin, "document": document}, {"pin": pin, "document": document}]
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_contents").fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_links").fetchone()[0] == 2


def test_first_use_config_capture_race_does_not_accept(service):
    document = service.create_document(service.test_project, {
        "document_id": "racing-config", "kind": "pack.config", "content": {"fps": 24},
    }, idempotency_key="config-before")["data"]
    pin = {"document_id": document["document_id"], "version": document["version"], "content_digest": digest(document["content"])}
    def action(context, port):
        port.config_source(pin)
        candidate = prepared(context, port)
        candidate["canonical_document"]["dependency_manifest"]["documents"] = [pin]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "config:racing-config", "kind": "source", "pin": pin, "policy": "exact"},
        ]
        service.update_document(service.test_project, document["document_id"], {
            "expected_version": 1, "content": {"fps": 60},
        }, idempotency_key="config-racer")
        return port.accept(candidate)
    use_provider(service, PreparedProvider(action))
    body = request(service)
    body["commands"][0]["op"] = "fixture.inspect"
    body["commands"][0]["args"]["config"] = pin
    with pytest.raises(RuntimeErrorBase):
        commit(service, body)
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history WHERE intent='recorded'").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_contents").fetchone()[0] == 0


@pytest.mark.parametrize("kind", ["source", "transcript", "media"])
@pytest.mark.parametrize("damage", [None, "uncaptured", "missing", "foreign", "version", "digest", "owner",
                                    "manifest", "kind"])
def test_recorded_input_requires_exact_capture_and_manifest_before_writes(service, kind, damage):
    project = service.test_project
    foreign = service.create_project({"slug": "input-foreign", "name": "Input foreign"})["id"]
    media = service.ingest(project, b"authority media", media_type="video/mp4", idempotency_key="input-media")["data"]
    if kind == "media":
        pin = {"media_id": media["object_id"], "content_digest": media["object_id"]}
        foreign_id = service.ingest(foreign, b"foreign media", media_type="video/mp4", idempotency_key="foreign-media")["data"]["object_id"]
        foreign_pin = {"media_id": foreign_id, "content_digest": foreign_id}
    else:
        document_kind = "media.transcript" if kind == "transcript" else "pack.config"
        content = ({"schema": "media.transcript/v1", "media_id": media["object_id"], "source_id": "default", "segments": []}
                   if kind == "transcript" else {"schema": "pack.config/v1", "fps": 24})
        document_id = (RuntimeService._transcript_document_id(project, media["object_id"], "default")
                       if kind == "transcript" else "input-config")
        source = service.create_document(project, {"document_id": document_id, "kind": document_kind,
                                                  "content": content}, idempotency_key="input-document")["data"]
        other = service.create_document(foreign, {"document_id": "foreign-config", "kind": "pack.config",
                                                  "content": {"fps": 25}}, idempotency_key="foreign-document")["data"]
        pin = {"document_id": source["document_id"], "version": source["version"], "content_digest": digest(content)}
        foreign_pin = {"document_id": other["document_id"], "version": other["version"], "content_digest": digest(other["content"])}

    def action(context, port):
        candidate = prepared(context, port)
        if damage not in {"uncaptured", "missing", "foreign"}:
            read = port.raw_media_info if kind == "media" else port.transcript_source if kind == "transcript" else port.config_source
            read(pin)
        recorded = copy.deepcopy(pin)
        if damage == "foreign":
            recorded = foreign_pin
        elif damage == "missing":
            recorded = ({"media_id": "sha256:" + "1" * 64, "content_digest": "sha256:" + "1" * 64}
                        if kind == "media" else {"document_id": "foreign-document", "version": 1,
                                                 "content_digest": "sha256:" + "1" * 64})
        elif damage == "version":
            recorded["version"] = 2
        elif damage == "digest":
            recorded["content_digest"] = "sha256:" + "1" * 64
        elif damage == "owner":
            recorded["project_id"] = foreign
        family = "media" if kind == "media" else "documents"
        if damage != "manifest":
            candidate["canonical_document"]["dependency_manifest"][family] = [pin]
        recorded_kind = ("source" if kind == "transcript" else "transcript") if damage == "kind" else kind
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "input.authority", "kind": recorded_kind, "policy": "exact", "pin": recorded}]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        return port.accept(candidate)

    use_provider(service, PreparedProvider(action))
    submitted = request(service)
    submitted["commands"][0].update(op="fixture.inspect", args={"pin": pin})
    before = tuple(service.store.conn.iterdump())
    history = service.list_timeline_commits(project, "main", authorize=lambda: None)
    head = service.get_project_timeline(project, "main")
    if damage is None:
        accepted = commit(service, submitted)
        assert accepted["data"] is not None
        assert accepted["data"]["status"] == "accepted"
        assert accepted["data"]["canonical_document"]["dependency_manifest"]["media" if kind == "media" else "documents"] == [pin]
        assert commit(service, submitted) == accepted
    else:
        with pytest.raises(RuntimeErrorBase):
            commit(service, submitted)
        assert tuple(service.store.conn.iterdump()) == before
        assert service.list_timeline_commits(project, "main", authorize=lambda: None) == history
        assert service.get_project_timeline(project, "main") == head


def test_tracked_legacy_publication_rejected_before_writes(service):
    body = request(service)
    publication = {"project_id": service.test_project, "timeline_id": "main", "expected_head": body["base_revision_id"],
                   "parent_revision_id": "legacy-replacement", "parent_composition": {"config": {}, "registry": {}, "clips": [], "occurrences": []}}
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        service.publish_parent_composition(service.test_project, "main", publication, idempotency_key="legacy")
    assert error.value.details["reason"] == "timeline_commit_required"
    assert rows(service) == before


@pytest.mark.parametrize("overrides", [{"unknown": 1}, {"dry_run": None}, {"source": None}, {"commands": []}, {"api_version": True}])
def test_request_validation_uses_frozen_schema(service, overrides):
    before = rows(service)
    with pytest.raises(ValidationError):
        commit(service, request(service, **overrides))
    assert rows(service) == before


def test_nonfinite_json_refuses_before_provider(service):
    body = request(service)
    body["commands"][0]["args"]["on"] = float("inf")
    before = rows(service)
    with pytest.raises(ValidationError):
        commit(service, body)
    assert service.test_provider.calls == 0 and rows(service) == before


def test_media_selection_uses_main_settlement_identity_and_rechecks_lifecycle(tmp_path):
    from test_generation_publish_v1_settlement import _effect, _fixture, _output, _settle
    def effect_factory(project_id):
        effect = _effect(project_id, groups=[{"group_key": "main", "selectors": [
            {"selector": "first", "ordinal": 0, "variant_key": "first", "output_port": "video"},
        ]}])
        effect["payload"]["metadata"] = {"params": {"duration_seconds": 2.0}}
        return effect
    service, project, task, attempt, effect = _fixture(tmp_path, effect_factory=effect_factory, slug="selection")
    try:
        _settle(service, attempt, [_output(b"video", output_port="video", group_key="main", variant_key="first",
            ordinal=0, filename="clip.mp4", media_type="video/mp4")], effect=effect)
        association = service.managed_outputs(task["task"]["id"])[0]
        selectors = {"association_id": association["association_id"], "object_id": association["object_id"], "version": 1}
        selection = service.get_project_media_selection(project["id"], selectors, authorize=lambda: None)
        legacy_selectors = {key: selection[key] for key in ("asset", "generation_id", "variant_id")}
        assert service.get_project_media_selection(project["id"], legacy_selectors, authorize=lambda: None) == selection
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
        with pytest.raises(RuntimeErrorBase):
            service.get_project_media_selection(foreign, legacy_selectors, authorize=lambda: None)
        service.test_project = project["id"]
        def action(context, port):
            media = port.selected_media(selection)
            assert media["selection"] == selection and media["duration_seconds"] == 2.0
            candidate = prepared(context, port)
            candidate["canonical_document"]["dependency_manifest"]["media"] = [
                {"media_id": selection["object_id"], "content_digest": selection["object_id"]},
            ]
            candidate["records"]["commands"][0]["dependencies"] = [
                {"key": "media:clip", "kind": "media", "pin": selection, "policy": "exact"},
            ]
            candidate["document_digest"] = digest(candidate["canonical_document"])
            return port.accept(candidate)
        provider = PreparedProvider(action)
        service.register_timeline_commit_provider(provider)
        service.create_timeline(project["id"], "main", idempotency_key="create-main")
        body = request(service)
        body["commands"][0]["op"] = "fixture.inspect"
        body["commands"][0]["args"]["selection"] = selection
        accepted = commit(service, body)
        service.update_managed_output_lifecycle(association["association_id"], {
            "operation": "pin", "expected_version": 1,
        }, idempotency_key="pin-after-accept")
        assert commit(service, body) == accepted and provider.calls == 1
        with pytest.raises(RuntimeErrorBase):
            commit(service, body, key="stale-catalog")
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history WHERE intent='recorded'").fetchone()[0] == 1
    finally:
        service.close()


def test_exact_commit_replay_after_restart_needs_no_provider(service):
    body = request(service)
    accepted = commit(service, body)
    project_id, root = service.test_project, service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project_id
        assert commit(restarted, body) == accepted
        assert restarted._timeline_commit_provider is None
    finally:
        restarted.close()


@pytest.mark.parametrize("corrupt", [False, True])
def test_existing_head_installs_only_verified_original_baseline_before_requests(tmp_path, monkeypatch, corrupt, request):
    # DESIGN rev 3 §8 (migration): retain this pre-activation U33 state on its owning binary.
    from runtime_protocol.store import SCHEMA_VERSION
    if SCHEMA_VERSION == 34:
        from custody_schema_fixtures import historical_case
        return historical_case(request.getfixturevalue('tmp_path'), request.node.nodeid, record_property=lambda name, value: request.node.user_properties.append((name, value)))
    captured = load_precut_realm_fixture(tmp_path)
    service = RuntimeService(captured.copy_roots[0])
    try:
        project, timeline = captured.pins["project_id"], captured.pins["timeline_id"]
        _disable_renderer(monkeypatch, service)
        assert service.get_project_timeline(project, timeline)["head_publication_id"] is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
        facts = verify_baseline(service.store.conn, project, timeline, read_object=service.cas.read)
        assert len(facts["entries"]) == 1
        receipt = facts["entries"][0]["receipt"]
        if corrupt:
            service.store.conn.execute("DELETE FROM command_idempotency WHERE txn_id=?", (receipt["receipt_id"],))
        provider = PreparedProvider()
        service.register_timeline_commit_provider(provider)
        before = rows(service)
        body = {"api_version": 1, "project_id": project, "timeline_id": timeline,
                "base_revision_id": captured.pins["parent_revision_id"],
                "base_publication_id": receipt["receipt_id"], "dry_run": True,
                "commands": [{"schema_version": 1, "op": "clip.move", "version": "1",
                              "select": "parent/clip:clip-1", "args": {"on": 2}}]}
        if corrupt:
            with pytest.raises(RuntimeErrorBase):
                service.commit_timeline(project, timeline, body, idempotency_key="edit-1", publisher="editor",
                                        invocation_path=route_path(project, timeline), authorize=lambda: None)
            assert provider.calls == 0
        else:
            history = service.list_timeline_commits(project, timeline, authorize=lambda: None)
            assert history["items"][0]["publication_id"] == receipt["receipt_id"]
            assert history["items"][0]["receipt"] == receipt
            assert history["items"][0]["intent"] == "legacy_unknown"
            assert service.commit_timeline(project, timeline, body, idempotency_key="edit-1", publisher="editor",
                                           invocation_path=route_path(project, timeline),
                                           authorize=lambda: None)["data"]["status"] == "preview"
        assert rows(service) == before
    finally:
        service.close()


@pytest.mark.parametrize("shape", [
    {"commands": []},
    {"commands": [{"op": "first"}, {"op": "second"}]},
    {"label": "Implicit", "commands": [{"op": "first"}, {"op": "second"}]},
    {"commands": [{"op": "first"}, {"op": "second"}],
     "steps": [{"command_ordinals": [0, 1]}]},
    {"commands": [{"op": "first"}, {"op": "second"}],
     "steps": [{"command_ordinals": [0]}, {"command_ordinals": [1]}]},
    {"steps": [{"command_ordinals": [0]}, {"command_ordinals": [1]}]},
    {"steps": []},
    {"steps": None},
    {"steps": [{}]},
    {"steps": [{"command_ordinals": []}]},
    {"steps": [{"command_ordinals": [1]}]},
    {"steps": [{"command_ordinals": [0, 1]}]},
    {"steps": [{"command_ordinals": [0, 0]}]},
])
@pytest.mark.parametrize("entry", ["prepared", "metadata"])
def test_prepared_fixture_refuses_unsupported_request_shapes(shape, entry):
    context = {"request": {"label": "Fixture", "commands": [{"op": "first"}], **copy.deepcopy(shape)}}
    document = {"parent_revision": {"payload": {}}, "shot_revisions": [],
                "internal_timeline_revisions": []}
    head = {"revision_id": "base"}
    records = {"label": "Existing", "steps": [{"patch": [{"value": "keep"}]}]}
    before = copy.deepcopy((context, document, head, records))

    class ClosurePort:
        def head(self):
            pytest.fail("unsupported request must be refused before reading head facts")

        def revision_closure(self, revision_id):
            pytest.fail("unsupported request must be refused before reading closure facts")

    with pytest.raises(ValueError, match="PreparedProvider fixture"):
        if entry == "prepared":
            prepared(context, ClosurePort())
        else:
            _complete_v2_metadata(context, ClosurePort(), document, head, records)
    assert (context, document, head, records) == before


@pytest.mark.parametrize("mutation", [None, "patch", "read"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_prepared_fixture_authenticates_sole_step_claims(service, mutation, dry_run):
    read = {"kind": "field", "ref": "parent", "path": ["fixture_label"],
            "state": {"state": "absent"}}
    change = {"op": "set", "ref": "parent", "path": ["fixture_label"],
              "before": {"state": "absent"}, "value": "edit-1"}
    step = {"id": "label", "label": "Label fixture", "intent": "Exercise claims",
            "tags": ["history", "fixture"], "command_ordinals": [0],
            "patch": [change], "reads": [read]}
    submitted = request(service, label="Fixture", steps=[copy.deepcopy(step)],
                        reads=[copy.deepcopy(read)], dry_run=dry_run)
    if mutation == "patch":
        submitted["steps"][0]["patch"][0]["value"] = "forged"
    elif mutation == "read":
        submitted["steps"][0]["reads"][0]["state"] = {"state": "present", "value": "forged"}
    original = copy.deepcopy(submitted)
    before = rows(service)
    if mutation:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
        assert rows(service) == before
    else:
        result = commit(service, submitted)
        assert result["data"]["status"] == ("preview" if dry_run else "accepted")
        accepted_step = result["data"]["steps"][0]
        for key in ("id", "label", "intent", "tags", "command_ordinals", "reads"):
            assert accepted_step[key] == step[key]
        assert change in accepted_step["patch"]
        assert accepted_step["dependencies"] == [read]
        if dry_run:
            assert result["receipt"] is None and rows(service) == before
        else:
            assert commit(service, submitted) == result
            history = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
            assert history["items"][-1]["steps"] == result["data"]["steps"]
    assert submitted == original
