from __future__ import annotations

import copy
import json
from pathlib import Path
import sqlite3
import tarfile

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from runtime_protocol import timeline_commit as abi
from runtime_protocol.errors import ProtocolError, RealmAdmissionError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected, StaleHead
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest, request_identity
from runtime_protocol.util import canonical_json
from precut_realm_fixture import load_precut_realm_fixture
from test_timeline_commit_integration import agent  # noqa: F401 (shared fixture)


def validate_prepared(prepared):
    # Consume the wire owner's actual schema; never mirror its DTOs in fixtures.
    root = Path(abi.__file__).resolve().parents[1] / "contract/schemas"
    schemas = {p.name: json.loads(p.read_text()) for p in root.glob("*.json")}
    base = "https://astrid.haus/workspace/v1/schemas/"
    registry = Registry().with_resources((base + name, Resource.from_contents(value, default_specification=DRAFT202012))
                                         for name, value in schemas.items())
    schema = {**schemas["timeline-commit.json"], "$ref": "#/$defs/PreparedCommit"}
    Draft202012Validator(schema, registry=registry).validate(prepared)


@pytest.fixture
def realm(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "acceptance", "name": "Acceptance"}, idempotency_key="project")["id"]
    service.create_timeline(project, "main", name="Main", idempotency_key="timeline")
    commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
    head = commits.bootstrap(project, "main", authorize=lambda: None)
    yield service, commits, project, head, root
    service.close()


def context(service, project, head, key="move", *, dry_run=False, op="clip.move"):
    command = {"schema_version": 1, "op": op, "version": "1", "select": "parent/clip:clip", "args": {"on": 2}}
    request = {"api_version": 1, "project_id": project, "timeline_id": "main", "base_revision_id": head["revision_id"],
               "base_publication_id": head["publication_id"], "commands": [command], "rationale": "Move clip"}
    if dry_run:
        request["dry_run"] = True
    value = {"request": request, "invocation": {"operation": "commitTimeline", "path": f"/v1/projects/{project}/timelines/main/commit", "body": copy.deepcopy(request)},
             "idempotency_key": key, "realm_id": service.realm["id"], "publisher": "author"}
    value["request_hash"] = request_identity(value)
    return value


def prepared(commits, ctx, *, expected=None, revision="parent-moved", on=2, reuse=False):
    request = ctx["request"]
    expected = expected or commits.head(request["project_id"], "main")
    document = commits.revision_closure(request["project_id"], "main", expected["revision_id"])
    if not reuse:
        parent = document["parent_revision"]
        parent["revision_id"] = revision
        parent["payload"]["config"] = {"clips": [], "tracks": []}
        parent["payload"]["clips"] = [{"id": "clip", "at": on, "hold": 1, "track": "picture", "clipType": "hold", "opaque": {"clear": None}}]
        parent["content_digest"] = digest(parent["payload"])
    command = copy.deepcopy(request["commands"][0])
    command["args"]["on"] = on
    record = {"ordinal": 0, "command": command,
              "writes": [{"ref": "parent/clip:clip", "path": ["at"], "before": {"state": "present", "value": on},
                          "after": {"state": "present", "value": on}}],
              "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [], "derived_writes": []}
    return {"expected_head": expected, "canonical_document": document, "document_digest": digest(document),
            "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
            "id_map": {"clip": "clip"}, "semantic_events": [], "provider_version": "fixture-1", "compiler_version": "fixture-1"}


def counts(service):
    result = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in
            ("parent_composition_revisions", "internal_timeline_revisions", "shot_revisions", "timeline_commit_history", "timeline_events", "command_idempotency", "project_sequences")}
    result["project_next_seq"] = service.store.conn.execute("SELECT COALESCE(SUM(next_seq), 0) FROM project_sequences").fetchone()[0]
    result["timeline_versions"] = service.store.conn.execute("SELECT COALESCE(SUM(version), 0) FROM timelines").fetchone()[0]
    return result


def accept(commits, ctx, value):
    return commits.accept(ctx, value, authorize=lambda: None)


def accepted_recorder(realm):
    from runtime_protocol.timeline_commit_inputs import (
        DocumentInputLink,
        capture_document_input,
        persist_document_input_links,
        validate_captured_document_inputs,
    )

    service, commits, project, head, _ = realm
    content = {"schema": "fixture.config/v1", "value": 1}
    service.create_document(project, {"document_id": "config", "kind": "fixture.config", "content": content}, idempotency_key="config")
    pin = {"document_id": "config", "version": 1, "content_digest": digest(content)}
    capture = capture_document_input(service.store.conn, project, pin, expected_kind="fixture.config", expected_schema=content["schema"])
    class Inputs:
        def validate(self, candidate):
            validate_captured_document_inputs(service.store.conn, [capture])
        def persist(self, candidate, publication_id, revision_id):
            persist_document_input_links(service.store.conn, project_id=project, timeline_id="main", publication_id=publication_id,
                                         revision_id=revision_id, links=[DocumentInputLink(capture, "source", 0)])
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    value["canonical_document"]["dependency_manifest"]["documents"] = [pin]
    value["document_digest"] = digest(value["canonical_document"])
    record = value["records"]["commands"][0]
    record["reads"] = [{"ref": "parent/clip:clip", "path": ["hold"], "state": {"state": "present", "value": 1}}]
    record["selections"] = [{"key": "clips", "query_version": 1, "owner": "parent", "members": ["parent/clip:clip"],
                              "order": ["parent/clip:clip"], "boundaries": ["cut:opening"], "policy": "guard-membership"}]
    record["bindings"] = [{"key": "target", "ref": "parent/clip:clip", "policy": "fixed", "dependencies": ["input"]}]
    record["created"] = [{"ref": "parent/clip:clip", "kind": "clip", "owner": "parent"}]
    record["dependencies"] = [{"key": "input", "kind": "source", "pin": pin, "policy": "exact"}]
    record["derived_writes"] = [{"ref": "parent/clip:clip", "path": ["compiled_start"], "before": {"state": "absent"},
                                 "after": {"state": "present", "value": 2}, "cause": 0}]
    value["records"]["undo_of"] = [head["publication_id"]]
    source = commits.revision_closure(project, "main", head["revision_id"])
    value["records"]["restored_from"] = {"revision_id": head["revision_id"], "content_digest": source["parent_revision"]["content_digest"]}
    result = commits.accept(ctx, value, authorize=lambda: None, inputs=Inputs())
    return ctx, value, result


RECORD_CORRUPTIONS = [
    (("commands", 0, "writes", 0, "before", "value"), 99),
    (("commands", 0, "writes", 0, "after", "value"), 99),
    (("commands", 0, "reads", 0, "state", "value"), 99),
    (("commands", 0, "selections", 0, "members", 0), "parent/clip:other"),
    (("commands", 0, "selections", 0, "order", 0), "parent/clip:other"),
    (("commands", 0, "selections", 0, "boundaries", 0), "cut:other"),
    (("commands", 0, "bindings", 0, "ref"), "parent/clip:other"),
    (("commands", 0, "created", 0, "ref"), "parent/clip:other"),
    (("commands", 0, "dependencies", 0, "pin", "version"), 99),
    (("commands", 0, "derived_writes", 0, "after", "value"), 99),
    (("undo_of", 0), "other-publication"),
    (("restored_from", "content_digest"), "sha256:" + "0" * 64),
]


def corrupt_recorder(service, value, result, path, replacement):
    changed = copy.deepcopy(value)
    leaf = changed["records"]
    for token in path[:-1]:
        leaf = leaf[token]
    leaf[path[-1]] = replacement
    validate_prepared(changed)  # Corruption still satisfies the authoritative schema.
    service.store.conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                               (canonical_json(changed["records"]), result["receipt"]["receipt_id"]))


def test_atomic_acceptance_exact_recorder_projection_and_same_content_edge(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    value["records"]["commands"][0]["command"]["rationale"] = "Recorded move"
    first = accept(commits, ctx, value)
    assert first["data"]["commands"] == [value["records"]["commands"][0]["command"]]
    assert first["data"]["commands"] != ctx["request"]["commands"]
    receipt = first["receipt"]
    assert receipt["result"] == first["data"]
    assert receipt["command_kind"] == "timeline.commit"
    assert receipt["request_hash"] == ctx["request_hash"]
    event = service.store.conn.execute("SELECT * FROM timeline_events WHERE id=?", (receipt["event_ids"][0],)).fetchone()
    assert event["kind"] == "timeline.commit.accepted"
    assert json.loads(event["payload_json"])["previous"] == head
    assert json.loads(event["payload_json"])["records_digest"] == digest(value["records"])
    next_head = commits.head(project, "main")
    second_ctx = context(service, project, next_head, "unchanged")
    second = accept(commits, second_ctx, prepared(commits, second_ctx, reuse=True))
    assert second["data"]["accepted_revision_id"] == first["data"]["accepted_revision_id"]
    assert second["receipt"]["receipt_id"] != receipt["receipt_id"]
    page = commits.history(project, "main", commits.head(project, "main"))
    assert len(page["items"]) == 3
    assert page["items"][-1]["previous"] == next_head
    assert page["items"][-1]["records"]["commands"][0]["writes"][0]["before"] == {"state": "present", "value": 2}
    assert service.store.integrity_report()["ok"]


def test_identical_retry_after_restart_and_head_advance(realm):
    service, commits, project, head, root = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    original = accept(commits, ctx, value)
    advanced = context(service, project, commits.head(project, "main"), "advance")
    accept(commits, advanced, prepared(commits, advanced, revision="parent-next", on=3))
    before = counts(service)
    service.close()
    restarted = RuntimeService(root)
    try:
        replay = TimelineCommitStore(restarted.store, validate_prepared=validate_prepared)
        assert canonical_json(replay.lookup(ctx, authorize=lambda: None)) == canonical_json(original)
        assert replay.accept(ctx, value, authorize=lambda: None) == original
        assert counts(restarted) == before
    finally:
        restarted.close()


def test_modern_labels_steps_effects_reads_and_actor_roundtrip_after_restart(realm):
    service, commits, project, head, root = realm
    seed_context = context(service, project, head, "modern-seed")
    seed = prepared(commits, seed_context, revision="modern-seed")
    payload = seed["canonical_document"]["parent_revision"]["payload"]
    payload["config"]["clips"] = copy.deepcopy(payload["clips"])
    seed["canonical_document"]["parent_revision"]["content_digest"] = digest(payload)
    seed["document_digest"] = digest(seed["canonical_document"])
    accept(commits, seed_context, seed)
    head = commits.head(project, "main")
    ctx = context(service, project, head, "modern")
    request = ctx["request"]
    request["commands"][0]["args"]["on"] = 3
    effect = {"op": "set", "ref": "parent", "path": ["clips", "id:clip", "at"],
              "before": {"state": "present", "value": 2}, "value": 3}
    reads = [{"kind": "field", "ref": "parent", "path": ["clips", "id:clip", "at"],
              "state": {"state": "present", "value": 2}}]
    request.update({
        "label": "Move opening clip",
        "merge": "fields",
        "reads": reads,
        "steps": [{"id": "opening", "label": "Move opening", "intent": "Set opening position",
                    "tags": ["opening"], "command_ordinals": [0], "patch": [effect],
                    "reads": reads}],
    })
    ctx["invocation"]["body"] = copy.deepcopy(request)
    ctx["request_hash"] = request_identity(ctx)
    value = prepared(commits, ctx, revision="modern-parent", on=3)
    payload = value["canonical_document"]["parent_revision"]["payload"]
    payload["config"]["clips"] = copy.deepcopy(payload["clips"])
    value["canonical_document"]["parent_revision"]["content_digest"] = digest(payload)
    value["document_digest"] = digest(value["canonical_document"])
    value["records"]["commands"][0]["command"]["args"]["on"] = 3
    value["records"]["commands"][0]["writes"] = [{"ref": "parent/clip:clip", "path": ["at"],
        "before": {"state": "present", "value": 2}, "after": {"state": "present", "value": 3}}]
    value["records"]["commands"][0]["bindings"] = [{
        "key": "doc.patch:0", "ref": "parent", "physical_ref": "parent",
        "revision_id": seed["canonical_document"]["parent_revision"]["revision_id"],
        "content_digest": seed["canonical_document"]["parent_revision"]["content_digest"],
        "boundary": {"base_revision_id": request["base_revision_id"],
                     "base_publication_id": request["base_publication_id"],
                     "evaluated_head": head, "step_id": "opening",
                     "command_ordinal": 0, "change_ordinal": 0, "phase": "input"},
        "policy": "fixed", "dependencies": [], "path": ["config", "clips", "id:clip", "at"],
        "change": effect, "write_range": [0, 1], "command_ordinal": 0,
        "change_ordinal": 0, "phase": "input",
    }]
    value["records"].update(label=request["label"], merge_mode="fields")
    dependencies = [{**read, "path": ["config", *read["path"]]} for read in reads]
    value["records"]["steps"] = [{**request["steps"][0], "patch": [effect], "dependencies": dependencies}]

    spoofed = copy.deepcopy(value)
    spoofed["records"]["commands"][0]["bindings"][0]["content_digest"] = "sha256:" + "0" * 64
    with pytest.raises(CommitRejected) as error:
        accept(commits, ctx, spoofed)
    assert error.value.failure["details"]["reason"] == "invalid_records"

    result = accept(commits, ctx, value)
    assert result["data"]["status"] == "accepted"
    assert result["data"]["label"] == request["label"]
    assert result["data"]["merge_mode"] == "fields"
    assert result["data"]["steps"] == value["records"]["steps"]
    assert result["data"]["publisher"] == "author"
    entry = commits.history_entry(project, "main", result["receipt"]["receipt_id"])
    assert entry["label"] == request["label"]
    assert entry["merge"] == entry["merge_mode"] == "fields"
    assert entry["reads"] == request["reads"]
    assert entry["steps"] == entry["records"]["steps"] == value["records"]["steps"]
    assert entry["publisher"] == result["data"]["publisher"] == "author"

    service.close()
    restarted = RuntimeService(root)
    try:
        replay_store = TimelineCommitStore(restarted.store, validate_prepared=validate_prepared)
        assert replay_store.lookup(ctx, authorize=lambda: None) == result
        assert replay_store.history_entry(project, "main", result["receipt"]["receipt_id"])["steps"] == value["records"]["steps"]
    finally:
        restarted.close()


def test_legacy_rebased_receipt_and_history_keep_v2_metadata_absent_after_restart(realm):
    service, commits, project, head, root = realm
    first_ctx = context(service, project, head, "legacy-first")
    accept(commits, first_ctx, prepared(commits, first_ctx, revision="legacy-first"))
    stale_ctx = context(service, project, head, "legacy-rebased")
    rebased = accept(commits, stale_ctx, prepared(commits, stale_ctx, expected=commits.head(project, "main"),
                                                   revision="legacy-rebased", on=4))

    assert rebased["data"]["status"] == "rebased"
    assert "label" not in rebased["data"]
    assert "merge_mode" not in rebased["data"]
    entry = commits.history_entry(project, "main", rebased["receipt"]["receipt_id"])
    assert entry["publisher"] == "author"
    assert "label" not in entry
    assert "merge" not in entry
    assert "merge_mode" not in entry
    assert "steps" not in entry
    assert json.loads(service.store.conn.execute(
        "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?",
        (rebased["receipt"]["receipt_id"],),
    ).fetchone()[0]) == {"rationale": "Move clip", "recorder_abi": 1}

    service.close()
    restarted = RuntimeService(root)
    try:
        replay_store = TimelineCommitStore(restarted.store, validate_prepared=validate_prepared)
        assert replay_store.lookup(stale_ctx, authorize=lambda: None) == rebased
        replay_entry = replay_store.history_entry(project, "main", rebased["receipt"]["receipt_id"])
        assert "label" not in replay_entry and "steps" not in replay_entry
        assert replay_store.integrity_errors() == []
    finally:
        restarted.close()


def test_recorder_digest_preserves_main_event_ids_and_stream_sequence(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    events = [{"command_ordinal": 0, "kind": "fixture.clip.moved", "subject_ref": "parent/clip:clip", "payload": {"on": 2}}]
    validated = []
    commits.validate_event = validated.append
    value["semantic_events"] = events
    result = accept(commits, ctx, value)
    assert validated == events
    ids = result["receipt"]["event_ids"]
    assert len(ids) == 2
    rows = service.store.conn.execute("SELECT * FROM timeline_events WHERE timeline_id='main' ORDER BY id").fetchall()
    assert ids == [str(row["id"]) for row in rows[-2:]]
    assert [row["kind"] for row in rows[-2:]] == [events[0]["kind"], "timeline.commit.accepted"]
    ledger = service.store.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (result["receipt"]["receipt_id"],)).fetchone()
    assert ledger["resulting_stream_seq"] == len(rows)
    assert [ledger["first_project_seq"], ledger["last_project_seq"]] == result["receipt"]["project_seq"]
    assert commits.lookup(ctx, authorize=lambda: None) == result
    assert commits.history_entry(project, "main", result["receipt"]["receipt_id"])["records"] == value["records"]
    assert commits.integrity_errors() == []


def test_changed_payload_and_publication_only_cas_refuse_without_writes(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    accept(commits, ctx, value)
    current = commits.head(project, "main")
    other = context(service, project, current, "same-content")
    accept(commits, other, prepared(commits, other, reuse=True))
    before = counts(service)
    changed = copy.deepcopy(ctx)
    changed["request"]["rationale"] = "different"
    changed["invocation"]["body"] = copy.deepcopy(changed["request"])
    changed["request_hash"] = request_identity(changed)
    with pytest.raises(CommitRejected) as mismatch:
        commits.lookup(changed, authorize=lambda: None)
    assert mismatch.value.failure["details"]["reason"] == "idempotency_mismatch"
    stale = context(service, project, current, "stale")
    stale_value = prepared(commits, stale, expected=current, revision="never-written")
    with pytest.raises(StaleHead) as race:
        accept(commits, stale, stale_value)
    assert race.value.current_head["revision_id"] == current["revision_id"]
    assert race.value.current_head["publication_id"] != current["publication_id"]
    assert counts(service) == before


@pytest.mark.parametrize("bad", ["digest", "manifest", "ordinal", "id_map", "unknown_field", "nonfinite", "event", "base_pair"])
def test_invalid_prepared_values_are_atomic(realm, bad):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    if bad == "digest":
        value["document_digest"] = "sha256:" + "0" * 64
    elif bad == "manifest":
        value["canonical_document"]["dependency_manifest"]["shots"] = [{"shot_id": "foreign", "revision_id": "foreign", "internal_timeline_revision_id": "foreign", "content_digest": "sha256:" + "0" * 64}]
        value["document_digest"] = digest(value["canonical_document"])
    elif bad == "ordinal":
        value["records"]["commands"][0]["ordinal"] = 2
    elif bad == "id_map":
        value["id_map"] = {"clip": "replacement"}
    elif bad == "unknown_field":
        value["receipt"] = {}
    elif bad == "nonfinite":
        value["records"]["commands"][0]["command"]["args"]["on"] = float("nan")
    elif bad == "event":
        value["semantic_events"] = [{"command_ordinal": 0, "kind": "unregistered", "subject_ref": None, "payload": {}}]
    elif bad == "base_pair":
        ctx["request"]["base_revision_id"] = "wrong"
        ctx["invocation"]["body"] = copy.deepcopy(ctx["request"])
        ctx["request_hash"] = request_identity(ctx)
    before = counts(service)
    with pytest.raises((CommitRejected, ValidationError)):
        accept(commits, ctx, value)
    assert counts(service) == before
    assert commits.head(project, "main") == head


def test_failure_after_receipt_rolls_back_every_row(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    class Inputs:
        def validate(self, prepared):
            pass
        def persist(self, *args):
            raise RuntimeError("crash before COMMIT")
    before = counts(service)
    with pytest.raises(RuntimeError, match="crash before COMMIT"):
        commits.accept(ctx, prepared(commits, ctx), authorize=lambda: None, inputs=Inputs())
    assert counts(service) == before
    assert commits.head(project, "main") == head
    assert commits.lookup(ctx, authorize=lambda: None) is None


@pytest.mark.parametrize("point", ["closure", "acceptance_event", "receipt"])
def test_failure_between_projection_steps_rolls_back_and_restart_retry_publishes_once(realm, monkeypatch, point):
    service, commits, project, head, root = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)

    def fail_after(owner, name, selected=lambda *args: True):
        original = getattr(owner, name)

        def failing(*args, **kwargs):
            result = original(*args, **kwargs)
            if selected(*args):
                raise RuntimeError(f"crash after {point}")
            return result
        monkeypatch.setattr(owner, name, failing)

    # Each point is a durable step inside the single acceptance transaction.
    if point == "closure":
        fail_after(commits, "_persist_closure")
    elif point == "acceptance_event":
        fail_after(service.store, "_append_timeline_event", lambda _, kind, *rest: kind == "timeline.commit.accepted")
    else:
        fail_after(service.store, "_record_command_receipt")
    before = counts(service)
    with pytest.raises(RuntimeError, match=f"crash after {point}"):
        accept(commits, ctx, value)
    assert counts(service) == before
    assert commits.head(project, "main") == head
    assert commits.lookup(ctx, authorize=lambda: None) is None
    assert service.store.integrity_report()["ok"]
    service.close()
    restarted = RuntimeService(root)
    try:
        replay = TimelineCommitStore(restarted.store, validate_prepared=validate_prepared)
        original = accept(replay, ctx, value)
        assert accept(replay, ctx, value) == original
        assert replay.lookup(ctx, authorize=lambda: None) == original
        after = counts(restarted)
        assert after["timeline_commit_history"] == before["timeline_commit_history"] + 1
        assert after["command_idempotency"] == before["command_idempotency"] + 1
        assert after["timeline_events"] == before["timeline_events"] + 1
        assert after["timeline_versions"] == before["timeline_versions"] + 1
        assert replay.head(project, "main")["publication_id"] == original["receipt"]["receipt_id"]
        assert restarted.store.integrity_report()["ok"]
    finally:
        restarted.close()


@pytest.mark.parametrize("intervening", [False, True])
def test_preview_is_validated_and_reserves_nothing(realm, intervening):
    service, commits, project, head, _ = realm
    if intervening:
        intervening_ctx = context(service, project, head, "intervening")
        accept(commits, intervening_ctx, prepared(commits, intervening_ctx, revision="intervening"))
    ctx = context(service, project, head, dry_run=True)
    evaluated_head = commits.head(project, "main")
    value = prepared(commits, ctx, expected=evaluated_head)
    before = counts(service)
    preview = commits.preview(ctx, value, authorize=lambda: None)
    assert preview["receipt"] is None
    assert preview["data"]["would_status"] == ("merged" if intervening else "accepted")
    assert preview["data"]["evaluated_head"] == evaluated_head
    assert preview["data"]["commands"] == [r["command"] for r in value["records"]["commands"]]
    with pytest.raises(CommitRejected) as error:
        accept(commits, ctx, value)
    assert error.value.failure["details"]["reason"] == "dry_run_accept"
    assert counts(service) == before


@pytest.mark.parametrize("aliases", ["equal", "parent-empty", "config-empty"])
def test_parent_clip_aliases_preserve_opaque_values_and_exact_retry(realm, monkeypatch, aliases):
    import runtime_protocol.visual_seam as visual_seam

    def unavailable(*args, **kwargs):
        pytest.fail("commit evaluated a scene")
    monkeypatch.setattr(visual_seam, "evaluate_closure", unavailable)
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    parent = value["canonical_document"]["parent_revision"]
    payload = parent["payload"]
    payload["opaque"] = {"clips": None, "pinned": {"clips": [{"value": None}]}}
    payload["config"]["app"] = {"clips": [{"opaque": None}]}
    payload["config"]["clips"] = copy.deepcopy(payload["clips"])
    if aliases == "parent-empty":
        payload["clips"] = []
    elif aliases == "config-empty":
        payload["config"]["clips"] = []
    parent["content_digest"] = digest(payload)
    value["document_digest"] = digest(value["canonical_document"])
    original = copy.deepcopy(value)
    before = tuple(service.store.conn.iterdump())
    preview_ctx = context(service, project, head, dry_run=True)
    preview = commits.preview(preview_ctx, value, authorize=lambda: None)
    assert preview["data"]["canonical_document"] == value["canonical_document"]
    assert tuple(service.store.conn.iterdump()) == before
    accepted = accept(commits, ctx, value)
    assert accepted["data"]["canonical_document"] == value["canonical_document"]
    assert commits.revision_closure(project, "main", parent["revision_id"]) == value["canonical_document"]
    assert value == original
    # The exact ledger retry must precede candidate structure validation.
    value["canonical_document"]["parent_revision"]["payload"]["config"]["clips"] = [{"id": "contradictory"}]
    monkeypatch.setattr(visual_seam, "parent_clips", unavailable)
    before = tuple(service.store.conn.iterdump())
    assert accept(commits, ctx, value) == accepted
    assert tuple(service.store.conn.iterdump()) == before


def test_history_pages_keep_fixed_bounds_and_reject_foreign_cursor(realm):
    service, commits, project, head, _ = realm
    for i in range(3):
        ctx = context(service, project, commits.head(project, "main"), f"move-{i}")
        accept(commits, ctx, prepared(commits, ctx, revision=f"parent-{i}", on=i))
    through = commits.head(project, "main")
    page = commits.history(project, "main", through, limit=2)
    ctx = context(service, project, through, "advance")
    accept(commits, ctx, prepared(commits, ctx, revision="past-bound"))
    rest = commits.history(project, "main", through, cursor=page["next_cursor"], limit=2)
    assert len(page["items"] + rest["items"]) == 4
    assert rest["head"] == through
    assert rest["items"][-1]["publication_id"] == through["publication_id"]
    with pytest.raises(ValidationError):
        commits.history(project, "main", commits.head(project, "main"), cursor=page["next_cursor"])
    with pytest.raises(ValidationError):
        commits.history(project, "main", through, limit=201)


def test_nested_acceptance_is_refused(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    with service.store._mutex, service.store._transaction():
        with pytest.raises(ProtocolError, match="outer transaction"):
            accept(commits, ctx, prepared(commits, ctx))


def test_timeline_commit_retention_survives_online_and_offline_compaction(realm):
    from datetime import datetime, timedelta, timezone
    from runtime_protocol.idempotency import command_result
    from runtime_protocol.upgrade import compact_idempotency_ledger

    service, commits, project, head, root = realm
    ctx = context(service, project, head)
    result = accept(commits, ctx, prepared(commits, ctx))
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="milliseconds")
    # Age the real accepted row, then capture its exact bytes/facts. This is
    # retention coverage, not a synthetic replacement for receipt acceptance.
    service.store.conn.execute("UPDATE command_idempotency SET created_at=? WHERE txn_id=?", (old, result["receipt"]["receipt_id"]))
    row = service.store.conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (result["receipt"]["receipt_id"],)).fetchone()
    assert command_result(row["result_json"], kind="timeline.commit", created_at=old) == result["data"]
    expected = commits.lookup(ctx, authorize=lambda: None)
    encoded = row["result_json"]
    service.store._last_idempotency_prune = 0
    service._command_record("test.trigger-prune", "test", "trigger", "hash", {"ok": True}, project_id=project)
    assert commits.lookup(ctx, authorize=lambda: None) == expected
    realm_id = service.realm["id"]
    service.close()
    compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    reopened = RuntimeService(root)
    try:
        replay = TimelineCommitStore(reopened.store, validate_prepared=validate_prepared)
        assert canonical_json(replay.lookup(ctx, authorize=lambda: None)) == canonical_json(expected)
        assert reopened.store.conn.execute("SELECT result_json FROM command_idempotency WHERE txn_id=?", (result["receipt"]["receipt_id"],)).fetchone()[0] == encoded
        assert reopened.store.integrity_report()["ok"]
    finally:
        reopened.close()


def test_verified_baseline_keeps_main_receipt_event_and_unknown_intent(tmp_path):
    from runtime_protocol.timeline_commit_baseline import verify_baseline
    from timeline_commit_film_fixture import build_film_fixture

    film = build_film_fixture(tmp_path)
    service = RuntimeService(film.duplicate_root)
    project, timeline = film.project_id, film.timeline_id
    try:
        commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
        # Read the immutable captured receipt, including its original times.
        # Ordinary old-command replay may expire independently of this proof.
        facts = verify_baseline(service.store.conn, project, timeline, read_object=service.cas.read)
        receipt = facts["entries"][0]["receipt"]
        before = counts(service)
        head = commits.install_verified_baseline(project, timeline, authorize=lambda: None)
        assert head == {"revision_id": film.parent_revision_id, "publication_id": receipt["receipt_id"]}
        entry = commits.history_entry(project, timeline, head["publication_id"])
        assert entry["receipt"] == receipt
        assert entry["intent"] == "legacy_unknown"
        assert entry["records"] is None
        assert entry["publisher"] is None
        assert counts(service) == {**before, "timeline_commit_history": 1}
        assert commits.install_verified_baseline(project, timeline, authorize=lambda: None) == head
        assert commits.revision_closure(project, timeline, film.parent_revision_id)["shot_revisions"][0]["shot_id"] == "shot-1"
        assert service.store.integrity_report()["ok"]
    finally:
        service.close()


def test_unproven_baseline_and_same_content_legacy_write_fail_closed(realm):
    service, commits, project, head, _ = realm
    # A later untracked write with unchanged revision bytes invalidates the
    # editable publication pair. Exact-key replay still precedes head reads.
    ctx = context(service, project, head)
    accepted = accept(commits, ctx, prepared(commits, ctx))
    service.store._append_timeline_event("main", "timeline.updated", {"project_id": project, "version": 99})
    with pytest.raises(CommitRejected) as unavailable:
        commits.head(project, "main")
    assert unavailable.value.failure["details"]["reason"] == "history_unavailable"
    assert commits.lookup(ctx, authorize=lambda: None) == accepted


def test_commit_integrity_detects_missing_history_and_corrupt_record(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    result = accept(commits, ctx, prepared(commits, ctx))
    service.store.conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                               ('{"commands":[]}', result["receipt"]["receipt_id"]))
    with pytest.raises(ProtocolError, match="corrupt"):
        commits.lookup(ctx, authorize=lambda: None)
    report = service.store.integrity_report()
    assert not report["ok"]
    assert any(error["table"] == "timeline_commit_history" for error in report["checks"]["revisions"]["errors"])


def assert_corrupt_acceptance(service, commits, ctx, value, result):
    project = ctx["request"]["project_id"]
    publication = result["receipt"]["receipt_id"]
    through = {"revision_id": result["data"]["accepted_revision_id"], "publication_id": publication}
    before = counts(service)
    head = tuple(service.store.conn.execute("SELECT * FROM parent_composition_heads WHERE timeline_id='main'").fetchone())
    for read in (lambda: commits.lookup(ctx, authorize=lambda: None),
                 lambda: commits.history_entry(project, "main", publication),
                 lambda: commits.history(project, "main", through),
                 lambda: commits.head(project, "main"),
                 lambda: accept(commits, ctx, value)):
        with pytest.raises(ProtocolError, match="corrupt"):
            read()
    assert any(error["id"] == publication for error in commits.integrity_errors())
    assert not service.store.integrity_report()["ok"]
    assert counts(service) == before
    assert tuple(service.store.conn.execute("SELECT * FROM parent_composition_heads WHERE timeline_id='main'").fetchone()) == head


def assert_corrupt_restart(service, root):
    import sqlite3

    service.close()
    def snapshot():
        with sqlite3.connect(f"file:{root / 'realm.sqlite3'}?mode=ro", uri=True) as conn:
            return list(conn.iterdump())
    before = snapshot()
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert not error.value.details["ok"]
    assert any(item["table"] == "timeline_commit_history" for item in error.value.details["checks"]["revisions"]["errors"])
    assert snapshot() == before


def test_complete_recorder_roundtrip_and_replay_after_restart(realm):
    service, commits, project, _, root = realm
    ctx, value, result = accepted_recorder(realm)
    before = counts(service)
    service.close()
    reopened = RuntimeService(root)
    try:
        persisted = TimelineCommitStore(reopened.store, validate_prepared=lambda _: pytest.fail("replay validated a new candidate"))
        assert persisted.history_entry(project, "main", result["receipt"]["receipt_id"])["records"] == value["records"]
        assert persisted.lookup(ctx, authorize=lambda: None) == result
        assert accept(persisted, ctx, value) == result
        assert persisted.integrity_errors() == []
        assert reopened.store.integrity_report()["ok"]
        assert counts(reopened) == before
    finally:
        reopened.close()


@pytest.mark.parametrize("path,replacement", RECORD_CORRUPTIONS)
def test_valid_json_recorder_corruption_fails_every_durable_read_after_restart(realm, path, replacement):
    service, commits, _, _, root = realm
    ctx, value, result = accepted_recorder(realm)
    corrupt_recorder(service, value, result, path, replacement)
    assert_corrupt_acceptance(service, commits, ctx, value, result)
    assert_corrupt_restart(service, root)


@pytest.mark.parametrize("bad", ["missing_digest", "changed_digest", "unknown_digest", "event_hash", "previous_hash",
                                "records_and_digest", "missing_event", "event_ids", "stream_seq", "primary_stream", "intent"])
def test_corrupt_acceptance_event_and_receipt_facts_fail_closed_after_restart(realm, bad):
    service, commits, _, _, root = realm
    ctx, value, result = accepted_recorder(realm)
    publication, event_id = result["receipt"]["receipt_id"], result["receipt"]["event_ids"][-1]
    conn = service.store.conn
    if bad in {"missing_digest", "changed_digest", "unknown_digest", "records_and_digest"}:
        payload = json.loads(conn.execute("SELECT payload_json FROM timeline_events WHERE id=?", (event_id,)).fetchone()[0])
        if bad == "missing_digest":
            del payload["records_digest"]
        elif bad == "records_and_digest":
            path, replacement = RECORD_CORRUPTIONS[0]
            corrupt_recorder(service, value, result, path, replacement)
            records = json.loads(conn.execute("SELECT records_json FROM timeline_commit_history WHERE publication_id=?", (publication,)).fetchone()[0])
            payload["records_digest"] = digest(records)
        else:
            payload["records_digest"] = "unknown" if bad == "unknown_digest" else "sha256:" + "0" * 64
        conn.execute("UPDATE timeline_events SET payload_json=? WHERE id=?", (canonical_json(payload), event_id))
        if bad != "records_and_digest":
            event = conn.execute("SELECT * FROM timeline_events WHERE id=?", (event_id,)).fetchone()
            hashed = {"timeline_id": event["timeline_id"], "kind": event["kind"], "payload": payload,
                      "previous_hash": event["previous_hash"], "created_at": event["created_at"]}
            conn.execute("UPDATE timeline_events SET event_hash=? WHERE id=?", (digest(hashed)[7:], event_id))
    elif bad in {"event_hash", "previous_hash"}:
        conn.execute(f"UPDATE timeline_events SET {bad}=? WHERE id=?", ("0" * 64, event_id))
    elif bad == "missing_event":
        conn.execute("DELETE FROM timeline_events WHERE id=?", (event_id,))
    elif bad == "event_ids":
        conn.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
    elif bad == "stream_seq":
        conn.execute("UPDATE command_idempotency SET resulting_stream_seq=resulting_stream_seq-1 WHERE txn_id=?", (publication,))
    elif bad == "primary_stream":
        conn.execute("UPDATE command_idempotency SET primary_stream_id='other' WHERE txn_id=?", (publication,))
    else:
        conn.execute("UPDATE timeline_commit_history SET intent='legacy_unknown' WHERE publication_id=?", (publication,))
    assert_corrupt_acceptance(service, commits, ctx, value, result)
    assert_corrupt_restart(service, root)


def test_retry_checks_accepted_event_prefix_without_repair(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    result = accept(commits, ctx, value)
    event_id = service.store.conn.execute("SELECT MIN(id) FROM timeline_events WHERE timeline_id='main'").fetchone()[0]
    service.store.conn.execute("UPDATE timeline_events SET event_hash=? WHERE id=?", ("0" * 64, event_id))
    before = counts(service)
    with pytest.raises(ProtocolError, match="corrupt"):
        commits.lookup(ctx, authorize=lambda: None)
    assert counts(service) == before
    assert service.store.conn.execute("SELECT event_hash FROM timeline_events WHERE id=?", (event_id,)).fetchone()[0] == "0" * 64


@pytest.mark.parametrize("column,replacement", [("event_hash", "0" * 64), ("payload_json", '{"corrupt":true}')])
def test_original_retry_ignores_corrupt_later_acceptance(realm, column, replacement):
    import sqlite3
    from types import SimpleNamespace
    from runtime_protocol.timeline_commit_execution import CommitExecutionCoordinator, CommitOutcomeUnknown

    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    original = accept(commits, ctx, value)
    accepted_head = commits.head(project, "main")
    next_ctx = context(service, project, accepted_head, "next")
    later = accept(commits, next_ctx, prepared(commits, next_ctx, revision="next-parent", on=3))
    event_id = later["receipt"]["event_ids"][-1]
    conn = service.store.conn
    conn.execute(f"UPDATE timeline_events SET {column}=? WHERE id=?", (replacement, event_id))
    before = list(conn.iterdump())
    coordinator = CommitExecutionCoordinator(commits)
    provider = SimpleNamespace(commit=lambda *_: pytest.fail("accepted retry ran provider"))
    def no_port(_):
        pytest.fail("accepted retry constructed semantic port")
    allowed = {"projects", "timelines", "command_idempotency", "timeline_commit_history", "timeline_events", "project_sequences"}
    denied = []
    def replay_reads_only(action, table, *_):
        if action == sqlite3.SQLITE_SELECT or (action == sqlite3.SQLITE_READ and table in allowed):
            return sqlite3.SQLITE_OK
        denied.append((action, table))
        return sqlite3.SQLITE_DENY
    conn.set_authorizer(replay_reads_only)
    try:
        replay = coordinator.execute(ctx, provider, no_port, authorize=lambda: None)
        assert canonical_json(replay) == canonical_json(original)
        assert commits.history_entry(project, "main", accepted_head["publication_id"])["records"] == value["records"]
        with pytest.raises(ProtocolError, match="corrupt"):
            commits.lookup(next_ctx, authorize=lambda: None)
        with pytest.raises(CommitOutcomeUnknown) as error:
            coordinator.execute(next_ctx, provider, no_port, authorize=lambda: None)
        assert isinstance(error.value.__cause__, ProtocolError)
    finally:
        conn.set_authorizer(None)
    assert denied == []  # No writes or mutable head/source/dependency reads.
    assert not coordinator._entries
    report = service.store.integrity_report()
    assert not report["ok"]
    assert any(str(error.get("event_id")) == event_id and error["reason"] == "hash_mismatch"
               for error in report["checks"]["event_chain"]["errors"])
    assert any(error["id"] == later["receipt"]["receipt_id"] for error in report["checks"]["revisions"]["errors"])
    assert not any(error["id"] == original["receipt"]["receipt_id"] for error in report["checks"]["revisions"]["errors"])
    assert list(conn.iterdump()) == before


def test_upstream_v31_schema_migration_installs_empty_history_without_invented_baselines(tmp_path):
    from runtime_protocol.upgrade import (
        _apply_v31_to_v32,
        _canonical_schema_identity,
        migrate_canonical_to_current,
    )

    archive = Path(__file__).with_name("fixtures") / "upstream-app-state-v31.tar.gz"
    root = tmp_path / "upstream-v31"
    with tarfile.open(archive, "r:gz") as contents:
        members = contents.getmembers()
        assert {member.name for member in members} >= {"realm.sqlite3", "PROVENANCE.json"}
        assert all(member.isfile() or member.isdir() for member in members)
        provenance = json.loads(contents.extractfile("PROVENANCE.json").read())
        assert provenance == {
            "created_by": "runtime_protocol.store.RealmStore.initialize",
            "realm_id": "upstream-app-state-v31",
            "schema_version": 31,
            "source_sha": "4563bb5ff06171b3290fc5e2300e08d7fa125b01",
        }
        root.mkdir()
        for member in members:
            if member.name != "PROVENANCE.json":
                contents.extract(member, root, filter="data")
    realm_id = "upstream-app-state-v31"
    connection = sqlite3.connect(root / "realm.sqlite3", isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        assert connection.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0] == 31
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_app_state'").fetchone()
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='timeline_commit_history'").fetchone() is None
        assert _canonical_schema_identity(connection)["version"] == 31
        connection.execute("BEGIN IMMEDIATE")
        assert _apply_v31_to_v32(connection)["target_schema_version"] == 32
        assert connection.in_transaction
        assert _canonical_schema_identity(connection)["version"] == 32
        assert connection.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM timeline_document_input_contents").fetchone()[0] == 0
        connection.rollback()
        assert _canonical_schema_identity(connection)["version"] == 31
    finally:
        connection.close()
    result = migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {realm_id}")
    assert result["target_schema_version"] == 32
    assert len(result["steps"]) == 1
    reopened = RealmStore(root)
    try:
        assert reopened.integrity_report()["ok"]
        assert reopened.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 0
    finally:
        reopened.close()


def test_legacy_timeline_v31_fixture_remains_a_distinct_migration_source(tmp_path):
    from runtime_protocol.upgrade import (
        _canonical_schema_identity,
        migrate_canonical_to_current,
    )

    fixture = load_precut_realm_fixture(tmp_path)
    root = fixture.copy_roots[0]
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0] == 31
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='timeline_commit_history'").fetchone()
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_app_state'").fetchone() is None
        assert _canonical_schema_identity(connection)["version"] == 31
    result = migrate_canonical_to_current(
        root,
        confirmation=f"MIGRATE CANONICAL {fixture.manifest['realm']['id']}",
    )
    assert result["target_schema_version"] == 32
    assert result["steps"][-1]["target_schema_version"] == 32
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT version FROM runtime_schema WHERE id=1").fetchone()[0] == 32
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_app_state'").fetchone()


@pytest.mark.parametrize("kind", ["config", "transcript"])
def test_real_acceptance_links_consumed_inputs_and_keeps_old_bytes_after_restart(realm, kind):
    from runtime_protocol.timeline_commit_inputs import (
        DocumentInputLink, capture_document_input, persist_document_input_links, validate_captured_document_inputs,
    )
    service, commits, project, head, root = realm
    if kind == "transcript":
        media_id = service.ingest(project, b"source-media", media_type="video/mp4", idempotency_key="media")["data"]["object_id"]
        document_id = RuntimeService._transcript_document_id(project, media_id, "default")
        content = {"schema": "media.transcript/v1", "media_id": media_id, "source_id": "default",
                   "segments": [{"id": "segment-1", "start": 0, "end": 1, "text": "hello",
                                 "words": [{"id": "word-1", "start": 0, "end": 1, "text": "hello"}]}]}
        document_kind = "media.transcript"
    else:
        document_id, document_kind = "editing-config", "fixture.config"
        content = {"schema": "fixture.config/v1", "value": 1, "opaque": {"clear": None}}
    document = service.create_document(project, {"document_id": document_id, "kind": document_kind, "content": content}, idempotency_key="source")["data"]
    pin = {"document_id": document_id, "version": document["version"], "content_digest": digest(content)}
    capture = capture_document_input(service.store.conn, project, pin, expected_kind=document_kind, expected_schema=content["schema"])
    class Inputs:
        def validate(self, candidate):
            assert candidate["canonical_document"]["dependency_manifest"]["documents"] == [pin]
            validate_captured_document_inputs(service.store.conn, [capture])
        def persist(self, candidate, publication_id, revision_id):
            persist_document_input_links(service.store.conn, project_id=project, timeline_id="main", publication_id=publication_id,
                                         revision_id=revision_id, links=[DocumentInputLink(capture, "transcript" if kind == "transcript" else "source", 0)])
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    value["canonical_document"]["dependency_manifest"]["documents"] = [pin]
    if kind == "transcript":
        value["canonical_document"]["dependency_manifest"]["media"] = [{"media_id": media_id, "content_digest": media_id}]
    value["document_digest"] = digest(value["canonical_document"])
    value["records"]["commands"][0]["dependencies"] = [{"key": "input", "kind": "transcript" if kind == "transcript" else "source", "pin": pin, "policy": "exact"}]
    result = commits.accept(ctx, value, authorize=lambda: None, inputs=Inputs())
    links = service.store.conn.execute("SELECT * FROM timeline_document_input_links WHERE publication_id=?", (result["receipt"]["receipt_id"],)).fetchall()
    assert len(links) == 1
    replacement = copy.deepcopy(content)
    if kind == "transcript":
        replacement["segments"][0]["words"][0]["text"] = "changed"
    else:
        replacement["value"] = 2
    service.update_document(project, document_id, {"expected_version": 1, "content": replacement}, idempotency_key="replace-input")
    service.close()
    reopened = RuntimeService(root)
    try:
        persisted = TimelineCommitStore(reopened.store, validate_prepared=validate_prepared)
        assert persisted.lookup(ctx, authorize=lambda: None) == result
        closure = persisted.revision_closure(project, "main", result["data"]["accepted_revision_id"])
        retained = capture_document_input(reopened.store.conn, project, pin, reachable_pins=closure["dependency_manifest"]["documents"],
                                          expected_kind=document_kind, expected_schema=content["schema"])
        assert retained.retained
        assert retained.document == document
        assert reopened.store.integrity_report()["ok"]
    finally:
        reopened.close()


def test_live_capture_accept_race_rolls_back_history_receipt_and_input_links(realm):
    from runtime_protocol.errors import ConflictError
    from runtime_protocol.timeline_commit_inputs import capture_document_input, validate_captured_document_inputs
    service, commits, project, head, _ = realm
    content = {"schema": "fixture.config/v1", "value": 1}
    service.create_document(project, {"document_id": "config", "kind": "fixture.config", "content": content}, idempotency_key="config")
    pin = {"document_id": "config", "version": 1, "content_digest": digest(content)}
    capture = capture_document_input(service.store.conn, project, pin, expected_kind="fixture.config", expected_schema=content["schema"])
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    value["canonical_document"]["dependency_manifest"]["documents"] = [pin]
    value["document_digest"] = digest(value["canonical_document"])
    class Inputs:
        def validate(self, prepared):
            validate_captured_document_inputs(service.store.conn, [capture])
        def persist(self, *args):
            pytest.fail("changed capture reached persistence")
    service.update_document(project, "config", {"expected_version": 1, "content": {**content, "value": 2}}, idempotency_key="update-config")
    before = counts(service)
    with pytest.raises(ConflictError):
        commits.accept(ctx, value, authorize=lambda: None, inputs=Inputs())
    assert counts(service) == before
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_links").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_document_input_contents").fetchone()[0] == 0


def test_complete_detached_child_closure_projects_and_reuses_exact_rows(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head, op="fixture.add-shot")
    value = prepared(commits, ctx)
    internal_payload = {"clips": [], "tracks": [], "app": {"opaque": None}}
    internal = {"timeline_id": "shot:shot-1", "revision_id": "internal-1", "payload": internal_payload, "content_digest": digest(internal_payload)}
    shot_payload = {"name": "Opening", "metadata": {"opaque": {"keep": None}}, "items": [], "internal_timeline_revision_id": "internal-1"}
    shot = {"shot_id": "shot-1", "revision_id": "shot-1-r1", "internal_timeline_revision_id": "internal-1", "payload": shot_payload, "content_digest": digest(shot_payload)}
    occurrence = {"occurrence_id": "occ-1", "shot_id": "shot-1", "shot_revision_id": "shot-1-r1", "placement": {"start_ms": 0},
                  "duration_ms": 1000, "source_offset": 0, "speed": {"numerator": 1, "denominator": 1}, "track": "picture",
                  "transform": {}, "gain": 1, "muted": False, "provenance": {}, "opaque": {"preserve": None}}
    document = value["canonical_document"]
    document["shot_revisions"], document["internal_timeline_revisions"] = [shot], [internal]
    document["parent_revision"]["payload"]["occurrences"] = [occurrence]
    document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
    document["dependency_manifest"]["shots"] = [{k: shot[k] for k in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}]
    document["dependency_manifest"]["internal_timelines"] = [{k: internal[k] for k in ("timeline_id", "revision_id", "content_digest")}]
    value["document_digest"] = digest(document)
    value["records"]["commands"][0]["created"] = [{"ref": "parent/occurrence:occ-1", "kind": "occurrence", "owner": "parent"}]
    result = accept(commits, ctx, value)
    assert commits.revision_closure(project, "main", result["data"]["accepted_revision_id"]) == document
    child = commits.shot_closure(project, "shot-1", "shot-1-r1")
    assert child["shot_revision"] == shot
    assert child["internal_timeline_revision"] == internal
    row = service.store.conn.execute("SELECT * FROM project_shots WHERE id='shot-1'").fetchone()
    assert row["name"] == "Opening"
    assert json.loads(row["metadata_json"]) == shot_payload["metadata"]
    before = counts(service)
    new_ctx = context(service, project, commits.head(project, "main"), "reuse-child")
    accept(commits, new_ctx, prepared(commits, new_ctx, reuse=True))
    assert counts(service)["shot_revisions"] == before["shot_revisions"]
    assert counts(service)["internal_timeline_revisions"] == before["internal_timeline_revisions"]
    assert service.store.integrity_report()["ok"]


def test_nonmanaged_project_media_relation_cannot_authorize_commit(realm):
    service, commits, project, head, _ = realm
    media_id = service.ingest(project, b"same-object", media_type="video/mp4", idempotency_key="import")["data"]["object_id"]
    service.store.conn.execute("UPDATE project_objects SET relation='referenced' WHERE project_id=? AND digest=?", (project, media_id.removeprefix("sha256:")))
    ctx = context(service, project, head)
    value = prepared(commits, ctx)
    value["canonical_document"]["dependency_manifest"]["media"] = [{"media_id": media_id, "content_digest": media_id}]
    value["document_digest"] = digest(value["canonical_document"])
    before = counts(service)
    with pytest.raises(CommitRejected) as error:
        accept(commits, ctx, value)
    assert error.value.failure["details"]["reason"] == "dependency_unavailable"
    assert counts(service) == before
    assert commits.head(project, "main") == head


@pytest.fixture
def film(tmp_path):
    from project_isolation_fixture import load_project_isolation_fixture

    return load_project_isolation_fixture(tmp_path)


@pytest.mark.integration
def test_real_provider_two_projects_keep_local_ids_and_commit_authority_isolated(film, request):
    from types import SimpleNamespace

    from runtime_protocol.errors import RuntimeErrorBase
    from runtime_protocol.timeline_commit_port import route_path
    from test_timeline_commit_integration import Editing, assert_json_equal, inverse, rows

    service = RuntimeService(film.fixture.duplicate_root)
    try:
        project = film.isolated.fixture.project_id
        timeline = film.isolated.fixture.timeline_id
        publication = film.isolated.publication

        # The shared Agent fixture disables rendering only after both Main API seeds.
        actual_agent = request.getfixturevalue("agent")
        service.register_timeline_commit_provider(actual_agent.provider())
        a = Editing(service, film, actual_agent)
        b = Editing(service, SimpleNamespace(fixture=SimpleNamespace(project_id=project, timeline_id=timeline)), actual_agent)
        a.assert_baseline()
        assert b.history()[0]["receipt"] == publication["receipt"]
        originals = {edit.project: edit.document() for edit in (a, b)}
        original_a, original_b = originals[a.project], originals[b.project]
        assert original_a["parent_revision"]["payload"]["clips"] == original_b["parent_revision"]["payload"]["clips"]
        assert [row["occurrence_id"] for row in original_a["parent_revision"]["payload"]["occurrences"]] == [
            row["occurrence_id"] for row in original_b["parent_revision"]["payload"]["occurrences"]]
        for family, identity in (("shot_revisions", "shot_id"), ("shot_revisions", "revision_id"),
                                 ("internal_timeline_revisions", "revision_id")):
            assert {row[identity] for row in original_a[family]}.isdisjoint(row[identity] for row in original_b[family])
        for left, right in zip(original_a["internal_timeline_revisions"], original_b["internal_timeline_revisions"]):
            left_clips, right_clips = copy.deepcopy(left["payload"]["clips"]), copy.deepcopy(right["payload"]["clips"])
            for clips in (left_clips, right_clips):
                for clip in clips:
                    if "elementRef" in clip:
                        clip["elementRef"]["binding_id"] = "project-owned-binding"
                        clip["elementRef"]["anchor"]["document_id"] = "project-owned-transcript"
            assert left_clips == right_clips

        def state(edit):
            # Complete project-owned rows, plus tables whose ownership is indirect.
            conn = service.store.conn
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            scoped = {}
            for table in tables:
                columns = {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}
                if "project_id" in columns:
                    scoped[table] = sorted(tuple(row) for row in conn.execute(
                        f'SELECT * FROM "{table}" WHERE project_id=?', (edit.project,)))
            scoped["timeline_events"] = [tuple(row) for row in conn.execute(
                "SELECT * FROM timeline_events WHERE timeline_id=? ORDER BY id", (edit.timeline,))]
            scoped["command_idempotency"] = [tuple(row) for row in conn.execute(
                "SELECT * FROM command_idempotency WHERE primary_stream_id=? OR aggregate_id=? ORDER BY txn_id",
                (edit.timeline, canonical_json([edit.project, edit.timeline])))]
            scoped["shot_items"] = [tuple(row) for row in conn.execute(
                "SELECT i.* FROM shot_items i JOIN project_shots s ON s.id=i.shot_id WHERE s.project_id=? ORDER BY i.id",
                (edit.project,))]
            scoped["composition_revision_dependencies"] = [tuple(row) for row in conn.execute(
                "SELECT d.* FROM composition_revision_dependencies d JOIN parent_composition_revisions p "
                "ON p.id=d.parent_revision_id WHERE p.project_id=? ORDER BY d.parent_revision_id, d.ordinal",
                (edit.project,))]
            return {"sql": scoped, "head": edit.head(), "closure": edit.document(), "history": edit.history()}

        def changed_only_own(edit, foreign, action):
            before, untouched = state(edit), state(foreign)
            unrelated_receipts = [tuple(row) for row in service.store.conn.execute(
                "SELECT * FROM command_idempotency WHERE NOT (command_kind='timeline.commit' AND aggregate_id=?) "
                "ORDER BY command_kind, aggregate_id, idempotency_key", (canonical_json([edit.project, edit.timeline]),))]
            next_seq = service.store.conn.execute("SELECT next_seq FROM project_sequences WHERE project_id=?",
                                                  (edit.project,)).fetchone()[0]
            accepted = action()
            assert state(foreign) == untouched
            assert [tuple(row) for row in service.store.conn.execute(
                "SELECT * FROM command_idempotency WHERE NOT (command_kind='timeline.commit' AND aggregate_id=?) "
                "ORDER BY command_kind, aggregate_id, idempotency_key", (canonical_json([edit.project, edit.timeline]),))] == unrelated_receipts
            after = state(edit)
            receipt = accepted["receipt"]
            assert receipt["project_id"] == edit.project
            assert receipt["project_seq"] == [next_seq, next_seq]
            assert service.store.conn.execute("SELECT next_seq FROM project_sequences WHERE project_id=?",
                                              (edit.project,)).fetchone()[0] == next_seq + 1
            assert after["head"] == {"revision_id": accepted["data"]["accepted_revision_id"],
                                     "publication_id": receipt["receipt_id"]}
            assert after["history"][:-1] == before["history"]
            assert after["history"][-1]["receipt"] == receipt
            assert after["sql"]["timeline_events"][:len(before["sql"]["timeline_events"])] == before["sql"]["timeline_events"]
            assert [str(row[0]) for row in after["sql"]["timeline_events"][len(before["sql"]["timeline_events"]):]] == receipt["event_ids"]
            edit.assert_readback(accepted)
            original = originals[edit.project]
            for family in ("shot_revisions", "internal_timeline_revisions", "dependency_manifest"):
                assert accepted["data"]["canonical_document"][family] == original[family]
            payload = accepted["data"]["canonical_document"]["parent_revision"]["payload"]
            baseline = original["parent_revision"]["payload"]
            assert payload["occurrences"] == baseline["occurrences"]
            assert payload["registry"] == baseline["registry"]
            for container, source in ((payload, baseline), (payload["config"], baseline["config"])):
                assert [clip["id"] for clip in container["clips"]] == [clip["id"] for clip in source["clips"]]
                assert_json_equal(container["clips"][1], source["clips"][1])
                for field in ("id", "clipType", "asset", "hold", "track", "volume", "effects"):
                    assert container["clips"][0][field] == source["clips"][0][field]
            return accepted

        def refused(action, foreign, supplied):
            before, own_states = rows(service), (state(a), state(b))
            with pytest.raises((RuntimeErrorBase, CommitRejected)) as error:
                action()
            failure = error.value.failure if isinstance(error.value, CommitRejected) else error.value.as_dict()
            serialized = canonical_json(failure)
            # Echoed request IDs are allowed; undisclosed foreign identities/data are not.
            forbidden = {foreign.project, foreign.head()["revision_id"], foreign.head()["publication_id"],
                         foreign.document()["parent_revision"]["content_digest"]}
            for identity in forbidden:
                if identity not in canonical_json(supplied):
                    assert identity not in serialized
            assert '"canonical_document"' not in serialized
            assert '"payload"' not in serialized
            assert '"receipt"' not in serialized
            assert rows(service) == before
            assert (state(a), state(b)) == own_states
            return failure

        key = "same-project-scoped-flight"
        flights, moved = {}, {}
        for edit, foreign in ((a, b), (b, a)):
            flights[edit.project] = edit.body([edit.move("music-bed", 1)])
            moved[edit.project] = changed_only_own(edit, foreign, lambda: edit.commit(flights[edit.project], key))
            assert moved[edit.project]["data"]["canonical_document"]["parent_revision"]["payload"]["clips"][0]["at"] == 1
        assert moved[a.project]["receipt"]["receipt_id"] != moved[b.project]["receipt"]["receipt_id"]
        assert moved[a.project]["data"]["accepted_revision_id"] != moved[b.project]["data"]["accepted_revision_id"]
        for edit in (a, b):
            before = rows(service)
            assert (
                edit.commit(copy.deepcopy(flights[edit.project]), key)
                == moved[edit.project]
            )
            assert rows(service) == before
        changed = copy.deepcopy(flights[a.project])
        changed["commands"][0]["args"]["on"] = 2
        assert refused(lambda: a.commit(changed, key), b, changed)["details"]["reason"] == "idempotency_mismatch"

        commits = service._timeline_commits()[0]
        for edit, foreign in ((a, b), (b, a)):
            foreign_head = foreign.head()
            foreign_page = service.list_timeline_commits(foreign.project, foreign.timeline, limit=1, authorize=lambda: None)
            cursor = foreign_page["next_cursor"]
            assert cursor is not None
            foreign_revision = service.list_project_parent_composition_revisions(foreign.project, foreign.timeline, limit=1)
            revision_cursor = foreign_revision["next_cursor"]
            assert revision_cursor is not None
            foreign_document = foreign.document()
            shot = foreign_document["shot_revisions"][0]
            internal = foreign_document["internal_timeline_revisions"][0]
            probes = [
                (lambda: service.get_project_timeline(edit.project, foreign.timeline), foreign.timeline),
                (lambda: service.list_timeline_commits(edit.project, foreign.timeline, authorize=lambda: None), foreign.timeline),
                (lambda: service.list_timeline_commits(edit.project, edit.timeline, cursor=cursor, authorize=lambda: None), cursor),
                (lambda: service.list_project_parent_composition_revisions(edit.project, foreign.timeline), foreign.timeline),
                (lambda: service.list_project_parent_composition_revisions(edit.project, edit.timeline, cursor=revision_cursor), revision_cursor),
                (lambda: service.get_project_parent_composition_revision(edit.project, edit.timeline, foreign_head["revision_id"]), foreign_head["revision_id"]),
                (lambda: service.get_project_shot_revision(edit.project, shot["shot_id"], shot["revision_id"]), shot),
                (lambda: service.get_project_timeline_revision(edit.project, internal["timeline_id"], internal["revision_id"]), internal),
                (lambda: commits.revision_closure(edit.project, edit.timeline, foreign_head["revision_id"]), foreign_head["revision_id"]),
                (lambda: commits.history_entry(edit.project, edit.timeline, foreign_head["publication_id"]), foreign_head["publication_id"]),
                (lambda: commits.history(edit.project, edit.timeline, foreign_head), foreign_head),
                (lambda: commits.history(edit.project, edit.timeline, edit.head(), after_publication_id=foreign_head["publication_id"]), foreign_head["publication_id"]),
            ]
            for action, supplied in probes:
                refused(action, foreign, supplied)
            for base in (foreign_head, {**edit.head(), "publication_id": foreign_head["publication_id"]},
                         {**edit.head(), "revision_id": foreign_head["revision_id"]}):
                invalid = edit.body([edit.move("music-bed", 2)], base)
                refused(lambda: edit.commit(invalid, "foreign-base-" + canonical_json(base)), foreign, invalid)
            invalid = edit.body([inverse(foreign_head["publication_id"])])
            refused(lambda: edit.commit(invalid, "foreign-inverse"), foreign, invalid)

            def restore(source, key):
                current = edit.head()
                return service.restore_project_parent_composition_revision(
                    edit.project, edit.timeline, source,
                    {"expected_head": current["revision_id"], "expected_publication_id": current["publication_id"]},
                    idempotency_key=key, publisher="integration-editor", authorize=lambda: None,
                    invocation_path=route_path(edit.project, edit.timeline, f"composition-revisions/{source}/restore"),
                )

            refused(lambda: restore(foreign_head["revision_id"], "foreign-restore"), foreign, foreign_head["revision_id"])
            undone = changed_only_own(edit, foreign, lambda: edit.commit(
                edit.body([inverse(moved[edit.project]["receipt"]["receipt_id"])]), "own-inverse"))
            assert edit.history()[-1]["records"]["undo_of"] == [moved[edit.project]["receipt"]["receipt_id"]]
            assert_json_equal(undone["data"]["canonical_document"]["parent_revision"]["payload"],
                              originals[edit.project]["parent_revision"]["payload"])
            restored = changed_only_own(edit, foreign, lambda: restore(moved[edit.project]["data"]["accepted_revision_id"], "own-restore"))
            assert_json_equal(restored["data"]["canonical_document"]["parent_revision"]["payload"],
                              moved[edit.project]["data"]["canonical_document"]["parent_revision"]["payload"])
            assert edit.history()[-1]["records"]["restored_from"] == {
                "revision_id": moved[edit.project]["data"]["accepted_revision_id"],
                "content_digest": moved[edit.project]["data"]["canonical_document"]["parent_revision"]["content_digest"],
            }
            # Original flights remain exact even after undo/restore and the other project advances.
            before = rows(service)
            assert edit.commit(copy.deepcopy(flights[edit.project]), key) == moved[edit.project]
            assert rows(service) == before
        assert service.store.integrity_report()["ok"]
    finally:
        service.close()
