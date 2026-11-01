"""Request-private original/landing execution carrier checks."""
from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_timeline_commit_authentication as auth

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected, StaleHead
from runtime_protocol.timeline_commit_auth import validate, validate_sequential_capture
from runtime_protocol.timeline_commit_validation import digest

service = auth.service


def _capture(context, port, prepared):
    request = context["request"]
    base = port.revision_closure(request["base_revision_id"])
    head = prepared["expected_head"]
    current = port.revision_closure(head["revision_id"])
    output = prepared["canonical_document"]
    boundary = {
        "base_revision_id": request["base_revision_id"],
        "base_publication_id": request["base_publication_id"],
        "evaluated_head": head,
        "step_id": prepared["records"]["steps"][0]["id"],
        "command_ordinal": 0,
        "phase": "input",
    }
    execution = {
        "evaluated_head": head,
        "commands": [{"boundary": boundary, "input": current, "output": output}],
        "records": copy.deepcopy(prepared["records"]),
    }
    original = copy.deepcopy(execution)
    original["evaluated_head"] = {
        "revision_id": request["base_revision_id"],
        "publication_id": request["base_publication_id"],
    }
    original["commands"][0]["boundary"]["evaluated_head"] = original["evaluated_head"]
    original["commands"][0]["input"] = base
    return {
        "schema_version": 1,
        "context": copy.deepcopy(context),
        "original": original,
        "landing": execution,
        "replay_bindings": [],
        "prepared_digest": digest(prepared),
    }


def _provider_with_capture(service, mutate=None):
    def execute(context, port):
        prepared = auth.candidate(context, port)
        capture = _capture(context, port, prepared)
        if mutate is not None:
            mutate(capture, prepared)
        port.capture_sequential_execution(capture)
        return port.accept(prepared)

    service.test_provider.action = execute


def test_private_sequential_carrier_accepts_authenticated_candidate(service):
    _provider_with_capture(service)
    result = auth.commit(service, auth.body(service), key="sequential-private-positive")
    assert result["data"]["status"] == "accepted"


def test_private_sequential_history_survives_restart_and_exact_retry(service):
    from runtime_protocol.service import RuntimeService

    _provider_with_capture(service)
    submitted = auth.body(service)
    result = auth.commit(service, submitted)
    project, root = service.test_project, service.store.root
    history = service.list_timeline_commits(project, "main", authorize=lambda: None)
    assert all("_sequential_execution" not in entry for entry in history["items"])
    metadata = json.loads(service.store.conn.execute(
        "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?",
        (result["receipt"]["receipt_id"],),
    ).fetchone()[0])
    assert metadata["_sequential_execution"]["capture"]["context"]["request"] == submitted
    assert "request_id" not in metadata["_sequential_execution"]["capture"]["context"]
    before = auth.rows(service)
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        assert auth.commit(restarted, submitted) == result
        assert restarted._timeline_commit_provider is None
        assert restarted.list_timeline_commits(project, "main", authorize=lambda: None) == history
        assert auth.rows(restarted) == before
    finally:
        restarted.close()


@pytest.mark.parametrize("damage", [
    "realm_id", "publisher", "idempotency_key", "request_hash", "invocation", "request",
    "prepared", "original_input", "original_effect", "landing", "replay_map",
])
def test_private_sequential_history_revalidates_retained_facts(service, damage):
    from runtime_protocol.errors import ProtocolError
    from runtime_protocol.util import canonical_json

    _provider_with_capture(service)
    submitted = auth.body(service)
    result = auth.commit(service, submitted)
    publication = result["receipt"]["receipt_id"]
    metadata = json.loads(service.store.conn.execute(
        "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?", (publication,),
    ).fetchone()[0])
    execution = metadata["_sequential_execution"]
    capture = execution["capture"]
    if damage in {"realm_id", "publisher", "idempotency_key", "request_hash"}:
        capture["context"][damage] = "forged"
    elif damage == "invocation":
        capture["context"]["invocation"]["path"] += "/forged"
    elif damage == "request":
        capture["context"]["request"]["label"] = "forged"
    elif damage == "prepared":
        execution["prepared"]["id_map"] = {"forged": "forged"}
        capture["prepared_digest"] = digest(execution["prepared"])
    elif damage == "original_input":
        image = capture["original"]["commands"][0]["input"]["parent_revision"]
        image["payload"]["meta"] = {"forged": True}
        image["content_digest"] = digest(image["payload"])
    elif damage == "original_effect":
        capture["original"]["records"]["commands"][0]["writes"][0]["after"]["value"] = {"forged": True}
    elif damage == "landing":
        capture["landing"]["records"]["commands"][0]["bindings"] = []
    else:
        capture["replay_bindings"].append({"kind": "forged"})
    service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, submitted)
    assert isinstance(error.value.__cause__, ProtocolError)
    assert str(error.value.__cause__) == "accepted commit record is corrupt"
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
    assert auth.rows(service) == before


def test_private_sequential_carrier_rejects_context_tampering_without_write(service):
    def mutate(capture, _prepared):
        capture["context"]["idempotency_key"] = "other-request"

    _provider_with_capture(service, mutate)
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, auth.body(service), key="sequential-private-context")
    assert error.value.details is not None
    assert error.value.details["reason"] == "invocation_mismatch"
    assert auth.rows(service) == before


def test_private_sequential_carrier_rejects_prepared_digest_and_boundary_tampering(service):
    def mutate(capture, prepared):
        if prepared["records"]["label"] == "digest":
            capture["prepared_digest"] = digest({"forged": True})
        else:
            capture["landing"]["commands"][0]["input"] = copy.deepcopy(capture["original"]["commands"][0]["input"])
            capture["landing"]["commands"][0]["input"]["parent_revision"]["content_digest"] = "sha256:" + "0" * 64

    for damage in ("digest", "input"):
        request = auth.body(service)
        request["label"] = damage
        _provider_with_capture(service, mutate)
        before = auth.rows(service)
        with pytest.raises(RuntimeErrorBase) as error:
            auth.commit(service, request, key="sequential-private-" + damage)
        assert error.value.details is not None
        assert error.value.details["reason"] == "invalid_records"
        assert auth.rows(service) == before


def test_private_sequential_carrier_rejects_parent_revision_forgery_with_equal_payload_digest(service):
    def mutate(capture, _prepared):
        image = capture["landing"]["commands"][0]["input"]["parent_revision"]
        payload, content_digest = copy.deepcopy(image["payload"]), image["content_digest"]
        image["revision_id"] = "forged-parent-revision"
        assert image["payload"] == payload and image["content_digest"] == content_digest

    _provider_with_capture(service, mutate)
    submitted = auth.body(service)
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, submitted, key="sequential-private-parent-revision")
    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert auth.rows(service) == before


def test_private_sequential_carrier_rejects_boolean_command_ordinal(service):
    def mutate(capture, _prepared):
        capture["landing"]["commands"][0]["boundary"]["command_ordinal"] = True

    _provider_with_capture(service, mutate)
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, auth.body(service), key="sequential-private-bool-ordinal")
    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert auth.rows(service) == before


def test_private_sequential_carrier_is_one_attempt_and_does_not_extend_history(service):
    def execute(context, port):
        prepared = auth.candidate(context, port)
        capture = _capture(context, port, prepared)
        port.capture_sequential_execution(capture)
        prepared["records"]["label"] = "forged-after-capture"
        return port.accept(prepared)

    service.test_provider.action = execute
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, auth.body(service), key="sequential-private-attempt")
    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert auth.rows(service) == before


def test_moved_head_staged_alias_without_private_proof_fails_closed(service):
    def execute(context, port):
        prepared = auth.candidate(context, port)
        binding = prepared["records"]["commands"][0]["bindings"][0]
        binding["ref"] = "internal-revision:staged-unlanded"
        binding["physical_ref"] = "internal-revision:staged-unlanded"
        return port.accept(prepared)

    service.test_provider.action = execute
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, auth.body(service), key="sequential-private-missing")
    assert error.value.details is not None
    assert error.value.details["reason"] == "sequential_proof_unavailable"
    assert auth.rows(service) == before


@pytest.fixture
def captured_sequence():
    # Actual Agent 1403 capture-1-0 from retained packet SHA-256 59e329b65a9b83c3.
    # Transport evidence only: this fixture does not qualify a production join.
    return json.loads((Path(__file__).parent / "fixtures/timeline_sequential_capture.json").read_text())


def _verify_packet(packet):
    continuations = {}
    entries = {entry["publication_id"]: entry for entry in packet["history"]["items"]}
    cursor = packet["history"]["head"]
    while cursor["publication_id"] != packet["request"]["base_publication_id"]:
        entry = entries[cursor["publication_id"]]
        for record in (entry["records"] or {}).get("commands", []):
            for binding in record["bindings"]:
                if binding.get("key") == "commit.materialization":
                    continuations.setdefault(binding["physical_ref"], set()).add(binding["successor"])
        cursor = entry["previous"]
    proof = validate_sequential_capture(packet["request"], packet["prepared"], packet["capture"],
                                        packet["head_document"], packet["source"], continuations)
    validate(packet["request"], packet["prepared"], packet["head_document"], packet["source"],
             continuations, sequential=proof)


def test_retained_real_capture_runs_both_verification_stages(captured_sequence):
    before = copy.deepcopy(captured_sequence)
    _verify_packet(captured_sequence)
    assert captured_sequence == before


def test_moved_history_replays_authenticated_original_and_landing(captured_sequence, monkeypatch):
    from runtime_protocol.errors import ProtocolError
    from runtime_protocol.timeline_commit_store import (
        TimelineCommitStore,
        _history_metadata,
    )
    from runtime_protocol.util import canonical_json

    packet = captured_sequence
    prepared, request, capture = packet["prepared"], packet["request"], packet["capture"]
    previous = prepared["expected_head"]
    assert previous["publication_id"] != request["base_publication_id"]
    document, records = prepared["canonical_document"], prepared["records"]
    publisher = capture["context"]["publisher"]
    data = {key: value for key, value in prepared.items() if key not in {"records", "semantic_events", "expected_head"}}
    data.update(status="merged", base_revision_id=request["base_revision_id"],
                base_publication_id=request["base_publication_id"], previous_revision_id=previous["revision_id"],
                previous_publication_id=previous["publication_id"], rebased_onto=previous,
                accepted_revision_id=document["parent_revision"]["revision_id"], publisher=publisher,
                commands=[record["command"] for record in records["commands"]],
                steps=records["steps"], label=records["label"], merge_mode=records["merge_mode"])
    data.update({key: request[key] for key in ("source", "rationale", "group_id")})
    metadata = _history_metadata(request, data)
    metadata["_sequential_execution"] = {"capture": capture, "prepared": prepared}
    event = {"timeline_id": request["timeline_id"], "kind": "timeline.commit.accepted",
             "payload": {"project_id": request["project_id"], "timeline_id": request["timeline_id"],
                         "previous": previous, "revision_id": data["accepted_revision_id"],
                         "publisher": publisher, "intent": "recorded", "records_digest": digest(records)},
             "previous_hash": "", "created_at": "2026-10-23T00:00:00Z"}
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE projects (id TEXT, realm_id TEXT);
            CREATE TABLE project_sequences (project_id TEXT, next_seq INTEGER);
            CREATE TABLE timeline_events (id INTEGER, timeline_id TEXT, kind TEXT, payload_json TEXT,
                                          previous_hash TEXT, event_hash TEXT, created_at TEXT);
        """)
        connection.execute("INSERT INTO projects VALUES (?, ?)",
                           (request["project_id"], capture["context"]["realm_id"]))
        connection.execute("INSERT INTO project_sequences VALUES (?, 2)", (request["project_id"],))
        connection.execute("INSERT INTO timeline_events VALUES (1, ?, ?, ?, '', ?, ?)",
                           (event["timeline_id"], event["kind"], canonical_json(event["payload"]),
                            digest(event)[7:], event["created_at"]))
        store = TimelineCommitStore(SimpleNamespace(conn=connection), validate_prepared=lambda _: None)
        closures = {value["parent_revision"]["revision_id"]: value for value in
                    (packet["source"], packet["head_document"], document)}
        monkeypatch.setattr(store, "revision_closure", lambda project, timeline, revision, **kw: closures[revision])
        continuations = {}
        for entry in packet["history"]["items"]:
            for record in (entry["records"] or {}).get("commands", []):
                for binding in record["bindings"]:
                    if binding.get("key") == "commit.materialization":
                        continuations.setdefault(binding["physical_ref"], set()).add(binding["successor"])
        monkeypatch.setattr(store, "_binding_continuations", lambda *args, **kw: continuations)
        monkeypatch.setattr(store, "_inverse_stage_history", lambda *args, **kw: {})
        edge = {"project_id": request["project_id"], "timeline_id": request["timeline_id"],
                "intent": "recorded", "publication_id": "accepted-sequence", "project_seq": 1,
                "previous_revision_id": previous["revision_id"], "previous_publication_id": previous["publication_id"],
                "revision_id": data["accepted_revision_id"], "publisher": publisher,
                "provider_version": data["provider_version"], "compiler_version": data["compiler_version"],
                "records_json": canonical_json(records), "metadata_json": canonical_json(metadata)}
        row = {"command_kind": "timeline.commit", "txn_id": edge["publication_id"],
               "aggregate_id": canonical_json([request["project_id"], request["timeline_id"]]),
               "primary_stream_id": request["timeline_id"], "first_project_seq": 1, "last_project_seq": 1,
               "resulting_stream_seq": 1, "event_ids_json": '["1"]', "result_json": canonical_json(data),
               "request_hash": capture["context"]["request_hash"],
               "idempotency_key": capture["context"]["idempotency_key"]}
        # Only the enclosing accepted receipt/event is constructed here. The
        # original, landing, BASE, HEAD and preceding edge are real captures.
        store._verify_accepted(row, edge)
        metadata.pop("_sequential_execution")
        edge["metadata_json"] = canonical_json(metadata)
        with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
            store._verify_accepted(row, edge)


@pytest.mark.parametrize("damage", ["omitted", "duplicate", "future", "owner", "terminal",
                                   "bool", "negative", "past_end", "malformed"])
def test_retained_real_capture_rejects_replay_forgery(captured_sequence, damage):
    replay = captured_sequence["capture"]["replay_bindings"]
    entry = replay[-1]
    if damage == "omitted":
        replay.pop()
    elif damage == "duplicate":
        replay.append(copy.deepcopy(entry))
    elif damage == "future":
        entry["source"]["step_id"] = "second"
    elif damage == "owner":
        entry["source"].update(owner="occurrence:foreign/shot", owners=["occurrence:foreign/shot"])
    elif damage == "terminal":
        entry["source"]["source"] = "internal-revision:foreign"
    elif damage == "malformed":
        entry["source"]["owners"] = {"owner": True}
    else:
        entry["command_ordinal"] = {"bool": True, "negative": -1, "past_end": 2}[damage]
    with pytest.raises(CommitRejected):
        _verify_packet(captured_sequence)


@pytest.mark.parametrize("side", ["original", "landing"])
@pytest.mark.parametrize("damage", ["record", "snapshot", "source"])
def test_coordinated_capture_record_map_and_digest_forgery(captured_sequence, side, damage):
    capture = captured_sequence["capture"]
    execution = capture[side]
    if damage == "record":
        # Keep both public recorder copies and the envelope digest in agreement.
        for record in execution["records"]["commands"]:
            for binding in record["bindings"]:
                if binding.get("key") == "commit.materialization":
                    binding["edge_before"] = "shot-revision:foreign"
        if side == "landing":
            captured_sequence["prepared"]["records"] = copy.deepcopy(execution["records"])
    elif damage == "snapshot":
        # Matching adjacent snapshots with freshly computed hashes cannot invent
        # an earlier command result. The actual submitted nudge is still 4.0.
        for document in (execution["commands"][0]["output"], execution["commands"][1]["input"]):
            image = document["internal_timeline_revisions"][0]
            next(row for row in image["payload"]["clips"] if row["id"] == "cross")["at"] = 9.0
            image["content_digest"] = digest(image["payload"])
        for binding in execution["records"]["commands"][1]["bindings"]:
            if binding.get("physical_ref", "").startswith("internal-revision:"):
                binding["content_digest"] = execution["commands"][1]["input"]["internal_timeline_revisions"][0]["content_digest"]
        if side == "landing":
            captured_sequence["prepared"]["records"] = copy.deepcopy(execution["records"])
    else:
        # A coordinated source/map rewrite must still originate at the captured
        # authenticated BASE or HEAD, even when every carrier agrees with it.
        image = execution["commands"][0]["input"]["internal_timeline_revisions"][0]
        old = image["revision_id"]
        encoded = json.dumps(execution).replace(old, "forged-internal")
        execution.update(json.loads(encoded))
        for entry in capture["replay_bindings"]:
            entry["source"] = json.loads(json.dumps(entry["source"]).replace(old, "forged-internal"))
        if side == "landing":
            captured_sequence["prepared"]["records"] = copy.deepcopy(execution["records"])
    capture["prepared_digest"] = digest(captured_sequence["prepared"])
    with pytest.raises(CommitRejected):
        _verify_packet(captured_sequence)


@pytest.mark.parametrize("damage", ["schema_bool", "binding_bool", "effect_bool", "effect_float", "missing_record_field",
                                   "bad_image", "bad_binding"])
def test_private_capture_malformed_json_has_a_structured_refusal(service, damage):
    def mutate(capture, prepared):
        if damage == "schema_bool":
            capture["schema_version"] = True
        elif damage == "binding_bool":
            capture["original"]["records"]["commands"][0]["bindings"][0]["boundary"]["command_ordinal"] = False
        elif damage in {"effect_bool", "effect_float"}:
            capture["original"]["records"]["commands"][0]["bindings"][0]["effect_ordinal"] = True if damage == "effect_bool" else 0.0
        elif damage == "missing_record_field":
            capture["original"]["records"]["commands"][0].pop("writes")
        elif damage == "bad_image":
            capture["original"]["commands"][0]["input"]["shot_revisions"] = [None]
        else:
            capture["original"]["records"]["commands"][0]["bindings"] = [None]

    _provider_with_capture(service, mutate)
    before = auth.rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        auth.commit(service, auth.body(service), key="malformed-sequential-" + damage)
    assert error.value.status < 500
    assert auth.rows(service) == before


@pytest.mark.parametrize("kind", ["read", "patch", "change"])
@pytest.mark.parametrize("ordinal", [-1, 2, True])
def test_real_capture_rejects_all_replay_ordinal_ranges(captured_sequence, kind, ordinal):
    entry = next(entry for entry in captured_sequence["capture"]["replay_bindings"]
                 if entry["kind"] == ("patch" if kind == "change" else kind))
    entry["change_ordinal" if kind == "change" else "command_ordinal"] = ordinal
    with pytest.raises(CommitRejected):
        _verify_packet(captured_sequence)


@pytest.mark.parametrize("damage", ["nested_self", "unconsumed_original", "missing_landing"])
def test_real_capture_requires_complete_ordered_correspondence(captured_sequence, damage):
    capture = captured_sequence["capture"]
    if damage == "nested_self":
        node = capture["replay_bindings"][-1]["source"]
        node["source"] = copy.deepcopy(node)
    elif damage == "unconsumed_original":
        bindings = capture["original"]["records"]["commands"][1]["bindings"]
        bindings.append(copy.deepcopy(bindings[0]))
    else:
        capture["landing"]["records"]["commands"][1]["bindings"].pop(0)
        captured_sequence["prepared"]["records"] = copy.deepcopy(capture["landing"]["records"])
        capture["prepared_digest"] = digest(captured_sequence["prepared"])
    with pytest.raises(CommitRejected):
        _verify_packet(captured_sequence)


def test_private_capture_detaches_and_consumes_on_validation_failure(service):
    def execute(context, port):
        prepared = auth.candidate(context, port)
        capture = _capture(context, port, prepared)
        port.capture_sequential_execution(capture)
        capture["prepared_digest"] = "sha256:" + "0" * 64
        source = port.revision_closure(prepared["expected_head"]["revision_id"])
        proof = port._validate_sequential_execution(prepared, source, source, {}, None)
        assert proof is not None
        assert port._validate_sequential_execution(prepared, source, source, {}, None) is None
        port.capture_sequential_execution(capture)
        with pytest.raises(CommitRejected):
            port._validate_sequential_execution(prepared, source, source, {}, None)
        assert port._validate_sequential_execution(prepared, source, source, {}, None) is None
        return port.accept(prepared)

    service.test_provider.action = execute
    result = auth.commit(service, auth.body(service), key="sequential-detached-consumed")
    assert result["data"]["status"] == "accepted"


@pytest.mark.parametrize("failure", ["invalid", "cas"])
def test_private_capture_is_discarded_before_a_later_accept_attempt(service, monkeypatch, failure):
    def execute(context, port):
        prepared = auth.candidate(context, port)
        port.capture_sequential_execution(_capture(context, port, prepared))
        source = port.revision_closure(prepared["expected_head"]["revision_id"])
        if failure == "invalid":
            with pytest.raises(CommitRejected):
                port.accept({**prepared, "document_digest": "sha256:" + "0" * 64})
        else:
            store = port._RequestCommitPort__store
            accept = store.accept

            def stale(*_args, **_kwargs):
                raise StaleHead(prepared["expected_head"])

            with monkeypatch.context() as patch:
                patch.setattr(store, "accept", stale)
                with pytest.raises(StaleHead):
                    port.accept(prepared)
            assert store.accept == accept
        assert port._validate_sequential_execution(prepared, source, source, {}, None) is None
        return port.accept(prepared)

    service.test_provider.action = execute
    result = auth.commit(service, auth.body(service), key="sequential-attempt-" + failure)
    assert result["data"]["status"] == "accepted"


@pytest.fixture
def three_products_seed(tmp_path, monkeypatch):
    from astrid.sdk.client import AstridClient
    from astrid.sdk.timeline.commit import bundle_from_document
    from test_timeline_clip_replacement import (
        _native_empty_document,
        _native_import_media,
    )

    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import RealmStore
    from runtime_protocol.timeline_commit_port import route_path
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    root = tmp_path / "three-products"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    project = runtime.create_project({"slug": "three-products", "name": "Three products"})["id"]
    runtime.create_timeline(project, "main", idempotency_key="bootstrap")
    head = runtime.get_project_timeline(project, "main")
    image, image_verified = _native_import_media(runtime, project, alias="image", kind="image")
    video, video_verified = _native_import_media(runtime, project, alias="video", duration=12)
    opaque = {"owner": "f2", "nested": [1, {"k": "v"}]}
    case = {"fixture": "three-products", "initialize": True, "project_id": project,
            "timeline_id": "main", "head_revision_id": head["head_revision_id"],
            "base_publication_id": head["head_publication_id"], "reference_at": 15,
            "transitions": "ordinary", "idempotency_key": "full-seed", "actor_id": "seed-test",
            "commit_path": route_path(project, "main"), "endpoint": "offline", "credential": "unused",
            "realm_id": "offline", "acceptance_file": str(tmp_path / "accepted.json"),
            "image": {"object_id": image["object_id"], "digest": image["object_id"]},
            "video": {"file": "f2-video.mp4", "media_type": "video/mp4",
                      "object_id": video["object_id"], "digest": video["object_id"]},
            "opaque": {"config": {**opaque, "flag": True}, "clip": opaque,
                       "shot": {**opaque, "owner": "f2-shot", "flag": True}},
            "media": {key: {"pin": pin, "verified": verified} for key, pin, verified in [
                ("f2-app", image, image_verified), ("f2-video", video, video_verified),
                ("f2-plate", image, image_verified), ("f2-placeholder", image, image_verified),
                ("f2-clear", image, image_verified)]}}
    document = _native_empty_document(runtime, project, "main")
    submitted = {}

    def commit(project_id, timeline_id, body, *, idempotency_key):
        submitted.update(copy.deepcopy(body))
        result = runtime.commit_timeline(project_id, timeline_id, body, idempotency_key=idempotency_key,
                                        publisher=case["actor_id"], invocation_path=case["commit_path"],
                                        authorize=lambda: None)
        return SimpleNamespace(ok=True, as_dict=lambda: result)

    client = SimpleNamespace(timelines=SimpleNamespace(
        open_bundle=lambda *args, **kwargs: SimpleNamespace(ok=True, data={"bundle": bundle_from_document(document)}),
        commit=commit))
    monkeypatch.setattr(AstridClient, "open", lambda **kwargs: client)
    fixture = json.loads((Path(__file__).parent / "fixtures/timeline_three_products_seed.json").read_text())
    script = tmp_path / "seed.py"
    script.write_text(fixture["script"])

    def run():
        import runpy
        import sys

        monkeypatch.setattr(sys, "argv", ["seed", json.dumps(case)])
        namespace = runpy.run_path(str(script))
        return namespace["accepted"]

    try:
        yield runtime, submitted, run
    finally:
        runtime.close()


def test_public_three_products_seed_preserves_full_raw_assertions_and_history(three_products_seed):
    from runtime_protocol.service import RuntimeService
    from runtime_protocol.timeline_commit_port import route_path

    runtime, submitted, run = three_products_seed
    result = run()
    assert len(submitted["commands"]) == len(submitted["steps"]) == 21
    history = runtime.list_timeline_commits(submitted["project_id"], "main", authorize=lambda: None)
    assert history["items"][-1]["steps"] == result["data"]["steps"]
    assert result["data"]["merge_mode"] == "atomic"
    root = runtime.store.root
    runtime.close()
    restarted = RuntimeService(root)
    try:
        before = list(restarted.store.conn.iterdump())
        project = submitted["project_id"]
        assert restarted._timeline_commit_provider is None
        assert restarted.commit_timeline(
            project, "main", submitted, idempotency_key="full-seed", publisher="seed-test",
            invocation_path=route_path(project, "main"), authorize=lambda: None,
        ) == result
        assert restarted.list_timeline_commits(project, "main", authorize=lambda: None) == history
        assert list(restarted.store.conn.iterdump()) == before
    finally:
        restarted.close()


@pytest.mark.parametrize("damage", [
    "missing_batch", "missing_step", "wrong_ordinal", "foreign", "outside",
    "duplicate", "ambiguous", "tampered_source", "wrong_phase",
])
def test_public_three_products_scope_forgery_refuses_without_write(three_products_seed, monkeypatch, damage):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, _, run = three_products_seed
    capture = RequestCommitPort.capture_sequential_execution

    def forged(self, value):
        value = copy.deepcopy(value)
        for side in ("original", "landing"):
            records = value[side]["records"]["commands"]
            ordinal = 0 if damage == "missing_batch" else 8
            bindings = records[ordinal]["bindings"]
            phase = "batch-read" if damage == "missing_batch" else "input"
            binding = next(item for item in bindings if item["key"] == "commit.read"
                           and item["ref"] == "timeline" and item["boundary"]["phase"] == phase)
            if damage in {"missing_batch", "missing_step"}:
                bindings.remove(binding)
            elif damage == "wrong_ordinal":
                binding["boundary"]["command_ordinal"] = ordinal - 1
            elif damage == "foreign":
                binding["physical_ref"] = "shot-revision:foreign"
            elif damage == "outside":
                binding["ref"] = "shot-revision:outside"
            elif damage in {"duplicate", "ambiguous"}:
                extra = copy.deepcopy(binding)
                if damage == "ambiguous":
                    extra["path"] = ["meta"]
                bindings.append(extra)
            elif damage == "tampered_source":
                binding["content_digest"] = "sha256:" + "0" * 64
            else:
                binding["boundary"]["phase"] = "batch-read"
        return capture(self, value)

    monkeypatch.setattr(RequestCommitPort, "capture_sequential_execution", forged)
    before = list(runtime.store.conn.iterdump())
    with pytest.raises(RuntimeErrorBase) as error:
        run()
    assert error.value.details is not None
    assert error.value.details["reason"] == "invalid_records"
    assert list(runtime.store.conn.iterdump()) == before
