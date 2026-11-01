"""D62 accept-time recorder authority and authenticated Runtime history."""
from __future__ import annotations

import copy
import json

import pytest
import test_timeline_commit_authentication as auth
import test_timeline_commit_port as port_tests

from runtime_protocol.errors import ProtocolError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_validation import digest, validate_commit_value
from runtime_protocol.util import canonical_json

service = auth.service


@pytest.fixture
def recorder(tmp_path, astrid_importable):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create
    from astrid.sdk.timeline.native_occurrence_fork import capture_occurrence_fork

    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    root = tmp_path / "recorder-realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "recorder", "name": "Recorder"})["id"]
    runtime.create_timeline(project, "film", idempotency_key="bootstrap")
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    runtime._timeline_commits()[0].bootstrap(project, "film", authorize=lambda: None)

    def document():
        commits = runtime._timeline_commits()[0]
        return commits.revision_closure(project, "film", commits.head(project, "film")["revision_id"])

    def request(command, modern):
        head = runtime._timeline_commits()[0].head(project, "film")
        body = {"api_version": 1, "project_id": project, "timeline_id": "film",
                "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"],
                "commands": [command], "source": {"via": "python"}, "dry_run": False}
        if modern:
            body.update(label="Fork", merge="fields", reads=[], steps=[{
                "id": "fork", "label": "Fork", "intent": "Fork occurrence", "tags": [],
                "command_ordinals": [0], "patch": [], "reads": []}])
        return body

    def publish(body, key):
        return runtime.commit_timeline(project, "film", body, idempotency_key=key, publisher="editor",
                                       invocation_path=route_path(project, "film"), authorize=lambda: None)

    try:
        track = capture_track_create(bundle_from_document(document()), "parent", {"id": "picture", "kind": "visual"})
        publish(request(track, False), "track")
        birth = capture_occurrence_create(bundle_from_document(document()), "opening", "source-shot",
                                          name="Opening", track="picture", on=0, duration=5)
        publish(request(birth, False), "birth")

        def fork(modern):
            command = capture_occurrence_fork(bundle_from_document(document()), "occurrence:opening", "fork-shot")
            return request(command, modern)

        yield runtime, project, fork, publish
    finally:
        runtime.close()


@pytest.mark.parametrize("abi", [1, 2])
def test_genuine_fork_recorder_authority_history_and_exact_retry(recorder, abi):
    runtime, project, fork, publish = recorder
    submitted = fork(abi == 2)
    result = publish(submitted, "fork")
    entry = runtime._timeline_commits()[0].history_entry(project, "film", result["receipt"]["receipt_id"])
    assert result["data"]["status"] == "accepted"
    assert publish(submitted, "fork") == result
    assert entry.get("recorder_abi", 1) == abi


@pytest.mark.parametrize("value", [1, 2, 0, 3, True, False, None, "2", 2.0, {}, []])
def test_caller_cannot_supply_recorder_authority(recorder, value):
    runtime, _project, fork, publish = recorder
    submitted = fork(True)
    submitted["recorder_abi"] = value
    before = tuple(runtime.store.conn.iterdump())
    with pytest.raises(RuntimeErrorBase):
        publish(submitted, "spoof")
    assert tuple(runtime.store.conn.iterdump()) == before


@pytest.mark.parametrize("value", [1, 0, 3, True, False, None, "2", 2.0, {}, []])
def test_history_authority_requires_accepted_event_commitment(recorder, value):
    runtime, project, fork, publish = recorder
    submitted = fork(True)
    result = publish(submitted, "fork")
    publication = result["receipt"]["receipt_id"]
    metadata = json.loads(runtime.store.conn.execute(
        "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?", (publication,),
    ).fetchone()[0])
    metadata["recorder_abi"] = copy.deepcopy(value)
    runtime.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        runtime._timeline_commits()[0].history_entry(project, "film", publication)


@pytest.mark.parametrize("full_rewrite", [False, True])
def test_through_and_through_legacy_submission_is_classified_as_abi_one(recorder, monkeypatch, full_rewrite):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, project, fork, publish = recorder
    submitted = fork(True)
    accept = RequestCommitPort.accept
    reached = []

    def attack(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        assert record["command"]["op"] == "occurrence.fork"
        assert any("physical_ref" in binding for binding in record["bindings"])
        legacy_keys = {"key", "ref", "policy", "dependencies"}
        record["bindings"] = [
            {key: item for key, item in binding.items() if key in legacy_keys}
            for binding in record["bindings"]
            if not full_rewrite or binding["key"] != "commit.effect"
        ]
        validate_commit_value(value, "PreparedCommit")
        reached.append(value)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", attack)
    result = publish(submitted, "stripped")
    assert reached
    entry = runtime._timeline_commits()[0].history_entry(project, "film", result["receipt"]["receipt_id"])
    assert entry["recorder_abi"] == 1
    assert publish(submitted, "stripped") == result


@pytest.mark.parametrize("private_capture", [False, True])
@pytest.mark.parametrize("omitted", ["fork.source", "native_bindings", "reads", "selections"])
def test_native_coverage_omissions_at_submit_keep_abi_two(
        recorder, monkeypatch, private_capture, omitted):
    """D62 defers submit completeness; surviving physical records remain ABI2."""
    from runtime_protocol.timeline_commit_port import RequestCommitPort
    from runtime_protocol.timeline_commit_validation import digest

    runtime, project, fork, publish = recorder
    submitted = fork(True)
    for key in ("resolved", "reads", "selections", "bindings", "expect", "authorship"):
        submitted["commands"][0].pop(key, None)
    validate_commit_value(submitted, "CommitRequest")
    accept = RequestCommitPort.accept
    reached = []

    def attack(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        assert {binding["key"] for binding in record["bindings"] if binding["key"] != "commit.effect"} == {
            "collection.owner:collection.clips", "collection.owner:collection.tracks", "fork.source", "fork.owner"}
        if omitted in {"fork.source", "native_bindings"}:
            record["bindings"] = [binding for binding in record["bindings"]
                                  if binding["key"] != omitted and (
                                      omitted != "native_bindings" or binding["key"] == "commit.effect")]
            if omitted == "native_bindings":
                record["command"]["bindings"] = {}
        else:
            assert record[omitted]
            record[omitted] = []
            record["command"][omitted] = []
        assert record["bindings"] and all("physical_ref" in binding for binding in record["bindings"])
        effects = [binding for binding in record["bindings"] if binding["key"] == "commit.effect"]
        assert len(effects) == sum(
            int(change["before"]["state"] == "present") + int(change["op"] != "remove")
            for change in value["records"]["steps"][0]["patch"])
        validate_commit_value(value, "PreparedCommit")
        if private_capture:
            context = port._provider_context()
            head = value["expected_head"]
            assert head == {"revision_id": submitted["base_revision_id"],
                            "publication_id": submitted["base_publication_id"]}
            execution = {"evaluated_head": head, "records": copy.deepcopy(value["records"]), "commands": [{
                "boundary": {"base_revision_id": submitted["base_revision_id"],
                             "base_publication_id": submitted["base_publication_id"],
                             "evaluated_head": head, "step_id": value["records"]["steps"][0]["id"],
                             "command_ordinal": 0, "phase": "input"},
                "input": port.revision_closure(head["revision_id"]),
                "output": copy.deepcopy(value["canonical_document"])}]}
            port.capture_sequential_execution({
                "schema_version": 1, "context": context,
                "original": copy.deepcopy(execution), "landing": copy.deepcopy(execution),
                "replay_bindings": [], "prepared_digest": digest(value)})
        reached.append(value)
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", attack)
    result = publish(submitted, "missing-native-coverage")
    assert reached
    entry = runtime._timeline_commits()[0].history_entry(project, "film", result["receipt"]["receipt_id"])
    assert entry["recorder_abi"] == 2
    assert entry["records"] == reached[0]["records"]
    assert publish(submitted, "missing-native-coverage") == result


def test_supported_genuine_legacy_acceptance_remains_replayable_after_restart(recorder):
    runtime, project, _fork, _publish = recorder
    commits = runtime._timeline_commits()[0]
    head = commits.head(project, "film")
    before = commits.history(project, "film", head)
    recorded = [entry for entry in before["items"] if entry["intent"] == "recorded"]
    assert [entry["records"]["commands"][0]["command"]["op"] for entry in recorded] == [
        "track.create", "occurrence.create"]
    assert all(entry.get("recorder_abi", 1) == 1 for entry in recorded)
    assert all(entry["source"] == {"via": "python"} for entry in recorded)
    root = runtime.store.root
    runtime.close()
    restarted = RuntimeService(root)
    try:
        assert restarted._timeline_commits()[0].history(project, "film", head) == before
    finally:
        restarted.close()


def test_legacy_history_cannot_acquire_injected_mode_two(recorder):
    runtime, project, _fork, _publish = recorder
    commits = runtime._timeline_commits()[0]
    publication = commits.head(project, "film")["publication_id"]
    entry = commits.history_entry(project, "film", publication)
    assert entry["records"]["commands"][0]["command"]["op"] == "occurrence.create"
    assert entry["recorder_abi"] == 1
    metadata = json.loads(runtime.store.conn.execute(
        "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?", (publication,),
    ).fetchone()[0])
    metadata["recorder_abi"] = 2
    runtime.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        commits.history_entry(project, "film", publication)


def _stored_acceptance(runtime, publication):
    edge = runtime.store.conn.execute(
        "SELECT * FROM timeline_commit_history WHERE publication_id=?", (publication,),
    ).fetchone()
    row = runtime.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE txn_id=?", (publication,),
    ).fetchone()
    event = runtime.store.conn.execute(
        "SELECT * FROM timeline_events WHERE id=?", (json.loads(row["event_ids_json"])[-1],),
    ).fetchone()
    return edge, row, event


def _replace_event(runtime, event, payload):
    # Rehash this final event to isolate correspondence checks from chain checks.
    hashed = {"timeline_id": event["timeline_id"], "kind": event["kind"], "payload": payload,
              "previous_hash": event["previous_hash"], "created_at": event["created_at"]}
    runtime.store.conn.execute("UPDATE timeline_events SET payload_json=?, event_hash=? WHERE id=?",
                               (canonical_json(payload), digest(hashed)[7:], event["id"]))


@pytest.mark.parametrize("abi", [1, 2])
@pytest.mark.parametrize("moved", [False, True])
def test_accept_and_merge_freeze_mode_and_bind_exact_records_request_and_metadata(service, abi, moved):
    submitted = auth.body(service) if abi == 2 else port_tests.request(service, label="Unchanged")
    if moved:
        auth.commit(service, port_tests.request(service), key="advance")
    if abi == 2:
        auth.provider(service)
    else:
        service.test_provider.action = lambda context, port: port.accept(port_tests.prepared(context, port, same=True))
    result = auth.commit(service, submitted)
    assert result["data"]["status"] == ("merged" if moved else "accepted")
    publication = result["receipt"]["receipt_id"]
    edge, row, event = _stored_acceptance(service, publication)
    metadata, payload = json.loads(edge["metadata_json"]), json.loads(event["payload_json"])
    assert metadata["recorder_abi"] == payload["recorder_abi"] == abi
    assert payload["records_digest"] == digest(json.loads(edge["records_json"]))
    assert payload["request_hash"] == row["request_hash"] == result["receipt"]["request_hash"]
    assert payload["metadata_digest"] == digest(metadata)
    assert "recorder_abi" not in result["data"]
    before = port_tests.rows(service)
    assert auth.commit(service, submitted) == result
    assert port_tests.rows(service) == before
    commits = service._timeline_commits()[0]
    history = commits.history_entry(service.test_project, "main", publication)
    assert history["recorder_abi"] == abi
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        setattr(restarted, "test_project", service.test_project)
        assert auth.commit(restarted, submitted) == result
        assert restarted._timeline_commits()[0].history_entry(service.test_project, "main", publication) == history
    finally:
        restarted.close()


def test_genuine_v2_preview_does_not_persist_recorder_authority(recorder):
    runtime, _project, fork, publish = recorder
    submitted = fork(True)
    submitted["dry_run"] = True
    before = tuple(runtime.store.conn.iterdump())
    result = publish(submitted, "preview")
    assert result["data"]["status"] == "preview"
    assert result["data"]["would_status"] == "accepted"
    assert result["receipt"] is None
    assert "recorder_abi" not in result["data"]
    assert tuple(runtime.store.conn.iterdump()) == before


@pytest.mark.parametrize("value", [1, 2])
def test_provider_cannot_supply_recorder_authority(service, value):
    def inject(prepared):
        prepared["recorder_abi"] = value

    auth.provider(service, inject)
    before = port_tests.rows(service)
    with pytest.raises(RuntimeErrorBase):
        auth.commit(service, auth.body(service))
    assert port_tests.rows(service) == before


@pytest.mark.parametrize("abi", [1, 2])
def test_prechange_both_absent_is_legacy_without_reclassifying_records(service, abi):
    submitted = auth.body(service) if abi == 2 else port_tests.request(service)
    if abi == 2:
        auth.provider(service)
    result = auth.commit(service, submitted)
    publication = result["receipt"]["receipt_id"]
    edge, _row, event = _stored_acceptance(service, publication)
    metadata, payload = json.loads(edge["metadata_json"]), json.loads(event["payload_json"])
    metadata.pop("recorder_abi")
    for key in ("recorder_abi", "request_hash", "metadata_digest"):
        payload.pop(key)
    service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    _replace_event(service, event, payload)
    entry = service._timeline_commits()[0].history_entry(service.test_project, "main", publication)
    assert entry.get("recorder_abi", 1) == 1
    assert auth.commit(service, submitted) == result
    # Old metadata alone cannot introduce authority, even on physical records.
    metadata["recorder_abi"] = 2
    service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        service._timeline_commits()[0].history_entry(service.test_project, "main", publication)


@pytest.mark.parametrize("damage", [
    "metadata_absent", "event_absent", "both_absent", "event_mode", "request_hash", "metadata_digest",
    "metadata_label", "records", "earlier_event", "private_capture",
])
def test_mode_commitment_rejects_unilateral_removal_and_metadata_records_or_chain_tamper(service, damage):
    if damage == "private_capture":
        from test_timeline_commit_sequential_verifier import _provider_with_capture
        _provider_with_capture(service)
    else:
        auth.provider(service)
    submitted = auth.body(service)
    result = auth.commit(service, submitted)
    publication = result["receipt"]["receipt_id"]
    edge, _row, event = _stored_acceptance(service, publication)
    metadata, payload = json.loads(edge["metadata_json"]), json.loads(event["payload_json"])
    if damage in {"metadata_absent", "both_absent"}:
        metadata.pop("recorder_abi")
    if damage in {"event_absent", "both_absent"}:
        payload.pop("recorder_abi")
    if damage == "event_mode":
        payload["recorder_abi"] = 1
    if damage == "request_hash":
        payload["request_hash"] = "0" * 64
    if damage == "metadata_digest":
        payload["metadata_digest"] = "sha256:" + "0" * 64
    if damage == "metadata_label":
        metadata["label"] = "Different label"
    if damage == "private_capture":
        metadata.pop("_sequential_execution")
    if damage == "records":
        records = json.loads(edge["records_json"])
        records["commands"][0]["bindings"][0]["policy"] = "different"
        service.store.conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                                   (canonical_json(records), publication))
    if damage == "earlier_event":
        service.store.conn.execute("UPDATE timeline_events SET event_hash=? WHERE id=("
                                   "SELECT MIN(id) FROM timeline_events WHERE timeline_id='main')", ("0" * 64,))
    service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                               (canonical_json(metadata), publication))
    _replace_event(service, event, payload)
    before = port_tests.rows(service)
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        service._timeline_commits()[0].history_entry(service.test_project, "main", publication)
    with pytest.raises(RuntimeErrorBase):
        auth.commit(service, submitted)
    assert port_tests.rows(service) == before


@pytest.mark.parametrize("side", ["event", "both"])
@pytest.mark.parametrize("value", [0, 3, True, False, None, "2", 2.0, {}, []])
def test_event_mode_requires_integer_enum_even_with_rehashed_event(service, side, value):
    auth.provider(service)
    result = auth.commit(service, auth.body(service))
    publication = result["receipt"]["receipt_id"]
    edge, _row, event = _stored_acceptance(service, publication)
    metadata, payload = json.loads(edge["metadata_json"]), json.loads(event["payload_json"])
    payload["recorder_abi"] = copy.deepcopy(value)
    if side == "both":
        metadata["recorder_abi"] = copy.deepcopy(value)
        payload["metadata_digest"] = digest(metadata)
        service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                                   (canonical_json(metadata), publication))
    _replace_event(service, event, payload)
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        service._timeline_commits()[0].history_entry(service.test_project, "main", publication)


@pytest.mark.parametrize("full_rewrite", [False, True])
def test_postaccept_stripping_and_fullrewrite_cannot_downgrade_frozen_mode(recorder, full_rewrite):
    runtime, project, fork, publish = recorder
    result = publish(fork(True), "fork")
    publication = result["receipt"]["receipt_id"]
    commits = runtime._timeline_commits()[0]
    entry = commits.history_entry(project, "film", publication)
    assert entry["recorder_abi"] == 2
    for record in entry["records"]["commands"]:
        legacy_keys = {"key", "ref", "policy", "dependencies"}
        record["bindings"] = [{key: value for key, value in binding.items() if key in legacy_keys}
                              for binding in record["bindings"]
                              if not full_rewrite or binding["key"] != "commit.effect"]
    assert entry["recorder_abi"] == 2
    assert commits.history_entry(project, "film", publication)["recorder_abi"] == 2
    runtime.store.conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                               (canonical_json(entry["records"]), publication))
    with pytest.raises(ProtocolError, match="accepted commit record is corrupt"):
        commits.history_entry(project, "film", publication)
