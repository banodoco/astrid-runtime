"""Forward allocation claims through the supported Agent provider and Runtime port."""
from __future__ import annotations

import copy
from typing import Any

import pytest
from test_timeline_commit_port import commit, request

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import validate_claims
from runtime_protocol.timeline_commit_port import RequestCommitPort
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider


@pytest.fixture
def runtime(tmp_path, astrid_importable, monkeypatch):
    root = tmp_path / "forward-realm"
    RealmStore.initialize(root).close()
    service: Any = RuntimeService(root)
    service.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    service.test_project = service.create_project({"slug": "forward", "name": "Forward"})["id"]
    service.create_timeline(service.test_project, "main", idempotency_key="bootstrap")
    accept, preview = RequestCommitPort.accept, RequestCommitPort.preview

    def checked_accept(port, prepared):
        result = accept(port, prepared)
        service.test_prepared = copy.deepcopy(prepared)
        return result

    def checked_preview(port, prepared):
        result = preview(port, prepared)
        service.test_prepared = copy.deepcopy(prepared)
        return result

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    monkeypatch.setattr(RequestCommitPort, "preview", checked_preview)
    try:
        yield service
    finally:
        service.close()


def command(identity="stable-track"):
    row: dict[str, Any] = {"id": identity, "kind": "visual"}
    if identity == "stable-track":
        row["opaque"] = [None, False]
    else:
        row["unknown"] = {"literal": identity, "value": None}
    return {"schema_version": 1, "op": "track.create", "version": "1",
            "select": "parent", "args": {"row": row}}


def body(runtime, call, *, v2=True, dry_run=False):
    submitted = request(runtime, commands=[call], dry_run=dry_run)
    if v2:
        submitted.update(label="Create track", merge="fields", reads=[], steps=[{
            "id": "track", "label": "Create track", "intent": "Add a track", "tags": ["forward"],
            "command_ordinals": [0], "patch": [], "reads": []}], source={"via": "python"},
            rationale="Authenticate omitted allocation claims", group_id="forward-track")
    return submitted


def snapshot(runtime):
    return tuple(runtime.store.conn.iterdump())


@pytest.mark.parametrize("identity", ["stable-track", "historical-track"])
@pytest.mark.parametrize("v2", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
def test_real_forward_omission_keeps_exact_allocations(runtime, identity, v2, dry_run):
    call = command(identity)
    submitted = body(runtime, call, v2=v2, dry_run=dry_run)
    before = snapshot(runtime)
    result = commit(runtime, submitted)
    assert "created" not in call and submitted["commands"] == [call]
    data = result["data"]
    assert data["status"] == ("preview" if dry_run else "accepted")
    assert data["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"] == [call["args"]["row"]]
    records = runtime.test_prepared["records"]
    record = records["commands"][0]
    ref = "parent/track:" + identity
    assert record["command"]["created"] == [ref]
    assert record["created"] == [{"ref": ref, "kind": "track", "owner": "parent"}]
    assert record["writes"] == [{"ref": ref, "path": [], "before": {"state": "absent"},
                                 "after": {"state": "present", "value": call["args"]["row"]}}]
    if dry_run:
        assert data["would_status"] == "accepted" and result["receipt"] is None
        assert snapshot(runtime) == before
    else:
        assert result["receipt"]["result"] == data
        assert commit(runtime, submitted) == result
        entry = runtime.list_timeline_commits(runtime.test_project, "main", authorize=lambda: None)["items"][-1]
        assert entry["records"] == records
        if v2:
            assert data["steps"][0]["id"] == "track"
            assert data["steps"][0]["patch"]
            assert data["steps"][0]["dependencies"] == records["steps"][0]["dependencies"]
            assert record["bindings"]


@pytest.mark.parametrize("claims", [[], ["parent/track:foreign"],
                                    ["parent/track:stable-track", "parent/track:extra"]])
@pytest.mark.parametrize("dry_run", [False, True])
def test_explicit_inexact_claims_refuse_without_writes(runtime, claims, dry_run):
    call = {**command(), "created": claims}
    before = snapshot(runtime)
    with pytest.raises(RuntimeErrorBase) as error:
        commit(runtime, body(runtime, call, dry_run=dry_run))
    assert error.value.details is not None and error.value.details["reason"] == "capture_mismatch"
    assert snapshot(runtime) == before


def test_declared_allocation_and_retired_reservation_remain_exact(runtime):
    call = {**command(), "created": ["parent/track:stable-track"]}
    created = commit(runtime, body(runtime, call), key="declared-create")
    assert runtime.test_prepared["records"]["commands"][0]["command"]["created"] == call["created"]
    inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
               "args": {"publications": [created["receipt"]["receipt_id"]]}}
    deleted = commit(runtime, body(runtime, inverse), key="delete-track")
    assert deleted["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"] == []
    for claim in (command(), call):
        before = snapshot(runtime)
        with pytest.raises(RuntimeErrorBase) as error:
            commit(runtime, body(runtime, claim), key="retired-" + str("created" in claim))
        assert error.value.details is not None and error.value.details["reason"] == "identity_collision"
        assert snapshot(runtime) == before
    inverse["args"]["publications"] = [deleted["receipt"]["receipt_id"]]
    restored = commit(runtime, body(runtime, inverse), key="restore-track")
    assert restored["data"]["canonical_document"] == created["data"]["canonical_document"]


def claim_case():
    call = command()
    ref = "parent/track:stable-track"
    record = {"command": {**copy.deepcopy(call), "created": [ref]},
              "created": [{"ref": ref, "kind": "track", "owner": "parent"}],
              "reads": [{"ref": ref, "path": [], "state": {"state": "absent"}}],
              "writes": [{"ref": ref, "path": [], "before": {"state": "absent"},
                          "after": {"state": "present", "value": copy.deepcopy(call["args"]["row"])}}],
              "derived_writes": []}
    return {"commands": [call]}, {"commands": [record]}


def test_omitted_claim_is_authenticated_from_the_exact_track_creation():
    submitted, records = claim_case()
    validate_claims(submitted, records)


@pytest.mark.parametrize("mutation", ["schema_version", "op", "version", "select", "args",
                                     "explicit-empty", "explicit-foreign", "extra-claim", "fact-ref",
                                     "fact-kind", "fact-owner", "missing-fact", "duplicate-fact",
                                     "missing-read", "present-read", "missing-write", "derived-only",
                                     "write-ref", "write-path", "write-before", "write-value"])
def test_omission_does_not_authorize_changed_commands_or_allocation_facts(mutation):
    submitted, records = claim_case()
    record = records["commands"][0]
    if mutation in {"schema_version", "op", "version", "select", "args"}:
        record["command"][mutation] = {"row": {"id": "foreign"}} if mutation == "args" else "foreign"
    elif mutation.startswith("explicit-"):
        submitted["commands"][0]["created"] = [] if mutation == "explicit-empty" else ["parent/track:foreign"]
    elif mutation == "extra-claim":
        record["command"]["created"].append("parent/track:extra")
    elif mutation.startswith("fact-"):
        record["created"][0][mutation.removeprefix("fact-")] = "foreign"
    elif mutation == "missing-fact":
        record["created"] = []
    elif mutation == "duplicate-fact":
        record["created"].append(copy.deepcopy(record["created"][0]))
    elif mutation == "missing-read":
        record["reads"] = []
    elif mutation == "present-read":
        record["reads"][0]["state"] = {"state": "present", "value": {}}
    elif mutation in {"missing-write", "derived-only"}:
        if mutation == "derived-only":
            record["derived_writes"] = copy.deepcopy(record["writes"])
        record["writes"] = []
    elif mutation == "write-ref":
        record["writes"][0]["ref"] = "parent/track:foreign"
    elif mutation == "write-path":
        record["writes"][0]["path"] = ["label"]
    elif mutation == "write-before":
        record["writes"][0]["before"] = {"state": "present", "value": {}}
    else:
        record["writes"][0]["after"]["value"]["opaque"] = [None, True]
    with pytest.raises(CommitRejected):
        validate_claims(submitted, records)


@pytest.mark.parametrize("mutation,declared", [
    ("command", False), ("command", True), ("claim", False), ("claim", True),
    ("fact", False), ("fact", True), ("write", False),
    ("binding", False), ("binding", True), ("effects", False), ("effects", True),
])
def test_mutated_provider_allocations_refuse_without_writes(runtime, monkeypatch, mutation, declared):
    accept = RequestCommitPort.accept
    reached = []

    def checked_accept(port, prepared):
        value = copy.deepcopy(prepared)
        record = value["records"]["commands"][0]
        reached.append(True)
        if mutation == "command":
            record["command"]["args"]["row"]["opaque"] = [None, True]
        elif mutation == "claim":
            record["command"]["created"] = ["parent/track:foreign"]
        elif mutation == "fact":
            record["created"][0]["ref"] = "parent/track:foreign"
        elif mutation == "write":
            record["writes"][0]["after"]["value"]["id"] = "foreign"
        elif mutation == "binding":
            record["bindings"][0]["content_digest"] = "sha256:" + "0" * 64
        else:
            value["records"]["steps"][0]["patch"] = []
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    before = snapshot(runtime)
    call = command()
    if declared:
        call["created"] = ["parent/track:stable-track"]
    with pytest.raises(RuntimeErrorBase) as error:
        commit(runtime, body(runtime, call))
    assert reached
    assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    assert snapshot(runtime) == before
