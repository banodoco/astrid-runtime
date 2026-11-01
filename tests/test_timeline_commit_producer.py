"""Adversarial reads through the real settled-producer request port."""
from __future__ import annotations

import base64
import copy
import json
from collections import defaultdict
from contextlib import contextmanager

import pytest
from test_timeline_producer_guards import (
    _assert_refused,
    _body,
    _candidate,
    _context,
    _digest,
    _execute,
    _settle,
    _state,
)
from test_timeline_producer_guards import (
    producer as producer,  # noqa: PLC0414 - expose the shared pytest fixture
)

from runtime_protocol import timeline_commit_producer
from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import RequestCommitPort


@pytest.mark.parametrize("field,value", [
    ("task_id", ""), ("attempt_id", None), ("executor_id", " "),
    ("fence", True), ("fence", 1.0), ("fence", 0),
    ("runtime_epoch", False), ("runtime_epoch", -1), ("runtime_epoch", 1.5),
    ("proposal_digest", "sha256:" + "A" * 64), ("proposal_digest", "0" * 64),
    ("lease_id", "secret"), ("task_id", "\ud800"),
])
def test_malformed_pin_refuses_422_without_reads_or_writes(producer, field, value):
    pin = copy.deepcopy(producer.pin)
    pin[field] = value
    commits, _ = producer.service._timeline_commits()
    port = RequestCommitPort(producer.service, commits, _context(producer), lambda: None)
    try:
        before = _state(producer.service)
        with pytest.raises(ValidationError) as error:
            port.producer_attempt(pin)
        assert error.value.status == 422
        assert _state(producer.service) == before
    finally:
        port.close()


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
    b'{"a":1e999}', b'{"a":"\\ud800"}', b'{"\\udfff":1}', b'\xff', b'{} trailing'])
def test_strict_settled_json_rejects_invalid_original_bytes(producer, raw):
    attempt = producer.attempt
    producer.service.settle_attempt(attempt["attempt_id"], {
        **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
        "outputs": [{"name": "authoring_proposal", "output_port": "authoring_proposal", "kind": "object",
            "filename": "proposal.json", "digest": _digest(raw), "size": len(raw), "media_type": "application/json",
            "durability": "durable", "data_base64": base64.b64encode(raw).decode()}],
    }, idempotency_key="settle-invalid-proposal")
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("damage", ["copy", "nested", "second", "inverse", "restore"])
def test_guard_requires_first_pin_only_and_no_other_authority_commands(producer, damage):
    _settle(producer)
    body = _body(producer)
    if damage == "copy":
        body["commands"][0]["args"]["proposal"] = copy.deepcopy(producer.proposal)
    elif damage == "nested":
        body["commands"] = [{"op": "timeline.batch", "args": {"commands": body["commands"]}}]
    elif damage == "second":
        body["commands"].append(copy.deepcopy(body["commands"][0]))
    else:
        body["commands"][1]["op"] = "timeline." + damage
    service = producer.service
    commits, _ = service._timeline_commits()
    port = RequestCommitPort(service, commits, _context(producer, body), lambda: None)
    try:
        _assert_refused(service, lambda: port.producer_attempt(producer.pin),
                        {"producer_dependency_unavailable", "producer_attempt_mismatch"})
    finally:
        port.close()


def test_unconsumed_completed_proposal_survives_runtime_restart(producer):
    _settle(producer)
    producer.service.close()
    producer.service = RuntimeService(producer.root)
    assert producer.service.health()["runtime_epoch"] > producer.pin["runtime_epoch"]
    assert _execute(producer)["data"]["status"] == "accepted"


def test_private_accessor_is_detached_and_record_boolean_cannot_forge_fence(producer):
    _settle(producer)
    service = producer.service
    commits, _ = service._timeline_commits()
    context = _context(producer)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        port.producer_attempt(producer.pin)
        candidate = _candidate(context, port, producer.pin)
        before = _state(service)
        captures = port._producer_captures(candidate)
        capture, = captures
        assert capture["proposal"] == producer.proposal
        assert capture["identity"]["request_hash"] == context["request_hash"]
        capture["pin"]["fence"] += 10
        assert port._producer_captures(candidate)[0]["pin"] == producer.pin
        assert _state(service) == before
        candidate["records"]["commands"][0]["dependencies"][0]["pin"]["fence"] = True
        _assert_refused(service, lambda: port._producer_captures(candidate), {"producer_dependency_unavailable"})
    finally:
        port.close()


def test_selected_child_lifecycle_change_after_capture_refuses(producer):
    _settle(producer)
    service = producer.service
    commits, _ = service._timeline_commits()
    context = _context(producer)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        port.producer_attempt(producer.pin)
        candidate = _candidate(context, port, producer.pin)
        child = producer.spec["runtime_dependencies"]["resolved_children"][0]["task_id"]
        association, = service.managed_outputs(child)
        service.update_managed_output_lifecycle(association["association_id"],
            {"operation": "promote", "expected_version": association["lifecycle"]["version"]},
            idempotency_key="promote-child")
        _assert_refused(service, lambda: port._producer_captures(candidate), {"producer_attempt_mismatch"})
    finally:
        port.close()


def _association(producer, source):
    task = producer.task if source == "proposal" else producer.spec["runtime_dependencies"]["resolved_children"][source]["task_id"]
    association, = producer.service.managed_outputs(task)
    return association


@pytest.mark.parametrize("source", ["proposal", 0, 1])
def test_nonmanaged_project_relation_refuses_without_writes(producer, source):
    _settle(producer)
    association = _association(producer, source)
    producer.service.store.conn.execute(
        "UPDATE project_objects SET relation='input' WHERE project_id=? AND digest=? AND relation='managed'",
        (producer.project, association["object_id"][7:]),
    )
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("source", ["proposal", 0, 1])
@pytest.mark.parametrize("field,value", [
    ("fence", True), ("fence", 1.0), ("runtime_epoch", True), ("runtime_epoch", 1.0),
    ("task_id", "foreign"), ("attempt_id", "foreign"),
    ("executor_id", "foreign"), ("capability_id", "foreign"),
])
def test_corrupt_managed_provenance_refuses_without_writes(producer, source, field, value):
    _settle(producer)
    association = _association(producer, source)
    provenance = association["provenance"]
    if type(value) in (bool, float):
        assert provenance[field] == value and type(provenance[field]) is int
    provenance[field] = value
    producer.service.store.conn.execute(
        "UPDATE managed_output_associations SET provenance_json=? WHERE association_id=?",
        (json.dumps(provenance), association["association_id"]),
    )
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("source", [0, 1])
@pytest.mark.parametrize("field", ["executor_id", "fence", "runtime_epoch"])
@pytest.mark.parametrize("side", ["task", "attempt-and-provenance"])
def test_selected_child_requires_consistent_current_attempt_identity(producer, source, field, side):
    _settle(producer)
    association = _association(producer, source)
    provenance = association["provenance"]
    value = "foreign" if field == "executor_id" else provenance[field] + 1
    conn = producer.service.store.conn
    if side == "task":
        column = "lease_fence" if field == "fence" else field
        conn.execute(f"UPDATE tasks SET {column}=? WHERE id=?", (value, association["task_id"]))
    else:
        conn.execute(f"UPDATE attempts SET {field}=? WHERE id=?", (value, association["attempt_id"]))
        # Even mutually agreeing attempt/provenance rows cannot replace the
        # selected child's persisted current executor, fence or epoch.
        provenance[field] = value
        conn.execute("UPDATE managed_output_associations SET provenance_json=? WHERE association_id=?",
                     (json.dumps(provenance), association["association_id"]))
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("promoted", [False, True])
def test_managed_proposal_and_ordered_children_remain_eligible(producer, promoted):
    _settle(producer)
    for source in ("proposal", 0, 1):
        association = _association(producer, source)
        if promoted:
            producer.service.update_managed_output_lifecycle(association["association_id"],
                {"operation": "promote", "expected_version": association["lifecycle"]["version"]},
                idempotency_key=f"promote-{source}")
    assert _execute(producer)["data"]["status"] == "accepted"


def test_capture_streams_exact_cas_bytes_in_bounded_reads(producer, monkeypatch):
    _settle(producer)
    service = producer.service
    associations = [_association(producer, source) for source in ("proposal", 0, 1)]
    expected = {item["object_id"][7:]: item["size"] for item in associations}
    reads = defaultdict(list)
    opened = service.cas.open
    # Tiny real CAS files cross several chunks without a large allocation.
    monkeypatch.setattr(timeline_commit_producer, "IO_CHUNK_BYTES", 3)

    @contextmanager
    def bounded_open(digest):
        class Reader:
            def read(self, size=-1):
                assert 0 < size <= 3, "producer CAS read must be bounded"
                chunk = stream.read(size)
                reads[digest].append(len(chunk))
                return chunk

        assert digest in expected
        with opened(digest) as stream:
            yield Reader()

    def unbounded_read(*args):
        pytest.fail("producer must stream CAS objects through open")

    monkeypatch.setattr(service.cas, "open", bounded_open)
    monkeypatch.setattr(service.cas, "read", unbounded_read)
    commits, _ = service._timeline_commits()
    context = _context(producer)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        before = _state(service)
        assert port.producer_attempt(producer.pin) == {"pin": producer.pin}
        assert {digest: sum(chunks) for digest, chunks in reads.items()} == expected
        assert all(chunks[-1] == 0 and len(chunks) > 2 for chunks in reads.values())
        capture, = port._producer_captures(_candidate(context, port, producer.pin))
        assert capture["proposal"] == producer.proposal
        assert set(capture) == {"pin", "proposal", "render_intent", "artifact", "identity", "authority"}
        continuation = capture["authority"]["continuation"]
        assert continuation["snapshot"]["children"] == producer.spec["runtime_dependencies"]["resolved_children"]
        assert continuation["associations"] == associations[1:]
        assert _state(service) == before
    finally:
        port.close()


@pytest.mark.parametrize("source", [0, 1])
@pytest.mark.parametrize("damage", ["same-size", "truncated", "extended"])
def test_streamed_child_media_still_requires_exact_size_and_sha(producer, source, damage):
    _settle(producer)
    association = _association(producer, source)
    path = producer.service.cas.path_for(association["object_id"][7:])
    original = path.read_bytes()
    raw = {"same-size": b"x" * len(original), "truncated": original[:-1], "extended": original + b"x"}[damage]
    assert raw != original
    path.write_bytes(raw)
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_attempt_mismatch"})


@pytest.mark.parametrize("over_limit", [False, True])
def test_proposal_materialization_uses_existing_runtime_object_limit(producer, monkeypatch, over_limit):
    _settle(producer)
    association = _association(producer, "proposal")
    monkeypatch.setattr(producer.service, "max_object_bytes", association["size"] - int(over_limit))
    commits, _ = producer.service._timeline_commits()
    port = RequestCommitPort(producer.service, commits, _context(producer), lambda: None)
    try:
        before = _state(producer.service)
        if over_limit:
            def forbidden_open(*args):
                pytest.fail("oversized proposal must refuse before materializing any bytes")
            monkeypatch.setattr(producer.service.cas, "open", forbidden_open)
            _assert_refused(producer.service, lambda: port.producer_attempt(producer.pin),
                            {"producer_dependency_unavailable"})
        else:
            assert port.producer_attempt(producer.pin) == {"pin": producer.pin}
        assert _state(producer.service) == before
    finally:
        port.close()
