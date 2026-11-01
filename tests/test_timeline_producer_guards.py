"""D13 settled-proposal contract at the real Runtime port/acceptance boundary.

Pin/carrier: orch/design/producer-commit-port.md (PIN-ONLY numeric decision). These are
unmarked requirements, intentionally red until the additive port is implemented.
The prepared provider exercises Runtime authority, not Agent command semantics.
It enters the existing coordinator directly: producer.guard's official command
schema is also pending, and HTTP/schema qualification belongs to its owners.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from runtime_protocol import timeline_commit as abi
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import RequestCommitPort, route_path
from runtime_protocol.timeline_commit_store import request_identity
from runtime_protocol.util import canonical_json
from test_timeline_commit_port import PreparedProvider, commit, prepared, request
from test_timeline_render_publication import _settle as settle_visual


CAPABILITY = "rendering.assemble_timeline"
EXECUTOR = "proposal-worker"


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _node_roundtrip(value):
    result = subprocess.run(
        ["node", "-e", 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(0, "utf8"))))'],
        input=_bytes(value), capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def _claim_identity(target):
    return {
        "actor": EXECUTOR,
        "scopes": ["worker:execute"],
        "execution_binding": {
            "actual": target,
            "verification": {
                "method": "credential_claim",
                "evidence_digest": _digest(_bytes(target)),
                "verified": True,
            },
            "executor_incarnation": "proposal-worker/incarnation-1",
        },
    }


@pytest.fixture
def producer(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        service.register_timeline_commit_provider(PreparedProvider())
        project = service.create_project({"slug": "producer-guards", "name": "Producer guards"},
                                         idempotency_key="project")["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        service.test_project = project
        body = request(service)
        body["commands"][0]["args"]["on"] = 1.0
        target = {key: body[key] for key in
                  ("project_id", "timeline_id", "base_revision_id", "base_publication_id")}
        capability_digest = _digest(CAPABILITY.encode())
        service.register_capability({"capability_id": CAPABILITY, "definition_digest": capability_digest})
        child_capability = "fixture.visual"
        child_digest = _digest(child_capability.encode())
        service.register_capability({"capability_id": child_capability, "definition_digest": child_digest})
        service.register_executor({"executor_id": EXECUTOR, "capabilities": [CAPABILITY, child_capability]},
                                  idempotency_key="register-worker")
        # Exercise the actual assembler continuation admission, including its
        # ordered settled visual outputs and frozen original target.
        children = []
        for index in range(2):
            child = service.create_task({"project": project, "capability_id": child_capability,
                "capability_digest": child_digest, "input_object_ids": [], "spec": {"index": index},
                "idempotency_key": f"visual-{index}"})
            claim = service.claim_next({"executor_id": EXECUTOR, "capability_ids": [child_capability],
                "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key=f"claim-visual-{index}")
            settle_visual(service, claim, f"settle-visual-{index}", f"visual-{index}")
            children.append(child["task"]["id"])
        spec = {"capability_id": CAPABILITY, "kind": "executor", "inputs": {},
                "runtime_dependencies": {"publication": {"admitted_target": target},
                    "edges": [{"from_task_id": task_id, "to": "self", "requires_event": "task.succeeded",
                               "fence": "runtime_task"} for task_id in children],
                    "aggregation": {"kind": "ordered_cas_inputs"}},
                "outputs": {"authoring_proposal": {"type": "file", "artifact_type": "timeline/authoring-proposal"}}}
        admitted = service.create_task({"project": project, "capability_id": CAPABILITY,
            "capability_digest": capability_digest, "input_object_ids": [], "spec": spec,
            "idempotency_key": "producer-task"})
        attempt = service.claim_next({"executor_id": EXECUTOR, "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-producer")
        assert attempt["task_id"] == admitted["task"]["id"]
        spec = service.task(attempt["task_id"])["task"]["spec"]["spec"]
        proposal = {"schema_version": 1,
            "producer": {"task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"],
                         "executor_id": EXECUTOR, "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"]},
            "admitted_target": target, "commands": body["commands"], "rationale": "Move from settled producer — reviewed"}
        proposal["proposal_digest"] = _digest(_bytes(proposal))
        pin = {**proposal["producer"], "admitted_target": copy.deepcopy(target),
               "proposal_digest": proposal["proposal_digest"]}
        yield SimpleNamespace(service=service, root=root, project=project, task=attempt["task_id"],
                              attempt=attempt, spec=spec, proposal=proposal, pin=pin)
    finally:
        service.close()


def _settle(producer, *, proposal=None, name="authoring_proposal"):
    raw = _bytes(producer.proposal if proposal is None else proposal)
    output = {"name": name, "output_port": name, "filename": "proposal.json", "kind": "object",
              "digest": _digest(raw), "size": len(raw), "media_type": "application/json", "durability": "durable",
              "data_base64": base64.b64encode(raw).decode("ascii")}
    attempt = producer.attempt
    return producer.service.settle_attempt(attempt["attempt_id"],
        {**{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}, "outputs": [output]},
        idempotency_key="settle-producer")


def _body(producer):
    return {"api_version": 1, **copy.deepcopy(producer.pin["admitted_target"]),
            "commands": [{"schema_version": 1, "op": "producer.guard", "version": "1", "select": None,
                          "args": {"pin": copy.deepcopy(producer.pin)}},
                         *copy.deepcopy(producer.proposal["commands"])], "rationale": producer.proposal["rationale"]}


def _context(producer, body=None, key="accept-proposal"):
    body = _body(producer) if body is None else copy.deepcopy(body)
    context = {"request": body, "invocation": {"operation": "commitTimeline",
        "path": route_path(body["project_id"], body["timeline_id"]), "body": copy.deepcopy(body)},
        "idempotency_key": key, "realm_id": producer.service.realm["id"], "publisher": "requesting-editor"}
    context["request_hash"] = request_identity(context)
    return context


def _candidate(context, port, pin):
    candidate = prepared(context, port)
    edit = candidate["records"]["commands"][0]
    edit["ordinal"] = 1
    edit["command"] = copy.deepcopy(context["request"]["commands"][1])
    guard = {"ordinal": 0, "command": copy.deepcopy(context["request"]["commands"][0]),
             "writes": [], "reads": [], "selections": [], "bindings": [], "created": [], "derived_writes": [],
             "dependencies": [{"key": "producer_attempt:" + pin["task_id"], "kind": "authority",
                               "policy": "exact", "pin": copy.deepcopy(pin)}]}
    candidate["records"]["commands"] = [guard, edit]
    return candidate


def _provider(*, after_capture=None, damage_record=None):
    def action(context, port):
        pin = context["request"]["commands"][0]["args"]["pin"]
        verified = port.producer_attempt(pin)
        assert verified == {"pin": pin}
        candidate = _candidate(context, port, verified["pin"])
        if damage_record:
            damage_record(candidate)
        if after_capture:
            after_capture()
        return port.preview(candidate) if context["request"].get("dry_run", False) else port.accept(candidate)
    return PreparedProvider(action)


def _execute(producer, *, body=None, key="accept-proposal", provider=None, port_factory=None):
    service = producer.service
    commits, coordinator = service._timeline_commits()
    context = _context(producer, body, key)
    selected = context["request"]
    authorize = service._timeline_authorize(selected["project_id"], selected["timeline_id"], lambda: None)
    factory = port_factory or (lambda ctx: RequestCommitPort(service, commits, ctx, authorize))
    return coordinator.execute(context, provider or _provider(), factory, authorize=authorize)


def _state(service):
    return list(service.store.conn.iterdump()), service.store.conn.total_changes


def _assert_refused(service, action, reasons):
    before = _state(service)
    with pytest.raises((CommitRejected, RuntimeErrorBase)) as error:
        action()
    failure = error.value.failure if isinstance(error.value, CommitRejected) else {
        "http_status": error.value.status, **error.value.as_dict()}
    assert failure["http_status"] == 409
    assert failure["details"]["reason"] in reasons
    assert "receipt" not in failure and "data" not in failure
    assert _state(service) == before


def _cancel(producer):
    producer.service.cancel_task_canonical(producer.task, {}, idempotency_key="cancel-producer")


def _supersede(producer, *, claim=True):
    service = producer.service
    service.retry_task(producer.task, {}, idempotency_key="retry-producer")
    if claim:
        newer = service.claim_next({"executor_id": EXECUTOR, "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-newer")
        assert newer["task_id"] == producer.task and newer["attempt_id"] != producer.attempt["attempt_id"]


def test_fixture_has_real_admission_settlement_and_managed_cas_output(producer):
    settled = _settle(producer)
    task = producer.service.task(producer.task)["task"]
    assert task["status"] == "completed"
    assert task["attempt_id"] == producer.pin["attempt_id"] and task["executor_id"] == EXECUTOR
    assert task["lease_fence"] == producer.pin["fence"] and task["runtime_epoch"] == producer.pin["runtime_epoch"]
    assert producer.service.store.conn.execute("SELECT settled FROM attempts WHERE id=?",
                                              (producer.pin["attempt_id"],)).fetchone()[0] == 1
    assert task["spec"]["spec"] == producer.spec
    assert task["result"] == settled["data"]["result"]
    output, = task["result"]["outputs"]
    association, = producer.service.managed_outputs(producer.task)
    assert association["project_id"] == producer.project
    assert association["task_id"] == producer.task
    assert association["attempt_id"] == producer.attempt["attempt_id"]
    assert association["object_id"] == output["digest"]
    assert association["durability"] == "durable" and association["lifecycle"]["state"] == "available"
    assert {key: association["provenance"][key] for key in
            ("task_id", "attempt_id", "executor_id", "fence", "runtime_epoch")} == producer.proposal["producer"]
    raw = producer.service.cas.read(output["digest"][7:])
    assert _digest(raw) == output["digest"] and len(raw) == output["size"]
    assert json.loads(raw) == producer.proposal
    assert _digest(_bytes({key: value for key, value in json.loads(raw).items()
                          if key != "proposal_digest"})) == producer.pin["proposal_digest"]
    assert output["digest"] != producer.pin["proposal_digest"]
    assert producer.service.store.timeline_render_publication(producer.task) is None


def test_admitted_utf8_script_input_stays_pinned_after_source_update_and_restart(producer):
    service = producer.service
    _settle(producer)
    old_script = "Café — original take\n"
    new_script = "Café — revised take\n"
    source = service.create_document(
        producer.project,
        {"document_id": "voiceover-script", "kind": "producer.config",
         "content": {"schema": "voiceover.script/v1", "text": old_script}},
        idempotency_key="voiceover-script-v1",
    )["data"]
    old_bytes = old_script.encode("utf-8")
    old_object_id = service.ingest(
        producer.project,
        old_bytes,
        media_type="text/plain; charset=utf-8",
        original_name="voiceover-script.txt",
        idempotency_key="voiceover-script-object-v1",
    )["data"]["digest"]
    descriptor = {
        "name": "script", "object_id": old_object_id,
        "filename": "voiceover-script.txt", "required": True,
        "digest": old_object_id,
    }
    execution_target = {"kind": "machine", "id": "machine-1"}
    request = {
        "schema_version": 1,
        "target": execution_target,
        "inputs": [descriptor],
    }
    task_spec = {
        "capability_id": CAPABILITY,
        "kind": "executor",
        "inputs": {"script": descriptor},
        "runtime_dependencies": {
            "publication": {"admitted_target": copy.deepcopy(producer.pin["admitted_target"])},
        },
        "outputs": {"authoring_proposal": {
            "type": "file", "artifact_type": "timeline/authoring-proposal",
        }},
    }
    admission = {
        "project": producer.project,
        "capability_id": CAPABILITY,
        "capability_digest": _digest(CAPABILITY.encode()),
        "input_object_ids": [old_object_id],
        "spec": task_spec,
        "execution_request": request,
        "idempotency_key": "voiceover-script-task",
    }
    admitted = service.create_task(admission, enforce_readiness=True)
    task_id = admitted["task"]["id"]
    assert admitted["task"]["status"] == "queued", admitted
    claimed = service.claim_next(
        {"executor_id": EXECUTOR, "capability_ids": [CAPABILITY],
             "runtime_epoch": service.health()["runtime_epoch"], "target": execution_target},
        idempotency_key="claim-voiceover-script-task",
        identity=_claim_identity(execution_target),
    )
    assert claimed.get("task_id") == task_id, claimed

    updated = service.update_document(
        producer.project,
        source["document_id"],
        {"expected_version": source["version"],
         "content": {"schema": "voiceover.script/v1", "text": new_script}},
        idempotency_key="voiceover-script-v2",
    )["data"]
    assert updated["version"] == 2
    assert updated["content"]["text"] == new_script

    expected_request_bytes = canonical_json(request).encode("utf-8")
    task = service.task(task_id)["task"]
    assert task["spec"]["input_object_ids"] == [old_object_id]
    assert task["spec"]["spec"]["inputs"]["script"] == descriptor
    assert task["spec"]["spec"]["runtime_dependencies"]["publication"]["admitted_target"] == producer.pin["admitted_target"]
    assert task["execution_request"]["inputs"] == [descriptor]
    assert canonical_json(task["execution_request"]).encode("utf-8") == expected_request_bytes
    assert service.cas.read(old_object_id.removeprefix("sha256:")) == old_bytes

    root = producer.root
    service.close()
    restarted = RuntimeService(root)
    producer.service = restarted
    try:
        replay = restarted.create_task(admission)
        replay_task = replay["task"]
        assert replay_task["id"] == task_id
        assert replay_task["run_id"] == admitted["run"]["id"]
        assert replay_task["spec"]["input_object_ids"] == [old_object_id]
        assert replay_task["spec"]["spec"]["inputs"]["script"] == descriptor
        assert replay_task["spec"]["spec"]["runtime_dependencies"]["publication"]["admitted_target"] == producer.pin["admitted_target"]
        assert replay_task["execution_request"]["inputs"] == [descriptor]
        assert restarted.cas.read(old_object_id.removeprefix("sha256:")) == old_bytes
    finally:
        restarted.close()


def test_protocol_declares_additive_producer_attempt_method():
    assert callable(getattr(abi.RuntimeCommitPort, "producer_attempt", None))


def test_settled_proposal_capture_is_verified_detached_and_read_only(producer):
    _settle(producer)
    service = producer.service
    commits, _ = service._timeline_commits()
    port = RequestCommitPort(service, commits, _context(producer), lambda: None)
    try:
        before = _state(service)
        expected = copy.deepcopy(producer.pin)
        verified = port.producer_attempt(producer.pin)
        assert verified == {"pin": expected}
        verified["pin"]["fence"] += 1
        assert producer.pin == expected
        assert port.producer_attempt(producer.pin) == {"pin": expected}
        assert _state(service) == before
    finally:
        port.close()


def test_current_settled_proposal_accepts_and_records_exact_authority(producer):
    _settle(producer)
    result = _execute(producer)
    assert result["data"]["status"] == "accepted"
    assert result["data"]["commands"] == _body(producer)["commands"]
    history = producer.service.list_timeline_commits(producer.project, "main", authorize=lambda: None)
    entry = history["items"][-1]
    assert entry["receipt"] == result["receipt"]
    assert entry["records"]["commands"][0]["dependencies"] == [{
        "key": "producer_attempt:" + producer.task, "kind": "authority", "policy": "exact", "pin": producer.pin}]
    assert "lease_id" not in canonical_json(entry["records"])


def test_node_forwarded_integral_float_accepts_using_original_artifact_digest(producer):
    _settle(producer)
    body = _body(producer)
    assert set(body["commands"][0]["args"]) == {"pin"}
    assert type(body["commands"][1]["args"]["on"]) is float
    forwarded = _node_roundtrip(body)
    assert type(forwarded["commands"][1]["args"]["on"]) is int
    assert forwarded["commands"][1]["args"]["on"] == 1
    assert forwarded["commands"][1:] == producer.proposal["commands"]
    assert forwarded["commands"][0]["args"] == {"pin": producer.pin}

    output, = producer.service.task(producer.task)["task"]["result"]["outputs"]
    raw = producer.service.cas.read(output["digest"][7:])
    assert _digest(raw) == output["digest"] and len(raw) == output["size"]
    authoritative = json.loads(raw)
    unsigned = {key: value for key, value in authoritative.items() if key != "proposal_digest"}
    assert _digest(_bytes(unsigned)) == authoritative["proposal_digest"] == producer.pin["proposal_digest"]
    # Rehashing the caller's numerically equal commands loses the original
    # digest. Only Runtime's immutable settled artifact can establish it.
    unsigned["commands"] = forwarded["commands"][1:]
    assert _digest(_bytes(unsigned)) != producer.pin["proposal_digest"]

    accepted = _execute(producer, body=forwarded)
    assert accepted["data"]["status"] == "accepted"
    assert accepted["data"]["commands"] == forwarded["commands"]
    history = producer.service.list_timeline_commits(producer.project, "main", authorize=lambda: None)
    assert history["items"][-1]["records"]["commands"][0]["dependencies"][0]["pin"] == producer.pin
    assert producer.service.cas.read(output["digest"][7:]) == raw


@pytest.mark.parametrize("on", [1.5, True], ids=["changed-number", "boolean-is-not-number"])
def test_node_forwarded_changed_value_refuses_without_writes(producer, on):
    _settle(producer)
    body = _body(producer)
    body["commands"][1]["args"]["on"] = on
    forwarded = _node_roundtrip(body)
    assert type(forwarded["commands"][1]["args"]["on"]) is type(on)
    assert forwarded["commands"][0]["args"] == {"pin": producer.pin}
    _assert_refused(producer.service, lambda: _execute(producer, body=forwarded),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


def test_preview_does_not_consume_settled_proposal(producer):
    _settle(producer)
    before = _state(producer.service)
    preview = _execute(producer, body={**_body(producer), "dry_run": True}, key="preview-proposal")
    assert preview["receipt"] is None and preview["data"]["status"] == "preview"
    assert _state(producer.service) == before
    assert _execute(producer)["data"]["status"] == "accepted"


@pytest.mark.parametrize("state", ["unsettled", "cancelled", "superseded", "retried-without-current"])
def test_noncurrent_or_ineligible_attempt_refuses_without_writes(producer, state):
    if state != "unsettled" and state != "cancelled":
        _settle(producer)
    if state.startswith("cancelled"):
        _cancel(producer)
    elif state in {"superseded", "retried-without-current"}:
        _supersede(producer, claim=state == "superseded")
    _assert_refused(producer.service, lambda: _execute(producer), {"producer_attempt_mismatch", "producer_dependency_unavailable"})


def _completed_task_and_attempt(producer):
    task = copy.deepcopy(producer.service.task(producer.task)["task"])
    attempt = producer.service.store.conn.execute(
        "SELECT * FROM attempts WHERE id=?", (producer.attempt["attempt_id"],)
    ).fetchone()
    return task, dict(attempt)


def test_completed_cancel_is_noop_and_proposal_remains_eligible(producer):
    _settle(producer)
    before = _completed_task_and_attempt(producer)
    _cancel(producer)
    assert _completed_task_and_attempt(producer) == before

    accepted = _execute(producer)
    assert accepted["data"]["status"] == "accepted"


def test_completed_cancel_after_capture_is_noop_and_proposal_accepts(producer):
    _settle(producer)
    before = _completed_task_and_attempt(producer)
    observed = []

    def cancel_after_capture():
        _cancel(producer)
        observed.append(_completed_task_and_attempt(producer))

    accepted = _execute(producer, provider=_provider(after_capture=cancel_after_capture))
    assert observed == [before]
    assert _completed_task_and_attempt(producer) == before
    assert accepted["data"]["status"] == "accepted"


@pytest.mark.parametrize("field", ["task_id", "attempt_id", "executor_id", "fence", "runtime_epoch", "proposal_digest",
                                    "project_id", "timeline_id", "base_revision_id", "base_publication_id"])
def test_wrong_pin_or_admitted_target_refuses_without_writes(producer, field):
    _settle(producer)
    body = _body(producer)
    pin = body["commands"][0]["args"]["pin"]
    target = pin["admitted_target"]
    if field in target:
        target[field] = "foreign-" + target[field]
    elif field == "proposal_digest":
        pin[field] = "sha256:" + "0" * 64
    elif field in {"fence", "runtime_epoch"}:
        pin[field] += 1
    else:
        pin[field] = "foreign-" + pin[field]
    _assert_refused(producer.service, lambda: _execute(producer, body=body),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


def test_real_foreign_project_cannot_commit_another_projects_settled_proposal(producer):
    _settle(producer)
    service = producer.service
    foreign = service.create_project({"slug": "other-project", "name": "Other project"},
                                     idempotency_key="other-project")["id"]
    service.create_timeline(foreign, "other-timeline", idempotency_key="other-timeline")
    head = service.get_project_timeline(foreign, "other-timeline")
    body = {**_body(producer), "project_id": foreign, "timeline_id": "other-timeline",
            "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"]}
    _assert_refused(service, lambda: _execute(producer, body=body),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


@pytest.mark.parametrize("scope", ["timeline", "project"])
def test_settled_artifact_cannot_widen_immutable_admitted_target(producer, scope):
    service = producer.service
    project = producer.project
    if scope == "project":
        project = service.create_project({"slug": "unadmitted", "name": "Unadmitted"},
                                         idempotency_key="unadmitted-project")["id"]
    service.create_timeline(project, "unadmitted", idempotency_key="unadmitted-timeline")
    head = service.get_project_timeline(project, "unadmitted")
    target = {"project_id": project, "timeline_id": "unadmitted", "base_revision_id": head["head_revision_id"],
              "base_publication_id": head["head_publication_id"]}
    producer.proposal["admitted_target"] = target
    producer.proposal["proposal_digest"] = _digest(_bytes({key: value for key, value in producer.proposal.items()
                                                         if key != "proposal_digest"}))
    producer.pin = {**producer.proposal["producer"], "admitted_target": copy.deepcopy(target),
                    "proposal_digest": producer.proposal["proposal_digest"]}
    _settle(producer)
    # Proposal, pin, artifact and request all agree. The Runtime-admitted spec
    # still names the original target; a producer result cannot widen it.
    _assert_refused(service, lambda: _execute(producer),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


@pytest.mark.parametrize("damage", ["extra-commands", "commands", "rationale", "request-target"])
def test_request_must_match_entire_settled_proposal(producer, damage):
    _settle(producer)
    body = _body(producer)
    if damage == "extra-commands":
        body["commands"].append(copy.deepcopy(body["commands"][1]))
    elif damage == "commands":
        body["commands"][1]["args"]["on"] = 99
    elif damage == "rationale":
        body["rationale"] += " changed"
    else:
        body["base_publication_id"] = "foreign-publication"
    _assert_refused(producer.service, lambda: _execute(producer, body=body),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


@pytest.mark.parametrize("damage", ["wrong-output-name", "incorrect-proposal-hash", "changed-cas-bytes",
                                   "same-size-cas-tamper"])
def test_real_settled_artifact_is_required_not_just_caller_digest(producer, damage):
    proposal = copy.deepcopy(producer.proposal)
    if damage == "incorrect-proposal-hash":
        proposal["commands"][0]["args"]["on"] = 99
        producer.proposal = proposal
    _settle(producer, proposal=proposal, name="unrelated_output" if damage == "wrong-output-name" else "authoring_proposal")
    if damage == "changed-cas-bytes":
        output, = producer.service.task(producer.task)["task"]["result"]["outputs"]
        producer.service.cas.path_for(output["digest"][7:]).write_bytes(b"damaged proposal")
    elif damage == "same-size-cas-tamper":
        output, = producer.service.task(producer.task)["task"]["result"]["outputs"]
        path = producer.service.cas.path_for(output["digest"][7:])
        original = path.read_bytes()
        tampered = original.replace(b'"on":1.0', b'"on":1e0', 1)
        assert len(tampered) == len(original) == output["size"]
        assert _digest(tampered) != output["digest"]
        assert _bytes(json.loads(tampered)) == _bytes(json.loads(original))
        path.write_bytes(tampered)
    _assert_refused(producer.service, lambda: _execute(producer),
                    {"producer_attempt_mismatch", "producer_dependency_unavailable"})


def test_authority_record_cannot_replace_private_producer_capture(producer):
    _settle(producer)
    service = producer.service
    commits, _ = service._timeline_commits()
    context = _context(producer)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        candidate = _candidate(context, port, producer.pin)
        # Isolate the existing input validator from the pending command schema.
        # No producer_attempt call has captured this provider-authored record.
        with service.store._mutex, service.store._transaction():
            _assert_refused(service, lambda: port.validate(candidate), {"producer_dependency_unavailable"})
    finally:
        port.close()


@pytest.mark.parametrize("damage", ["missing", "forged"])
def test_private_capture_requires_exact_recorded_authority_dependency(producer, damage):
    _settle(producer)
    def alter(candidate):
        dependencies = candidate["records"]["commands"][0]["dependencies"]
        if damage == "missing":
            dependencies.clear()
        else:
            dependencies[0]["pin"]["fence"] += 1
    _assert_refused(producer.service, lambda: _execute(producer, provider=_provider(damage_record=alter)),
                    {"producer_dependency_unavailable"})


def test_two_new_commit_keys_cannot_consume_one_settled_proposal_twice(producer):
    _settle(producer)
    first = _execute(producer, key="first-new-commit")
    assert first["data"]["status"] == "accepted"
    _assert_refused(producer.service, lambda: _execute(producer, key="second-new-commit"),
                    {"producer_proposal_consumed"})
    before = _state(producer.service)
    assert _execute(producer, key="first-new-commit") == first
    assert _state(producer.service) == before


def test_supersession_after_capture_before_accept_is_rechecked_atomically(producer):
    _settle(producer)
    observed = []
    def invalidate_after_capture():
        _supersede(producer)
        observed.append(_state(producer.service))
    provider = _provider(after_capture=invalidate_after_capture)
    # The deterministic interleaving changes real task state after a verified
    # capture, then enters real accept/validate. No validator is substituted.
    with pytest.raises((CommitRejected, RuntimeErrorBase)) as error:
        _execute(producer, provider=provider)
    assert len(observed) == 1
    failure = error.value.failure if isinstance(error.value, CommitRejected) else {
        "http_status": error.value.status, **error.value.as_dict()}
    assert failure["http_status"] == 409
    assert failure["details"]["reason"] in {"producer_attempt_mismatch", "producer_dependency_unavailable"}
    assert _state(producer.service) == observed[0]


def test_exact_accepted_replay_after_cancel_expiry_restart_and_head_advance_uses_no_live_guard(producer, monkeypatch):
    _settle(producer)
    original = _execute(producer)
    _cancel(producer)
    service = producer.service
    deadline = service.store.conn.execute("SELECT lease_expires_at FROM attempts WHERE id=?",
                                          (producer.attempt["attempt_id"],)).fetchone()[0]
    future = datetime.fromisoformat(deadline) + timedelta(days=1)
    class ExpiredClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future.astimezone(tz or timezone.utc)
    monkeypatch.setattr("runtime_protocol.store.datetime", ExpiredClock)
    monkeypatch.setattr("runtime_protocol.service.datetime", ExpiredClock)
    assert ExpiredClock.now(timezone.utc) > datetime.fromisoformat(deadline)
    commit(service, request(service), key="unrelated-head-advance")
    service.close()
    restarted = RuntimeService(producer.root)
    try:
        producer.service = restarted
        assert restarted.health()["runtime_epoch"] > producer.pin["runtime_epoch"]
        assert restarted.get_project_timeline(producer.project, "main")["head_publication_id"] != original["receipt"]["receipt_id"]
        def forbidden(*args, **kwargs):
            pytest.fail("accepted replay must not construct a port or run a live producer guard")
        monkeypatch.setattr(RequestCommitPort, "validate", forbidden)
        before = _state(restarted)
        replay = _execute(producer, provider=PreparedProvider(forbidden), port_factory=forbidden)
        assert _bytes(replay) == _bytes(original)
        assert _state(restarted) == before
    finally:
        restarted.close()
