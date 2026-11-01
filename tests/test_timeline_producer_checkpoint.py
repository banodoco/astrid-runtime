"""Atomic one-shot acceptance through real settled artifacts and task admission."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from test_timeline_commit_port import PreparedProvider, commit, request
from test_timeline_producer_guards import (
    CAPABILITY,
    EXECUTOR,
    _assert_refused,
    _body,
    _bytes,
    _cancel,
    _context,
    _digest,
    _execute,
    _provider,
    _settle,
    _state,
    _supersede,
)
from test_timeline_render_publication import _settle as settle_visual

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected, StaleHead
from runtime_protocol.timeline_commit_port import RequestCommitPort, digest
from runtime_protocol.timeline_commit_producer_checkpoint import KIND, _pending_render
from runtime_protocol.timeline_commit_store import request_identity


@pytest.fixture
def producer(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        service.register_timeline_commit_provider(PreparedProvider())
        project = service.create_project({"slug": "checkpoint", "name": "Checkpoint"})["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        service.test_project = project
        body = request(service)
        body["commands"][0]["args"]["on"] = 1.0
        target = {key: body[key] for key in ("project_id", "timeline_id", "base_revision_id", "base_publication_id")}
        cap_digest, render_digest = _digest(CAPABILITY.encode()), _digest(b"rendering.render")
        for capability, value in ((CAPABILITY, cap_digest), ("rendering.render", render_digest)):
            service.register_capability({"capability_id": capability, "definition_digest": value})
        child_cap = "fixture.visual"
        child_digest = _digest(child_cap.encode())
        service.register_capability({"capability_id": child_cap, "definition_digest": child_digest})
        service.register_executor({"executor_id": EXECUTOR, "capabilities": [CAPABILITY, "rendering.render", child_cap],
                                   "max_concurrency": 4}, idempotency_key="worker-with-children")
        children = []
        for index in range(2):
            child = service.create_task({"project": project, "capability_id": child_cap, "capability_digest": child_digest,
                "input_object_ids": [], "spec": {"index": index}, "idempotency_key": f"child-{index}"})
            claim = service.claim_next({"executor_id": EXECUTOR, "capability_ids": [child_cap],
                "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key=f"claim-child-{index}")
            settle_visual(service, claim, f"settle-child-{index}", f"visual-{index}")
            children.append(child["task"]["id"])
        render = {"capability_id": "rendering.render", "capability_digest": render_digest,
                  "spec": {"family": "render", "params": {"timeline_ref": "main", "selector": "rendering.remotion",
                           "expected_version": 1, "canonical_head_revision_id": target["base_revision_id"]},
                           "inputs": {"output_name": "accepted.mp4", "expected_version": 1}}}
        spec = {"capability_id": CAPABILITY, "kind": "executor", "inputs": {},
                "outputs": {"authoring_proposal": {"type": "file", "artifact_type": "timeline/authoring-proposal"}},
                "runtime_dependencies": {"publication": {"admitted_target": target, "render": render},
                    "edges": [{"from_task_id": task_id, "to": "self", "requires_event": "task.succeeded",
                               "fence": "runtime_task"} for task_id in children],
                    "aggregation": {"kind": "ordered_cas_inputs"}}}
        service.create_task({"project": project, "capability_id": CAPABILITY, "capability_digest": cap_digest,
                             "input_object_ids": [], "spec": spec, "idempotency_key": "producer"})
        attempt = service.claim_next({"executor_id": EXECUTOR, "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-producer")
        proposal = {"schema_version": 1,
                    "producer": {"task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"],
                                 "executor_id": EXECUTOR, "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"]},
                    "admitted_target": target, "commands": body["commands"], "rationale": "Reviewed producer"}
        proposal["proposal_digest"] = _digest(_bytes(proposal))
        pin = {**proposal["producer"], "admitted_target": copy.deepcopy(target),
               "proposal_digest": proposal["proposal_digest"]}
        yield SimpleNamespace(service=service, root=root, project=project, task=attempt["task_id"], attempt=attempt,
                              proposal=proposal, pin=pin, spec=spec, render=render)
    finally:
        service.close()


def _checkpoint(producer):
    return producer.service.store.timeline_render_publication(producer.task)


def _admit(producer, pending=None):
    pending = pending or _checkpoint(producer)["prepared"]["pending_render"]
    return producer.service.create_task({**copy.deepcopy(pending["body"]), "idempotency_key": pending["idempotency_key"]})


def test_pending_spec_is_detached_and_drops_only_mutable_expectations():
    selector = {"project_id": "p", "timeline_id": "t", "revision_id": "a", "publication_id": "receipt-a",
                "content_digest": digest({})}
    render = {"capability_id": "rendering.render", "capability_digest": digest("render"),
              "spec": {"params": {"timeline_ref": "old", "expected_version": 1,
                                   "canonical_head_revision_id": "old"},
                       "inputs": {"expected_version": 2, "output_name": "approved.mp4"}}}
    original = copy.deepcopy(render)
    pending = _pending_render("producer", render, selector)
    assert render == original
    assert pending["body"]["spec"]["params"] == {"timeline_ref": "t", "canonical_revision": selector}
    assert pending["body"]["spec"]["inputs"] == {"output_name": "approved.mp4"}
    selector["revision_id"] = "c"
    assert pending["body"]["spec"]["params"]["canonical_revision"]["revision_id"] == "a"


def test_capture_and_preview_do_not_prepare_or_consume(producer):
    _settle(producer)
    before = _state(producer.service)
    body = _body(producer)
    body["dry_run"] = True
    result = _execute(producer, body=body)
    assert result["receipt"] is None
    assert _checkpoint(producer) is None
    assert _state(producer.service) == before


def test_acceptance_atomically_freezes_exact_receipt_and_pending_render(producer):
    _settle(producer)
    accepted = _execute(producer)
    checkpoint = _checkpoint(producer)
    assert checkpoint["state"] == "prepared"
    assert checkpoint["prepared"]["kind"] == KIND
    assert checkpoint["prepared"]["pin"] == producer.pin
    assert checkpoint["prepared"]["identity"] == {key: _context(producer)[key] for key in
        ("realm_id", "publisher", "idempotency_key", "request_hash")} | {"project_id": producer.project, "timeline_id": "main"}
    assert checkpoint["request_hash"] == digest(checkpoint["prepared"])
    assert checkpoint["result"]["accepted"]["receipt"] == accepted["receipt"]
    selector = checkpoint["prepared"]["pending_render"]["body"]["spec"]["params"]["canonical_revision"]
    assert checkpoint["result"]["accepted"] == {"receipt": accepted["receipt"], **selector}
    assert selector["publication_id"] == accepted["receipt"]["receipt_id"]
    assert selector["revision_id"] == accepted["data"]["accepted_revision_id"]
    assert selector["content_digest"] == accepted["data"]["canonical_document"]["parent_revision"]["content_digest"]
    assert checkpoint["render_task_id"] is None


@pytest.mark.parametrize("seam", ["prepare", "accepted-link"])
def test_checkpoint_failure_rolls_back_revision_receipt_history_and_checkpoint(producer, monkeypatch, seam):
    _settle(producer)
    store = producer.service.store
    reached = []
    if seam == "prepare":
        original = store.prepare_timeline_render_publication
        def fail(*args, **kwargs):
            original(*args, **kwargs)
            reached.append(True)
            raise RuntimeError("after producer checkpoint")
        monkeypatch.setattr(store, "prepare_timeline_render_publication", fail)
    else:
        original = RequestCommitPort.persist
        def fail(*args, **kwargs):
            original(*args, **kwargs)
            assert _checkpoint(producer)["result"]["accepted"]
            reached.append(True)
            raise RuntimeError("after accepted link")
        monkeypatch.setattr(RequestCommitPort, "persist", fail)
    before = list(store.conn.iterdump())
    with pytest.raises(RuntimeError, match="after"):
        _execute(producer)
    assert reached == [True]
    assert list(store.conn.iterdump()) == before
    assert _checkpoint(producer) is None


def test_competing_keys_serialize_once_per_task(producer):
    _settle(producer)
    barrier = Barrier(2)
    def accept(key):
        barrier.wait()
        try:
            try:
                return _execute(producer, key=key)
            except StaleHead:
                # Match the provider's normal head-race retry, preserving the
                # original proposal, guards, base and request identity.
                return _execute(producer, key=key)
        except CommitRejected as error:
            return error.failure
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(accept, ["competing-one", "competing-two"]))
    winner, = [value for value in results if "receipt" in value]
    loser, = [value for value in results if "http_status" in value]
    assert loser["details"]["reason"] == "producer_proposal_consumed"
    assert _checkpoint(producer)["result"]["accepted"]["receipt"] == winner["receipt"]
    assert _execute(producer, key=winner["receipt"]["idempotency_key"]) == winner


def test_completed_cancel_both_orders_preserves_acceptance(producer):
    _settle(producer)
    _cancel(producer)
    assert producer.service.task(producer.task)["task"]["status"] == "completed"
    accepted = _execute(producer)
    _cancel(producer)
    assert _execute(producer) == accepted
    assert _checkpoint(producer)["result"]["accepted"]["receipt"] == accepted["receipt"]


def test_acceptance_first_survives_supersession_and_exact_replay(producer):
    _settle(producer)
    accepted = _execute(producer)
    checkpoint = _checkpoint(producer)
    _supersede(producer)
    assert _execute(producer) == accepted
    _assert_refused(producer.service, lambda: _execute(producer, key="new-key-after-retry"),
                    {"producer_proposal_consumed", "producer_attempt_mismatch"})
    assert _checkpoint(producer) == checkpoint


def test_a_new_settled_attempt_cannot_consume_the_accepted_task_again(producer):
    _settle(producer)
    body = _body(producer)
    accepted = _execute(producer)
    _supersede(producer, claim=False)
    producer.attempt = producer.service.claim_next({"executor_id": EXECUTOR, "capability_ids": [CAPABILITY],
        "runtime_epoch": producer.service.health()["runtime_epoch"]}, idempotency_key="new-attempt")
    producer.proposal["producer"].update({key: producer.attempt[key] for key in
                                         ("task_id", "attempt_id", "fence", "runtime_epoch")})
    producer.proposal["proposal_digest"] = _digest(_bytes({key: value for key, value in producer.proposal.items()
                                                         if key != "proposal_digest"}))
    producer.pin = {**producer.proposal["producer"], "admitted_target": producer.proposal["admitted_target"],
                    "proposal_digest": producer.proposal["proposal_digest"]}
    _settle(producer)
    _assert_refused(producer.service, lambda: _execute(producer, key="new-attempt-key"),
                    {"producer_proposal_consumed", "producer_dependency_unavailable"})
    assert _execute(producer, body=body) == accepted


def test_a_new_actor_with_a_new_key_cannot_consume_the_accepted_task(producer):
    _settle(producer)
    accepted = _execute(producer)
    service = producer.service
    commits, coordinator = service._timeline_commits()
    context = _context(producer, key="other-editor-key")
    context["publisher"] = "other-editor"
    context["request_hash"] = request_identity(context)
    authorize = service._timeline_authorize(producer.project, "main", lambda: None)
    _assert_refused(service, lambda: coordinator.execute(context, _provider(),
        lambda ctx: RequestCommitPort(service, commits, ctx, authorize), authorize=authorize),
        {"producer_proposal_consumed"})
    assert _execute(producer) == accepted


def test_altered_pending_identity_refuses_before_freezing_or_cas(producer, monkeypatch):
    _settle(producer)
    _execute(producer)
    pending = copy.deepcopy(_checkpoint(producer)["prepared"]["pending_render"])
    pending["body"]["spec"]["inputs"]["output_name"] = "changed.mp4"
    def forbidden(*args, **kwargs):
        pytest.fail("changed handoff identity must refuse before freezer/CAS")
    monkeypatch.setattr(producer.service.store, "_freeze_managed_render_inputs", forbidden)
    before = _state(producer.service)
    with pytest.raises(ConflictError, match="identity changed"):
        _admit(producer, pending)
    assert _state(producer.service) == before


def test_first_admission_after_ack_restart_and_c_uses_accepted_a_and_exact_link(producer):
    _settle(producer)
    accepted = _execute(producer)
    pending = copy.deepcopy(_checkpoint(producer)["prepared"]["pending_render"])
    later = commit(producer.service, request(producer.service), key="unrelated-c")
    assert later["receipt"]["receipt_id"] != accepted["receipt"]["receipt_id"]
    producer.service.close()
    producer.service = RuntimeService(producer.root)
    admitted = _admit(producer, pending)
    task = admitted["task"]
    authority = task["spec"]["spec"]["inputs"]["timeline_authority"]
    selector = pending["body"]["spec"]["params"]["canonical_revision"]
    assert authority["parent_revision_id"] == accepted["data"]["accepted_revision_id"]
    assert authority["publication_id"] == accepted["receipt"]["receipt_id"]
    assert authority["parent_content_digest"] == selector["content_digest"]
    linked = _checkpoint(producer)
    assert linked["state"] == "published"
    assert linked["prepared"]["pending_render"] == pending
    receipt = producer.service.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='task.create' AND idempotency_key=?",
        (pending["idempotency_key"],)).fetchone()
    assert linked["result"]["render"] == {"task_id": task["id"], "run_id": admitted["run"]["id"],
        "receipt_id": receipt["txn_id"], "request_hash": receipt["request_hash"], "idempotency_key": pending["idempotency_key"]}
    producer.service.close()
    producer.service = RuntimeService(producer.root)
    assert _admit(producer, pending)["task"]["id"] == task["id"]
    assert _checkpoint(producer) == linked


def test_render_link_failure_rolls_back_task_run_receipt_and_keeps_acceptance(producer, monkeypatch):
    _settle(producer)
    accepted = _execute(producer)
    before = list(producer.service.store.conn.iterdump())
    original = producer.service.store.complete_timeline_render_publication
    reached = []
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        reached.append(True)
        raise RuntimeError("after render link")
    monkeypatch.setattr(producer.service.store, "complete_timeline_render_publication", fail)
    with pytest.raises(RuntimeError, match="after render link"):
        _admit(producer)
    assert reached == [True]
    assert list(producer.service.store.conn.iterdump()) == before
    assert _checkpoint(producer)["result"]["accepted"]["receipt"] == accepted["receipt"]
    assert _checkpoint(producer)["state"] == "prepared"
