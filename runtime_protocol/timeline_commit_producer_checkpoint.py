"""One-shot producer consumption and its immutable receipt-to-render handoff.

Authority is captured and verified by the request port. These helpers only run
under the existing store mutex and acceptance/task-admission transactions.
"""
from __future__ import annotations

import copy

from .errors import ConflictError, ProtocolError, ValidationError
from .timeline_commit_port import digest, refused
from .util import canonical_json, now

KIND = "timeline.producer.acceptance"
VERSION = 1


def _producer(row):
    return row["prepared"].get("kind") == KIND and row["prepared"].get("version") == VERSION


def check_producer_consumption(store, task_id):
    """Read only; exact accepted ledger replay must be resolved before this."""
    row = store.timeline_render_publication(task_id)
    if row is None:
        return
    if _producer(row) and row["result"] and row["result"].get("accepted"):
        raise refused("producer_proposal_consumed", "producer proposal has already been accepted")
    raise refused("producer_dependency_unavailable", "producer publication checkpoint is unavailable")


def _pending_render(task_id, render, selector):
    if render is None:
        return None
    render = copy.deepcopy(render)
    if not isinstance(render, dict) or render.get("capability_id") != "rendering.render":
        raise ValidationError("producer render intent requires rendering.render")
    spec = render.get("spec")
    if not isinstance(spec, dict):
        raise ValidationError("producer render intent requires a task spec")
    params = spec.setdefault("params", {})
    if not isinstance(params, dict):
        raise ValidationError("producer render params must be an object")
    inputs = spec.get("inputs", {})
    if not isinstance(inputs, dict):
        raise ValidationError("producer render inputs must be an object")
    # The original admission can contain mutable expectations. The handoff
    # selects the accepted image even when its first dispatch follows C.
    for location in (params, inputs):
        for field in ("expected_version", "canonical_head_revision_id", "canonical_occurrence_ids"):
            location.pop(field, None)
    params["timeline_ref"] = selector["timeline_id"]
    params["canonical_revision"] = copy.deepcopy(selector)
    return {"idempotency_key": "timeline-producer-render-" + task_id,
            "body": {**render, "project": selector["project_id"], "input_object_ids": render.get("input_object_ids", [])}}


def persist_producer_checkpoint(commit_store, context, captures, publication_id, revision_id):
    if not captures:
        return
    store = commit_store.store
    if not store.conn.in_transaction:
        raise ProtocolError("producer checkpoint requires the acceptance transaction")
    accepted = commit_store._lookup(context)
    if accepted is None or accepted["receipt"]["receipt_id"] != publication_id:
        raise ProtocolError("producer checkpoint requires its accepted receipt")
    document = accepted["data"]["canonical_document"]
    selector = {"project_id": document["project_id"], "timeline_id": document["timeline_id"],
                "revision_id": revision_id, "publication_id": publication_id,
                "content_digest": document["parent_revision"]["content_digest"]}
    if document["parent_revision"]["revision_id"] != revision_id:
        raise ProtocolError("producer checkpoint revision differs from acceptance")
    for capture in captures:
        pin = capture["pin"]
        check_producer_consumption(store, pin["task_id"])
        identity = {key: context[key] for key in ("realm_id", "publisher", "idempotency_key", "request_hash")}
        identity.update({key: context["request"][key] for key in ("project_id", "timeline_id")})
        if capture["identity"] != identity:
            raise refused("producer_dependency_unavailable", "producer capture belongs to another request")
        prepared = {"kind": KIND, "version": VERSION, "pin": pin, "proposal_digest": pin["proposal_digest"],
                    "identity": identity, "render_intent": capture["render_intent"],
                    "pending_render": _pending_render(pin["task_id"], capture["render_intent"], selector)}
        store.prepare_timeline_render_publication(pin["task_id"], pin["attempt_id"], pin["fence"],
                                                 pin["runtime_epoch"], digest(prepared), prepared)
        timeline_version = store.conn.execute("SELECT version FROM timelines WHERE project_id=? AND id=?",
                                              (selector["project_id"], selector["timeline_id"])).fetchone()[0]
        store.conn.execute(
            "UPDATE timeline_render_publications SET timeline_id=?, timeline_version=?, result_json=?, updated_at=? "
            "WHERE authoring_task_id=? AND state='prepared'",
            (selector["timeline_id"], timeline_version, canonical_json({"accepted": {"receipt": accepted["receipt"], **selector}}),
             now(), pin["task_id"]),
        )


def validate_pending_render(store, project_id, capability, spec, key, effect, capability_digest, execution_request):
    """Validate a reserved handoff identity before the freezer can publish CAS."""
    if not isinstance(key, str) or not key.startswith("timeline-producer-render-"):
        return None
    task_id = key.removeprefix("timeline-producer-render-")
    row = store.timeline_render_publication(task_id)
    if row is None or not _producer(row) or not row["result"] or not row["result"].get("accepted"):
        raise ConflictError("producer render checkpoint is unavailable")
    if row["request_hash"] != digest(row["prepared"]):
        raise ConflictError("producer render checkpoint identity is corrupt")
    pending = row["prepared"]["pending_render"]
    if pending is None:
        raise ConflictError("producer acceptance has no approved render intent")
    body = pending["body"]
    selector = body["spec"]["params"]["canonical_revision"]
    accepted = row["result"]["accepted"]
    if ({key: accepted[key] for key in selector} != selector
            or accepted["receipt"]["receipt_id"] != selector["publication_id"]):
        raise ConflictError("producer render acceptance identity is corrupt")
    expected_spec = {"input_object_ids": body.get("input_object_ids", []),
                     "schema_version": body.get("schema_version", "1"),
                     "capability_digest": body["capability_digest"], "spec": body["spec"]}
    for field in ("required_facts", "storage_estimate"):
        if field in body:
            expected_spec[field] = body[field]
    if (key != pending["idempotency_key"] or project_id != body["project"]
            or capability != body["capability_id"] or capability_digest != body["capability_digest"]
            or canonical_json(spec) != canonical_json(expected_spec)
            or canonical_json(effect) != canonical_json(body.get("settlement_effect"))
            or canonical_json(execution_request) != canonical_json(body.get("execution_request"))):
        raise ConflictError("producer render admission identity changed")
    return row


def complete_pending_render(store, checkpoint, value, key):
    if checkpoint is None:
        return value
    if not store.conn.in_transaction:
        raise ProtocolError("producer render link requires the task admission transaction")
    task, run = value["task"], value["run"]
    selector = checkpoint["prepared"]["pending_render"]["body"]["spec"]["params"]["canonical_revision"]
    authority = task["spec"]["spec"].get("inputs", {}).get("timeline_authority", {})
    if any(authority.get(field) != selector[key] for field, key in (
            ("project_id", "project_id"), ("timeline_id", "timeline_id"),
            ("parent_revision_id", "revision_id"), ("publication_id", "publication_id"),
            ("parent_content_digest", "content_digest"))):
        raise ConflictError("producer render did not freeze its accepted revision")
    receipt = store.conn.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='task.create' AND aggregate_id=? AND idempotency_key=?",
        (run["project_id"], key),
    ).fetchone()
    if receipt is None or receipt["primary_stream_id"] != run["id"] or task["run_id"] != run["id"]:
        raise ProtocolError("producer render admission receipt is unavailable")
    locator = {"task_id": task["id"], "run_id": run["id"], "receipt_id": receipt["txn_id"],
               "idempotency_key": key, "request_hash": receipt["request_hash"]}
    result = copy.deepcopy(checkpoint["result"])
    if checkpoint["state"] == "published":
        if result.get("render") != locator:
            raise ConflictError("producer render admission link changed")
        return value
    result["render"] = locator
    pin = checkpoint["prepared"]["pin"]
    store.complete_timeline_render_publication(
        checkpoint["authoring_task_id"], attempt_id=pin["attempt_id"], fence=pin["fence"],
        runtime_epoch=pin["runtime_epoch"], timeline_id=result["accepted"]["timeline_id"],
        timeline_version=checkpoint["timeline_version"],
        render_task_id=task["id"], render_run_id=run["id"], result=result,
    )
    return value
