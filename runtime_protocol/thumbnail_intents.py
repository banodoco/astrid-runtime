"""Durable enhancement work derived from a fenced generation settlement.

An intent lives in the completed task result in the same transaction as the
primary effect. The worker can admit only that proposal, never a new project,
source or effect. Ordinary task admission, claiming and retry remain in charge.
"""
from __future__ import annotations

import hashlib
import json

from .errors import AuthorizationError, ConflictError, NotFoundError, ValidationError
from .util import canonical_json

CAPABILITY_ID = "generation.thumbnail_backfill"
RECIPE_VERSION = 1


def settlement_intents(store, *, task, attempt_id, project_id, managed_outputs):
    intents = []
    seen = set()
    for output in managed_outputs:
        generation_id = output.get("generation_id")
        source = output.get("object_id")
        if (not generation_id or output.get("role") not in {"result", "output"}
                or not str(output.get("media_type", "")).startswith(("image/", "video/"))
                or (generation_id, source) in seen):
            continue
        generation = store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
        primary = store._generation_primary_variant(generation_id)
        if (generation is None or generation["project_id"] != project_id
                or "sha256:" + primary["object_id"] != source):
            continue
        thumbnail = json.loads(generation["metadata_json"]).get("thumbnail")
        if isinstance(thumbnail, dict) and thumbnail.get("source_object_id") == source:
            continue
        identity = {"task_id": task["id"], "attempt_id": attempt_id,
                    "executor_id": task["executor_id"], "project_id": project_id,
                    "generation_id": generation_id, "source_object_id": source,
                    "source_size": output["size"], "source_media_type": output["media_type"],
                    "association_id": output["association_id"], "recipe_version": RECIPE_VERSION}
        intent_id = hashlib.sha256(canonical_json(identity).encode()).hexdigest()
        intents.append({"intent_id": intent_id, **identity})
        seen.add((generation_id, source))
    return intents


def _worker(service, body, identity, *, pagination=False):
    allowed = {"executor_id", "runtime_epoch"} | ({"cursor", "limit"} if pagination else set())
    if not isinstance(body, dict) or set(body) - allowed or not {"executor_id", "runtime_epoch"} <= set(body):
        raise ValidationError("thumbnail intent request has invalid fields")
    executor_id = body["executor_id"]
    if not isinstance(executor_id, str) or not executor_id:
        raise ValidationError("executor_id is required")
    service._assert_executor_identity(identity, executor_id)
    service._assert_local_claim_admission(executor_id, identity=identity)
    service.store._validate_runtime_epoch(body["runtime_epoch"], identity="executor", identity_id=executor_id, required=True)
    executor = service.store.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
    if executor is None or int(executor["runtime_epoch"]) != service.store._current_runtime_epoch():
        raise ConflictError("thumbnail host must register in the current runtime epoch")
    return executor


def _admitted(store, intent):
    key = "thumbnail-intent-" + intent["intent_id"]
    row = store.conn.execute(
        "SELECT t.id FROM tasks t JOIN runs r ON r.id=t.run_id WHERE r.project_id=? AND r.idempotency_key=?",
        (intent["project_id"], key),
    ).fetchone()
    if row is None:
        return None
    value = store.get_task(row["id"])
    spec = value["task"].get("spec", {}).get("spec", {})
    if spec.get("thumbnail_intent_id") != intent["intent_id"] or spec.get("parent_attempt_id") != intent["attempt_id"]:
        raise ConflictError("thumbnail intent admission key is already occupied")
    return value


def pending(service, body, *, identity=None):
    with service.store._mutex:
        executor = _worker(service, body, identity, pagination=True)
        limit = body.get("limit", 50)
        cursor = body.get("cursor") or ""
        if (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100
                or not isinstance(cursor, str)):
            raise ValidationError("thumbnail intent pagination is invalid")
        rows = service.store.conn.execute(
            "SELECT id, result_json FROM tasks WHERE status='completed' AND executor_id=? AND id>? "
            "AND json_type(result_json, '$.thumbnail_intents')='array' ORDER BY id LIMIT ?",
            (executor["id"], cursor, limit + 1),
        ).fetchall()
        items = []
        for row in rows[:limit]:
            for intent in json.loads(row["result_json"])["thumbnail_intents"]:
                if _admitted(service.store, intent) is None:
                    items.append(intent)
        return {"items": items, "next_cursor": rows[limit - 1]["id"] if len(rows) > limit else None}


def admit(service, task_id, intent_id, body, *, identity=None):
    store = service.store
    with store._mutex, store._transaction():
        executor = _worker(service, body, identity)
        parent = store.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if parent is None:
            raise NotFoundError("thumbnail intent parent task not found")
        if parent["executor_id"] != executor["id"]:
            raise AuthorizationError("thumbnail intent belongs to a different executor")
        if parent["status"] != "completed":
            raise ConflictError("thumbnail intent parent has not durably completed")
        intents = json.loads(parent["result_json"]).get("thumbnail_intents", [])
        intent = next((item for item in intents if item["intent_id"] == intent_id), None)
        if intent is None:
            raise NotFoundError("thumbnail intent not found")
        if intent["attempt_id"] != parent["attempt_id"] or intent["task_id"] != task_id:
            raise ConflictError("thumbnail intent parent identity changed")
        existing = _admitted(store, intent)
        if existing is not None:
            return existing
        capability = store._executor_capability(executor, CAPABILITY_ID)
        digest = capability.get("definition_digest") if capability else None
        if not digest or not store._executor_can_run(executor, CAPABILITY_ID, digest):
            raise ConflictError("thumbnail host has no ready installed thumbnail capability")
        association = store.get_managed_output(intent["association_id"])
        if (association["attempt_id"] != intent["attempt_id"] or association["task_id"] != task_id
                or association["project_id"] != intent["project_id"]
                or association["object_id"] != intent["source_object_id"]
                or association["size"] != intent["source_size"] or association["durability"] != "durable"):
            raise ConflictError("thumbnail intent source association changed")
        generation = store.conn.execute("SELECT * FROM generations WHERE id=?", (intent["generation_id"],)).fetchone()
        if generation is None:
            raise NotFoundError("thumbnail intent generation not found")
        effect = {"effect_type": "generation.thumbnail.attach", "target_id": intent["generation_id"],
                  "expected_version": int(generation["version"]), "payload": {
                      "source_object_id": intent["source_object_id"], "output_name": "thumbnail",
                      "output_ordinal": 0, "recipe_version": intent["recipe_version"]}}
        # Reuses the existing project/primary-source/input/recipe validator.
        store._validate_settlement_effect(effect, project_id=intent["project_id"],
                                         input_object_ids=[intent["source_object_id"]])
        return service.create_task({"capability_id": CAPABILITY_ID, "capability_digest": digest,
            "project": intent["project_id"], "input_object_ids": [intent["source_object_id"]],
            "settlement_effect": effect, "idempotency_key": "thumbnail-intent-" + intent_id,
            "spec": {"thumbnail_intent_id": intent_id, "parent_attempt_id": intent["attempt_id"],
                "inputs": {"source": {"object_id": intent["source_object_id"], "digest": intent["source_object_id"],
                    "sha256": intent["source_object_id"].removeprefix("sha256:"),
                    "filename": "source", "size": intent["source_size"],
                    "media_type": intent["source_media_type"]}, "source_media_type": intent["source_media_type"]}},
            "storage_estimate": {"scratch_bytes": intent["source_size"] + 2 * 1024 * 1024,
                                 "output_bytes": 512 * 1024}}, enforce_readiness=True, identity=identity)
