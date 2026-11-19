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
BINDING_KEY = "_runtime_thumbnail_intent"


def _settled_variant_id(task, result, association):
    """Resolve the Runtime-published variant using the immutable output selector.

    Old intents did not carry variant_id. Their completed effect and managed
    association still identify it, including equal bytes in distinct variants.
    """
    effect = json.loads(task["expected_effect_json"])
    if effect["effect_type"] == "generation.publish_v1":
        variants = [
            variant
            for publication in result["generation_publish_v1"]["publications"]
            if (publication.get("generation_id") == association["generation_id"]
                and publication["group_key"] == association["group_key"])
            for variant in publication["variants"]
            if (variant["output_port"] == association["output_port"]
                and variant["variant_key"] == association["variant_key"]
                and variant["ordinal"] == association["ordinal"]
                and variant["object_id"] == association["object_id"])
        ]
    elif effect["effect_type"] in {"generation.create_with_variant", "generation.variant.append"}:
        variant = result["generation_variant"]
        variants = [variant] if (
            variant["generation_id"] == association["generation_id"]
            and variant["object_id"] == association["object_id"]
            and effect["payload"]["output_ordinal"] == association["ordinal"]
        ) else []
    else:
        variants = []
    if len(variants) != 1:
        raise ConflictError("thumbnail intent does not identify one settled variant")
    return variants[0]["variant_id"]


def _validated_intent(store, parent, intent):
    if (parent["status"] != "completed" or intent["task_id"] != parent["id"]
            or intent["attempt_id"] != parent["attempt_id"]
            or intent["executor_id"] != parent["executor_id"]):
        raise ConflictError("thumbnail intent parent identity changed")
    association = store.get_managed_output(intent["association_id"])
    if (association["attempt_id"] != intent["attempt_id"]
            or association["task_id"] != parent["id"]
            or association["project_id"] != intent["project_id"]
            or association["generation_id"] != intent["generation_id"]
            or association["object_id"] != intent["source_object_id"]
            or association["size"] != intent["source_size"]
            or association["media_type"] != intent["source_media_type"]
            or association["durability"] != "durable"):
        raise ConflictError("thumbnail intent source association changed")
    variant_id = _settled_variant_id(parent, json.loads(parent["result_json"]), association)
    if intent.get("variant_id", variant_id) != variant_id:
        raise ConflictError("thumbnail intent settled variant changed")
    variant = store.conn.execute(
        "SELECT v.*, g.project_id FROM generation_variants v "
        "JOIN generations g ON g.id=v.generation_id WHERE v.id=?", (variant_id,),
    ).fetchone()
    if (variant is None or variant["generation_id"] != intent["generation_id"]
            or variant["project_id"] != intent["project_id"]
            or "sha256:" + variant["object_id"] != intent["source_object_id"]):
        raise ConflictError("thumbnail intent variant source changed")
    return {**intent, "variant_id": variant_id}


def binding_intent(store, binding):
    """Read authority from Runtime-owned parent state, never a worker result."""
    if (not isinstance(binding, dict) or set(binding) != {"task_id", "intent_id"}
            or any(not isinstance(value, str) or not value for value in binding.values())):
        raise ValidationError("thumbnail intent binding is invalid")
    parent = store.conn.execute("SELECT * FROM tasks WHERE id=?", (binding["task_id"],)).fetchone()
    if parent is None:
        raise NotFoundError("thumbnail intent parent task not found")
    intents = json.loads(parent["result_json"]).get("thumbnail_intents", [])
    intent = next((item for item in intents if item["intent_id"] == binding["intent_id"]), None)
    if intent is None:
        raise NotFoundError("thumbnail intent not found")
    return _validated_intent(store, parent, intent)


def task_intent(store, task):
    binding = store._spec(task).get(BINDING_KEY)
    if binding is None:
        return None
    if task["capability"] != CAPABILITY_ID:
        raise ConflictError("thumbnail intent task capability changed")
    return binding_intent(store, binding)


def settlement_intents(store, *, task, attempt_id, project_id, managed_outputs, result):
    intents = []
    seen = set()
    for output in managed_outputs:
        generation_id = output.get("generation_id")
        source = output.get("object_id")
        if (not generation_id or output.get("role") not in {"result", "output"}
                or not str(output.get("media_type", "")).startswith(("image/", "video/"))):
            continue
        generation = store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
        if generation is None or generation["project_id"] != project_id:
            continue
        variant_id = _settled_variant_id(task, result, output)
        variant = store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone()
        if (variant is None or variant["generation_id"] != generation_id
                or "sha256:" + variant["object_id"] != source):
            raise ConflictError("thumbnail intent variant source changed")
        if (variant_id, source) in seen:
            continue
        if (variant["thumbnail_object_id"]
                and variant["thumbnail_source_object_id"] == variant["object_id"]
                and variant["thumbnail_recipe_version"] == RECIPE_VERSION):
            continue
        identity = {"task_id": task["id"], "attempt_id": attempt_id,
                    "executor_id": task["executor_id"], "project_id": project_id,
                    "generation_id": generation_id, "variant_id": variant_id, "source_object_id": source,
                    "source_size": output["size"], "source_media_type": output["media_type"],
                    "association_id": output["association_id"], "recipe_version": RECIPE_VERSION}
        intent_id = hashlib.sha256(canonical_json(identity).encode()).hexdigest()
        intents.append({"intent_id": intent_id, **identity})
        seen.add((variant_id, source))
    return intents


def apply_thumbnail(store, plan, *, project_id, settled_at):
    """Enhance the bound variant without consuming the generation edit version."""
    generation, variant = plan["generation"], plan["variant"]
    descriptor = store._thumbnail_metadata_descriptor(plan["thumbnail"], "sha256:" + variant["object_id"])
    columns = store._variant_thumbnail_columns(descriptor)
    previous = tuple(variant[field] for field in (
        "thumbnail_object_id", "thumbnail_source_object_id", "thumbnail_recipe_version",
    ))
    changed = previous != columns
    if changed:
        updated = store.conn.execute(
            "UPDATE generation_variants SET thumbnail_object_id=?, thumbnail_source_object_id=?, "
            "thumbnail_recipe_version=? WHERE id=? AND generation_id=? AND object_id=?",
            (*columns, variant["id"], generation["id"], variant["object_id"]),
        )
        if updated.rowcount != 1:
            raise ConflictError("thumbnail intent variant source changed")
    if store._generation_primary_variant(generation["id"])["id"] == variant["id"]:
        metadata = json.loads(generation["metadata_json"])
        store._validate_existing_generation_thumbnail(metadata.get("thumbnail"), generation_id=generation["id"])
        if metadata.get("thumbnail") != descriptor:
            metadata["thumbnail"] = descriptor
            updated = store.conn.execute(
                "UPDATE generations SET metadata_json=?, updated_at=? WHERE id=? AND project_id=? AND version=?",
                (canonical_json(metadata), settled_at, generation["id"], str(project_id), int(generation["version"])),
            )
            if updated.rowcount != 1:
                raise ConflictError("thumbnail intent generation changed")
            changed = True
    return {
        "effect_type": "generation.thumbnail.attach", "generation_id": generation["id"],
        "thumbnail": descriptor, "changed": changed, "version": int(generation["version"]),
    }


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
        intent = _validated_intent(store, parent, intent)
        generation = store.conn.execute("SELECT * FROM generations WHERE id=?", (intent["generation_id"],)).fetchone()
        if generation is None:
            raise NotFoundError("thumbnail intent generation not found")
        effect = {"effect_type": "generation.thumbnail.attach", "target_id": intent["generation_id"],
                  "expected_version": int(generation["version"]), "payload": {
                      "source_object_id": intent["source_object_id"], "output_name": "thumbnail",
                      "output_ordinal": 0, "recipe_version": intent["recipe_version"]}}
        # The stored intent authorizes this exact settled variant. Explicit
        # caller-admitted thumbnail effects retain their version/primary guard.
        store._validate_settlement_effect(effect, project_id=intent["project_id"],
                                         input_object_ids=[intent["source_object_id"]], thumbnail_intent=intent)
        return service.create_task({"capability_id": CAPABILITY_ID, "capability_digest": digest,
            "project": intent["project_id"], "input_object_ids": [intent["source_object_id"]],
            "settlement_effect": effect, "idempotency_key": "thumbnail-intent-" + intent_id,
            "spec": {"thumbnail_intent_id": intent_id, "parent_attempt_id": intent["attempt_id"],
                "inputs": {"source": {"object_id": intent["source_object_id"], "digest": intent["source_object_id"],
                    "sha256": intent["source_object_id"].removeprefix("sha256:"),
                    "filename": "source", "size": intent["source_size"],
                    "media_type": intent["source_media_type"]}, "source_media_type": intent["source_media_type"]}},
            "storage_estimate": {"scratch_bytes": intent["source_size"] + 2 * 1024 * 1024,
                                 "output_bytes": 512 * 1024}}, enforce_readiness=True, identity=identity,
            _thumbnail_intent={"task_id": task_id, "intent_id": intent_id})
