"""Native preview recovery must preserve settled variants and independent edits."""
from __future__ import annotations

import struct
from types import SimpleNamespace
import zlib

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from tests.test_generation_thumbnail_settlement import CAPABILITY, _digest, _output, _thumbnail
from tests.test_thumbnail_attach_log_boundary import JPEG


THUMBNAIL = "generation.thumbnail_backfill"


def _png(red: int, green: int, blue: int) -> bytes:
    """One real RGB pixel, without adding an image-decoder dependency."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes((0, red, green, blue))))
        + chunk(b"IEND", b"")
    )


ORIGINAL = _png(48, 96, 144)
EDITED = _png(144, 96, 48)


def _register(realm):
    service = realm.service
    service.register_executor(
        {
            "executor_id": realm.executor,
            "runtime_epoch": service.health()["runtime_epoch"],
            "max_concurrency": 4,
            "capabilities": [
                {
                    "capability_id": capability,
                    "definition_digest": _digest(capability),
                    "status": "ready",
                    "required_resource_keys": [],
                    "estimated_scratch_bytes": 2 * 1024 * 1024,
                    "estimated_output_bytes": 512 * 1024,
                }
                for capability in (CAPABILITY, THUMBNAIL)
            ],
        },
        idempotency_key=f"register-{service.health()['runtime_epoch']}",
    )


@pytest.fixture
def realm(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    value = SimpleNamespace(
        root=root, service=service, executor="variant-preview-worker",
        identity={"actor": "variant-preview-worker", "scopes": ["worker:execute"]},
    )
    _register(value)
    value.project = service.create_project(
        {"slug": "variant-preview", "name": "Variant preview"}, idempotency_key="project",
    )["id"]
    try:
        yield value
    finally:
        value.service.close()


def _worker(realm):
    return {
        "executor_id": realm.executor,
        "runtime_epoch": realm.service.health()["runtime_epoch"],
    }


def _claim(realm, task_id, capability, key):
    claim = realm.service.claim_next(
        {**_worker(realm), "capability_ids": [capability]},
        idempotency_key=key, identity=realm.identity,
    )
    assert claim["task_id"] == task_id
    return claim


def _admit(realm, effect, inputs, key, *, capability=CAPABILITY, spec=None):
    admitted = realm.service.create_task({
        "capability_id": capability, "capability_digest": _digest(capability),
        "project": realm.project, "input_object_ids": inputs,
        "settlement_effect": effect, "idempotency_key": key,
        "spec": spec or {},
    })
    task_id = admitted["task"]["id"]
    return task_id, _claim(realm, task_id, capability, key + "-claim")


def _settle(realm, claim, outputs, key):
    return realm.service.settle_attempt(
        claim["attempt_id"],
        {
            **{field: claim[field] for field in ("lease_id", "fence", "runtime_epoch")},
            "effect": claim["expected_effect"], "outputs": outputs,
        },
        idempotency_key=key, identity=realm.identity,
    )


def _seed(realm, *, inline_thumbnail=False):
    source = realm.service.ingest(
        realm.project, ORIGINAL, media_type="image/png", idempotency_key="seed-input",
    )["data"]["digest"]
    effect = {
        "effect_type": "generation.create_with_variant", "target_id": realm.project,
        "payload": {
            "generation_type": "image", "metadata": {"prompt": "original"},
            "variant_type": "original", "output_name": "image", "output_ordinal": 0,
            "primary_policy": "preserve",
        },
    }
    task_id, claim = _admit(realm, effect, [source], "seed")
    outputs = [_output(ORIGINAL, name="image", media_type="image/png", ordinal=0)]
    if inline_thumbnail:
        outputs.append(_thumbnail(JPEG, [source]))
    result = _settle(realm, claim, outputs, "seed-settle")["data"]["result"]
    return {"task_id": task_id, **result["generation_variant"]}


def _edit(realm, seeded, *, key="edit"):
    effect = {
        "effect_type": "generation.variant.append", "target_id": seeded["generation_id"],
        "expected_version": realm.service.get_generation(seeded["generation_id"])["version"],
        "payload": {
            "source_variant_id": seeded["variant_id"], "source_object_id": seeded["object_id"],
            "variant_type": "edit", "output_name": "image", "output_ordinal": 0,
            "primary_policy": "preserve",
        },
    }
    return _admit(realm, effect, [seeded["object_id"]], key)


def _settle_edit(realm, claim, *, key="edit-settle"):
    output = _output(EDITED, name="image", media_type="image/png", ordinal=0)
    return _settle(realm, claim, [output], key)["data"]["result"]["generation_variant"]


def _pending(realm):
    return realm.service.pending_thumbnail_intents(
        _worker(realm), identity=realm.identity,
    )["items"]


def _intent(realm, task_id, source):
    candidates = [
        item for item in _pending(realm)
        if item["task_id"] == task_id and item["source_object_id"] == source
    ]
    assert len(candidates) == 1, "every settled visual variant needs its own durable preview intent"
    return candidates[0]


def _admit_preview(realm, intent, *, key="preview"):
    admitted = realm.service.admit_thumbnail_intent(
        intent["task_id"], intent["intent_id"], _worker(realm), identity=realm.identity,
    )
    task_id = admitted["task"]["id"]
    return task_id, _claim(realm, task_id, THUMBNAIL, key + "-claim")


def _settle_preview(realm, claim, source, *, key="preview-settle"):
    output = _thumbnail(JPEG, [source])
    output.update(name="thumbnail", filename="thumbnail.jpg")
    _settle(realm, claim, [output], key)
    return {"object_id": output["digest"], "source_object_id": source, "recipe_version": 1}


def _restart(realm):
    realm.service.close()
    realm.service = RuntimeService(realm.root)
    _register(realm)


@pytest.mark.parametrize("first", ["preview", "edit"])
def test_native_preview_and_already_admitted_edit_both_settle(realm, first):
    seeded = _seed(realm)
    intent = _intent(realm, seeded["task_id"], seeded["object_id"])
    preview_task, preview_claim = _admit_preview(realm, intent)
    edit_task, edit_claim = _edit(realm, seeded)
    assert preview_claim["expected_effect"]["expected_version"] == 1
    assert edit_claim["expected_effect"]["expected_version"] == 1

    if first == "preview":
        descriptor = _settle_preview(realm, preview_claim, seeded["object_id"])
        edited = _settle_edit(realm, edit_claim)
    else:
        edited = _settle_edit(realm, edit_claim)
        descriptor = _settle_preview(realm, preview_claim, seeded["object_id"])

    for task_id in (seeded["task_id"], preview_task, edit_task):
        assert realm.service.store.get_task(task_id)["task"]["status"] == "completed"
    generation = realm.service.get_generation(seeded["generation_id"])
    assert generation["version"] == 2
    assert generation["source_task_id"] == seeded["task_id"]
    assert generation["metadata"]["thumbnail"] == descriptor
    assert realm.service.get_variant(seeded["variant_id"])["thumbnail"] == descriptor
    assert realm.service.get_variant(edited["variant_id"])["object_id"] == _digest(EDITED)
    assert len(realm.service.list_variants(seeded["generation_id"])["items"]) == 2
    assert realm.service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1


def test_owner_retry_of_native_preview_survives_intervening_preserved_edit(realm):
    seeded = _seed(realm)
    intent = _intent(realm, seeded["task_id"], seeded["object_id"])
    preview_task, first_claim = _admit_preview(realm, intent)
    realm.service.fail_attempt(
        first_claim["attempt_id"],
        {
            **{field: first_claim[field] for field in ("lease_id", "fence", "runtime_epoch")},
            "error": {"code": "thumbnail_extraction_failed", "message": "decoder temporarily unavailable"},
        },
        idempotency_key="preview-fail", identity=realm.identity,
    )
    failed = realm.service._task_resource(realm.service.task(preview_task))
    assert failed["state"] == "failed"
    edit_task, edit_claim = _edit(realm, seeded)
    _settle_edit(realm, edit_claim)
    assert realm.service.get_generation(seeded["generation_id"])["version"] == 2

    # The ordinary owner retry keeps the original admitted effect and task.
    realm.service.retry_task(
        preview_task, {"expected_version": failed["version"]}, idempotency_key="preview-retry",
    )
    retried = _claim(realm, preview_task, THUMBNAIL, "preview-retry-claim")
    assert retried["attempt_id"] != first_claim["attempt_id"]
    assert retried["fence"] > first_claim["fence"]
    assert retried["expected_effect"] == first_claim["expected_effect"]
    descriptor = _settle_preview(realm, retried, seeded["object_id"], key="preview-retry-settle")
    assert realm.service.store.get_task(preview_task)["task"]["status"] == "completed"
    assert realm.service.store.get_task(edit_task)["task"]["status"] == "completed"
    assert realm.service.get_generation(seeded["generation_id"])["version"] == 2
    assert realm.service.get_variant(seeded["variant_id"])["thumbnail"] == descriptor
    assert len(realm.service.managed_outputs(preview_task)) == 1
    replay = realm.service.admit_thumbnail_intent(
        intent["task_id"], intent["intent_id"], _worker(realm), identity=realm.identity,
    )
    assert replay["task"]["id"] == preview_task
    assert realm.service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
    assert realm.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 3


def test_primary_preview_recovers_both_generation_and_variant_readbacks(realm):
    seeded = _seed(realm)
    _restart(realm)
    intent = _intent(realm, seeded["task_id"], seeded["object_id"])
    preview_task, claim = _admit_preview(realm, intent)
    descriptor = _settle_preview(realm, claim, seeded["object_id"])
    _restart(realm)

    assert realm.service.get_generation(seeded["generation_id"])["metadata"]["thumbnail"] == descriptor
    assert realm.service.get_variant(seeded["variant_id"])["thumbnail"] == descriptor
    variant, = realm.service.list_variants(seeded["generation_id"])["items"]
    assert variant["variant_id"] == seeded["variant_id"]
    assert variant["thumbnail"] == descriptor
    assert _pending(realm) == []
    assert realm.service.store.get_task(preview_task)["task"]["status"] == "completed"
    assert len(realm.service.managed_outputs(preview_task)) == 1


def test_preserved_edit_preview_recovers_without_replacing_primary_thumbnail(realm):
    seeded = _seed(realm, inline_thumbnail=True)
    original_thumbnail = realm.service.get_generation(seeded["generation_id"])["metadata"]["thumbnail"]
    edit_task, edit_claim = _edit(realm, seeded)
    edited = _settle_edit(realm, edit_claim)
    _restart(realm)
    intent = _intent(realm, edit_task, edited["object_id"])
    preview_task, claim = _admit_preview(realm, intent)
    descriptor = _settle_preview(realm, claim, edited["object_id"])
    _restart(realm)

    generation = realm.service.get_generation(seeded["generation_id"])
    assert generation["version"] == 2
    assert generation["metadata"]["thumbnail"] == original_thumbnail
    assert realm.service.get_variant(seeded["variant_id"])["thumbnail"] == original_thumbnail
    assert realm.service.get_variant(edited["variant_id"])["thumbnail"] == descriptor
    variants = {item["variant_id"]: item for item in realm.service.list_variants(seeded["generation_id"])["items"]}
    assert set(variants) == {seeded["variant_id"], edited["variant_id"]}
    assert variants[seeded["variant_id"]]["thumbnail"] == original_thumbnail
    assert variants[edited["variant_id"]]["thumbnail"] == descriptor
    assert _pending(realm) == []
    assert realm.service.store.get_task(preview_task)["task"]["status"] == "completed"
    assert realm.service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1


def test_publish_v1_recovers_primary_and_other_visual_variant_previews(realm):
    effect = {
        "effect_type": "generation.publish_v1", "target_id": realm.project,
        "payload": {
            "version": 1, "modality": "image", "generation_type": "image", "metadata": {},
            "partial_success_policy": "reject",
            "groups": [{"group_key": "main", "selectors": [
                {"selector": "left", "ordinal": 0, "variant_key": "original", "output_port": "image"},
                {"selector": "right", "ordinal": 1, "variant_key": "alternate", "output_port": "image"},
            ]}],
        },
    }
    task_id, claim = _admit(realm, effect, [], "publish")
    outputs = [
        _output(ORIGINAL, name="left", media_type="image/png", output_port="image", group_key="main", variant_key="original", ordinal=0),
        _output(EDITED, name="right", media_type="image/png", output_port="image", group_key="main", variant_key="alternate", ordinal=1),
    ]
    result = _settle(realm, claim, outputs, "publish-settle")["data"]["result"]
    publication, = result["generation_publish_v1"]["publications"]
    _restart(realm)
    intents = _pending(realm)
    assert len(intents) == 2
    assert {item["source_object_id"] for item in intents} == {_digest(ORIGINAL), _digest(EDITED)}
    assert {item["task_id"] for item in intents} == {task_id}
    for index, intent in enumerate(intents):
        _, preview = _admit_preview(realm, intent, key=f"preview-{index}")
        _settle_preview(realm, preview, intent["source_object_id"], key=f"preview-{index}-settle")
    _restart(realm)
    for variant in publication["variants"]:
        readback = realm.service.get_variant(variant["variant_id"])
        assert readback["thumbnail"] == {
            "object_id": _digest(JPEG), "source_object_id": variant["object_id"], "recipe_version": 1,
        }
    generation = realm.service.get_generation(publication["generation_id"])
    assert generation["version"] == 1
    assert generation["metadata"]["thumbnail"]["source_object_id"] == _digest(ORIGINAL)
    assert _pending(realm) == []


def test_caller_supplied_intent_labels_do_not_relax_explicit_attach_version(realm):
    seeded = _seed(realm)
    intent = _intent(realm, seeded["task_id"], seeded["object_id"])
    explicit_effect = {
        "effect_type": "generation.thumbnail.attach", "target_id": seeded["generation_id"],
        "expected_version": 1,
        "payload": {"source_object_id": seeded["object_id"], "output_name": "thumbnail",
                    "output_ordinal": 0, "recipe_version": 1},
    }
    explicit_task, explicit_claim = _admit(
        realm, explicit_effect, [seeded["object_id"]], "caller-explicit-attach", capability=THUMBNAIL,
        spec={"thumbnail_intent_id": intent["intent_id"], "parent_attempt_id": intent["attempt_id"]},
    )
    _, edit_claim = _edit(realm, seeded)
    _settle_edit(realm, edit_claim)
    with pytest.raises(ConflictError, match="stale thumbnail attachment target generation version"):
        _settle_preview(realm, explicit_claim, seeded["object_id"])
    assert realm.service.store.get_task(explicit_task)["task"]["status"] == "running"
    assert realm.service.managed_outputs(explicit_task) == []
    assert "thumbnail" not in realm.service.get_generation(seeded["generation_id"])["metadata"]
