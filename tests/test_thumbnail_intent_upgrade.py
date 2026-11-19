"""Read the previous Runtime-owned intent shape without guessing by digest."""
from __future__ import annotations

import hashlib
import json

from runtime_protocol.util import canonical_json
from tests.test_generation_thumbnail_settlement import _digest, _output
from tests.test_thumbnail_variant_recovery import (
    ORIGINAL, _admit, _admit_preview, _pending, _restart, _settle,
    _settle_preview, realm,  # noqa: F401 -- shared ordinary Runtime fixture
)


def test_old_native_intent_binds_exact_publication_variant_with_equal_bytes(realm):
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
    task_id, claim = _admit(realm, effect, [], "old-publish")
    outputs = [
        _output(ORIGINAL, name="left", media_type="image/png", output_port="image", group_key="main", variant_key="original", ordinal=0),
        _output(ORIGINAL, name="right", media_type="image/png", output_port="image", group_key="main", variant_key="alternate", ordinal=1),
    ]
    result = _settle(realm, claim, outputs, "old-publish-settle")["data"]["result"]
    publication, = result["generation_publish_v1"]["publications"]
    original = next(item for item in publication["variants"] if item["variant_key"] == "original")
    alternate = next(item for item in publication["variants"] if item["variant_key"] == "alternate")
    assert original["object_id"] == alternate["object_id"] == _digest(ORIGINAL)
    assert original["variant_id"] != alternate["variant_id"]

    # Persist precisely the a09a38ef intent shape: that release emitted only
    # the primary intent and did not include variant_id in its hashed identity.
    # The completed Runtime effect and immutable associations stay untouched.
    original_association = next(
        item for item in realm.service.managed_outputs(task_id)
        if item["variant_key"] == "original" and item["ordinal"] == 0
    )
    intent = next(
        item for item in result["thumbnail_intents"]
        if item["association_id"] == original_association["association_id"]
    )
    identity = {key: value for key, value in intent.items() if key not in {"intent_id", "variant_id"}}
    old_intent = {"intent_id": hashlib.sha256(canonical_json(identity).encode()).hexdigest(), **identity}
    retained = json.loads(realm.service.store.conn.execute(
        "SELECT result_json FROM tasks WHERE id=?", (task_id,),
    ).fetchone()[0])
    retained["thumbnail_intents"] = [old_intent]
    with realm.service.store._transaction():
        realm.service.store.conn.execute(
            "UPDATE tasks SET result_json=? WHERE id=?", (canonical_json(retained), task_id),
        )
    _restart(realm)

    assert _pending(realm) == [old_intent]
    preview_task, preview = _admit_preview(realm, old_intent)
    descriptor = _settle_preview(realm, preview, old_intent["source_object_id"])
    _restart(realm)

    assert realm.service.get_variant(original["variant_id"])["thumbnail"] == descriptor
    assert realm.service.get_variant(alternate["variant_id"])["thumbnail"] is None
    generation = realm.service.get_generation(publication["generation_id"])
    assert generation["metadata"]["thumbnail"] == descriptor
    assert generation["version"] == 1
    assert _pending(realm) == []
    assert realm.service.store.get_task(preview_task)["task"]["status"] == "completed"
    assert realm.service.store.get_task(task_id)["task"]["result"]["thumbnail_intents"] == [old_intent]
