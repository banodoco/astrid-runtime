from __future__ import annotations

import hashlib
import json

from runtime_protocol.local_execution_handoff import canonical as handoff_canonical
from runtime_protocol.local_execution_handoff import decode as handoff_decode
from runtime_protocol.local_execution_handoff import digest as handoff_digest
from runtime_protocol.release_identity import canonical_bytes
from runtime_protocol.timeline_commit_inputs import content_digest
from runtime_protocol.timeline_commit_port import digest as port_digest
from runtime_protocol.timeline_inspection import _authored_projection
from runtime_protocol.util import canonical_json

PROTO_KEYS = ("__proto__", "constructor", "prototype")


def test_prototype_named_keys_are_plain_authored_data_through_every_encoder():
    authored = {key: {"value": index} for index, key in enumerate(PROTO_KEYS)}
    authored["__proto__"] = {"nested": {"__proto__": "still data"}}
    raw = {"parameters": authored, **{key: f"top-{key}" for key in PROTO_KEYS}}

    # set/get: the authored projection keeps every spelling as an own key with its value.
    projected = _authored_projection(raw)
    assert projected["parameters"] == authored
    for key in PROTO_KEYS:
        assert projected["authored_fields"][key] == f"top-{key}"
    assert projected["authored_fields"]["parameters"] == authored

    # encode: each canonical encoder emits every key exactly once and nothing is dropped.
    encoded = canonical_json(authored)
    assert json.loads(encoded) == authored
    assert encoded.count('"__proto__"') == 2
    assert canonical_bytes(authored) == encoded.encode()
    assert handoff_canonical(authored) == encoded.encode()

    # digest: the digest follows the authored content, so distinct keys never collide.
    expected = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
    assert handoff_digest(authored) == expected
    assert port_digest(authored) == expected
    assert content_digest(authored) == expected
    variant = {**authored, "constructor": {"value": 99}}
    assert content_digest(variant) != content_digest(authored)
    assert port_digest(variant) != port_digest(authored)

    # inverse: decoding the canonical bytes restores the same own data.
    assert handoff_decode(handoff_canonical(authored)) == authored
