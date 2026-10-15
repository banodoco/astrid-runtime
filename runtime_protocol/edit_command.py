"""Generated from Astrid OpCall; no timing or edit execution."""
from typing import Any, Mapping
OPCALL_SCHEMA = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'https://astrid.local/schemas/change-contract/opcall.schema.json', 'title': 'OpCall', 'description': 'Candidate single EditCommand envelope (SDK executable name: EditCommand). D RUNNER emits canonical OpCalls in Plan.calls and journal calls. Handler ids remain open. This increment is not a schema freeze.', 'type': 'object', 'required': ['op', 'select', 'args'], 'additionalProperties': False, 'properties': {'op': {'type': 'string', 'description': 'Qualified operation id, e.g. timeline.opacity or myteam.stagger.', 'pattern': '^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)+$'}, 'select': {'type': ['string', 'null'], 'description': 'Authoring selector; executed calls use the canonical stable selector resolved by the runner. null for timeline-level operations.'}, 'args': {'type': 'object', 'description': 'Opaque finite JSON operation arguments in authoring units. Omitted keys, JSON null, explicit clip.clear keys, and ordinary objects (including {$absent:true} or {op:clear}) remain distinct. Only the selected handler interprets these values.', 'additionalProperties': True}, 'version': {'type': ['string', 'null'], 'description': 'The tool version when it ran (filled by the runner).'}, 'resolved': {'type': 'array', 'description': 'Runner-populated stable string identities. The admitted producer uses local identities; globally scoped ScopedId mapping remains unresolved and is not imposed here.', 'items': {'type': 'string'}, 'default': []}}}

def validate_edit_command(value: Any) -> Mapping[str, Any]:
    """Validate only the OpCall envelope; return the exact unmodified value."""
    import math
    import re
    def finite_json(item):
        if item is None or isinstance(item, (str, bool, int)):
            return True
        if isinstance(item, float):
            return math.isfinite(item)
        if isinstance(item, list):
            return all(finite_json(v) for v in item)
        if isinstance(item, dict):
            return all(isinstance(k, str) and finite_json(v) for k, v in item.items())
        return False
    if not isinstance(value, dict):
        raise ValueError("OpCall must be an object")
    fields = OPCALL_SCHEMA["properties"]
    if set(value) - set(fields) or not set(OPCALL_SCHEMA["required"]) <= set(value):
        raise ValueError("OpCall missing or unknown field")
    try:
        valid_json = finite_json(value)
    except RecursionError:
        valid_json = False
    if not valid_json:
        raise ValueError("OpCall requires finite JSON values")
    types = {"string": lambda v: isinstance(v, str), "null": lambda v: v is None,
             "object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list)}
    for key, item in value.items():
        field = fields[key]
        kinds = field["type"] if isinstance(field["type"], list) else [field["type"]]
        if not any(types[kind](item) for kind in kinds):
            raise ValueError("OpCall invalid " + key)
        if "pattern" in field and re.search(field["pattern"], item) is None:
            raise ValueError("OpCall invalid " + key)
        if "items" in field and any(not types[field["items"]["type"]](v) for v in item):
            raise ValueError("OpCall invalid " + key)
    return value


def validate_edit_command_bytes(raw: bytes) -> bytes:
    """Validate without reserializing: whitespace, key order and UTF-8 survive."""
    import json
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result
    validate_edit_command(json.loads(raw, object_pairs_hook=unique_object))
    return raw
