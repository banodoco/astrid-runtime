"""Generated from Astrid OpCall; no timing or edit execution."""
from typing import Any, Mapping
OPCALL_SCHEMA = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'https://astrid.local/schemas/change-contract/opcall.schema.json', 'title': 'OpCall', 'description': 'Candidate single EditCommand envelope (SDK executable name: EditCommand). D RUNNER emits canonical OpCalls in Plan.calls and journal calls. Handler ids remain open. This increment is not a schema freeze.', 'type': 'object', 'required': ['op', 'select', 'args'], 'additionalProperties': False, '$defs': {'scopedId': {'type': 'string', 'description': 'Current ScopedId vocabulary: parent, shot, or occurrence clip/track ids, plus cut ids.', 'pattern': '^(?:(?:parent|shot:[^/]+|occurrence:[^/]+)/(?:clip|track):[^/]+|cut:[^/:]+)$'}, 'anchorIdentity': {'description': 'Current resolved anchor identities, including scoped entity ids and the documented word, beat, and cut anchors.', 'oneOf': [{'$ref': '#/$defs/scopedId'}, {'type': 'string', 'pattern': '^(?:word:[^:]+:[0-9]+|beat:[0-9]+|cut:[^/:]+:(?:start|end))$'}]}}, 'properties': {'op': {'type': 'string', 'description': 'Qualified operation id, e.g. timeline.opacity or myteam.stagger.', 'pattern': '^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)+$'}, 'select': {'type': ['string', 'null'], 'description': 'Authoring selector; executed calls use the canonical stable selector resolved by the runner. null for timeline-level operations.'}, 'args': {'type': 'object', 'description': 'Opaque finite JSON operation arguments in authoring units. Omitted keys, JSON null, explicit clip.clear keys, and ordinary objects (including {$absent:true} or {op:clear}) remain distinct. Only the selected handler interprets these values.', 'additionalProperties': True}, 'expect': {'type': 'object', 'description': 'Optional prior values keyed by direct-write path. Absence and present JSON values are tagged separately; command-specific requirements remain producer/consumer rules.', 'additionalProperties': {'oneOf': [{'type': 'object', 'required': ['state'], 'properties': {'state': {'const': 'absent'}}, 'additionalProperties': False}, {'type': 'object', 'required': ['state', 'value'], 'properties': {'state': {'const': 'present'}, 'value': {}}, 'additionalProperties': False}]}}, 'bindings': {'type': 'object', 'description': 'Runner-resolved anchor identity keyed by the exact authored TimeRef text.', 'additionalProperties': {'$ref': '#/$defs/anchorIdentity'}}, 'created': {'type': 'array', 'description': 'Scoped IDs allocated by the runner for this call.', 'items': {'$ref': '#/$defs/scopedId'}}, 'authorship': {'type': 'object', 'description': 'Per-write-path authorship classification; it carries no actor or authentication claim.', 'additionalProperties': {'enum': ['direct', 'consequence']}}, 'version': {'type': ['string', 'null'], 'description': 'The tool version when it ran (filled by the runner).'}, 'resolved': {'type': 'array', 'description': 'Runner-populated IDs of the selected targets in the current ScopedId vocabulary.', 'items': {'$ref': '#/$defs/scopedId'}, 'default': []}}}

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

    def matches_type(item, kind):
        return {
            "object": lambda: isinstance(item, dict),
            "array": lambda: isinstance(item, list),
            "string": lambda: isinstance(item, str),
            "null": lambda: item is None,
            "boolean": lambda: isinstance(item, bool),
            "integer": lambda: isinstance(item, int) and not isinstance(item, bool),
            "number": lambda: isinstance(item, (int, float)) and not isinstance(item, bool),
        }.get(kind, lambda: False)()

    def schema_valid(item, schema):
        if not isinstance(schema, dict):
            return False
        ref = schema.get("$ref")
        if ref is not None:
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return False
            target = OPCALL_SCHEMA
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    return False
                target = target[part]
            return schema_valid(item, target)

        if "type" in schema:
            kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(matches_type(item, kind) for kind in kinds):
                return False
        if "const" in schema and item != schema["const"]:
            return False
        if "enum" in schema and item not in schema["enum"]:
            return False
        if "pattern" in schema and (not isinstance(item, str) or re.search(schema["pattern"], item) is None):
            return False
        if "oneOf" in schema:
            alternatives = schema["oneOf"]
            if not isinstance(alternatives, list) or sum(schema_valid(item, option) for option in alternatives) != 1:
                return False

        if isinstance(item, dict):
            required = schema.get("required", [])
            if not isinstance(required, list) or any(key not in item for key in required):
                return False
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                return False
            additional = schema.get("additionalProperties", True)
            for key, child in item.items():
                if key in properties:
                    if not schema_valid(child, properties[key]):
                        return False
                elif additional is False:
                    return False
                elif isinstance(additional, dict) and not schema_valid(child, additional):
                    return False
        if isinstance(item, list) and "items" in schema:
            if not all(schema_valid(child, schema["items"]) for child in item):
                return False
        return True

    if not isinstance(value, dict):
        raise ValueError("OpCall must be an object")
    try:
        valid_json = finite_json(value)
    except RecursionError:
        valid_json = False
    if not valid_json:
        raise ValueError("OpCall requires finite JSON values")
    if not schema_valid(value, OPCALL_SCHEMA):
        raise ValueError("OpCall schema violation")
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
