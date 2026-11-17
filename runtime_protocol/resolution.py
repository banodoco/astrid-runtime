"""Versioned data-only request resolution from authenticated registrations.

Only scalar/default mappings and named placements are supported. There is no
import, callback, filesystem lookup, target probe, or executable expression.
Anything requiring those operations must use ordinary full-path admission.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import secrets

from .errors import ConflictError, RuntimeErrorBase, ValidationError
from .store import _normalize_execution_request, _normalize_execution_target
from .util import canonical_json


DESCRIPTOR_KEY = "_runtime_resolution_descriptors"
ADMISSION_KEY = "_runtime_thin_admission"
FORMAT = "runtime.resolution/v1"
ERROR_TEXT = "$input_error"
ERROR_FIELD = "$input_field"
ERROR_FIELDS = "$input_fields"
MAX_BYTES = 65536
SCALAR_TYPES = frozenset({"string", "integer", "number", "boolean", "json", "object", "array"})


class ResolutionUnavailable(ConflictError):
    code = "thin_request_unavailable"


class ResolutionRefusal(RuntimeErrorBase):
    def __init__(self, envelope):
        self.code = envelope["code"]
        self.status = 422
        super().__init__(envelope["message"], details=envelope.get("details"))


def bounded(value):
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        raise ValidationError("resolution data must be finite JSON") from None
    if len(encoded.encode()) > MAX_BYTES:
        raise ValidationError("resolution data exceeds 65536 bytes")
    def walk(item, depth=0):
        if depth > 12:
            raise ValidationError("resolution data exceeds maximum depth")
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                raise ValidationError("resolution data keys must be strings")
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
    walk(value)
    return copy.deepcopy(value)


def descriptor_digest(descriptor):
    return "sha256:" + hashlib.sha256(canonical_json(descriptor).encode()).hexdigest()


def _envelope(value):
    if not isinstance(value, dict) or set(value) - {"code", "message", "details"} or not all(isinstance(value.get(k), str) and value[k] for k in ("code", "message")):
        raise ValidationError("resolution refusal must contain code, message and optional details")


def validate_descriptor(value, registration):
    value = bounded(value)
    required = {"format", "entry_id", "capability_id", "capability_digest", "source_digest", "source_epoch",
                "settings_digest", "placement_generation", "project_id", "inputs", "admission", "bindings"}
    optional = {"mode", "placements", "default_placement", "seed_parameter", "input_error", "refusal", "settings_ref"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        raise ValidationError("unsupported resolution descriptor fields")
    if value["format"] != FORMAT:
        raise ResolutionUnavailable("unsupported resolution descriptor format")
    for name in required - {"inputs", "admission", "bindings", "project_id"}:
        if not isinstance(value[name], str) or not value[name] or len(value[name]) > 512:
            raise ValidationError(f"resolution descriptor {name} must be a bounded non-empty string")
    for field in ("source_digest", "source_epoch"):
        if value[field] != registration.get(field):
            raise ValidationError(f"resolution descriptor {field} differs from its admitted host")
    caps = registration.get("capabilities", [])
    if not any(isinstance(c, dict) and c.get("capability_id") == value["capability_id"] and c.get("definition_digest") == value["capability_digest"] for c in caps):
        raise ValidationError("resolution descriptor is not bound to an advertised capability definition")
    if value["project_id"] is not None and (not isinstance(value["project_id"], str) or not value["project_id"]):
        raise ValidationError("resolution descriptor project_id must be an exact project or null")
    if "mode" in value and (not isinstance(value["mode"], str) or not value["mode"]):
        raise ValidationError("resolution mode must be a non-empty string")
    settings = value.get("settings_ref")
    if settings is not None:
        if (not isinstance(settings, dict) or set(settings) != {"actor", "key", "version"}
                or not isinstance(settings["actor"], str) or not settings["actor"]
                or not isinstance(settings["key"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", settings["key"])
                or type(settings["version"]) is not int or settings["version"] < 0):
            raise ValidationError("resolution settings_ref must bind an exact actor, key and version")
    ports = value["inputs"]
    if not isinstance(ports, list) or len(ports) > 64:
        raise ValidationError("resolution inputs must be a bounded list")
    names, aliases = set(), set()
    for port in ports:
        if not isinstance(port, dict) or set(port) - {"name", "type", "required", "default", "aliases", "choices", "min", "max", "_explicit_required"}:
            raise ResolutionUnavailable("input needs unsupported executable or file resolution")
        name = port.get("name")
        if not isinstance(name, str) or not name or len(name) > 128 or name in names or name in aliases or name.startswith("node:"):
            raise ValidationError("resolution input names must be unique scalar names")
        names.add(name)
        if port.get("type") not in SCALAR_TYPES:
            raise ResolutionUnavailable("input needs unsupported executable or file resolution")
        alias_values = port.get("aliases", [])
        if not isinstance(alias_values, list) or len(alias_values) > 16:
            raise ValidationError("resolution aliases must be a bounded list")
        for alias in alias_values:
            if not isinstance(alias, str) or not alias or alias in names or alias in aliases or alias.startswith("node:"):
                raise ValidationError("resolution input aliases must be unambiguous")
            aliases.add(alias)
        if any(type(port[k]) is not bool for k in ("required", "_explicit_required") if k in port):
            raise ValidationError("resolution required flags must be booleans")
        for bound in ("min", "max"):
            if bound in port and (port["type"] not in {"integer", "number"} or type(port[bound]) not in {int, float}):
                raise ValidationError("resolution numeric bounds require a number")
        if "choices" in port and (not isinstance(port["choices"], list) or len(port["choices"]) > 256):
            raise ValidationError("resolution choices must be a bounded list")
    # Defaults are admitted data, not a way around the input contract.
    defaults = {p["name"]: p["default"] for p in ports if "default" in p}
    try:
        _input_values({"inputs": [{**p, "required": False} for p in ports]}, defaults)
    except ValueError as exc:
        raise ValidationError("invalid resolution default: " + str(exc)) from None
    admission = value["admission"]
    allowed = {"spec", "execution_request", "generation_intent", "settlement_effect", "required_facts", "storage_estimate", "schema_version"}
    if not isinstance(admission, dict) or set(admission) - allowed or not isinstance(admission.get("spec", {}), dict):
        raise ValidationError("resolution admission must use ordinary task fields")
    if any(k in admission.get("spec", {}) for k in (ADMISSION_KEY, "execution_binding", "execution_request", "child_delegation", "delegated_parent")):
        raise ValidationError("resolution descriptor cannot supply Runtime-owned authority")
    if admission.get("execution_request") is not None:
        # Input-bearing requests are resolved by the full path until a
        # data-only admitted-input descriptor format is supported.
        _normalize_execution_request(admission["execution_request"], [])
    bindings = value["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != names:
        raise ValidationError("each resolution input needs exactly one declared binding")
    paths = []
    for path in bindings.values():
        if (not isinstance(path, list) or not 2 <= len(path) <= 6 or path[0] != "spec"
                or any(not isinstance(p, str) or not p or p.startswith("_") or p in {"execution_binding", "execution_request", "child_delegation"} for p in path)):
            raise ValidationError("resolution bindings must be bounded ordinary spec field paths")
        if any(path[:len(old)] == old or old[:len(path)] == path for old in paths):
            raise ValidationError("resolution binding paths overlap")
        paths.append(path)
    placements = value.get("placements", {})
    if not isinstance(placements, dict) or len(placements) > 32 or any(not isinstance(k, str) or not k for k in placements):
        raise ValidationError("resolution placements must be a bounded named map")
    for target in placements.values():
        _normalize_execution_target(target)
    if placements and admission.get("execution_request") is None:
        raise ValidationError("named placements require an execution_request")
    if "default_placement" in value and value["default_placement"] not in placements:
        raise ValidationError("default placement is not registered")
    seed = value.get("seed_parameter")
    if seed is not None and not any(p["name"] == seed and p["type"] == "integer" and "default" not in p for p in ports):
        raise ValidationError("generated seed must name an integer input without a fixed default")
    for key in ("refusal", "input_error"):
        if key in value:
            _envelope(value[key])
    return value


def registration_capabilities(body):
    caps = bounded(body.get("capabilities", []))
    if any(isinstance(c, dict) and DESCRIPTOR_KEY in c for c in caps):
        raise ValidationError("capability extra keys cannot register resolution descriptors")
    descriptors = body.get("resolution_descriptors", [])
    if not isinstance(descriptors, list) or len(descriptors) > 64:
        raise ValidationError("resolution_descriptors must be a bounded list")
    bounded(descriptors)
    identities = set()
    for descriptor in descriptors:
        descriptor = validate_descriptor(descriptor, body)
        identity = (descriptor["entry_id"], descriptor.get("mode"), descriptor["project_id"])
        if identity in identities:
            raise ValidationError("resolution entry is registered more than once")
        identities.add(identity)
        cap = next(c for c in caps if isinstance(c, dict) and c.get("capability_id") == descriptor["capability_id"])
        cap.setdefault(DESCRIPTOR_KEY, []).append(descriptor)
    return caps


class InputRejection(ValueError):
    def __init__(self, message, fields):
        super().__init__(message)
        self.fields = fields


def _input_values(descriptor, supplied):
    ports = {p["name"]: p for p in descriptor["inputs"]}
    aliases = {a: p["name"] for p in ports.values() for a in p.get("aliases", [])}
    values = {}
    for supplied_name, value in supplied.items():
        name = aliases.get(supplied_name, supplied_name)
        if name not in ports:
            raise InputRejection("unsupported entry inputs: " + supplied_name, [supplied_name])
        if name in values:
            raise InputRejection(f"duplicate/conflicting entry inputs for {name!r}", [name])
        port, kind = ports[name], ports[name]["type"]
        if value is None:
            raise InputRejection(f"entry input {name!r} must not be null", [name])
        if kind == "string" and not isinstance(value, str):
            raise InputRejection(f"entry input {name!r} requires a string", [name])
        if kind == "integer" and type(value) is not int:
            raise InputRejection(f"entry input {name!r} requires an integer", [name])
        if kind == "number" and (type(value) not in {int, float} or isinstance(value, float) and not math.isfinite(value)):
            raise InputRejection(f"entry input {name!r} requires a finite number", [name])
        if kind == "boolean" and type(value) is not bool:
            raise InputRejection(f"entry input {name!r} requires a boolean", [name])
        if (kind == "object" and not isinstance(value, dict)) or (kind == "array" and not isinstance(value, list)):
            raise InputRejection(f"entry input {name!r} requires {kind}", [name])
        if "choices" in port and value not in port["choices"]:
            raise InputRejection(f"entry input {name!r} must be one of {port['choices']!r}", [name])
        for bound, violated in (("min", lambda x: value < x), ("max", lambda x: value > x)):
            if bound in port and violated(port[bound]):
                raise InputRejection(f"entry input {name!r} violates {bound}={port[bound]}", [name])
        values[name] = value
    missing = [name for name, port in ports.items() if port.get("required")
               and ((name in values and isinstance(values[name], str) and not values[name].strip())
                    or (name not in values and (port.get("_explicit_required") or port.get("default") in (None, ""))))]
    if missing:
        raise InputRejection("missing required entry inputs: " + ", ".join(missing), missing)
    return {**{name: p["default"] for name, p in ports.items() if "default" in p}, **values}

def _error_text(value, message, fields):
    if isinstance(value, dict):
        return {k: _error_text(v, message, fields) for k, v in value.items()
                if not (v == ERROR_FIELD and not fields) and not (v == ERROR_FIELDS and len(fields) < 2)}
    if isinstance(value, list):
        return [_error_text(v, message, fields) for v in value]
    if value == ERROR_FIELD:
        return fields[0] if fields else None
    if value == ERROR_FIELDS:
        return list(fields)
    return value.replace(ERROR_TEXT, message) if isinstance(value, str) else value


def resolve(descriptor, request):
    values = request.get("values", {})
    if not isinstance(values, dict):
        raise ValidationError("thin request values must be an object")
    bounded(values)
    try:
        values = _input_values(descriptor, values)
    except ValueError as exc:
        envelope = descriptor.get("input_error", {"code": "input_rejected", "message": ERROR_TEXT})
        raise ResolutionRefusal(_error_text(envelope, str(exc), getattr(exc, "fields", []))) from None
    if "refusal" in descriptor:
        raise ResolutionRefusal(descriptor["refusal"])
    seed = descriptor.get("seed_parameter")
    if seed is not None and seed not in values:
        values[seed] = secrets.randbelow(2**32)
    result = copy.deepcopy(descriptor["admission"])
    for name, value in values.items():
        path = descriptor["bindings"][name]
        target = result
        for part in path[:-1]:
            child = target.setdefault(part, {})
            if not isinstance(child, dict):
                raise ValidationError("resolution binding conflicts with admitted data")
            target = child
        target[path[-1]] = value
    placement = request.get("placement", descriptor.get("default_placement"))
    if placement is not None:
        if placement not in descriptor.get("placements", {}):
            raise ResolutionUnavailable("requested placement is not registered; use the full path")
        execution = result["execution_request"]
        if "execution" in execution:
            raise ResolutionUnavailable("nested execution placement requires the full path")
        execution["target"] = copy.deepcopy(descriptor["placements"][placement])
    result.update(capability_id=descriptor["capability_id"], capability_digest=descriptor["capability_digest"], input_object_ids=[])
    if result.get("execution_request") is not None:
        result["execution_request"] = _normalize_execution_request(result["execution_request"], [])
    return result, values
