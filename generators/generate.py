#!/usr/bin/env python3
"""Render checked-in contract metadata and the Python client from canonical inputs.

The release/conformance client generators consume the same component manifest;
this small repository-local command keeps the package artifacts bound to that
manifest as well.  The Python client is rendered from the tracked template;
``--check`` remains a read-only stale-artifact check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contract" / "manifest.json"
COMPONENT_MANIFEST = ROOT / "contract" / "component-manifest.json"
PYTHON_CLIENT_TEMPLATE = ROOT / "generators" / "python_client_template.py"
PYTHON_CLIENT_OUTPUT = ROOT / "packages" / "python" / "banodoco_workspace_client" / "generated.py"
TYPESCRIPT_CLIENT_OUTPUT = ROOT / "packages" / "typescript" / "src" / "generated.ts"


def _regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} must be a regular file")
    return path.read_bytes()


def _component(path: Path = COMPONENT_MANIFEST) -> tuple[bytes, Mapping[str, Any]]:
    raw = _regular(path, "component manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("component manifest must be UTF-8 JSON") from exc
    canonical = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if raw != canonical:
        raise SystemExit("component manifest must use canonical JSON bytes")
    if value.get("schema_version") != 1 or value.get("manifest_id") != "GENERATOR-CONFORMANCE-ID":
        raise SystemExit("component manifest identity is invalid")
    return raw, value


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def contract_digest(manifest_path: Path = MANIFEST) -> str:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    paths = [ROOT / "contract" / manifest["openapi"], *(ROOT / "contract" / p for p in manifest["schemas"])]
    h = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode()
        data = _regular(path, "contract input")
        h.update(len(relative).to_bytes(4, "big")); h.update(relative)
        h.update(len(data).to_bytes(8, "big")); h.update(data)
    data = _regular(OPCALL_SCHEMA, "Astrid OpCall contract input")
    logical = opcall_schema()["$id"].encode()
    h.update(len(logical).to_bytes(4, "big")); h.update(logical)
    h.update(len(data).to_bytes(8, "big")); h.update(data)
    return "sha256:" + h.hexdigest()


def operation_index(manifest_path: Path = MANIFEST) -> list[str]:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    text = (ROOT / "contract" / manifest["openapi"]).read_text(encoding="utf-8")
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if re.match(r"^\s+operationId:", line)]


# One source, explicitly selected for isolated source tuples. No editable Runtime copy.
OPCALL_SCHEMA = Path(os.environ.get("ASTRID_OPCALL_SCHEMA", str(ROOT.parent / "Astrid/schemas/change-contract/opcall.schema.json")))


def opcall_schema() -> dict[str, Any]:
    value = json.loads(_regular(OPCALL_SCHEMA, "Astrid OpCall schema (use --opcall-schema or --astrid-root)"))
    if value.get("$id") != "https://astrid.local/schemas/change-contract/opcall.schema.json":
        raise SystemExit("unexpected OpCall source identity")
    # Keep the projection fail-closed: these are the JSON Schema keywords the
    # generated recursive validators implement. New keywords require a paired
    # projection and conformance update rather than being silently ignored.
    allowed = {
        "$defs", "$id", "$ref", "$schema", "additionalProperties", "const",
        "default", "description", "enum", "items", "oneOf", "pattern",
        "properties", "required", "title", "type",
    }

    def check_keywords(schema: Any) -> None:
        if not isinstance(schema, dict):
            raise SystemExit("OpCall validator projection requires object schemas")
        unsupported = set(schema) - allowed
        if unsupported:
            raise SystemExit("OpCall validator projection has unsupported keywords: " + ", ".join(sorted(unsupported)))
        ref = schema.get("$ref")
        if ref is not None:
            if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
                raise SystemExit("OpCall validator projection supports only local $defs references")
            if set(schema) != {"$ref"}:
                raise SystemExit("OpCall validator projection does not support $ref siblings")
        schema_types = {"object", "array", "string", "null", "boolean", "integer", "number"}
        kinds = schema.get("type")
        if kinds is not None and (not isinstance(kinds, (str, list)) or (isinstance(kinds, list) and any(kind not in schema_types for kind in kinds)) or (isinstance(kinds, str) and kinds not in schema_types)):
            raise SystemExit("OpCall validator projection has an unsupported type")
        if "pattern" in schema and not isinstance(schema["pattern"], str):
            raise SystemExit("OpCall validator projection requires string patterns")
        if "const" in schema and isinstance(schema["const"], (dict, list)):
            raise SystemExit("OpCall validator projection supports scalar const values only")
        if "enum" in schema and (not isinstance(schema["enum"], list) or any(isinstance(item, (dict, list)) for item in schema["enum"])):
            raise SystemExit("OpCall validator projection supports scalar enum values only")
        if "required" in schema and (not isinstance(schema["required"], list) or any(not isinstance(key, str) for key in schema["required"])):
            raise SystemExit("OpCall validator projection requires string property names")
        for mapping_keyword in ("$defs", "properties"):
            mapping = schema.get(mapping_keyword, {})
            if not isinstance(mapping, dict):
                raise SystemExit("OpCall validator projection requires object " + mapping_keyword)
            for child in mapping.values():
                check_keywords(child)
        items = schema.get("items")
        if items is not None:
            check_keywords(items)
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            check_keywords(additional)
        elif additional is not None and not isinstance(additional, bool):
            raise SystemExit("OpCall validator projection requires boolean or object additionalProperties")
        if "oneOf" in schema:
            alternatives = schema["oneOf"]
            if not isinstance(alternatives, list):
                raise SystemExit("OpCall validator projection requires a oneOf schema array")
            for child in alternatives:
                check_keywords(child)

    check_keywords(value)
    expected_properties = {"op", "select", "args", "version", "resolved", "expect", "bindings", "created", "authorship"}
    required = set(value.get("required", []))
    if value.get("type") != "object" or set(value.get("properties", {})) != expected_properties or not {"op", "select", "args"} <= required <= expected_properties or value.get("additionalProperties") is not False:
        raise SystemExit("OpCall envelope projection needs an explicit update")
    return value


COMMIT_SCHEMA = ROOT / "contract" / "schemas" / "timeline-commit.json"
COMMIT_START = "// BEGIN GENERATED TIMELINE COMMIT"
COMMIT_END = "// END GENERATED TIMELINE COMMIT"


def commit_types(language: str) -> str:
    """Project structural types from the Runtime schema, never from generated output.

    JSON Schema conditionals remain validator-enforced. EditCommand and canonical
    timeline documents remain opaque; OpCall comes from its existing Astrid schema.
    """
    opcall = opcall_schema()
    opcall_definitions = {
        "OpCall" + name[0].upper() + name[1:]: schema
        for name, schema in opcall.get("$defs", {}).items()
    }
    definitions = {"EditCommand": opcall, **opcall_definitions, **json.loads(_regular(COMMIT_SCHEMA, "timeline commit schema"))["$defs"]}

    lines: list[str] = []

    def expression(schema: Mapping[str, Any], name: str) -> str:
        if "$ref" in schema:
            if schema["$ref"] == opcall["$id"]:
                return "EditCommand"
            if schema["$ref"].startswith("#/$defs/"):
                definition = schema["$ref"].rsplit("/", 1)[-1]
                return ("OpCall" + definition[0].upper() + definition[1:]
                        if definition in opcall.get("$defs", {}) else definition)
            return schema["$ref"].rsplit("/", 1)[-1]
        if "allOf" in schema and "properties" not in schema:
            # allOf here refines a named structural type using JSON conditionals.
            return expression(schema["allOf"][0], name)
        if "const" in schema or "enum" in schema:
            values = schema.get("enum", [schema.get("const")])
            if language == "typescript":
                return " | ".join(json.dumps(v) for v in values)
            return "Literal[" + ", ".join(repr(v) for v in values) + "]"
        for union in ("oneOf", "anyOf"):
            if union in schema:
                return " | ".join(expression(v, name + str(i)) for i, v in enumerate(schema[union]))
        kind = schema.get("type")
        if isinstance(kind, list):
            return " | ".join(expression({**schema, "type": item}, name) for item in kind)
        if kind == "array":
            inner = expression(schema["items"], name + "Item")
            return f"Array<{inner}>" if language == "typescript" else f"list[{inner}]"
        if kind == "object":
            properties = schema.get("properties")
            if properties is None:
                inner = expression(schema.get("additionalProperties") if isinstance(schema.get("additionalProperties"), dict) else {}, name + "Value")
                return f"Record<string, {inner}>" if language == "typescript" else f"dict[str, {inner}]"
            required = schema.get("required", [])
            fields = []
            for key, value in properties.items():
                inner = expression(value, name + key.title().replace("_", ""))
                if language == "typescript":
                    fields.append(json.dumps(key) + ("" if key in required else "?") + ": " + inner)
                else:
                    annotation = repr(inner) if key in required else "NotRequired[" + repr(inner) + "]"
                    fields.append(repr(key) + ": " + annotation)
            if language == "typescript":
                return "{ " + "; ".join(fields) + " }"
            lines.append(name + " = TypedDict(" + repr(name) + ", {" + ", ".join(fields) + "})")
            return name
        return ({"string": "string", "integer": "number", "number": "number", "boolean": "boolean", "null": "null"}.get(kind, "unknown")
                if language == "typescript" else {"string": "str", "integer": "int", "number": "float", "boolean": "bool", "null": "None"}.get(kind, "Any"))

    for name, schema in definitions.items():
        value = expression(schema, name)
        if language == "typescript" or value != name:
            lines.append(f"export type {name} = {value};" if language == "typescript" else f"{name} = {value}")
    interface = json.loads(_regular(COMMIT_SCHEMA, "timeline commit schema"))["x-runtime-interface"]
    lines.append("export interface RuntimeAcceptance {" if language == "typescript" else "class RuntimeAcceptance(Protocol):")
    for name, method in interface.items():
        parameters = ", ".join(key + ": " + expression(value, name + key) for key, value in method["parameters"].items())
        result = expression(method["returns"], name + "Result")
        lines.append(f"  {name}({parameters}): Promise<{result}>;" if language == "typescript" else f"    def {name}(self, {parameters}) -> {result}: ...")
    if language == "typescript":
        lines.append("}")
    return "\n".join(lines) + "\n" + command_support(language)


def command_support(language: str) -> str:
    schema = opcall_schema()
    if language == "python":
        return "OPCALL_SCHEMA = " + repr(schema) + "\n" + PYTHON_COMMAND_VALIDATOR
    return "export const OPCALL_SCHEMA = " + json.dumps(schema, ensure_ascii=False) + " as const;\n" + TYPESCRIPT_COMMAND_VALIDATOR


PYTHON_COMMAND_VALIDATOR = r'''
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
'''

TYPESCRIPT_COMMAND_VALIDATOR = r'''
export function validateEditCommand(value: unknown): EditCommand {
  const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
  const seen = new Set<object>();
  const finiteJson = (v: unknown): boolean => {
    if (v === null || typeof v === "string" || typeof v === "boolean") return true;
    if (typeof v === "number") return Number.isFinite(v);
    if (typeof v !== "object" || seen.has(v)) return false;
    seen.add(v);
    const valid = Array.isArray(v) ? v.every(finiteJson) : object(v) && Object.values(v).every(finiteJson);
    seen.delete(v);
    return valid;
  };

  const matchesType = (candidate: unknown, kind: string): boolean => {
    if (kind === "object") return object(candidate);
    if (kind === "array") return Array.isArray(candidate);
    if (kind === "string") return typeof candidate === "string";
    if (kind === "null") return candidate === null;
    if (kind === "boolean") return typeof candidate === "boolean";
    if (kind === "integer") return typeof candidate === "number" && Number.isInteger(candidate);
    if (kind === "number") return typeof candidate === "number" && Number.isFinite(candidate);
    return false;
  };
  const rootSchema = OPCALL_SCHEMA as unknown as Record<string, any>;
  const schemaValid = (candidate: unknown, schema: Record<string, any>): boolean => {
    if (typeof schema !== "object" || schema === null || Array.isArray(schema)) return false;
    if (typeof schema.$ref === "string") {
      if (!schema.$ref.startsWith("#/")) return false;
      let target: any = rootSchema;
      for (const part of schema.$ref.slice(2).split("/")) {
        const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
        if (!object(target) || !(key in target)) return false;
        target = target[key];
      }
      return schemaValid(candidate, target);
    }
    if (schema.type !== undefined) {
      const kinds: string[] = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!kinds.some(kind => matchesType(candidate, kind))) return false;
    }
    if (Object.prototype.hasOwnProperty.call(schema, "const") && candidate !== schema.const) return false;
    if (Array.isArray(schema.enum) && !schema.enum.some((entry: unknown) => candidate === entry)) return false;
    if (schema.pattern !== undefined && (typeof candidate !== "string" || !new RegExp(schema.pattern).test(candidate))) return false;
    if (schema.oneOf !== undefined) {
      if (!Array.isArray(schema.oneOf) || schema.oneOf.filter((option: Record<string, any>) => schemaValid(candidate, option)).length !== 1) return false;
    }
    if (object(candidate)) {
      if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some((key: string) => !(key in candidate)))) return false;
      const properties = schema.properties === undefined ? {} : schema.properties;
      if (!object(properties)) return false;
      const additional = schema.additionalProperties;
      for (const [key, child] of Object.entries(candidate)) {
        if (Object.prototype.hasOwnProperty.call(properties, key)) {
          if (!schemaValid(child, properties[key])) return false;
        } else if (additional === false) {
          return false;
        } else if (object(additional) && !schemaValid(child, additional)) {
          return false;
        }
      }
    }
    if (Array.isArray(candidate) && schema.items !== undefined && !candidate.every(child => schemaValid(child, schema.items))) return false;
    return true;
  };

  if (!object(value)) throw new TypeError("OpCall must be an object");
  if (!finiteJson(value)) throw new TypeError("OpCall requires finite JSON values");
  if (!schemaValid(value, rootSchema)) throw new TypeError("OpCall schema violation");
  return value as EditCommand;
}
'''


def commit_route() -> str:
    text = (ROOT / "contract/openapi/workspace-v1.yaml").read_text()
    match = re.search(r"^  (/[^\n]+):\n    post:\n      operationId: commitTimeline$", text, re.MULTILINE)
    if not match:
        raise SystemExit("commitTimeline POST route missing from OpenAPI")
    return match[1]


def render_commit_typescript(source: str) -> str:
    block = COMMIT_START + "\n" + commit_types("typescript") + "\n" + COMMIT_END
    if COMMIT_START in source:
        source, count = re.subn(re.escape(COMMIT_START) + r".*?" + re.escape(COMMIT_END), lambda _: block, source, flags=re.DOTALL)
        if count != 1:
            raise SystemExit("invalid generated commit type markers")
    else:
        source = source.replace("export const PROTOCOL", block + "\nexport const PROTOCOL", 1)
    route = commit_route().replace("{project_id}", "${encodeURIComponent(body.project_id)}").replace("{timeline_id}", "${encodeURIComponent(body.timeline_id)}")
    method = '  async commitTimeline(body: CommitRequest): Promise<CommitResult> { return this.json<CommitResult>((await this.request("POST", `' + route + '`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": body.request_id, "X-Astrid-Session": body.session_id }, [200, 400, 503])).body) }'
    if re.search(r"^  async commitTimeline\(", source, re.MULTILINE):
        source = re.sub(r"^  async commitTimeline\(.*$", lambda _: method, source, flags=re.MULTILINE)
    else:
        source = source.replace("  async health()", method + "\n  async health()", 1)
    return source


def render_python_client(manifest_path: Path = MANIFEST) -> str:
    """Render the checked-in Python client from its tracked template.

    The template is deliberately separate from the output: ``--check`` must
    detect a mutated generated client rather than merely re-reading it.  The
    contract digest and operation projection are embedded so the artifact is
    also bound to the canonical OpenAPI/schema inputs.
    """
    template = _regular(PYTHON_CLIENT_TEMPLATE, "Python client template").decode("utf-8")
    if "__SCHEMA_DIGEST__" not in template or "__OPERATIONS__" not in template:
        raise SystemExit("Python client template is missing generator placeholders")
    operations = operation_index(manifest_path)
    if not operations or len(operations) != len(set(operations)):
        raise SystemExit("contract operation projection must be non-empty and unique")
    rendered = template.replace("Authoritative Python client template; rendered by generators/generate.py.", "Generated from contract/openapi/workspace-v1.yaml; do not edit by hand.")
    rendered = rendered.replace("__SCHEMA_DIGEST__", contract_digest(manifest_path))
    rendered = rendered.replace("__OPERATIONS__", repr(tuple(operations)))
    rendered = rendered.replace("__COMMIT_TYPES__", commit_types("python"))
    rendered = rendered.replace("__COMMIT_ROUTE__", commit_route().replace("{project_id}", "{_path_part(body['project_id'])}").replace("{timeline_id}", "{_path_part(body['timeline_id'])}"))
    return rendered


def render_typescript_client() -> str:
    """Render the source-frame thumbnail operations into the typed TS client."""
    source = render_commit_typescript(_regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8"))
    child_authority_types = (
        'export interface ChildAuthorityChild { child_id: string; capability_id: string; capability_digest: string }\n'
        'export interface DerivedInputDescriptor { name: string; output_port: string; filename: string; object_id: string; size: number; media_type: string }\n'
        'export interface ChildAuthorityRequest { lease_id: string; fence: number; runtime_epoch: number; child?: ChildAuthorityChild; derived_inputs?: DerivedInputDescriptor[] }'
    )
    if "export interface ChildAuthorityRequest " not in source:
        anchor = "export interface ObjectLocation"
        if anchor not in source:
            raise SystemExit("TypeScript client is missing the child-authority type insertion point")
        source = source.replace(anchor, child_authority_types + "\n" + anchor, 1)
    old_child_authority_method = '  async issueChildAuthority(attemptId: string, body: { lease_id: string; fence: number; runtime_epoch: number }): Promise<Record<string, unknown>>'
    new_child_authority_method = '  async issueChildAuthority(attemptId: string, body: ChildAuthorityRequest): Promise<Record<string, unknown>>'
    if new_child_authority_method not in source:
        if old_child_authority_method not in source:
            raise SystemExit("TypeScript child-authority client projection is partially present")
        source = source.replace(old_child_authority_method, new_child_authority_method, 1)
    snapshot_type = 'export interface RecoverableSnapshotRequest { lease_id: string; fence: number; runtime_epoch: number; revision: number; output: DerivedInputDescriptor }'
    if "export interface RecoverableSnapshotRequest " not in source:
        source = source.replace("export interface ObjectLocation", snapshot_type + "\nexport interface ObjectLocation", 1)
    snapshot_method = '  async publishRecoverableSnapshot(attemptId: string, body: RecoverableSnapshotRequest, idempotencyKey: string): Promise<MutationResult<ManagedOutput>> { return this.mutation<ManagedOutput>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/recoverable-snapshots`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    if "  async publishRecoverableSnapshot(" not in source:
        source = source.replace("  async issueChildAuthority(", snapshot_method + "\n  async issueChildAuthority(", 1)
    source = source.replace(
        'export interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: { object_id: string; source_object_id: string; recipe_version: number } | null; viewed_at?: string | null; created_at: string }',
        'export interface ThumbnailDescriptor { object_id: string; source_object_id: string; recipe_version: number; selection?: { kind: "variant" | "source_frame"; source_time_seconds?: number } }\nexport interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: ThumbnailDescriptor | null; viewed_at?: string | null; created_at: string }',
        1,
    )
    get_method = '  async getSourceFrameThumbnail(projectId: string, sourceObjectId: string, sourceTimeSeconds: number, recipeVersion = 1): Promise<Record<string, unknown> | null> { const query = `source_object_id=${encodeURIComponent(sourceObjectId)}&source_time_seconds=${sourceTimeSeconds.toFixed(6)}&recipe_version=${recipeVersion}`; return this.json<{ thumbnail: Record<string, unknown> | null }>((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame?${query}`)).body).thumbnail }'
    ensure_method = '  async ensureSourceFrameThumbnail(projectId: string, thumbnail: Record<string, unknown>, idempotencyKey: string): Promise<MutationResult<Record<string, unknown>>> { return this.mutation<Record<string, unknown>>((await this.request("POST", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame`, new TextEncoder().encode(JSON.stringify(thumbnail)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }'
    markers = ("  async getSourceFrameThumbnail(", "  async ensureSourceFrameThumbnail(")
    present = tuple(marker in source for marker in markers)
    if all(present):
        return source
    if any(present):
        raise SystemExit("TypeScript source-frame thumbnail client projection is partially present")
    anchor = next((line for line in source.splitlines() if line.startswith("  async listMediaRelations(")), None)
    if anchor is None:
        raise SystemExit("TypeScript client is missing the listMediaRelations insertion point")
    return source.replace(anchor, anchor + "\n" + get_method + "\n" + ensure_method, 1)


def validate_typescript_client(manifest_path: Path = MANIFEST) -> None:
    """Fail closed when the typed product projection drifts from OpenAPI.

    The TypeScript client remains a typed repository source rather than a
    Python-template copy.  This check still binds every public method to the
    canonical operation projection and asserts the execution binding fields
    whose types cannot be inferred by the small metadata renderer.
    """
    source = _regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8")
    methods = set(re.findall(r"^  async (\w+)\(", source, re.MULTILINE))
    expected = set(operation_index(manifest_path)) | {"updateTimelineDocument"}
    if methods != expected:
        missing = sorted(expected - methods)
        extra = sorted(methods - expected)
        raise SystemExit(
            "TypeScript client operation projection drifted"
            + (f"; missing={missing}" if missing else "")
            + (f"; extra={extra}" if extra else "")
        )
    required_fragments = (
        "actual_target?: ExecutionTarget",
        "verification?: ExecutionBindingVerification",
        "executor_incarnation?: string",
        "run_id: string; project_id: string | null; lease_id: string",
        "lease_expires_at: string; runtime_epoch: number",
        "provider_state_unknown",
    )
    missing_fragments = [value for value in required_fragments if value not in source]
    if missing_fragments:
        raise SystemExit(
            "TypeScript execution contract projection is stale: "
            + ", ".join(missing_fragments)
        )


def render(manifest_path: Path = MANIFEST, component_path: Path = COMPONENT_MANIFEST) -> dict[str, str]:
    component_bytes, component = _component(component_path)
    digest = contract_digest(manifest_path)
    operations = operation_index(manifest_path)
    component_digest = _digest(component_bytes)
    py = ('"""Generated contract metadata; do not edit by hand."""\n\n'
          'PROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
          '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    ts = ('/** Generated contract metadata; do not edit by hand. */\n\n'
          'export const PROTOCOL = "workspace.v1" as const;\nexport const COMPONENT_MANIFEST_SHA256 = ' + json.dumps(component_digest) +
          ';\nexport const SCHEMA_DIGEST = ' + json.dumps(digest) + ";\nexport const OPERATIONS = " + json.dumps(operations) + " as const;\n")
    runtime = ('"""Generated contract metadata; do not edit by hand."""\n\n'
               'PROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
               '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    # Keep the three package metadata modules bound to the same manifest.  The
    # standalone Python/TypeScript client artifacts and fixture bundle are
    # emitted by their language-specific conformance generators.
    _ = component
    return {"packages/python/banodoco_workspace_client/contract_metadata.py": py, "packages/typescript/src/contract-metadata.ts": ts, "runtime_protocol/contract_metadata.py": runtime}


def main() -> int:
    parser = argparse.ArgumentParser()
    global OPCALL_SCHEMA
    parser.add_argument("--opcall-schema", help="existing Astrid OpCall source, not a Runtime schema copy")
    parser.add_argument("--check", action="store_true", help="fail if generated metadata differs")
    parser.add_argument("--component-manifest", default=str(COMPONENT_MANIFEST))
    parser.add_argument("--python-output", default=str(PYTHON_CLIENT_OUTPUT), help="Python client output path (for isolated checks)")
    parser.add_argument("--typescript-output", default=str(TYPESCRIPT_CLIENT_OUTPUT), help="TypeScript client output path (for isolated checks)")
    parser.add_argument("--astrid-root", help="sync/check only the existing Astrid generated client and metadata")
    parser.add_argument("--app-root", help="sync/check only the existing App generated client and metadata")
    args = parser.parse_args()
    if args.opcall_schema:
        OPCALL_SCHEMA = Path(args.opcall_schema).expanduser().resolve()
    elif args.astrid_root:
        OPCALL_SCHEMA = Path(args.astrid_root).expanduser().resolve() / "schemas/change-contract/opcall.schema.json"
    generated = render(component_path=Path(args.component_manifest).expanduser())
    generated["runtime_protocol/edit_command.py"] = ('"""Generated from Astrid OpCall; no timing or edit execution."""\nfrom typing import Any, Mapping\n' + command_support("python"))
    generated["packages/python/banodoco_workspace_client/generated.py"] = render_python_client()
    generated["packages/typescript/src/generated.ts"] = render_typescript_client()
    products: dict[Path, str] = {}
    if args.astrid_root:
        product = Path(args.astrid_root).expanduser().resolve() / "banodoco_workspace_client"
        if not (product / "generated.py").is_file():
            raise SystemExit("Astrid existing generated client is required")
        products[product / "generated.py"] = generated["packages/python/banodoco_workspace_client/generated.py"]
        products[product / "contract_metadata.py"] = generated["packages/python/banodoco_workspace_client/contract_metadata.py"]
    if args.app_root:
        product = Path(args.app_root).expanduser().resolve() / "src/integrations/runtime"
        if not (product / "generated.ts").is_file():
            raise SystemExit("App existing generated client is required")
        products[product / "generated.ts"] = generated["packages/typescript/src/generated.ts"]
        products[product / "generated-contract-metadata.ts"] = generated["packages/typescript/src/contract-metadata.ts"]
    for path, content in products.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                print(f"stale generated product file: {path}")
                return 1
        else:
            path.write_text(content, encoding="utf-8")
            print(path)
    for relative, content in generated.items():
        if relative == "packages/python/banodoco_workspace_client/generated.py":
            path = Path(args.python_output).expanduser().resolve()
        elif relative == "packages/typescript/src/generated.ts":
            path = Path(args.typescript_output).expanduser().resolve()
        else:
            path = ROOT / relative
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"stale generated file: {relative}")
                return 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(relative)
    validate_typescript_client()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
