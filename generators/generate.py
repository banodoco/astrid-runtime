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
    # Hash source identity/bytes independently of language projection support.
    # Generating a validator still calls opcall_schema() and refuses constructs
    # it cannot enforce; an unrelated projection must not invent a digest.
    identity = json.loads(data).get("$id")
    if identity != "https://astrid.local/schemas/change-contract/opcall.schema.json":
        raise SystemExit("unexpected OpCall source identity")
    logical = identity.encode()
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
    # The bounded validator below implements this envelope only; refuse new schema
    # constructs until its projection is extended and tested rather than ignore them.
    if set(value["properties"]) != {"op", "select", "args", "version", "resolved"} or value["additionalProperties"] is not False:
        raise SystemExit("OpCall validator projection needs an explicit update")
    allowed = {"type", "description", "pattern", "items", "default", "additionalProperties"}
    if any(set(field) - allowed for field in value["properties"].values()):
        raise SystemExit("OpCall validator projection has an unsupported field constraint")
    if value["properties"]["args"].get("additionalProperties") is not True or value["properties"]["resolved"].get("items") != {"type": "string"}:
        raise SystemExit("OpCall opaque args or resolved projection needs an explicit update")
    return value


COMMIT_SCHEMA = ROOT / "contract" / "schemas" / "timeline-commit.json"
COMMIT_START = "// BEGIN GENERATED TIMELINE COMMIT"
COMMIT_END = "// END GENERATED TIMELINE COMMIT"


def commit_types(language: str) -> str:
    """Project structural types from the Runtime schema, never from generated output.

    JSON Schema conditionals remain validator-enforced. EditCommand and canonical
    timeline documents remain opaque; OpCall comes from its existing Astrid schema.
    """
    definitions = {"EditCommand": opcall_schema(), **json.loads(_regular(COMMIT_SCHEMA, "timeline commit schema"))["$defs"]}

    lines: list[str] = []

    def expression(schema: Mapping[str, Any], name: str) -> str:
        if "$ref" in schema:
            return "EditCommand" if schema["$ref"] == opcall_schema()["$id"] else schema["$ref"].rsplit("/", 1)[-1]
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
  if (!object(value)) throw new TypeError("OpCall must be an object");
  const fields = OPCALL_SCHEMA.properties as Record<string, { type: string | readonly string[]; pattern?: string; items?: { type: string } }>;
  if (Object.keys(value).some(key => !(key in fields)) || OPCALL_SCHEMA.required.some(key => !(key in value))) throw new TypeError("OpCall missing or unknown field");
  if (!finiteJson(value)) throw new TypeError("OpCall requires finite JSON values");
  const types: Record<string, (v: unknown) => boolean> = { string: v => typeof v === "string", null: v => v === null, object, array: Array.isArray };
  for (const [key, item] of Object.entries(value)) {
    const field = fields[key];
    const kinds = typeof field.type === "string" ? [field.type] : field.type;
    if (!kinds.some(kind => types[kind](item)) || (field.pattern && !new RegExp(field.pattern).test(item as string)) || (field.items && (item as unknown[]).some(v => !types[field.items!.type](v)))) throw new TypeError("OpCall invalid " + key);
  }
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
