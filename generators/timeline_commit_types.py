"""Render detached commit DTOs from Runtime envelopes and the Agent schema pin."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _refine(base: dict, branch: dict) -> dict:
    """Keep shared object fields when a union branch narrows their constraints."""
    result = {**base, **branch}
    if "properties" in base or "properties" in branch:
        properties = base.get("properties", {})
        result["properties"] = {
            key: _refine(properties.get(key, {}), value)
            for key, value in {**properties, **branch.get("properties", {})}.items()
        }
        result["required"] = list(
            dict.fromkeys(base.get("required", []) + branch.get("required", []))
        )
    return result


def render() -> dict[str, str]:
    runtime = json.loads((ROOT / "contract/schemas/timeline-commit.json").read_text())[
        "$defs"
    ]
    agent = json.loads((ROOT / "contract/schemas/edit-command.json").read_text())[
        "$defs"
    ]
    definitions = {**agent, **runtime}
    # Resolve the imported Agent aliases without maintaining a second leaf schema.
    for name, schema in list(definitions.items()):
        if schema.get("$ref", "").startswith("edit-command.json#/$defs/"):
            definitions[name] = agent[schema["$ref"].rsplit("/", 1)[1]]

    openapi = yaml.safe_load((ROOT / "contract/openapi/workspace-v1.yaml").read_text())
    definitions["MutationReceipt"] = openapi["components"]["schemas"][
        "CommittedMutation"
    ]["properties"]["receipt"]
    pending = list(definitions)
    for name in pending:
        schema = definitions[name]
        for keyword in ("oneOf", "anyOf"):
            base = {key: value for key, value in schema.items() if key != keyword}
            for index, variant in enumerate(schema.get(keyword, [])):
                if "properties" in variant:
                    variant = _refine({"type": "object", **base}, variant)
                    variant_name = f"{name}Variant{index + 1}"
                    definitions[variant_name] = variant
                    pending.append(variant_name)
                    schema[keyword][index] = {"$ref": "#/$defs/" + variant_name}
            if keyword in schema:
                definitions[name] = {keyword: schema[keyword]}
        if "oneOf" in schema or "anyOf" in schema:
            continue
        properties = schema.get("properties", {})
        if (
            properties
            and schema.get("additionalProperties") is False
            and schema.get("minProperties") == len(properties)
        ):
            schema["required"] = list(properties)
        for key, value in properties.items():
            if value.get("type") == "object" and "properties" in value:
                nested_name = f"{name}{key[0].upper()}{key[1:]}"
                definitions[nested_name] = value
                pending.append(nested_name)
                properties[key] = {"$ref": "#/$defs/" + nested_name}

    def expression(schema: dict, language: str) -> str:
        py = language == "python"
        if "$ref" in schema:
            target = schema["$ref"]
            if target.startswith(("#/$defs/", "edit-command.json#/$defs/")):
                name, *path = target.split("#/$defs/", 1)[1].split("/")
                if path:
                    value = definitions[name]
                    for token in path:
                        value = value[token.replace("~1", "/").replace("~0", "~")]
                    return expression(value, language)
                return repr(name) if py else name
            # Canonical payloads remain open, owned by their existing schemas.
            return "dict[str, Any]" if py else "Record<string, unknown>"
        if "const" in schema or "enum" in schema:
            values = schema.get("enum", [schema.get("const")])
            return (
                ("Literal[" + ", ".join(repr(v) for v in values) + "]")
                if py
                else " | ".join(json.dumps(v) for v in values)
            )
        variants = schema.get("oneOf", schema.get("anyOf"))
        if variants:
            parts = [expression(v, language) for v in variants]
            return (
                "Union[" + ", ".join(parts) + "]"
                if py
                else "(" + " | ".join(parts) + ")"
            )
        kind = schema.get("type")
        if isinstance(kind, list):
            parts = [expression({"type": t}, language) for t in kind]
            return (
                "Union[" + ", ".join(parts) + "]"
                if py
                else "(" + " | ".join(parts) + ")"
            )
        if kind == "array":
            item = expression(schema.get("items", {}), language)
            min_items = schema.get("minItems")
            max_items = schema.get("maxItems")
            if (
                not py
                and isinstance(min_items, int)
                and min_items == max_items
                and min_items <= 16
            ):
                return "[" + ", ".join([item] * min_items) + "]"
            if not py and isinstance(min_items, int) and 0 < min_items <= 16:
                return "[" + ", ".join([item] * min_items) + f", ...Array<{item}>]"
            return f"list[{item}]" if py else f"Array<{item}>"
        if kind == "object":
            if "properties" in schema:
                required = schema.get("required", [])
                fields = []
                for key, value in schema["properties"].items():
                    item = expression(value, language)
                    if py:
                        if key not in required:
                            item = f"NotRequired[{item}]"
                        fields.append(f"{key!r}: {item}")
                    else:
                        fields.append(f"{key}{'' if key in required else '?'}: {item}")
                if not py and schema.get("additionalProperties", True) is not False:
                    additional = schema.get("additionalProperties", {})
                    item = expression(additional, language) if isinstance(additional, dict) else "unknown"
                    fields.append(f"[key: string]: {item}")
                elif not py and not fields:
                    fields.append("[key: string]: never")
                return (
                    "{ " + "; ".join(fields) + " }"
                    if not py
                    else "{" + ", ".join(fields) + "}"
                )
            additional = schema.get("additionalProperties", {})
            item = (
                expression(additional, language)
                if isinstance(additional, dict)
                else ("Any" if py else "unknown")
            )
            return f"dict[str, {item}]" if py else "{ [key: string]: " + item + " }"
        return (
            {
                "null": "None",
                "boolean": "bool",
                "number": "float",
                "integer": "int",
                "string": "str",
            }.get(kind, "Any")
            if py
            else {
                "null": "null",
                "boolean": "boolean",
                "number": "number",
                "integer": "number",
                "string": "string",
            }.get(kind, "unknown")
        )

    python = [
        '"""Generated timeline commit DTOs; do not edit by hand."""',
        "",
        "from typing import Any, Literal, NotRequired, TypedDict, Union",
        "",
    ]
    typescript = ["/** Generated timeline commit DTOs; do not edit by hand. */", ""]
    for name, schema in definitions.items():
        value = expression(schema, "python")
        if schema.get("$ref", "").startswith("#/$defs/"):
            value = schema["$ref"].rsplit("/", 1)[1]
        if schema.get("type") == "object" and "properties" in schema:
            python.append(f"{name} = TypedDict({name!r}, {value})")
        else:
            python.append(f"{name} = {value}")
        typescript.append(f"export type {name} = {expression(schema, 'typescript')};")
    py = "\n".join(python) + "\n"
    ts = "\n".join(typescript) + "\n"
    return {
        "runtime_protocol/timeline_commit_types.py": py,
        "packages/python/astrid_runtime_client/timeline_commit_types.py": py,
        "packages/typescript/src/timeline-commit-types.ts": ts,
    }
