"""Package the authoritative commit schema and its local reference closure."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urldefrag, urljoin

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://astrid.haus/workspace/v1/"
COMMIT_URI = BASE + "schemas/timeline-commit.json"
OPENAPI_URI = BASE + "openapi/workspace-v1.yaml"
RECEIPT_REF = "/components/schemas/CommittedMutation/properties/receipt"
OUTPUT = "runtime_protocol/schemas/timeline-commit-bundle.json"


def render(root: Path = ROOT) -> dict[str, str]:
    sources = {}
    for path in (root / "contract/schemas").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        uri = BASE + "schemas/" + path.name
        sources[uri] = (uri, schema)
        if "$id" in schema:
            sources[schema["$id"]] = (uri, schema)

    resources = {}

    def include(uri: str, fragment: str = "") -> None:
        if uri == OPENAPI_URI:
            if fragment != RECEIPT_REF:
                raise ValueError("commit schemas may only import the OpenAPI receipt")
            if uri not in resources:
                document = yaml.safe_load(
                    (root / "contract/openapi/workspace-v1.yaml").read_text(
                        encoding="utf-8"
                    )
                )
                receipt = document["components"]["schemas"]["CommittedMutation"][
                    "properties"
                ]["receipt"]
                resources[uri] = {
                    "components": {
                        "schemas": {
                            "CommittedMutation": {"properties": {"receipt": receipt}}
                        }
                    }
                }
                visit(resources[uri], uri)
            return
        if uri not in sources:
            raise ValueError(f"unpackaged commit schema reference: {uri}")
        location, schema = sources[uri]
        if location not in resources:
            resources[location] = schema
            visit(schema, location)

    def visit(value, base: str) -> None:
        if isinstance(value, dict):
            base = urljoin(base, value.get("$id", ""))
            if "$ref" in value:
                include(*urldefrag(urljoin(base, value["$ref"])))
            for child in value.values():
                visit(child, base)
        elif isinstance(value, list):
            for child in value:
                visit(child, base)

    include(COMMIT_URI)
    bundle = {"root": COMMIT_URI, "resources": resources}
    return {
        OUTPUT: json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    }
