from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_timeline_commit_contract import validator

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
FIELDS = {"object_id", "digest", "size", "media_type", "bytes_base64"}


def document_object():
    return {"object_id": DIGEST, "digest": DIGEST, "size": 2,
            "media_type": "application/json", "bytes_base64": "e30="}


def malformed_objects():
    for field in sorted(FIELDS):
        value = document_object()
        del value[field]
        yield value
    for field, invalid in (
        ("unknown", None), ("size", True), ("size", False),
        ("size", 0), ("size", -1), ("size", 1.5), ("size", "2"),
        ("media_type", "text/plain"), ("media_type", None),
        ("object_id", "sha256:" + "A" * 64), ("digest", "a" * 64),
        ("bytes_base64", b"e30="), ("bytes_base64", None),
    ):
        yield {**document_object(), field: invalid}


def test_document_object_is_closed_and_preserves_json():
    value = document_object()
    before = copy.deepcopy(value)
    validator("VerifiedDocumentObject").validate(value)
    assert value == before == json.loads(json.dumps(value))
    assert set(value) == FIELDS
    # Sibling equality, byte decoding, size and raw hash checks belong to custody.
    value.update(digest="sha256:" + "b" * 64)
    validator("VerifiedDocumentObject").validate(value)


@pytest.mark.parametrize("value", list(malformed_objects()))
def test_document_object_rejects_malformed_fields(value):
    assert not validator("VerifiedDocumentObject").is_valid(value)


@pytest.fixture(scope="module")
def generated_tree(tmp_path_factory):
    # Verify source-only staging without rewriting frozen release artifacts.
    root = tmp_path_factory.mktemp("document-object") / "runtime"
    shutil.copytree(
        ROOT, root,
        ignore=shutil.ignore_patterns(
            ".git", ".agents", ".aws", ".codex", "__pycache__",
            ".pytest_cache", ".mypy_cache", "node_modules", "dist", "build",
        ),
    )
    subprocess.run([sys.executable, "generators/generate.py"], cwd=root, check=True)
    yield root
    shutil.rmtree(root.parent)


def generated_env(root):
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(root), str(root / "packages/python"))),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def test_generated_python_type_and_protocol_are_reachable(generated_tree):
    subprocess.run(
        [sys.executable, "-S", "-c", """
import sys
from typing import Literal, get_type_hints
from astrid_runtime_client.timeline_commit_types import VerifiedDocumentObject as client
from runtime_protocol.timeline_commit import RuntimeCommitPort, VerifiedDocumentObject
from runtime_protocol import timeline_commit_types as dto
assert client.__required_keys__ == VerifiedDocumentObject.__required_keys__ == {
    'object_id', 'digest', 'size', 'media_type', 'bytes_base64',
}
assert client.__optional_keys__ == VerifiedDocumentObject.__optional_keys__ == set()
assert get_type_hints(client) == get_type_hints(VerifiedDocumentObject) == {
    'object_id': str, 'digest': str, 'size': int,
    'media_type': Literal['application/json'], 'bytes_base64': str,
}
assert get_type_hints(RuntimeCommitPort.document_object) == {
    'pin': dto.DocumentPin, 'object_id': dto.Digest, 'return': dto.VerifiedDocumentObject,
}
assert not any(n.startswith(('jsonschema', 'referencing', 'yaml', 'astrid.')) for n in sys.modules)
"""],
        cwd=generated_tree, env=generated_env(generated_tree), check=True,
    )


def test_generated_bundle_validates_document_objects(generated_tree):
    # bytes are rejected before schema validation and are not JSON serializable.
    invalid = [v for v in malformed_objects() if not isinstance(v.get("bytes_base64"), bytes)]
    subprocess.run(
        [sys.executable, "-c", """
import json, sys
from runtime_protocol.errors import ValidationError
from runtime_protocol.timeline_commit_validation import validate_commit_value
valid, invalid = json.load(sys.stdin)
validate_commit_value(valid, 'VerifiedDocumentObject')
for value in invalid:
    try:
        validate_commit_value(value, 'VerifiedDocumentObject')
    except ValidationError:
        pass
    else:
        raise AssertionError(value)
"""],
        input=json.dumps([document_object(), invalid]), text=True,
        cwd=generated_tree, env=generated_env(generated_tree), check=True,
    )


def test_generated_typescript_package_exports_document_object(generated_tree):
    subprocess.run([
        "tsc", "--noEmit", "--strict", "--module", "NodeNext", "--target", "ES2022",
        str(generated_tree / "tests/fixtures/timeline-document-object-types.mts"),
    ], cwd=generated_tree, check=True)
