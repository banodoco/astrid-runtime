from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import zipfile
from decimal import Decimal
from pathlib import Path
from urllib.parse import urljoin

import pytest
import yaml
from referencing.exceptions import Unresolvable

from runtime_protocol.errors import ValidationError
from runtime_protocol.timeline_commit_validation import (
    _schema_resources,
    validate_commit_value,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
PIN = {"revision_id": "r", "publication_id": "txn"}


def command():
    return {
        "schema_version": 1,
        "op": "clip.move",
        "version": "1",
        "select": "parent/clip:c",
        "args": {"on": 2},
    }


def request():
    return {
        "api_version": 1,
        "project_id": "p",
        "timeline_id": "t",
        "base_revision_id": "r",
        "base_publication_id": "txn",
        "commands": [command()],
    }


def prepared():
    record = {
        "ordinal": 0,
        "command": command(),
        "writes": [],
        "reads": [],
        "selections": [],
        "bindings": [],
        "created": [],
        "dependencies": [],
        "derived_writes": [],
    }
    config = {"clips": [], "tracks": []}
    document = {
        "schema_version": 1,
        "project_id": "p",
        "timeline_id": "t",
        "parent_revision": {
            "revision_id": "r",
            "content_digest": DIGEST,
            "payload": {
                "config": copy.deepcopy(config),
                "registry": {},
                "clips": [],
                "occurrences": [],
            },
        },
        "shot_revisions": [
            {
                "shot_id": "s",
                "revision_id": "s1",
                "internal_timeline_revision_id": "i1",
                "content_digest": DIGEST,
                "payload": {"opaque": {"clear": None}},
            }
        ],
        "internal_timeline_revisions": [
            {
                "timeline_id": "i",
                "revision_id": "i1",
                "content_digest": DIGEST,
                "payload": config,
            }
        ],
        "dependency_manifest": {
            "shots": [],
            "internal_timelines": [],
            "media": [],
            "documents": [],
        },
    }
    return {
        "expected_head": copy.deepcopy(PIN),
        "canonical_document": document,
        "document_digest": DIGEST,
        "id_map": {},
        "provider_version": "1",
        "compiler_version": "1",
        "semantic_events": [],
        "records": {
            "schema_version": 1,
            "commands": [record],
            "undo_of": [],
            "restored_from": None,
        },
    }


def failure():
    conflict = {
        "kind": "overlap",
        "ref": "parent/clip:c",
        "path": ["at"],
        "base": {"state": "absent"},
        "theirs": {"state": "present", "value": None},
        "ours": {"state": "present", "value": {"opaque": [None, False]}},
        "choices": [command()],
    }
    return {
        "http_status": 409,
        "code": "conflict",
        "message": "changed",
        "details": {
            "status": "conflict",
            "reason": "overlap",
            "base": copy.deepcopy(PIN),
            "current": copy.deepcopy(PIN),
            "conflicts": [conflict],
        },
    }


def test_schema_owned_values_preserve_opaque_null_absence_and_defaults():
    value = request()
    value["commands"][0].update(
        op="vendor.decorate",
        select=None,
        args={
            "project_id": "foreign-looking-data",
            "opaque": {"op": "clear", "$absent": True, "value": None},
        },
        expect={
            "at": {"state": "absent"},
            "config": {"state": "present", "value": None},
        },
    )
    for definition, body in (
        ("CommitRequest", value),
        ("PreparedCommit", prepared()),
        ("CommitFailure", failure()),
    ):
        before = copy.deepcopy(body)
        assert validate_commit_value(body, definition) is None
        assert body == before == json.loads(json.dumps(body, allow_nan=False))
    assert "dry_run" not in value
    assert "source" not in value
    shared = {"value": None}
    value["commands"][0]["args"] = {"a": shared, "b": shared}
    validate_commit_value(value, "CommitRequest")


@pytest.mark.parametrize(
    "args",
    [
        {"values": {"label": "Picture é 🎬"}, "clear": []},
        {"values": {"label": ""}, "clear": []},
        {"values": {}, "clear": ["label"]},
    ],
)
@pytest.mark.parametrize("before", [{"state": "absent"}, {"state": "present", "value": "Old"}])
def test_packaged_track_set_accepts_labels_and_clear_without_changing_input(args, before):
    value = request()
    value["commands"][0].update(
        op="track.set",
        select="parent/track:picture",
        args=copy.deepcopy(args),
        expect={"label": copy.deepcopy(before)},
    )
    original = copy.deepcopy(value)
    validate_commit_value(value, "CommitRequest")
    assert value == original


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"values": {"label": "Picture"}},
        {"clear": ["label"]},
        {"values": {}, "clear": []},
        {"values": {"label": None}, "clear": []},
        {"values": {"label": False}, "clear": []},
        {"values": {"label": 1}, "clear": []},
        {"values": {"volume": 1}, "clear": []},
        {"values": [], "clear": ["label"]},
        {"values": {}, "clear": None},
        {"values": {}, "clear": ["volume"]},
        {"values": {}, "clear": ["label", "label"]},
        {"values": {"label": "Picture"}, "clear": [], "unknown": None},
    ],
)
def test_packaged_track_set_rejects_malformed_args(args):
    value = request()
    value["commands"][0].update(
        op="track.set", select="parent/track:picture", args=args
    )
    with pytest.raises(ValidationError):
        validate_commit_value(value, "CommitRequest")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(unknown=True),
        lambda v: v.update(api_version=True),
        lambda v: v.update(commands=[]),
        lambda v: v.update(base_publication_id=None),
        lambda v: v.update(source={"via": "gateway"}),
        lambda v: v.update(source=None),
        lambda v: v["commands"][0].update(unknown=True),
        lambda v: v["commands"][0].pop("version"),
        lambda v: v["commands"][0].update(schema_version=True),
        lambda v: v["commands"][0].update(
            expect={"at": {"state": "absent", "value": None}}
        ),
    ],
)
def test_bad_requests_use_the_authoritative_command_schema(mutate):
    value = request()
    mutate(value)
    with pytest.raises(ValidationError):
        validate_commit_value(value, "CommitRequest")


@pytest.mark.parametrize("number", [-1, True, 0.5])
def test_schema_rejects_invalid_record_ordinals_and_derived_causes(number):
    value = prepared()
    record = value["records"]["commands"][0]
    record["ordinal"] = number
    with pytest.raises(ValidationError):
        validate_commit_value(value, "PreparedCommit")
    record["ordinal"] = 0
    record["derived_writes"] = [
        {
            "ref": "parent/clip:c",
            "path": ["compiled"],
            "before": {"state": "absent"},
            "after": {"state": "present", "value": None},
            "cause": number,
        }
    ]
    with pytest.raises(ValidationError):
        validate_commit_value(value, "PreparedCommit")


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        -float("inf"),
        json.loads("1e999"),
        {1: "bad-key"},
        (1, 2),
        {1, 2},
        b"bytes",
        Decimal(2),
        object(),
    ],
)
def test_non_json_is_rejected_even_inside_untyped_payloads(value):
    body = prepared()
    body["canonical_document"]["shot_revisions"][0]["payload"]["opaque"] = value
    with pytest.raises(ValidationError):
        validate_commit_value(body, "PreparedCommit")


def test_cyclic_json_is_rejected():
    value = request()
    value["commands"][0]["args"]["cycle"] = value
    with pytest.raises(ValidationError, match="cycles"):
        validate_commit_value(value, "CommitRequest")


def test_transitive_config_schema_rejects_bool_as_number_without_inserting_defaults():
    value = prepared()
    track = {"id": "v", "kind": "visual", "label": "Video", "volume": 1}
    value["canonical_document"]["internal_timeline_revisions"][0]["payload"][
        "tracks"
    ] = [track]
    validate_commit_value(value, "PreparedCommit")
    assert "role" not in track
    track["volume"] = True
    with pytest.raises(ValidationError):
        validate_commit_value(value, "PreparedCommit")


def test_closed_prepared_failure_and_restore_envelopes():
    restore = {"expected_head": "r", "expected_publication_id": "txn"}
    validate_commit_value(restore, "RestoreParentCompositionRevision")
    for definition, value in (
        ("PreparedCommit", prepared()),
        ("CommitFailure", failure()),
        ("RestoreParentCompositionRevision", restore),
    ):
        value["unknown"] = None
        with pytest.raises(ValidationError):
            validate_commit_value(value, definition)
    value = request()
    value["commands"] = [
        {
            "schema_version": 1,
            "op": "timeline.restore",
            "version": "1",
            "select": None,
            "args": {"revision_id": "old", "content_digest": DIGEST},
        }
    ]
    validate_commit_value(value, "CommitRequest")
    value["commands"].append(command())
    with pytest.raises(ValidationError):
        validate_commit_value(value, "CommitRequest")
    with pytest.raises(ValidationError):
        validate_commit_value(
            {"expected_head": "r"}, "RestoreParentCompositionRevision"
        )


def test_bundle_matches_canonical_resources_and_generator():
    manifest_path = ROOT / "scripts" / "artifact_manifest.py"
    manifest_spec = importlib.util.spec_from_file_location(
        "_runtime_timeline_artifact_manifest", manifest_path
    )
    assert manifest_spec is not None and manifest_spec.loader is not None
    manifest = importlib.util.module_from_spec(manifest_spec)
    manifest_spec.loader.exec_module(manifest)
    assert Path(manifest.__file__).resolve() == manifest_path.resolve()

    artifacts = manifest.digests()
    for relative in (
        "packages/python/astrid_runtime_client/timeline_commit_types.py",
        "packages/typescript/src/timeline-commit-types.ts",
        "runtime_protocol/schemas/timeline-commit-bundle.json",
    ):
        assert relative in artifacts
    spec = importlib.util.spec_from_file_location(
        "commit_resources", ROOT / "generators/timeline_commit_resources.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert (ROOT / generator.OUTPUT).read_text() == generator.render(ROOT)[
        generator.OUTPUT
    ]
    bundle, _ = _schema_resources()
    assert len(bundle["resources"]) == 6
    for uri, schema in bundle["resources"].items():
        if uri.endswith(".json"):
            assert schema == json.loads(
                (ROOT / "contract/schemas" / uri.rsplit("/", 1)[1]).read_text()
            )
        else:
            receipt = yaml.safe_load(
                (ROOT / "contract/openapi/workspace-v1.yaml").read_text()
            )["components"]["schemas"]["CommittedMutation"]["properties"]["receipt"]
            assert schema == {
                "components": {
                    "schemas": {
                        "CommittedMutation": {"properties": {"receipt": receipt}}
                    }
                }
            }


def test_every_reference_is_local_and_unknown_uris_fail_closed(monkeypatch):
    import socket
    import urllib.request

    def no_network(*args, **kwargs):
        pytest.fail("schema validation attempted external resolution")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    bundle, registry = _schema_resources()

    def visit(value, base):
        if isinstance(value, dict):
            base = urljoin(base, value.get("$id", ""))
            if "$ref" in value:
                registry.resolver(base).lookup(value["$ref"])
            for child in value.values():
                visit(child, base)
        elif isinstance(value, list):
            for child in value:
                visit(child, base)

    for uri, schema in bundle["resources"].items():
        visit(schema, uri)
    for uri in (
        "https://example.invalid/schema.json",
        "file:///tmp/unpackaged-schema.json",
    ):
        with pytest.raises(Unresolvable):
            registry.resolver().lookup(uri)
    with pytest.raises(ValidationError, match="unknown commit schema"):
        validate_commit_value({}, "https://example.invalid/schema.json")


def test_installed_wheel_validates_outside_checkout_and_abi_is_stdlib_only(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for filename in ("pyproject.toml", "setup.py", "LICENSE"):
        shutil.copy2(ROOT / filename, source / filename)
    for package in ("astrid_runtime", "runtime_protocol"):
        shutil.copytree(
            ROOT / package,
            source / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    builder = None
    for candidate in (
        sys.executable,
        "python3.11",
        "python3.12",
        "python3.13",
        "python3",
        "python",
    ):
        try:
            probe = subprocess.run(
                [candidate, "-c", "import setuptools.build_meta, wheel, pip"],
                capture_output=True,
                check=False,
            )
        except OSError:
            continue
        if probe.returncode == 0:
            builder = candidate
            break
    assert builder is not None, (
        "offline wheel test requires Python with setuptools>=68, wheel and pip"
    )
    wheelhouse = tmp_path / "wheels"
    build_env = os.environ.copy()
    if builder == sys.executable:
        build_env.pop("SETUPTOOLS_USE_DISTUTILS", None)
    else:
        build_env["SETUPTOOLS_USE_DISTUTILS"] = "stdlib"
    subprocess.run(
        [
            builder,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-cache-dir",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(source),
        ],
        env=build_env,
        check=True,
    )
    (wheel,) = wheelhouse.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        resource = "runtime_protocol/schemas/timeline-commit-bundle.json"
        assert archive.read(resource) == (ROOT / resource).read_bytes()
        (metadata,) = (
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        assert "Requires-Dist: jsonschema >=4" in archive.read(
            metadata
        ).decode().replace("jsonschema>=", "jsonschema >=")
    target = tmp_path / "installed"
    subprocess.run(
        [
            builder,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--target",
            str(target),
            str(wheel),
        ],
        check=True,
    )
    shutil.rmtree(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    values = [
        ["CommitRequest", request()],
        ["PreparedCommit", prepared()],
        ["CommitFailure", failure()],
        [
            "RestoreParentCompositionRevision",
            {"expected_head": "r", "expected_publication_id": "txn"},
        ],
    ]
    (outside / "values.json").write_text(json.dumps(values))
    env = {**os.environ, "PYTHONPATH": str(target), "PYTHONDONTWRITEBYTECODE": "1"}
    probe = """
import json, pathlib, socket, sys
import runtime_protocol.timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
assert pathlib.Path(validation.__file__).is_relative_to(pathlib.Path(sys.path[1]))
assert 'yaml' not in sys.modules and 'jsonschema' not in sys.modules
def forbidden(*args, **kwargs):
    raise AssertionError('network resolution attempted')
socket.socket = forbidden
for name, body in json.loads(pathlib.Path('values.json').read_text()):
    validation.validate_commit_value(body, name)
    body['unknown'] = True
    try:
        validation.validate_commit_value(body, name)
    except ValidationError:
        pass
    else:
        raise AssertionError('unknown field accepted')
from referencing.exceptions import Unresolvable
_, registry = validation._schema_resources()
try:
    registry.resolver().lookup('https://example.invalid/schema.json')
except Unresolvable:
    pass
else:
    raise AssertionError('external schema resolved')
assert 'yaml' not in sys.modules
"""
    subprocess.run(
        [sys.executable, "-c", probe],
        cwd=outside,
        env=env,
        check=True,
        capture_output=True,
    )
    abi = """
import sys
from runtime_protocol.timeline_commit import RuntimeCommitPort, CommitRequest
from runtime_protocol.timeline_commit_validation import validate_commit_value
assert not any(n.startswith(('jsonschema', 'referencing', 'yaml', 'astrid.')) for n in sys.modules)
"""
    subprocess.run(
        [sys.executable, "-S", "-c", abi],
        cwd=outside,
        env={**env, "PATH": ""},
        check=True,
        capture_output=True,
    )
