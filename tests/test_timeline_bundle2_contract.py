"""Ordinary/PARAM bundle validation and public generated-type reachability."""
from __future__ import annotations

import copy
import subprocess
from pathlib import Path
from typing import get_type_hints

import astrid_runtime_client as client
import pytest
import test_timeline_commit_port as support
from astrid_runtime_client import timeline_commit_types as dto
from test_timeline_commit_port import commit, request

from runtime_protocol.errors import ValidationError
from runtime_protocol.timeline_commit_validation import validate_commit_value

service = support.service
ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
PIN = {"document_id": "pack", "version": 1, "content_digest": DIGEST}
MEDIA = {"asset": "asset", "generation_id": "g", "variant_id": "v",
         "object_id": DIGEST, "catalog_digest": DIGEST}
ROW = {"id": "c", "clipType": "media", "track": "video", "at": 0, "hold": 1,
       "opaque": {"nil": None, "empty": []}}
CASES = [
    ("clip.move", "parent/clip:c", {"on": 1.5}),
    ("clip.delete", "parent/clip:c", {}),
    ("track.set", "parent/track:video", {"values": {"label": ""}, "clear": []}),
    ("track.create", "parent", {"row": {"id": "v", "kind": "video", "future": None}}),
    ("clip.set-params", "parent/clip:c", {"values": {"literal.key": None}, "clear": [], "schema_source": PIN}),
    ("clip.add", "parent", {"row": ROW}),
    ("clip.set", "occurrence:o/clip:c", {"values": {}, "clear": ["hold", "asset", "transition"]}),
    ("clip.trim", "parent/clip:c", {"in_s": None, "out_s": 2.5}),
    ("clip.split", "parent/clip:c", {"on": 2.5, "right_id": "right"}),
    ("occurrence.add-media", "occurrence:o", {"row": ROW, "media": MEDIA}),
    ("occurrence.swap-media", "occurrence:o/clip:c", {"old_media": MEDIA, "media": MEDIA}),
    ("placement.move", "occurrence:o/clip:c", {"on": 1.5}),
    ("timeline.inverse", None, {"publications": ["receipt"]}),
    ("timeline.restore", None, {"revision_id": "r", "content_digest": DIGEST}),
]


@pytest.mark.parametrize("op,select,args", CASES, ids=[case[0] for case in CASES])
def test_packaged_bundle2_commands_preserve_native_args(service, op, select, args):
    body = request(service)
    body["commands"][0].update(op=op, select=select, args=copy.deepcopy(args))
    before = copy.deepcopy(body)
    validate_commit_value(body, "CommitRequest")
    assert body == before


@pytest.mark.parametrize("op,select,args", CASES, ids=[case[0] for case in CASES])
def test_bundle2_closed_args_refuse_422_before_provider_or_writes(service, op, select, args):
    body = request(service)
    body["commands"][0].update(op=op, select=select, args={**copy.deepcopy(args), "unknown": None})
    before = tuple(service.store.conn.iterdump())
    with pytest.raises(ValidationError) as caught:
        commit(service, body)
    assert caught.value.status == 422
    assert service.test_provider.calls == 0
    assert tuple(service.store.conn.iterdump()) == before


@pytest.mark.parametrize("pin", [
    {}, {**PIN, "version": True}, {**PIN, "version": 0},
    {**PIN, "project_id": "other"}, {**PIN, "content_digest": "bad"},
])
def test_params_source_pin_is_closed_and_complete(service, pin):
    body = request(service)
    body["commands"][0].update(op="clip.set-params", args={"values": {"seed": 1}, "clear": [], "schema_source": pin})
    with pytest.raises(ValidationError):
        validate_commit_value(body, "CommitRequest")


def test_python_package_exports_native_args_and_nested_row_type():
    names = (
        "ClipAddArgs", "ClipDeleteArgs", "ClipMoveArgs", "ClipSetArgs", "ClipSetParamsArgs",
        "ClipSplitArgs", "ClipTrimArgs", "InverseArgs", "OccurrenceAddMediaArgs",
        "OccurrenceSwapMediaArgs", "RestoreArgs", "TrackCreateArgs", "TrackSetArgs",
        "DocumentPin", "MediaSelection", "VerifiedDocument", "VerifiedDocumentObject", "VerifiedMedia",
    )
    for name in names:
        assert getattr(client, name) is getattr(dto, name)
        assert name in client.__all__
    assert get_type_hints(dto.OccurrenceAddMediaArgs)["row"] is dto.ClipAddArgsRow
    assert dto.ClipAddArgsRow.__required_keys__ == {"id", "clipType", "track", "at", "hold"}
    assert dto.ClipDeleteArgs.__required_keys__ == dto.ClipDeleteArgs.__optional_keys__ == set()


def test_typescript_package_exports_native_args_and_open_rows():
    subprocess.run([
        "tsc", "--noEmit", "--strict", "--module", "NodeNext", "--target", "ES2022",
        str(ROOT / "tests/fixtures/timeline-bundle2-types.mts"),
    ], check=True)
