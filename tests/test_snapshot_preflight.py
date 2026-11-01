"""A later capture carrier must refuse before an earlier one publishes."""
from copy import deepcopy

import pytest

from runtime_protocol.util import canonical_json
from tests.test_snapshot_authority_refusal import (
    _admit_and_claim,
    _assert_refused_without_writes,
    _ref,
    _request,
)
from tests.test_snapshot_authority_refusal import capture as capture_fixture


@pytest.fixture
def capture(tmp_path):
    yield from capture_fixture.__wrapped__(tmp_path)


def _native_snapshot(capture):
    snapshot = deepcopy(capture[3])
    snapshot["metadata"].pop("capture_authority")
    snapshot["metadata"].pop("canonical_timeline")
    return snapshot


@pytest.mark.parametrize("second", ["inline", "missing-ref", "malformed-ref"])
def test_later_invalid_alias_does_not_publish_first_snapshot(capture, second):
    service = capture[0]
    snapshot = _native_snapshot(capture)
    request = _request(capture, snapshot=snapshot, inline=True)
    context = request["spec"]["authority_context"]
    if second == "inline":
        replacement = deepcopy(snapshot)
        replacement["registry"] = []
        context["input_snapshot"] = replacement
    elif second == "missing-ref":
        context["input_snapshot_ref"] = {
            "digest": "sha256:" + "0" * 64, "project_id": capture[1], "source_kind": "cas",
        }
    else:
        obj = service.ingest(capture[1], b"{}", idempotency_key="malformed")["data"]["object_id"]
        context["input_snapshot_ref"] = {
            "digest": obj, "project_id": capture[1], "timeline_id": "main", "source_kind": "cas",
        }
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(context)
    _assert_refused_without_writes(service, request)


@pytest.mark.parametrize("field", ["capture_snapshot", "timeline_snapshot"])
def test_inline_snapshot_cannot_replace_a_different_ref(capture, field):
    snapshot = _native_snapshot(capture)
    request = _request(capture, snapshot=snapshot, inline=True)
    context = request["spec"]["authority_context"]
    replacement = deepcopy(snapshot)
    replacement["config"]["different"] = True
    if field == "capture_snapshot":
        context["capture_snapshot_ref"] = _ref(capture[0], capture[1], replacement)
    else:
        request["spec"]["timeline_snapshot"] = snapshot
        request["spec"]["timeline_snapshot_ref"] = _ref(capture[0], capture[1], replacement)
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(context)
    _assert_refused_without_writes(capture[0], request)


@pytest.mark.parametrize("field", ["project_id", "timeline_id", "revision_id"])
def test_duplicate_scope_is_checked_before_inline_publication(capture, field):
    request = _request(capture, snapshot=_native_snapshot(capture), inline=True)
    duplicate = deepcopy(request["spec"]["authority_context"])
    duplicate[field] = "another-scope"
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(duplicate)
    _assert_refused_without_writes(capture[0], request)


def test_native_aliases_still_publish_and_retry_exactly(capture):
    snapshot = _native_snapshot(capture)
    request = _request(capture, snapshot=snapshot, inline=True)
    context = request["spec"]["authority_context"]
    context["input_snapshot"] = deepcopy(snapshot)
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(context)
    ref = _admit_and_claim(capture, request)
    first = capture[0].create_task(request)
    second = capture[0].create_task(request)
    assert first["task"]["id"] == second["task"]["id"]
    assert first["task"]["spec"]["spec"]["authority_context"]["input_snapshot_ref"] == ref


def test_explicit_cas_ref_keeps_leftover_metadata_uncertified(capture):
    request = _request(capture)
    context = request["spec"]["authority_context"]
    ref = context["capture_snapshot_ref"]
    ref.update(source_kind="cas", revision_id=None, revision_digest=None)
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(context)
    admitted = _admit_and_claim(capture, request)
    assert admitted["source_kind"] == "cas"
    assert admitted["revision_id"] is None
    assert admitted["revision_digest"] is None


@pytest.mark.parametrize("provider", ["absent", "without-method"])
def test_missing_optional_projector_refuses_claim_before_writes(capture, monkeypatch, provider):
    if provider == "absent":
        monkeypatch.setattr(capture[0], "_timeline_commit_provider", None)
    else:
        monkeypatch.delattr(type(capture[0]._timeline_commit_provider), "project_capture")
    _assert_refused_without_writes(capture[0], _request(capture, inline=True))
    request = _request(capture, snapshot=_native_snapshot(capture), inline=True)
    assert _admit_and_claim(capture, request)["source_kind"] == "cas"


@pytest.mark.parametrize("replacement", [True, 1])
def test_equal_python_numbers_cannot_replace_exact_projection(capture, replacement):
    snapshot = deepcopy(capture[3])
    assert snapshot["config"]["clips"][0]["hold"] == replacement
    snapshot["config"]["clips"][0]["hold"] = replacement
    _assert_refused_without_writes(capture[0], _request(capture, snapshot=snapshot, inline=True))


def test_later_forged_projection_does_not_publish_valid_first_alias(capture):
    request = _request(capture, inline=True)
    context = request["spec"]["authority_context"]
    replacement = deepcopy(context["capture_snapshot"])
    replacement["registry"]["assets"]["forged"] = {"opaque": True}
    context["input_snapshot"] = replacement
    request["spec"]["inputs"]["filmstrip_authority"] = canonical_json(context)
    _assert_refused_without_writes(capture[0], request)


def test_retained_media_is_verified_before_projector_or_publication(capture, monkeypatch):
    service, _, _, _, media = capture
    service.cas.path_for(media.removeprefix("sha256:")).write_bytes(b"corrupt retained media")

    def unexpected_projection(*args, **kwargs):
        raise AssertionError("provider must not receive an unverified closure")

    monkeypatch.setattr(service._timeline_commit_provider, "project_capture", unexpected_projection)
    _assert_refused_without_writes(service, _request(capture, inline=True))
