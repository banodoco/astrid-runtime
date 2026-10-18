"""F231 internal diagnostics on the real Runtime/frozen-provider source path.

Only fresh offline identities are submitted. Optional qualification inputs are
retained public command/response records, never the original session envelope.
"""
import hashlib
import inspect
import json
import logging
import os
from pathlib import Path

import pytest

from runtime_protocol import timeline_commit
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from test_occurrence_preview_provider import (  # noqa: F401
    bound, fixture, occurrence_preview, runtime_preview,
)
from test_selected_media_commit import snapshot


def assert_source_and_saved_shape(body):
    import astrid
    from astrid.sdk.timeline import commit
    root = Path(__file__).resolve().parents[1]
    expected = root / "runtime_protocol/timeline_commit.py"
    assert Path(timeline_commit.__file__).resolve() == expected
    assert Path(inspect.getsourcefile(RuntimeService.commit_timeline)).resolve() == expected
    sdk = Path(os.environ.get("F231_SDK_ROOT", Path(astrid.__file__).resolve().parents[1]))
    assert Path(commit.__file__).resolve() == sdk / "astrid/sdk/timeline/commit.py"
    if "F231_SDK_ROOT" in os.environ:
        assert hashlib.sha256(Path(commit.__file__).read_bytes()).hexdigest() == (
            "1f55c2bd8ce92ecd71b04bc2cf3e56cfd6020c9f07dee5f1a44d4ddff009d48e")

    def normalize(call):
        ids = {**call["args"]["source"], **call["args"]["identities"]}
        text = json.dumps(call, sort_keys=True)
        for key, value in sorted(ids.items(), key=lambda item: len(item[1]), reverse=True):
            text = text.replace(value, "$" + key)
        return text
    if "F231_SAVED_CALLS" in os.environ:
        retained = json.loads(Path(os.environ["F231_SAVED_CALLS"]).read_text())["commands"]
        assert len(retained) == 1
        assert normalize(retained[0]) == normalize(body["change"]["commands"][0])


def expected_failure(body):
    expected = timeline_commit.result_template(body, timeline_commit.digest(body))
    expected["error"] = dict(code="runtime_unavailable",
        message="Astrid commit provider failed; outcome may be unknown",
        hint="Acceptance may already be durable", next_action="Retry the original request id unchanged")
    if "F231_RESPONSE" in os.environ:
        retained = json.loads(Path(os.environ["F231_RESPONSE"]).read_text())["response"]
        # Only offline fixture identities differ; every other public byte/field
        # must retain the original captured error's canonical serialization.
        for field in ("request_id", "request_hash", "base_revision_id"):
            retained[field] = expected[field]
        assert json.dumps(retained, sort_keys=True) == json.dumps(expected, sort_keys=True)
    return expected


@pytest.mark.parametrize("occurrence_preview", ["saved"], indirect=True)
@pytest.mark.parametrize("stage", ["provider_commit", "preview_scene_validation"])
@pytest.mark.parametrize("sink_available", [True, False])
def test_real_saved_occurrence_records_stage_without_changing_public_result(
        occurrence_preview, monkeypatch, caplog, stage, sink_available):
    from astrid.sdk.timeline.commit import RuntimeCommitService, create_runtime_commit_service
    w, body = occurrence_preview
    assert_source_and_saved_shape(body)
    secret = "credential-canary session-canary fd-999 /private/canary raw-body-canary"
    if stage == "provider_commit":
        # A missing immutable pin naturally raises the real Runtime's closure
        # ConflictError during the SDK provider's declared-source read.
        body["change"]["commands"][0]["args"]["source"]["shot_revision_id"] = "missing-revision-canary"
        w.s._timeline_commit_provider = create_runtime_commit_service()
        diagnostic = dict(stage=stage, exception_class="ConflictError", error_code="conflict")
    else:
        class IncompletePreview(RuntimeCommitService):
            def commit(self, request, port):
                result = super().commit(request, port)
                assert result["status"] == "preview"
                # The provider/evaluation/compiler all ran successfully. The
                # existing scene validator recomputes the candidate digest;
                # a non-JSON value naturally raises TypeError inside that path.
                result["canonical_document"]["private-fixture-canary"] = object()
                return result
        w.s._timeline_commit_provider = IncompletePreview()
        diagnostic = dict(stage=stage, exception_class="TypeError")
    if not sink_available:
        def unavailable(*args, **kwargs):
            raise OSError(secret)
        monkeypatch.setattr(timeline_commit._LOGGER, "error", unavailable)
    before = snapshot(w.s)
    with caplog.at_level(logging.ERROR, logger=timeline_commit.__name__):
        result = runtime_preview(w, body)
    assert json.dumps(result, sort_keys=True) == json.dumps(expected_failure(body), sort_keys=True)
    records = [r for r in caplog.records if r.name == timeline_commit.__name__]
    if sink_available:
        assert len(records) == 1
        record = records[0]
        assert record.getMessage() == "timeline_commit_failure " + timeline_commit.canonical_json(diagnostic)
        assert record.exc_info is None and record.stack_info is None
        assert len(record.getMessage()) < 200
    else:
        assert not records
    assert secret not in caplog.text and secret not in json.dumps(result)
    assert "missing-revision-canary" not in caplog.text
    assert "private-fixture-canary" not in caplog.text
    assert all(value not in caplog.text for value in (body["request_id"], body["session_id"], w.identity["actor"]))
    assert "exception_class" not in json.dumps(result) and "provider_commit" not in json.dumps(result)
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


@pytest.mark.parametrize("kind", ["runtime-code", "unknown-class", "spoofed-class"])
def test_internal_diagnostic_never_reads_exception_data(caplog, kind):
    secret = "credential-canary session-canary fd-999 /private/canary raw-body-canary"
    if kind == "runtime-code":
        exc = ConflictError(secret, details={"secret": secret})
        exc.code = secret
        expected = dict(stage="unknown", exception_class="ConflictError", error_code="conflict")
    else:
        class PrivateFailure(Exception):
            @property
            def code(self):
                pytest.fail("diagnostics must not inspect arbitrary exception attributes")
            def __str__(self):
                pytest.fail("diagnostics must not stringify exceptions")
            def __repr__(self):
                pytest.fail("diagnostics must not repr exceptions")
        PrivateFailure.__name__ = "NotFoundError" if kind == "spoofed-class" else secret * 100
        exc = PrivateFailure(secret)
        expected = dict(stage="unknown", exception_class="OtherException")
    with caplog.at_level(logging.ERROR, logger=timeline_commit.__name__):
        timeline_commit._record_commit_failure(secret, exc)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.getMessage() == "timeline_commit_failure " + timeline_commit.canonical_json(expected)
    assert record.exc_info is None and record.stack_info is None
    assert secret not in caplog.text
