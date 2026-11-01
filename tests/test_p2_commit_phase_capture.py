from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import os
import pstats
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest_plugins = ("test_timeline_commit_port",)

from test_timeline_commit_port import request as commit_request

from runtime_protocol.server import RuntimeHandler, RuntimeHTTPServer
from tests.helpers.p2_commit_phase_capture import PHASES, P2CommitPhaseCapture


class _Credentials:
    def require(self, token, scope):
        assert token == "phase-token"
        assert scope == "projects:write"
        return {"actor": "phase-editor", "scopes": ["projects:write"]}


def _handler(runtime, body, *, key="phase-key"):
    raw = json.dumps(body, separators=(",", ":")).encode()
    handler: Any = object.__new__(RuntimeHandler)
    handler.server = SimpleNamespace(runtime=runtime, credentials=_Credentials())
    handler.command = "POST"
    handler.path = f"/v1/projects/{body['project_id']}/timelines/{body['timeline_id']}/commit"
    handler.headers = {
        "Content-Length": str(len(raw)),
        "Authorization": "Bearer phase-token",
        "Idempotency-Key": key,
    }
    handler.rfile = io.BytesIO(raw)
    handler.wfile = io.BytesIO()
    handler.send_response = lambda status: setattr(handler, "sent_status", status)
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None
    handler._defer_response = False
    return handler


def _summary(capture):
    return [event for event in capture.events if event["phase"] == "summary"]


def test_supported_app_bootstrap_loads_this_pinned_helper_offline(tmp_path, monkeypatch):
    """Exercise the normal sitecustomize loader without starting Runtime or HTTP."""
    helper_path = str((Path(__file__).parent / "helpers/p2_commit_phase_capture.py").resolve())
    bootstrap_path = Path("/home/user/work/app/scripts/testing/sitecustomize.py")
    assert bootstrap_path.is_file()
    sink = tmp_path / "normal-loader.jsonl"
    monkeypatch.setenv("ASTRID_P2_COMMIT_PHASE_CAPTURE_SINK", str(sink))
    monkeypatch.setenv("ASTRID_P2_COMMIT_PHASE_CAPTURE_HELPER", helper_path)
    monkeypatch.setattr(sys, "argv", ["-m", "start"])
    spec = importlib.util.spec_from_file_location("d124_sitecustomize", bootstrap_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._start_capture()
    try:
        assert module._capture is not None
        assert module._capture.active
        assert module._capture.__class__.__module__ == "_astrid_p2_commit_phase_capture"
    finally:
        module._capture.stop()
    assert sink.exists()


class _FakeTimer:
    def __init__(self, delay, callback):
        self.delay = delay
        self.callback = callback
        self.daemon = False
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        self.callback()


def test_capture_is_disabled_by_default_and_explicitly_bounded(tmp_path):
    capture = P2CommitPhaseCapture(tmp_path / "disabled.jsonl")
    with capture:
        capture._begin(1, "handler_entry")
    assert capture.events == []
    assert not (tmp_path / "disabled.jsonl").exists()

    bounded = P2CommitPhaseCapture(enabled=True, max_requests=2, max_events=4, max_bytes=1024)
    bounded.start()
    first = bounded._new_request()
    second = bounded._new_request()
    third = bounded._new_request()
    assert first is not None
    assert first == 1 and second == 2 and third is None
    bounded._begin(first, "handler_entry")
    bounded._end(first, "handler_entry")
    bounded.stop()
    assert len(bounded.events) <= 4
    assert bounded.truncated


def test_capture_attach_detach_restores_process_and_thread_traces():
    previous_process = sys.gettrace()
    previous_threads = threading.gettrace()
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    assert sys.gettrace() == capture._trace
    assert threading.gettrace() == capture._trace
    capture.stop()
    assert sys.gettrace() == previous_process
    assert threading.gettrace() == previous_threads


def test_capture_allowlist_redacts_by_not_retaining_transport_values(tmp_path):
    capture = P2CommitPhaseCapture(tmp_path / "phase.jsonl", enabled=True)
    capture.start()
    request = capture._new_request()
    assert request is not None
    capture._begin(request, "handler_entry", status="not-allowlisted")
    capture._end(request, "handler_entry", error=True)
    capture.stop()

    serialized = (tmp_path / "phase.jsonl").read_text()
    assert {event["phase"] for event in capture.events} <= set(PHASES) | {"summary"}
    assert "phase-token" not in serialized
    assert "not-allowlisted" not in serialized
    assert "error" not in serialized or '"error":true' not in serialized
    assert all(set(event) <= {"schema_version", "request", "phase", "state", "at_ms", "count",
                              "status", "last_phase", "phases", "durations_ms", "utc", "namespace",
                              "capture_namespace", "pid", "birth_ticks", "method", "route_template",
                              "idempotency_key_sha256", "dispatch_start_ms", "sampling",
                              "capture_anchor", "unknown_boundaries", "unsupported_boundaries",
                              "truncated", "retention", "lifecycle"}
               for event in capture.events)


def test_ring_retains_late_failing_request_after_successful_setup_events():
    capture = P2CommitPhaseCapture(enabled=True, max_events=8, max_bytes=64 * 1024)
    capture.start()
    try:
        setup = capture._new_request()
        assert setup is not None
        for _index in range(90):
            capture._begin(setup, "provider")
        capture._end(setup, "provider")
        capture._requests[setup]["dispatch_finished"] = True
        capture._requests[setup]["dispatch_returned"] = True

        failing = capture._new_request()
        assert failing is not None
        for _index in range(150):
            capture._begin(failing, "provider")
        capture._end(failing, "provider", error=True)
        capture._requests[failing]["dispatch_finished"] = True
        capture._requests[failing]["dispatch_returned"] = True
        capture._requests[failing]["dispatch_raised"] = True
    finally:
        capture.stop()

    final_events = [event for event in capture.events
                    if event.get("request") == failing and event["phase"] != "summary"]
    assert len(final_events) == capture._requests[failing]["events_seen"]
    assert capture.retention["final_request"] == {
        "request": failing,
        "outcome": "raised",
        "events_seen": capture._requests[failing]["events_seen"],
        "events_retained": len(final_events),
        "buffer_complete": True,
        "complete": True,
        "incomplete_limit": None,
    }
    assert capture.retention["rolling"]["capacity_events"] == 8
    assert capture.retention["rolling"]["capacity_dropped_events"] > 128
    assert capture.retention["output"]["bytes"] <= capture.max_bytes


def test_final_request_byte_bound_reports_exact_incomplete_limit():
    capture = P2CommitPhaseCapture(enabled=True, max_events=4, max_bytes=512)
    capture.start()
    try:
        request = capture._new_request()
        assert request is not None
        for _index in range(30):
            capture._begin(request, "provider")
        capture._end(request, "provider", error=True)
        capture._requests[request]["dispatch_finished"] = True
        capture._requests[request]["dispatch_returned"] = True
        capture._requests[request]["dispatch_raised"] = True
    finally:
        capture.stop()

    final = capture.retention["final_request"]
    assert final["request"] == request
    assert final["outcome"] == "raised"
    assert final["buffer_complete"] is False
    assert not final["complete"]
    limit = final["incomplete_limit"]
    assert limit["reason"] == "max_bytes"
    assert limit["limit_bytes"] == capture.max_bytes
    assert limit["required_bytes"] == capture._requests[request]["events_required_bytes"]
    assert limit["dropped_events"] == capture._requests[request]["events_dropped"]
    assert limit["dropped_bytes"] == capture._requests[request]["events_dropped_bytes"]
    assert capture.retention["output"]["bytes"] <= capture.max_bytes


def test_pending_request_is_the_final_correlated_request_and_shutdown_is_deterministic():
    def snapshot():
        capture = P2CommitPhaseCapture(enabled=True, max_events=6, clock_ns=lambda: 0)
        capture.start()
        request = capture._new_request()
        assert request is not None
        capture._begin(request, "handler_entry")
        capture.stop()
        return capture.events, capture.retention, capture.namespace

    first_events, first_retention, first_namespace = snapshot()
    second_events, second_retention, second_namespace = snapshot()
    def without_restart_identity(events):
        normalized = []
        for event in events:
            value = {key: value for key, value in event.items()
                     if key not in {"capture_namespace", "utc", "pid", "birth_ticks"}}
            if "sampling" in value:
                value["sampling"] = {
                    key: item for key, item in value["sampling"].items()
                    if key != "observer_cpu_ms"
                }
            if "capture_anchor" in value:
                value["capture_anchor"] = {"utc": "normalized", "at_ms": 0.0}
            normalized.append(value)
        return normalized
    assert without_restart_identity(first_events) == without_restart_identity(second_events)
    assert first_namespace != second_namespace
    assert first_retention["final_request"]["request"] == 1
    assert first_retention["final_request"]["outcome"] == "pending_at_stop"
    assert first_retention["final_request"]["buffer_complete"] is True
    first_retention["output"].pop("bytes")
    second_retention["output"].pop("bytes")
    assert first_retention == second_retention


def test_nearest_safe_leaf_is_projected_separately_from_routing_frames(monkeypatch):
    capture = P2CommitPhaseCapture(enabled=True)
    request = capture._new_request()
    assert request is not None

    routing = SimpleNamespace(
        f_code=SimpleNamespace(co_filename="/checkout/runtime_protocol/server.py",
                               co_name="_dispatch"),
        f_lineno=20,
        f_back=None,
    )
    leaf = SimpleNamespace(
        f_code=SimpleNamespace(co_filename="/checkout/runtime_protocol/provider.py",
                               co_name="commit"),
        f_lineno=42,
        f_back=routing,
    )
    monkeypatch.setattr(sys, "_current_frames", lambda: {threading.get_ident(): leaf})
    capture._sample_once()
    request_state = capture._requests[request]
    request_state["lost_samples"] = 2

    sampling = capture._sampling_summary(request_state, None)
    assert sampling["top_inclusive_frames"] == [
        {"file": "<runtime>/provider.py", "function": "commit", "line": 42,
         "sample_count": 1, "sample_total": 1, "lost_samples": 2,
         "sample_share": 1.0, "dispatch_wall_share": None},
        {"file": "<runtime>/server.py", "function": "_dispatch", "line": 20,
         "sample_count": 1, "sample_total": 1, "lost_samples": 2,
         "sample_share": 1.0, "dispatch_wall_share": None},
    ]
    assert sampling["top_leaf_frames"] == [
        {"file": "<runtime>/provider.py", "function": "commit", "line": 42,
         "sample_count": 1, "sample_total": 1, "lost_samples": 2,
         "sample_share": 1.0, "dispatch_wall_share": None},
    ]


def test_leaf_projection_counter_and_output_remain_bounded():
    capture = P2CommitPhaseCapture(enabled=True, max_events=2, max_bytes=512)
    request = capture._new_request()
    assert request is not None
    request_state = capture._requests[request]
    request_state["sample_total"] = 20
    request_state["leaf_counts"] = {
        ("<runtime>/provider.py", f"leaf_{index}", index): 20 - index
        for index in range(20)
    }
    rows = capture._sample_rows(request_state, None, interval=0.02, counter="leaf_counts")
    assert len(rows) == 10
    assert rows[0]["sample_total"] == 20
    assert rows[0]["lost_samples"] == 0
    request_state["leaf_counts"] = {}
    assert capture._sampling_summary(request_state, None)["top_leaf_frames"] == []


def test_return_without_response_is_not_buffer_completion_or_request_completion():
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        request = capture._new_request()
        assert request is not None
        capture._begin(request, "handler_entry")
        request_state = capture._requests[request]
        request_state["dispatch_finished"] = True
        request_state["dispatch_returned"] = True
    finally:
        capture.stop()

    final = capture.retention["final_request"]
    assert final["outcome"] == "returned_without_response"
    assert final["buffer_complete"] is True
    assert final["complete"] is True
    assert _summary(capture)[0]["lifecycle"] == "returned_without_response"


def test_raised_dispatch_is_labeled_without_inventing_a_duration(tmp_path):
    marker = RuntimeError("original raised dispatch")
    capture = P2CommitPhaseCapture(tmp_path / "raised-dispatch.jsonl", enabled=True)
    handler = _handler(object(), {
        "api_version": 1,
        "project_id": "project-raised-dispatch",
        "timeline_id": "timeline-raised-dispatch",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    })

    def raise_from_error(_exc):
        raise marker

    handler._error = raise_from_error
    capture.start()
    try:
        with pytest.raises(RuntimeError) as caught:
            handler._dispatch()
    finally:
        capture.stop()

    assert caught.value is marker
    final = capture.retention["final_request"]
    assert final["outcome"] == "raised"
    summary = _summary(capture)[0]
    assert summary["lifecycle"] == "raised"
    assert summary["durations_ms"]["handler_ms"] is None
    assert "original raised dispatch" not in json.dumps(capture.events)


def test_observer_failure_does_not_replace_original_exception():
    marker = RuntimeError("original exception text must stay outside capture")

    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            raise marker

    body = {
        "api_version": 1,
        "project_id": "project/opaque",
        "timeline_id": "timeline/opaque",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    }
    handler = _handler(Runtime(), body)
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        with pytest.raises(RuntimeError) as caught:
            handler._timeline_commit("project/opaque", "timeline/opaque", "commit")
    finally:
        capture.stop()
    assert caught.value is marker
    assert "original exception text" not in json.dumps(capture.events)


def _element_request_body(project="project-element", *, dry_run=False):
    # ElementsLibraryPanel -> element-adapter -> timelineLocalSaveHandoff ->
    # documentPatchIntent -> localSaveSession's persisted outbox request.
    row = {"id": "inserted-clip", "at": 0, "track": "visual", "clipType": "effect",
           "hold": 2, "elementRef": {"id": "effect", "kind": "effect",
                                     "revision": "r1", "packId": "catalog"}}
    changes = [{"op": "list.insert", "ref": "parent", "path": ["clips"],
                "id": row["id"], "before": {"state": "absent"}, "value": row,
                "order_before": ["clip-1"], "after_id": "clip-1"}]
    reads = [{"kind": "collection", "ref": "parent", "path": ["clips"],
              "members": ["clip-1"], "order": ["clip-1"]}]
    selected = {"id": "clip-1", "clipType": "video", "hold": 2, "track": "visual", "at": 0}
    for field in ("id", "clipType", "hold", "from", "to", "speed", "track", "at"):
        reads.append({"kind": "field", "ref": "parent", "path": ["clips", "id:clip-1", field],
                      "state": {"state": "present", "value": selected[field]}
                      if field in selected else {"state": "absent"}})
    reads.append({"kind": "field", "ref": "parent", "path": ["config", "tracks"],
                  "state": {"state": "present", "value": [{"id": "visual", "kind": "visual"}]}})
    body = {
        "api_version": 1,
        "project_id": project,
        "timeline_id": "timeline-element",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [{
            "schema_version": 1,
            "op": "doc.patch",
            "version": "1",
            "select": None,
            "created": [f"parent/clip:{row['id']}"],
            "args": {"changes": changes},
        }],
        "label": "Edit timeline",
        "steps": [{"id": "apply-step", "label": "Edit timeline",
                   "intent": "timeline.apply_element", "tags": [],
                   "command_ordinals": [0], "patch": changes, "reads": reads}],
        "merge": "atomic", "reads": reads, "dry_run": dry_run, "source": {"via": "app"},
    }
    if dry_run:
        body["dry_run"] = True
    return body


def test_actual_element_doc_patch_insertion_is_selected_structurally():
    body = _element_request_body()
    handler = _handler(object(), body)
    handler._prefetched_body = json.dumps(body).encode()
    assert P2CommitPhaseCapture._is_element_request(handler)
    # Identities are operands, never a catalog/fixture allowlist.
    command = body["commands"][0]
    change = command["args"]["changes"][0]
    change["id"] = change["value"]["id"] = "another-clip"
    change["value"]["elementRef"]["id"] = change["value"]["clipType"] = "another-effect"
    change["value"]["elementRef"]["packId"] = "another-pack"
    command["created"] = ["parent/clip:another-clip"]
    handler._prefetched_body = json.dumps(body).encode()
    assert P2CommitPhaseCapture._is_element_request(handler)


def test_direct_handler_with_forged_prefetch_cannot_arm_or_consume_selection():
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    body = _element_request_body()
    handler = _handler(Runtime(), body)
    handler._prefetched_body = json.dumps(body).encode()
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        handler._timeline_commit(body["project_id"], body["timeline_id"], "commit")
        assert not capture._profile_selection_closed
        assert all(not state["profile_eligible"] for state in capture._requests.values())
        _handler(Runtime(), body)._dispatch()
    finally:
        capture.stop()
    assert "cprofile" not in _summary(capture)[0]
    assert _summary(capture)[1]["cprofile"]["status"] == "captured"
    assert sys.getprofile() is None


@pytest.mark.parametrize(("path", "value"), [
    (("source",), {"via": "python"}),
    (("dry_run",), True),
    (("commands", 0, "op"), "clip.set-element"),
    (("commands", 0, "select"), "parent/clip:clip-1"),
    (("commands", 0, "schema_version"), 2),
    (("commands", 0, "version"), "2"),
    (("commands", 0, "created"), []),
    (("commands", 0, "args", "changes", 0, "op"), "set"),
    (("commands", 0, "args", "changes", 0, "ref"), "internal:child"),
    (("commands", 0, "args", "changes", 0, "path"), ["config", "clips"]),
    (("commands", 0, "args", "changes", 0, "path"), ["tracks"]),
    (("commands", 0, "args", "changes", 0, "before"), {"state": "present", "value": None}),
    (("commands", 0, "args", "changes", 0, "after_id"), None),
    (("commands", 0, "args", "changes", 0, "order_before"), ["inserted-clip"]),
    (("commands", 0, "args", "changes", 0, "value", "id"), "wrong-clip"),
    (("commands", 0, "args", "changes", 0, "value", "clipType"), "video"),
    (("commands", 0, "args", "changes", 0, "value", "elementRef"), None),
    (("commands", 0, "args", "changes", 0, "value", "elementRef", "kind"), "animation"),
    (("commands", 0, "args", "changes", 0, "value", "elementRef", "revision"), ""),
    (("commands", 0, "args", "changes", 0, "value", "elementRef", "packId"), ""),
    (("steps", 0, "intent"), "timeline.update_element"),
    (("steps", 0, "command_ordinals"), [0, 1]),
    (("steps", 0, "patch"), []),
])
def test_actual_element_selection_rejects_other_structures(path, value):
    body = _element_request_body()
    target = body
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    handler = _handler(object(), body)
    handler._prefetched_body = json.dumps(body).encode()
    assert not P2CommitPhaseCapture._is_element_request(handler)


def test_mounted_params_undo_and_setup_do_not_consume_first_element_selection():
    sent = []

    class Runtime:
        def commit_timeline(self, _project, _timeline, body, **kwargs):
            sent.append((body, kwargs["idempotency_key"]))
            return {"data": {"status": "accepted"}, "receipt": None}

    params = _element_request_body()
    params["commands"][0]["created"] = []
    params["commands"][0]["args"]["changes"] = [{
        "op": "set", "ref": "parent", "path": ["clips", "id:clip-1", "params"],
        "before": {"state": "absent"}, "value": {"bob": 12},
    }]
    params["steps"][0].update(intent="timeline.update_element",
                               patch=params["commands"][0]["args"]["changes"])
    undo = _element_request_body()
    undo["commands"] = [{"schema_version": 1, "op": "timeline.inverse", "version": "1",
                         "select": None, "args": {"publications": ["publication-1"]}}]
    setup = _element_request_body()
    setup["commands"][0]["args"]["changes"][0]["value"].pop("elementRef")
    bodies = [params, undo, setup, _element_request_body()]
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        for index, body in enumerate(bodies):
            _handler(Runtime(), body, key=f"key-{index}")._dispatch()
    finally:
        capture.stop()
    assert all("cprofile" not in summary for summary in _summary(capture)[:3])
    summary = _summary(capture)[3]
    assert summary["cprofile"]["status"] == "captured"
    assert summary["idempotency_key_sha256"] == hashlib.sha256(b"key-3").hexdigest()
    assert sent == [(body, f"key-{index}") for index, body in enumerate(bodies)]


@pytest.mark.parametrize("refusal", ["dry_run", "mixed_changes", "mixed_commands"])
def test_first_element_attempt_consumes_selection_before_retry(refusal):
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    body = _element_request_body()
    if refusal == "dry_run":
        body["dry_run"] = True
    elif refusal == "mixed_changes":
        body["commands"][0]["args"]["changes"].append({
            "op": "set", "ref": "parent", "path": ["name"],
            "before": {"state": "present", "value": "before"}, "value": "after",
        })
    else:
        body["commands"].append({"schema_version": 1, "op": "timeline.inverse", "version": "1",
                                 "select": None, "args": {"publications": ["publication-1"]}})
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        _handler(Runtime(), body)._dispatch()
        _handler(Runtime(), _element_request_body())._dispatch()
    finally:
        capture.stop()
    assert capture._profile_selection_closed
    assert len(_summary(capture)) == 2
    assert all("cprofile" not in summary for summary in _summary(capture))


def test_dispatch_without_real_prefetch_does_not_arm_profile():
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    body = _element_request_body()
    handler = _handler(Runtime(), body)
    handler._prefetch_body = lambda _limit: setattr(handler, "_prefetched_body", json.dumps(body).encode())
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        handler._dispatch()
        assert not capture._profile_selection_closed
        _handler(Runtime(), body)._dispatch()
    finally:
        capture.stop()
    assert "cprofile" not in _summary(capture)[0]
    assert _summary(capture)[1]["cprofile"]["status"] == "captured"


def test_mounted_element_handler_profiles_only_the_selected_request(tmp_path):
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    body = _element_request_body()
    raw_sink = tmp_path / "element.prof"
    capture = P2CommitPhaseCapture(
        tmp_path / "element.jsonl", enabled=True, raw_pstats_sink=raw_sink)
    handler = _handler(Runtime(), body, key="element-profile")
    capture.start()
    try:
        handler._dispatch()
    finally:
        capture.stop()

    assert handler.sent_status == 200
    summary = _summary(capture)[0]
    profile = summary["cprofile"]
    assert profile["status"] == "captured"
    assert profile["scope"] == "RuntimeHandler._timeline_commit"
    assert len(profile["functions"]) <= 40
    assert len(profile["edges"]) <= 1600
    assert profile["rank_meaning"].startswith("functions sorted descending cumtime")
    assert "original budget" in profile["timing_note"]
    assert all(set(row) == {
        "rank", "file", "line", "function", "ncalls", "primitive_calls", "tottime", "cumtime"
    } for row in profile["functions"])
    assert all(set(edge) == {"caller", "callee", "ncalls"} for edge in profile["edges"])
    assert all(not name.startswith("/") for row in profile["functions"] for name in (row["file"],))
    serialized = json.dumps(capture.events)
    assert body["project_id"] not in serialized
    assert "element-profile" not in serialized
    assert raw_sink.exists()
    assert os.stat(raw_sink).st_mode & 0o777 == 0o600
    assert os.stat(tmp_path).st_mode & 0o777 == 0o700
    assert sys.getprofile() is None


def test_element_profile_predicate_refuses_non_element_and_dry_run_requests():
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    bodies = [
        {
            "api_version": 1,
            "project_id": "project-move",
            "timeline_id": "timeline-element",
            "base_revision_id": "revision-1",
            "base_publication_id": "publication-1",
            "commands": [{"schema_version": 1, "op": "clip.move", "version": "1",
                          "select": "parent/clip:clip-1", "args": {"on": 2}}],
        },
        _element_request_body("project-preview", dry_run=True),
    ]
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        for body in bodies:
            _handler(Runtime(), body)._dispatch()
    finally:
        capture.stop()

    summaries = _summary(capture)
    assert len(summaries) == 2
    assert all("cprofile" not in summary for summary in summaries)
    assert sys.getprofile() is None


def test_element_profile_disables_on_handler_exception_without_exporting_exception_text():
    marker = RuntimeError("element profile exception must remain private")

    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            raise marker

    body = _element_request_body("project-exception")
    handler = _handler(Runtime(), body, key="element-exception")

    def raise_from_error(_exc):
        raise marker

    handler._error = raise_from_error
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        with pytest.raises(RuntimeError) as caught:
            handler._dispatch()
    finally:
        capture.stop()

    assert caught.value is marker
    assert sys.getprofile() is None
    serialized = json.dumps(capture.events)
    assert "element profile exception must remain private" not in serialized
    assert _summary(capture)[0]["cprofile"]["status"] == "captured"


def test_element_profile_selects_one_exact_element_post_and_rejects_mixed_or_retry(tmp_path):
    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    mixed = _element_request_body("project-mixed")
    mixed["commands"].append({
        "schema_version": 1,
        "op": "clip.move",
        "version": "1",
        "select": "parent/clip:clip-1",
        "args": {"on": 2},
    })
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        _handler(Runtime(), mixed)._dispatch()
        _handler(Runtime(), _element_request_body("project-element-1"))._dispatch()
        _handler(Runtime(), _element_request_body("project-element-2"))._dispatch()
    finally:
        capture.stop()

    summaries = _summary(capture)
    assert len(summaries) == 3
    assert all("cprofile" not in summary for summary in summaries)
    assert capture._profile_selection_closed

    capture = P2CommitPhaseCapture(tmp_path / "one.jsonl", enabled=True)
    capture.start()
    try:
        _handler(Runtime(), _element_request_body("project-first"))._dispatch()
        _handler(Runtime(), _element_request_body("project-retry"))._dispatch()
    finally:
        capture.stop()
    summaries = _summary(capture)
    assert len(summaries) == 2
    assert sum("cprofile" in summary for summary in summaries) == 1
    assert sys.getprofile() is None


def test_element_profile_rejects_wrong_request_path_method_and_unselected_handler():
    body = _element_request_body()
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        cases = []
        for command, path in (("GET", None), ("POST", "/v1/projects/p/timelines/t/commit?x=1"),
                              ("POST", "/v1/projects/p/timelines/t/not-commit")):
            handler = _handler(object(), body)
            handler.command = command
            if path is not None:
                handler.path = path
            handler._prefetched_body = json.dumps(body, separators=(",", ":")).encode()
            cases.append(handler)
        unselected = SimpleNamespace(command="POST", path=body["project_id"],
                                     _prefetched_body=json.dumps(body).encode())
        cases.append(unselected)
        for handler in cases:
            request = capture._new_request(handler=handler)
            assert request is not None
            capture._start_profile(capture._requests[request], handler)
    finally:
        capture.stop()
    assert all(not request["profile_eligible"] for request in capture._requests.values())
    assert sys.getprofile() is None


def test_partial_profile_enable_disables_and_restores_previous_binding():
    previous = sys.getprofile()

    class PartialProfile:
        def __init__(self):
            self.disabled = False

        def __call__(self, *_args):
            return None

        def enable(self):
            sys.setprofile(self)
            raise RuntimeError("private enable failure")

        def disable(self):
            self.disabled = True
            sys.setprofile(None)

    profile = PartialProfile()
    capture = P2CommitPhaseCapture(enabled=True, profile_factory=lambda: profile)

    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    handler = _handler(Runtime(), _element_request_body())
    capture.start()
    try:
        handler._dispatch()
    finally:
        capture.stop()
    request = next(iter(capture._requests), None)
    assert request is not None
    capture._start_profile(capture._requests[request], handler)
    assert profile.disabled
    assert capture._requests[request]["profile_failed"]
    assert capture._requests[request]["profile_stopped"]
    assert sys.getprofile() is previous


def test_profile_projection_bounds_rows_and_preserves_caller_edge_counts(monkeypatch):
    outer = ("/checkout/runtime_protocol/outer.py", 10, "outer")
    inner = ("/checkout/runtime_protocol/inner.py", 20, "inner")
    third = ("/checkout/runtime_protocol/third.py", 30, "third")
    values = {
        outer: (1, 1, 0.3, 0.3, {}),
        inner: (2, 2, 0.2, 0.2, {outer: (2, 2, 0.0, 0.0)}),
        third: (1, 1, 0.1, 0.1, {outer: (1, 1, 0.0, 0.0)}),
    }

    class FakeStats:
        def __init__(self, _profile):
            self.stats = values

    monkeypatch.setattr(pstats, "Stats", FakeStats)
    capture = P2CommitPhaseCapture(enabled=True, profile_top_functions=2, profile_max_edges=1)
    request = capture._new_request()
    assert request is not None
    request_state = capture._requests[request]
    request_state["profile"] = object()
    projection = capture._profile_projection(request_state)
    assert projection["status"] == "captured"
    assert len(projection["functions"]) == 2
    assert projection["limits"]["dropped_rows"] == 1
    assert len(projection["edges"]) == 1
    assert projection["edges"][0]["caller"]["function"] == "outer"
    assert projection["edges"][0]["callee"]["function"] == "inner"
    assert projection["edges"][0]["ncalls"] == 2


def test_raw_profile_path_rejects_symlink_overwrite_shared_and_unprivate_parents(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    os.chmod(private, 0o700)
    capture = P2CommitPhaseCapture(enabled=True, raw_pstats_sink=private / "raw.prof")
    assert capture._raw_profile_path(1) == private / "raw.prof"
    assert os.stat(private / "raw.prof").st_mode & 0o777 == 0o600

    existing = private / "existing.prof"
    existing.write_bytes(b"existing")
    capture.raw_pstats_sink = existing
    assert capture._raw_profile_path(1) is None

    target = tmp_path / "target"
    target.mkdir()
    os.chmod(target, 0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    capture.raw_pstats_sink = linked / "raw.prof"
    assert capture._raw_profile_path(1) is None

    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    capture.raw_pstats_sink = shared / "raw.prof"
    assert capture._raw_profile_path(1) is None
    assert os.stat(shared).st_mode & 0o777 == 0o755

    capture.raw_pstats_sink = Path(os.environ.get("TMPDIR", "/tmp")) / "shared.prof"
    assert capture._raw_profile_path(1) is None


def test_concurrent_requests_keep_local_ordinals_and_phase_state_isolated():
    calls = []

    class Runtime:
        def commit_timeline(self, project, timeline, body, *, authorize, **_kwargs):
            authorize()
            calls.append((project, timeline))
            time.sleep(0.01)
            return {"data": {"status": "accepted"}, "receipt": None}

    bodies = [
        {
            "api_version": 1,
            "project_id": f"project-{index}",
            "timeline_id": f"timeline-{index}",
            "base_revision_id": "revision-1",
            "base_publication_id": "publication-1",
            "commands": [],
        }
        for index in (1, 2)
    ]
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda body: _handler(Runtime(), body)._timeline_commit(
                body["project_id"], body["timeline_id"], "commit"), bodies))
    finally:
        capture.stop()
    assert len(results) == 2
    summaries = _summary(capture)
    assert {summary["request"] for summary in summaries} == {1, 2}
    assert all(summary["phases"]["handler_entry"]["status"] == "observed" for summary in summaries)
    assert all(summary["phases"]["authorization"]["status"] == "observed" for summary in summaries)
    assert all(summary["last_phase"] == "http_response" for summary in summaries)
    assert sorted(calls) == [("project-1", "timeline-1"), ("project-2", "timeline-2")]


def test_mounted_http_commit_route_and_provider_are_observed(service, tmp_path):
    body = commit_request(service, commands=[{
        "schema_version": 1,
        "op": "clip.move",
        "version": "1",
        "select": "parent/clip:clip-1",
        "args": {"on": 2},
    }])
    server: Any = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = service
    server.credentials = _Credentials()
    capture = P2CommitPhaseCapture(tmp_path / "mounted-phase.jsonl", enabled=True)
    capture.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        path = f"/v1/projects/{body['project_id']}/timelines/main/commit"
        connection.request("POST", path, body=json.dumps(body), headers={
            "Authorization": "Bearer phase-token",
            "Content-Type": "application/json",
            "Idempotency-Key": "mounted-phase",
        })
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        capture.stop()

    assert response.status == 200
    assert payload["data"]["status"] == "accepted"
    summaries = _summary(capture)
    assert len(summaries) == 1
    phases = summaries[0]["phases"]
    assert phases["arrival"]["status"] == "unsupported"
    assert phases["arrival"]["start_ms"] is None
    assert phases["arrival"]["end_ms"] is None
    assert phases["dispatch_queue"]["status"] == "observed"
    assert phases["dispatch_queue"]["end_ms"] is not None
    for phase in ("handler_entry", "authorization", "coordinator_admission", "coordinator_lock",
                  "provider", "accept", "receipt", "http_response"):
        assert phases[phase]["status"] == "observed", (phase, summaries)
    for phase in ("coordinator_admission", "coordinator_lock"):
        assert phases[phase]["count"] == 1
        assert phases[phase]["end_ms"] is not None
    assert summaries[0]["last_phase"] == "http_response"
    durations = summaries[0]["durations_ms"]
    assert durations["dispatch_queue_ms"] is not None
    assert durations["handler_ms"] is not None
    assert durations["dispatch_total_ms"] is not None
    assert durations["dispatch_to_completion_wall_ms"] == durations["dispatch_total_ms"]
    assert durations["provider_wall_ms"] == pytest.approx(
        phases["provider"]["end_ms"] - phases["provider"]["start_ms"], abs=0.001)
    assert durations["execution_lock_wait_ms"] is None
    assert durations["caller_receipt_ms"] is None
    assert summaries[0]["method"] == "POST"
    assert summaries[0]["route_template"] == "/v1/projects/{project_id}/timelines/{timeline_id}/commit"
    assert summaries[0]["idempotency_key_sha256"] == hashlib.sha256(b"mounted-phase").hexdigest()
    assert summaries[0]["dispatch_start_ms"] == phases["dispatch_queue"]["start_ms"]
    assert summaries[0]["sampling"]["dispatch_wall_denominator_ms"] == durations[
        "dispatch_to_completion_wall_ms"]
    assert summaries[0]["sampling"]["sampling_interval_ms"] == 20
    assert summaries[0]["sampling"]["counter_limits"]["top_frames"] == 10
    assert all(body["project_id"] not in json.dumps(event) for event in capture.events)
    assert all("/timelines/main/" not in json.dumps(event) for event in capture.events)
    assert summaries[0]["unknown_boundaries"]["client_request_to_server_receive"] == (
        "unsupported: no earlier socket/server-accept hook")
    assert summaries[0]["unknown_boundaries"]["request_body_receive"] == (
        "unsupported: no body-read hook; body time is not separately measured")
    assert summaries[0]["unsupported_boundaries"]["network_arrival_ms"] is None
    assert summaries[0]["unsupported_boundaries"]["request_body_receive_ms"] is None
    assert all(event["phase"] != "arrival" for event in capture.events)
    serialized = (tmp_path / "mounted-phase.jsonl").read_text()
    assert body["project_id"] not in serialized
    assert "mounted-phase" not in serialized
    assert "phase-token" not in serialized
    assert capture.failures == 0


def test_overlapping_requests_do_not_receive_duplicate_per_request_sampler_cpu(tmp_path):
    entered = {"one": threading.Event(), "two": threading.Event()}
    release = threading.Event()

    class Runtime:
        def commit_timeline(self, project, *_args, **_kwargs):
            name = project.rsplit("-", 1)[-1]
            entered[name].set()
            assert release.wait(2)
            return {"data": {"status": "accepted"}, "receipt": None}

    bodies = [
        {"api_version": 1, "project_id": f"project-{name}",
         "timeline_id": "timeline-overhead", "base_revision_id": "revision-1",
         "base_publication_id": "publication-1", "commands": []}
        for name in ("one", "two")
    ]
    handlers = [_handler(Runtime(), body, key=f"overhead-{name}")
                for name, body in zip(("one", "two"), bodies)]
    capture = P2CommitPhaseCapture(tmp_path / "overhead.jsonl", enabled=True,
                                   sampling_interval=0.001)
    threads = [threading.Thread(target=handler._dispatch) for handler in handlers]
    capture.start()
    try:
        threads[0].start()
        assert entered["one"].wait(2)
        threads[1].start()
        assert entered["two"].wait(2)
        time.sleep(0.03)
        release.set()
        for thread in threads:
            thread.join(timeout=2)
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=2)
        capture.stop()

    summaries = _summary(capture)
    assert len(summaries) == 2
    samplings = [summary["sampling"] for summary in summaries]
    assert {sampling["observer_cpu_scope"] for sampling in samplings} == {"capture-wide"}
    assert len({sampling["observer_cpu_ms"] for sampling in samplings}) == 1
    assert all("request_cpu_ms" not in sampling for sampling in samplings)
    assert all("not attributed to this request" in sampling["observer_cpu_attribution"]
               for sampling in samplings)


def test_dispatch_scope_expires_after_deferred_response_before_handler_reuse(service):
    body = commit_request(service, commands=[{
        "schema_version": 1,
        "op": "clip.move",
        "version": "1",
        "select": "parent/clip:clip-1",
        "args": {"on": 2},
    }])
    handler = _handler(service, body, key="dispatch-scope")
    capture = P2CommitPhaseCapture(enabled=True)
    capture.start()
    try:
        handler._dispatch()
        assert handler.wfile.getvalue()
        assert capture._handler_requests == {}
        assert capture._thread_requests == {}

        # Reuse the handler and thread for unrelated traffic after the real
        # deferred response has been flushed.
        handler.command = "GET"
        handler.path = "/v1/health"
        handler.headers = {}
        handler.rfile = io.BytesIO()
        handler.wfile = io.BytesIO()
        handler._dispatch()
    finally:
        capture.stop()

    summaries = _summary(capture)
    assert len(summaries) == 1
    phases = summaries[0]["phases"]
    assert phases["http_response"]["count"] == 2
    assert capture._handler_requests == {}
    assert capture._thread_requests == {}


def test_observer_avoids_line_events_and_unrelated_request_lookups(service):
    counts = {"line": 0, "unrelated_lookup": 0}

    class CountingCapture(P2CommitPhaseCapture):
        def _trace_inner(self, frame, event, arg):
            if event == "line":
                counts["line"] += 1
            return super()._trace_inner(frame, event, arg)

        def _request_for_frame(self, frame):
            if (self._phase(frame) is None
                    and frame.f_code.co_qualname != "CommitExecutionCoordinator.execute"
                    and frame.f_code not in self._frames):
                counts["unrelated_lookup"] += 1
            return super()._request_for_frame(frame)

    body = commit_request(service)
    handler = _handler(service, body)
    capture = CountingCapture(enabled=True)
    with capture:
        handler._dispatch()

    assert handler.sent_status == 200
    assert json.loads(handler.wfile.getvalue())["data"]["status"] == "accepted"
    assert _summary(capture)[0]["phases"]["receipt"]["status"] == "observed"
    assert _summary(capture)[0]["lifecycle"] == "completed"
    assert capture.failures == 0
    assert counts == {"line": 0, "unrelated_lookup": 0}


def test_watchdog_captures_a_genuine_pending_handler_with_all_python_threads(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    timers = []
    dumps = []

    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            entered.set()
            assert release.wait(2)
            return {"data": {"status": "accepted"}, "receipt": None}

    def timer_factory(delay, callback):
        timer = _FakeTimer(delay, callback)
        timers.append(timer)
        return timer

    def dump_traceback(*, file, all_threads):
        dumps.append((file, all_threads))
        file.write("Thread watchdog pending\n")

    now = [0]
    capture = P2CommitPhaseCapture(
        tmp_path / "phase.jsonl",
        enabled=True,
        watchdog_seconds=20,
        timer_factory=timer_factory,
        clock_ns=lambda: now[0],
        dump_traceback=dump_traceback,
    )
    handler = _handler(Runtime(), {
        "api_version": 1,
        "project_id": "project-watchdog",
        "timeline_id": "timeline-watchdog",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    })
    thread = threading.Thread(target=handler._dispatch, name="watchdog-handler")
    capture.start()
    try:
        thread.start()
        assert entered.wait(2)
        assert len(timers) == 1 and timers[0].started and timers[0].daemon
        now[0] = 20_000_000_000
        timers[0].fire()
        release.set()
        thread.join(timeout=2)
    finally:
        release.set()
        thread.join(timeout=2)
        capture.stop()

    assert not thread.is_alive()
    assert dumps and dumps[0][1] is True
    assert capture.watchdog_captures == 1
    assert capture.watchdog_sink is not None
    assert capture.watchdog_sink.stat().st_mode & 0o777 == 0o600
    assert capture.watchdog_sink.read_text() == "Thread watchdog pending\n"
    assert _summary(capture)[0]["phases"]["handler_entry"]["status"] == "observed"


def test_five_second_watchdog_schedules_one_bounded_thirty_second_followup(tmp_path):
    timers = []
    dumps = []

    def timer_factory(delay, callback):
        timer = _FakeTimer(delay, callback)
        timers.append(timer)
        return timer

    def dump_traceback(*, file, all_threads):
        dumps.append(all_threads)
        file.write("bounded pending\n")

    capture = P2CommitPhaseCapture(
        tmp_path / "five-thirty.jsonl", enabled=True, watchdog_seconds=5,
        timer_factory=timer_factory, dump_traceback=dump_traceback,
    )
    capture.start()
    try:
        ordinal = capture._new_request(handler=object(), emit_handler=True)
        assert ordinal == 1
        timers[0].fire()
        assert len(timers) == 2
        assert timers[0].delay == 5
        assert timers[1].delay == 25
        timers[1].fire()
    finally:
        capture.stop()

    assert dumps == [True, True]
    assert capture.watchdog_captures == 2
    assert timers[1].cancelled is False


def test_watchdog_finish_raised_disabled_and_late_callbacks_are_safe(tmp_path):
    timers = []

    class FinishedRuntime:
        def commit_timeline(self, *_args, **_kwargs):
            return {"data": {"status": "accepted"}, "receipt": None}

    def timer_factory(delay, callback):
        timer = _FakeTimer(delay, callback)
        timers.append(timer)
        return timer

    capture = P2CommitPhaseCapture(tmp_path / "finish.jsonl", enabled=True,
                                   timer_factory=timer_factory)
    handler = _handler(FinishedRuntime(), {
        "api_version": 1,
        "project_id": "project-watchdog",
        "timeline_id": "timeline-watchdog",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    })
    capture.start()
    try:
        handler._dispatch()
        assert timers[0].cancelled
        timers[0].fire()
        assert capture.watchdog_captures == 0
    finally:
        capture.stop()

    raised_timer = []

    class RaisedRuntime:
        def commit_timeline(self, *_args, **_kwargs):
            raise RuntimeError("raised commit")

    raised = P2CommitPhaseCapture(tmp_path / "raised.jsonl", enabled=True,
                                  timer_factory=lambda delay, callback: raised_timer.append(
                                      _FakeTimer(delay, callback)) or raised_timer[-1])
    raised.start()
    try:
        _handler(RaisedRuntime(), {
            "api_version": 1,
            "project_id": "project-watchdog",
            "timeline_id": "timeline-watchdog",
            "base_revision_id": "revision-1",
            "base_publication_id": "publication-1",
            "commands": [],
        })._dispatch()
    finally:
        raised.stop()
    assert raised_timer[0].cancelled
    assert raised.watchdog_captures == 0

    aborted_timer = []

    class AbortedRuntime:
        def commit_timeline(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    aborted = P2CommitPhaseCapture(
        tmp_path / "aborted.jsonl", enabled=True,
        timer_factory=lambda delay, callback: aborted_timer.append(
            _FakeTimer(delay, callback)) or aborted_timer[-1],
    )
    aborted.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            _handler(AbortedRuntime(), {
                "api_version": 1,
                "project_id": "project-watchdog",
                "timeline_id": "timeline-watchdog",
                "base_revision_id": "revision-1",
                "base_publication_id": "publication-1",
                "commands": [],
            })._dispatch()
    finally:
        aborted.stop()
    assert aborted_timer[0].cancelled
    assert aborted.watchdog_captures == 0

    disabled_timer = []
    disabled = P2CommitPhaseCapture(tmp_path / "disabled-watchdog.jsonl",
                                    timer_factory=lambda *_args: disabled_timer.append(True))
    disabled.start()
    assert disabled_timer == []
    disabled.stop()


def test_watchdog_overlap_is_request_owned_and_global_capture_cap_is_bounded(tmp_path):
    entered = {"one": threading.Event(), "two": threading.Event()}
    release = {"one": threading.Event(), "two": threading.Event()}
    dumps = []

    class Runtime:
        def commit_timeline(self, project, *_args, **_kwargs):
            name = project.rsplit("-", 1)[-1]
            entered[name].set()
            assert release[name].wait(2)
            return {"data": {"status": "accepted"}, "receipt": None}

    def dump_traceback(*, file, all_threads):
        dumps.append(all_threads)
        file.write("overlap\n")

    capture = P2CommitPhaseCapture(
        tmp_path / "overlap.jsonl", enabled=True, max_watchdog_captures=1,
        timer_factory=lambda delay, callback: _FakeTimer(delay, callback),
        dump_traceback=dump_traceback,
    )
    bodies = [
        {"api_version": 1, "project_id": f"project-{name}", "timeline_id": "timeline-watchdog",
         "base_revision_id": "revision-1", "base_publication_id": "publication-1", "commands": []}
        for name in ("one", "two")
    ]
    handlers = [_handler(Runtime(), body, key=f"overlap-{index}") for index, body in enumerate(bodies)]
    threads = [threading.Thread(target=handler._dispatch) for handler in handlers]
    capture.start()
    try:
        threads[0].start()
        assert entered["one"].wait(2)
        threads[1].start()
        assert entered["two"].wait(2)
        first_timer = capture._requests[1]["watchdog_timer"]
        second_timer = capture._requests[2]["watchdog_timer"]
        assert first_timer is not None and second_timer is not None
        first_timer.fire()
        second_timer.fire()
        release["one"].set()
        threads[0].join(timeout=2)
        assert first_timer.cancelled is False
        assert second_timer.cancelled is False
        release["two"].set()
        threads[1].join(timeout=2)
    finally:
        for event in release.values():
            event.set()
        for thread in threads:
            thread.join(timeout=2)
        capture.stop()

    assert dumps == [True]
    assert capture.watchdog_captures == 1
    assert capture._handler_requests == {}
    assert capture._thread_requests == {}


def test_live_watchdog_uses_real_handler_and_private_faulthandler_output(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    class Runtime:
        def commit_timeline(self, *_args, **_kwargs):
            entered.set()
            assert release.wait(2)
            return {"data": {"status": "accepted"}, "receipt": None}

    body = {
        "api_version": 1,
        "project_id": "project-live-watchdog",
        "timeline_id": "timeline-live-watchdog",
        "base_revision_id": "revision-1",
        "base_publication_id": "publication-1",
        "commands": [],
    }
    server: Any = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = Runtime()
    server.credentials = _Credentials()
    capture = P2CommitPhaseCapture(tmp_path / "live.jsonl", enabled=True, watchdog_seconds=0.01)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    request_result = []

    def request():
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        connection.request("POST", "/v1/projects/project-live-watchdog/timelines/timeline-live-watchdog/commit",
                           body=json.dumps(body), headers={
                               "Authorization": "Bearer phase-token",
                               "Content-Type": "application/json",
                               "Idempotency-Key": "live-watchdog",
                           })
        response = connection.getresponse()
        request_result.append(response.status)
        response.read()
        connection.close()

    capture.start()
    server_thread.start()
    request_thread = threading.Thread(target=request)
    request_thread.start()
    try:
        assert entered.wait(2)
        time.sleep(0.05)
        release.set()
        request_thread.join(timeout=2)
    finally:
        release.set()
        request_thread.join(timeout=2)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        capture.stop()

    assert request_result == [200]
    assert capture.watchdog_sink is not None
    assert capture.watchdog_sink.exists()
    assert os.stat(capture.watchdog_sink).st_mode & 0o777 == 0o600
    assert "Thread" in capture.watchdog_sink.read_text()
    summary = _summary(capture)[0]
    sampling = summary["sampling"]
    assert sampling["sample_total"] > 0
    assert sampling["dispatch_wall_denominator_ms"] == summary["durations_ms"][
        "dispatch_to_completion_wall_ms"]
    assert len(sampling["top_inclusive_frames"]) <= 10
    assert sampling["sampler_errors"] == []


def test_watchdog_stop_is_truthful_before_a_new_daemon_capture(tmp_path):
    timers = []

    def timer_factory(delay, callback):
        timer = _FakeTimer(delay, callback)
        timers.append(timer)
        return timer

    first = P2CommitPhaseCapture(tmp_path / "restart-1.jsonl", enabled=True,
                                 timer_factory=timer_factory)
    first.start()
    request = first._new_request(handler=object(), emit_handler=True)
    assert request == 1
    first.stop()
    assert timers[0].cancelled
    timers[0].fire()
    assert first.watchdog_captures == 0

    second = P2CommitPhaseCapture(tmp_path / "restart-2.jsonl", enabled=True,
                                  timer_factory=timer_factory)
    second.start()
    try:
        assert second.active
    finally:
        second.stop()
    assert not second.active
