"""Opt-in C3 loopback sampler; run through the central test service only.

Explicit filename selection keeps this diagnostic out of normal collection.
Uses a generated realm, the installed Astrid provider, and Runtime DEBUG stage
records. No renderer, admitted project pack, or owner fixture is involved.
Select with ``pytest -s -m integration tests/samplers/element_save_sampler.py``.
Only C3_DURABLE lines qualify completed samples; stages are inclusive (store
acceptance is inside provider time), integer milliseconds from Runtime itself.
"""
from __future__ import annotations

import http.client
import json
import logging
import queue
import time
from urllib.parse import urlsplit

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

pytestmark = pytest.mark.integration

SEED_CLIPS = 24
SAMPLES = 5
TIMING_FIELDS = {
    "handler", "service_admission", "initial_replay_lookup", "provider_commit",
    "port_store_accept", "close", "durable_reconciliation", "wire_response", "total",
}


def _request(service, project, commands):
    head = service.get_project_timeline(project, "main")
    return {
        "api_version": 1, "project_id": project, "timeline_id": "main",
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"], "commands": commands,
    }


def _seed(service):
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.commit import bundle_from_document

    project = service.create_project({"slug": "element-sampler", "name": "Element sampler"})["id"]
    service.create_timeline(project, "main", idempotency_key="sampler-create")
    head = service.get_project_timeline(project, "main")
    document = service._timeline_commits()[0].revision_closure(
        project, "main", head["head_revision_id"],
    )
    calls = [{"schema_version": 1, "op": "track.create", "version": "1", "select": "parent",
              "args": {"row": {"id": "picture", "kind": "visual", "role": "output"}}}]
    calls.extend({
        "schema_version": 1, "op": "clip.add", "version": "1", "select": "parent",
        "args": {"row": {"id": f"seed-{index}", "clipType": "text", "track": "picture",
                         "at": index * 2, "hold": 2, "params": {"text": f"Fixture {index}"}}},
    } for index in range(SEED_CLIPS))
    captured = execute(bundle_from_document(document), calls).commands
    service.commit_timeline(
        project, "main", _request(service, project, captured), idempotency_key="sampler-seed",
        publisher="owner", invocation_path=route_path(project, "main"), authorize=lambda: None,
    )
    return project


def _add_request(service, project, index):
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.timeline.commit import bundle_from_document

    head = service.get_project_timeline(project, "main")
    document = service._timeline_commits()[0].revision_closure(
        project, "main", head["head_revision_id"],
    )
    # Same literal overlay envelope as App elementOverlayCapture: the first
    # save creates an output track; later saves reuse it. No pack schema edit.
    row = {"id": f"element-{index}", "clipType": "glow", "track": "overlay",
           "at": index * 2, "hold": 1.25,
           "elementRef": {"id": "glow", "kind": "effect", "revision": "sha256:literal"},
           "params": {"amount": 0.7, "clearable": None}}
    calls = []
    if index == 0:
        calls.append({"schema_version": 1, "op": "track.create", "version": "1", "select": "parent",
                      "args": {"row": {"id": "overlay", "kind": "visual", "role": "output"}}})
    calls.append({"schema_version": 1, "op": "clip.add", "version": "1", "select": "parent",
                  "args": {"row": row}})
    captured = execute(bundle_from_document(document), calls).commands
    return _request(service, project, captured), row


class _Timings(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = queue.Queue()

    def emit(self, record):
        prefix = "runtime.timeline_commit.timing "
        message = record.getMessage()
        if message.startswith(prefix):
            self.records.put(json.loads(message[len(prefix):]))


def _post(daemon, body, key):
    encoded = json.dumps(body).encode()
    endpoint = urlsplit(daemon.endpoint)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=90)
    started = time.monotonic_ns()
    try:
        connection.request("POST", route_path(body["project_id"], "main"), body=encoded, headers={
            "Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json",
            "Idempotency-Key": key, "X-Request-ID": key,
        })
        response = connection.getresponse()
        received = response.read()
        elapsed = (time.monotonic_ns() - started) / 1_000_000
        payload = json.loads(received)
        assert response.status == 200, payload
        assert payload["data"]["status"] == "accepted", payload
        return payload, elapsed, len(encoded), len(received)
    finally:
        connection.close()


def _timing(capture, outcome):
    # The handler emits after writing the response, so reading HTTP 200 alone
    # is insufficient synchronization. Only one commit is in flight at a time.
    record = capture.records.get(timeout=5)
    assert capture.records.empty(), "unexpected extra commit timing record"
    assert record["event"] == "timeline_commit_timing" and record["outcome"] == outcome, record
    values = record["timings_ms"]
    assert set(values) == TIMING_FIELDS
    assert all(type(value) is int and 0 <= value < 24 * 60 * 60 * 1000 for value in values.values())
    assert values["total"] >= values["handler"] >= values["provider_commit"] >= values["port_store_accept"]
    return record


def test_five_real_add_element_saves(tmp_path, astrid_importable):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        service.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
        project = _seed(service)
    finally:
        service.close()

    logger = logging.getLogger("runtime_protocol.timeline_commit_execution")
    capture, previous_level = _Timings(), logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.DEBUG)
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile="astrid",
                           log_directory=tmp_path / "logs")
    saved = []
    try:
        daemon.start()
        for index in range(SAMPLES):
            body, row = _add_request(daemon.service, project, index)
            key = f"sampler-add-{index}"
            result, elapsed, sent_bytes, received_bytes = _post(daemon, body, key)
            record = _timing(capture, "accepted")
            # New successful requests must exercise the provider, not replay.
            document = result["data"]["canonical_document"]
            payload = document["parent_revision"]["payload"]
            assert payload["clips"][-1] == row
            assert payload["config"]["clips"] == payload["clips"]
            assert len(payload["clips"]) == SEED_CLIPS + index + 1
            sample = {"sample": index + 1, "ops": [command["op"] for command in body["commands"]],
                      "clips_before": SEED_CLIPS + index, "request_bytes": sent_bytes,
                      "response_bytes": received_bytes, "client_wall_ms": round(elapsed, 3),
                      "timing": record}
            saved.append((body, key, row, result, sample))
            print("C3_SAVE " + json.dumps(sample, sort_keys=True), flush=True)
        daemon.stop()
        daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile="astrid",
                               log_directory=tmp_path / "logs")
        daemon.start()
        head = daemon.service.get_project_timeline(project, "main")
        assert head["head_publication_id"] == saved[-1][3]["receipt"]["receipt_id"]
        document = daemon.service._timeline_commits()[0].revision_closure(
            project, "main", head["head_revision_id"],
        )
        assert document == saved[-1][3]["data"]["canonical_document"]
        assert document["parent_revision"]["payload"]["clips"][-SAMPLES:] == [item[2] for item in saved]
        for body, key, _, accepted, sample in saved:
            replay, _, _, _ = _post(daemon, body, key)
            assert replay == accepted
            record = _timing(capture, "replay")
            assert record["timings_ms"]["provider_commit"] == 0
            sample["durable_after_restart"] = True
            print("C3_DURABLE " + json.dumps(sample, sort_keys=True), flush=True)
        assert len({item[4]["timing"]["request_id"] for item in saved}) == SAMPLES
    finally:
        try:
            daemon.stop()
        finally:
            logger.removeHandler(capture)
            logger.setLevel(previous_level)
            capture.close()
