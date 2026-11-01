from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from tests.runtime_credentials import provision_executor_token

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from astrid_runtime_client import ApiError, Capability, ClaimWaiting, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


def _patch_opener(monkeypatch, open_response):
    """Replace the network step of the client's loopback opener, keeping the opener itself real."""
    monkeypatch.setattr(
        urllib.request.OpenerDirector, "open",
        lambda self, request, data=None, timeout=None: open_response(request, timeout=timeout),
    )


@pytest.mark.parametrize("filters", [{}, {"kind": "video", "model": "X /&?", "target": "runpod", "tag": "hero +"}, {"tag": ""}])
def test_generation_list_filters_encode_through_generated_transport(filters):
    from urllib.parse import parse_qs, urlsplit

    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path))
        return 200, {}, b'{"items":[],"next_cursor":"page-two"}'

    client = WorkspaceClient("http://runtime", transport=transport)
    assert client.list_generations("project /&?", cursor="page +", limit=7, **filters) == ([], "page-two")
    method, path = calls.pop()
    assert method == "GET"
    assert urlsplit(path).path == "/v1/projects/project%20%2F%26%3F/generations"
    assert parse_qs(urlsplit(path).query, keep_blank_values=True) == {
        "cursor": ["page +"], "limit": ["7"], **{name: [value] for name, value in filters.items()},
    }


def test_generated_abandon_client_roundtrips_exact_identity_receipt_and_wire_schema(tmp_path):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    import yaml
    from tests.test_tasks_clear import _external_cli_task

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        task_id, attempt = _external_cli_task(daemon)
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        client.cancel_task(task_id, idempotency_key="client-abandon-cancel")
        observed = client.get_task_settlement(task_id)["task"]
        body = {"expected_task_version": observed["version"], "attempt_id": attempt["attempt_id"],
            **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "execution_binding": observed["execution_binding"], "reason": "owner clears provider uncertainty"}
        result = client.abandon_task(task_id, body, idempotency_key="client-abandon")
        assert result["disposition"] == "lost" and result["task"]["state"] == "failed"
        assert result.receipt["command_kind"] == "task.abandon"
        assert client.abandon_task(task_id, body, idempotency_key="client-abandon") == result
        base = Path(__file__).parents[1]
        schemas = [json.loads((base / "contract/schemas" / name).read_text()) for name in ("task.json", "task-abandon.json", "worker.json")]
        document = yaml.safe_load((base / "contract/openapi/workspace-v1.yaml").read_text())
        document.update({"$id": "https://astrid.haus/workspace/v1/workspace-v1.yaml", "$schema": schemas[0]["$schema"]})
        registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in [*schemas, document])
        Draft202012Validator(schemas[1], registry=registry).validate(body)
        response_schema = {"$id": document["$id"], "components": document["components"],
                           **document["components"]["schemas"]["TaskAbandonMutation"]}
        Draft202012Validator(response_schema, registry=registry).validate({
            "data": {key: value for key, value in result.items() if key != "receipt"}, "receipt": result.receipt})
        settlement = client.get_task_settlement(task_id)
        lost = settlement["lost_disposition"]
        assert lost["attempt_id"] == attempt["attempt_id"] and lost["reason"] == body["reason"]
        event = daemon.service.store.conn.execute("SELECT kind FROM events WHERE id=?", (lost["event_id"],)).fetchone()
        assert event["kind"] == "task.abandoned"
        worker = schemas[2]
        settlement_schema = {"$id": worker["$id"], "definitions": worker["definitions"],
                             **worker["definitions"]["TaskSettlement"]}
        validator = Draft202012Validator(settlement_schema, registry=registry)
        validator.validate(settlement)
        assert list(validator.iter_errors({**settlement, "lost_disposition": {"reason": "untrusted"}}))
        for field in ("event_id", "attempt_id", "reason"):
            incomplete = {key: value for key, value in lost.items() if key != field}
            assert list(validator.iter_errors({**settlement, "lost_disposition": incomplete})), field
            for malformed in (None, "", 123, True, [], {}):
                invalid = {**lost, field: malformed}
                assert list(validator.iter_errors({**settlement, "lost_disposition": invalid})), (field, malformed)
        for malformed in (None, [], "lost", {**lost, "reason": "x" * 4097}):
            assert list(validator.iter_errors({**settlement, "lost_disposition": malformed})), malformed
        for field, value in (("extra", None), ("", None),
                             ("remote_stop_confirmed", True), ("billing_stop_confirmed", True),
                             ("remote_stop_confirmed", False), ("billing_stop_confirmed", False)):
            invalid = {**lost, field: value}
            errors = list(validator.iter_errors({**settlement, "lost_disposition": invalid}))
            assert any(error.validator == "additionalProperties" for error in errors), (field, value)
        daemon.service.retry_task(task_id, idempotency_key="client-abandon-retry")
        retried = client.get_task_settlement(task_id)
        assert "lost_disposition" not in retried
        validator.validate(retried)
    finally:
        daemon.stop()


class _AcquisitionStream(io.BytesIO):
    def __init__(self, body, chunk=None):
        super().__init__(body)
        self.status = 200
        self.headers = {}
        self.chunk = chunk
        self.read_sizes = []
        self.acquired = 0

    def read(self, size=-1):
        self.read_sizes.append(size)
        data = super().read(min(size, self.chunk) if self.chunk and size >= 0 else size)
        self.acquired += len(data)
        return data


@pytest.mark.parametrize("error", [False, True])
@pytest.mark.parametrize("chunk", [None, 1, 3])
@pytest.mark.parametrize("extra", [-1, 0, 1, 1000])
def test_acquisition_reader_stream_bounds_and_closure(monkeypatch, error, chunk, extra):
    cap = 8
    stream = _AcquisitionStream(b"x" * (cap + extra), chunk)
    def open_response(request, timeout):
        assert request.get_header("Authorization") == "Bearer token"
        assert request.get_header("X-request-id") == "selected-request"
        assert timeout == 7
        if error:
            raise urllib.error.HTTPError(request.full_url, 409, "Conflict", {}, stream)
        return stream
    _patch_opener(monkeypatch, open_response)
    def reader(response):
        result = bytearray()
        while True:
            data = response.read(cap + 1 - len(result))
            result.extend(data)
            if len(result) > cap:
                raise ValueError("overflow")
            if not data:
                return bytes(result)
    client = WorkspaceClient("http://127.0.0.1:9", "token", timeout=7)
    if extra > 0:
        with pytest.raises(ValueError, match="overflow"):
            client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)
        assert stream.acquired == cap + 1
    elif error:
        with pytest.raises(ApiError) as caught:
            client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)
        assert caught.value.status == 409
    else:
        assert client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)[2] == b"x" * (cap + extra)
    assert stream.closed
    assert all(0 < size <= cap + 1 for size in stream.read_sizes)
    assert stream.acquired <= cap + 1


@pytest.mark.parametrize("http_error", [False, True])
@pytest.mark.parametrize("failure", [ValueError("reader"), TimeoutError("reader"), urllib.error.URLError("reader")])
def test_acquisition_reader_policy_exception_propagates_and_closes(monkeypatch, http_error, failure):
    stream = _AcquisitionStream(b"private-body")
    def open_response(request, timeout):
        if http_error:
            raise urllib.error.HTTPError(request.full_url, 400, "Bad", {}, stream)
        return stream
    _patch_opener(monkeypatch, open_response)
    def reader(response):
        raise failure
    with pytest.raises(type(failure)) as caught:
        WorkspaceClient("http://127.0.0.1:9")._request("GET", "/probe", response_reader=reader)
    assert caught.value is failure
    assert stream.closed and not stream.read_sizes


def test_acquisition_reader_default_behavior_and_four_argument_transport(monkeypatch):
    stream = _AcquisitionStream(b"{}")
    _patch_opener(monkeypatch, lambda request, timeout: stream)
    assert WorkspaceClient("http://127.0.0.1:9")._request("GET", "/probe")[2] == b"{}"
    assert stream.read_sizes == [-1] and stream.closed
    calls = []
    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        return 200, {}, b"{}"
    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert client._request("GET", "/probe")[2] == b"{}"
    assert client._request("GET", "/probe", response_reader=lambda response: response.read(3))[2] == b"{}"
    assert len(calls) == 2 and all(len(call) == 4 for call in calls)
    assert all(call[2]["Authorization"] == "Bearer token" for call in calls)


def test_acquisition_selected_python_renderer_parity(tmp_path):
    import importlib.util
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location("selected_python_renderer", root / "generators/generate.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    isolated = tmp_path / "selected-generated.py"
    isolated.write_text(renderer.render_python_client())
    assert f'SCHEMA_DIGEST = "{renderer.contract_digest()}"' in isolated.read_text()
    assert isolated.read_bytes() == (root / "packages/python/astrid_runtime_client/generated.py").read_bytes()


def test_generated_client_smoke_and_scoped_handshake() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/health":
            return 200, {}, json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1, "runtime_session_id": "runtime-session-1", "runtime_instance_id": "runtime-instance-1", "identity": {"release": 0, "managed_by": None}}).encode()
        if path == "/v1/handshake":
            return 200, {}, json.dumps({"protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "session_id": "session-1", "actor_id": "actor-1", "realm_id": "realm-1", "scopes": ["realm:read", "project:write"]}).encode()
        if path == "/v1/projects" and method == "POST":
            return 201, {}, json.dumps({"data": {"project_id": "project-1", "realm_id": "realm-1", "name": "Neutral", "version": 1, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}, "receipt": {"receipt_id": "runtime-command-1", "command_kind": "project.create", "idempotency_key": "create-1", "request_hash": "sha256:" + "a" * 64, "project_id": "project-1", "project_seq": [1, 1], "event_ids": [], "result": {}, "created_at": "2026-01-01T00:00:00Z"}}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    health = client.health()
    assert health["protocol"] == "workspace.v1"
    assert health.runtime_session_id == "runtime-session-1"
    assert health.runtime_instance_id == "runtime-instance-1"
    session = client.handshake("second-product", "0.1.0", ["realm:read", "project:write"])
    assert session.realm_id == "realm-1"
    project = client.create_project("Neutral", idempotency_key="create-1")
    assert project.project_id == "project-1"
    assert project.receipt["command_kind"] == "project.create"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    assert calls[-1][2]["Idempotency-Key"] == "create-1"


def test_connected_register_executor_response_uses_generated_capability_parser(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        registered = client.register_executor(
            {
                "executor_id": "ordinary-worker",
                "max_concurrency": 1,
                "resource_keys": [],
                # Runtime keeps the existing ID-list registration input
                # compatibility; the response must still satisfy the
                # canonical generated Executor parser.
                "capabilities": ["render.basic"],
                "protocol": "workspace.v1",
            },
            idempotency_key="register-ordinary-worker",
        )
        capability = registered.capabilities[0]
        assert isinstance(capability, Capability)
        assert capability.capability_id == "render.basic"
        assert capability.definition_digest.startswith("sha256:")
        task = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="admit-after-register",
        )
        assert task["capability_id"] == capability.capability_id
    finally:
        daemon.stop()


def test_owner_get_executor_observes_exact_readiness_and_session(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        owner.register_executor({
            "executor_id": "exact-worker", "max_concurrency": 1,
            "resource_keys": [], "capabilities": ["render.basic"],
            "protocol": "workspace.v1", "source_digest": "sha256:" + "a" * 64,
        }, idempotency_key="exact-worker-register")
        observed = owner.get_executor("exact-worker")
        assert observed.executor_id == "exact-worker"
        assert observed.readiness == "ready"
        assert observed.runtime_epoch == daemon.service.store._current_runtime_epoch()
        assert observed.runtime_session_id == daemon.service.runtime_session_id
        assert observed.source_digest == "sha256:" + "a" * 64
        assert observed.last_seen_at
        daemon.service.store.set_executor_readiness(
            "exact-worker", ready=False, reason="observer_probe",
            runtime_epoch=observed.runtime_epoch,
        )
        not_ready = owner.get_executor("exact-worker")
        assert not_ready.readiness == "not_ready"
        assert not_ready.readiness_reason == "observer_probe"
        with pytest.raises(ApiError) as missing:
            owner.get_executor("foreign-worker")
        assert missing.value.status == 404
        with pytest.raises(ApiError) as denied:
            WorkspaceClient(daemon.endpoint, daemon.worker_token).get_executor("exact-worker")
        assert denied.value.status in {401, 403}
    finally:
        daemon.stop()


def test_generated_owner_local_generation_readback() -> None:
    def transport(method, path, _headers, body):
        if (method, path) == ("GET", "/v1/control/local-worker/generation"):
            return 200, {}, json.dumps({
                "executor_incarnation": "incarnation-1",
                "evidence_digest": "sha256:" + "a" * 64,
                "profile_id": "astrid", "workspace_uuid": "realm-1",
                "state": "stop_unknown",
            }).encode()
        assert (method, path) == ("POST", "/v1/control/local-worker/relinquish")
        assert json.loads(body) == {
            "executor_incarnation": "incarnation-1",
            "evidence_digest": "sha256:" + "a" * 64,
        }
        return 200, {}, b'{"state":"relinquished","executor_incarnation":"incarnation-1"}'

    client = WorkspaceClient("http://runtime", "owner-token", transport=transport)
    observed = client.get_local_worker_generation()
    assert observed["executor_incarnation"] == "incarnation-1"
    assert observed["state"] == "stop_unknown"
    assert client.relinquish_local_worker(
        observed["executor_incarnation"], observed["evidence_digest"]
    )["state"] == "relinquished"


def test_generated_owner_local_worker_restart():
    expected = {
        "state": "active", "operation_id": "operation-1", "profile_id": "astrid",
        "workspace_uuid": "realm-1", "machine_id": "machine-1",
        "executor_incarnation": "incarnation-2",
        "evidence_digest": "sha256:" + "b" * 64,
    }

    def transport(method, path, _headers, body):
        assert (method, path) == ("POST", "/v1/control/local-worker/start")
        assert json.loads(body) == {
            "profile_id": "astrid", "expected_workspace_uuid": "realm-1",
        }
        return 200, {}, json.dumps(expected).encode()

    client = WorkspaceClient("http://runtime", "owner-token", transport=transport)
    assert client.start_local_worker("astrid", "realm-1") == expected


def test_generated_owner_task_settlement_and_named_relinquish():
    expected = {"task_id": "task/with space", "state": "cancelled", "settled": True, "blockers": []}
    def transport(method, path, headers, body):
        if method == "GET":
            assert path == "/v1/control/tasks/task%2Fwith%20space/settlement"
            return 200, {}, json.dumps(expected).encode()
        assert (method, path) == ("POST", "/v1/control/local-worker/relinquish")
        assert json.loads(body) == {"executor_incarnation": "inc-1", "evidence_digest": "sha256:" + "a" * 64,
                                    "expected_task_ids": ["task/with space", "other"]}
        return 200, {}, b'{"state":"relinquished","executor_incarnation":"inc-1"}'
    client = WorkspaceClient("http://runtime", "owner-token", transport=transport)
    assert client.get_task_settlement("task/with space") == expected
    assert client.relinquish_local_worker("inc-1", "sha256:" + "a" * 64,
                                         expected_task_ids=["task/with space", "other"])["state"] == "relinquished"


def test_generation_intent_round_trips_through_admission_claim_and_terminal_readback(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    intent = {
        "version": 1,
        "modality": "video",
        "partial_success_policy": "allow",
        "groups": [
            {
                "group_key": "main",
                "selectors": [
                    {"selector": "video", "ordinal": 0, "variant_key": "original"},
                ],
            },
        ],
    }
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        registered = client.register_executor(
            {
                "executor_id": "generation-intent-worker",
                "max_concurrency": 1,
                "resource_keys": [],
                "capabilities": ["generation.intent"],
                "protocol": "workspace.v1",
            },
            idempotency_key="generation-intent-register",
        )
        capability = registered.capabilities[0]
        admitted = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="generation-intent-admit",
            generation_intent=intent,
        )
        assert admitted["generation_intent"] == intent
        assert "generation_intent" not in admitted["spec"]

        task = client.get_task(admitted["task_id"])
        assert task.generation_intent == intent
        assert "generation_intent" not in task.spec
        worker = WorkspaceClient(daemon.endpoint, provision_executor_token(daemon, "generation-intent-worker"))
        attempt = worker.claim_task(
            executor_id="generation-intent-worker",
            capability_ids=[capability.capability_id],
            idempotency_key="generation-intent-claim",
            runtime_epoch=worker.health().runtime_epoch,
        )
        assert attempt.generation_intent == intent
        assert "generation_intent" not in attempt.spec
        settled = worker.settle_attempt(
            attempt.attempt_id,
            {
                "lease_id": attempt.lease_id,
                "fence": attempt.fence,
                "runtime_epoch": attempt.runtime_epoch,
                "outputs": [],
                "effect": None,
            },
            idempotency_key="generation-intent-settle",
        )
        assert settled["state"] == "succeeded"
        terminal = client.get_task(task.task_id)
        assert terminal.state == "succeeded"
        assert terminal.generation_intent == intent
        assert "generation_intent" not in terminal.spec

        # Read a row written by the pre-fix Runtime shape: the legacy key is
        # accepted for compatibility but never leaks into public spec.
        row = daemon.service.store.conn.execute(
            "SELECT spec_digest FROM tasks WHERE id=?", (task.task_id,)
        ).fetchone()
        legacy_spec = daemon.service.store._load_spec(row["spec_digest"])
        legacy_spec["generation_intent"] = legacy_spec.pop("__runtime_generation_intent")
        daemon.service.store.conn.execute(
            "UPDATE tasks SET spec_digest=? WHERE id=?",
            (daemon.service.store._store_spec(legacy_spec), task.task_id),
        )
        daemon.service.store.conn.commit()
        legacy = client.get_task(task.task_id)
        assert legacy.generation_intent == intent
        assert "generation_intent" not in legacy.spec

        generic = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="generation-intent-generic-admit",
        )
        assert "generation_intent" not in generic
        assert client.get_task(generic["task_id"]).generation_intent is None
    finally:
        daemon.stop()


def test_expected_effect_round_trips_through_public_task_read(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    effect_payload = {
        "version": 1,
        "modality": "video",
        "generation_type": "vibecomfy.run",
        "metadata": {"h3_av": {"request_digest": "sha256:" + "a" * 64}},
        "partial_success_policy": "reject",
        "groups": [{
            "group_key": "main",
            "selectors": [{
                "selector": "video",
                "ordinal": 0,
                "variant_key": "original",
                "output_port": "vibecomfy_run",
            }],
        }],
    }
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project(
            "H3 receipt projection",
            idempotency_key="effect-projection-project",
            slug="h3-receipt-projection",
        )
        effect = {
            "effect_type": "generation.publish_v1",
            "target_id": project.project_id,
            "payload": effect_payload,
        }
        admitted = client.admit_task(
            capability_id="vibecomfy.run",
            capability_digest="sha256:" + hashlib.sha256(b"vibecomfy.run").hexdigest(),
            input_object_ids=[],
            idempotency_key="effect-projection-task",
            project_id=project.project_id,
            settlement_effect=effect,
            generation_intent={
                "version": 1,
                "modality": "video",
                "partial_success_policy": "reject",
                "metadata": effect_payload["metadata"],
                "groups": effect_payload["groups"],
            },
        )

        task = client.get_task(admitted["task_id"])
        assert task.expected_effect == effect
    finally:
        daemon.stop()


def test_object_byte_range_etag_and_head_are_preserved() -> None:
    payload = b"0123456789"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers))
        assert headers["Range"] == "bytes=2-5"
        result = {"ETag": f'"{digest}"', "Content-Range": "bytes 2-5/10", "Accept-Ranges": "bytes"}
        return 206, result, payload[2:6] if method == "GET" else b""

    client = WorkspaceClient("http://runtime", transport=transport)
    result = client.get_object("obj-1", byte_range=(2, 5))
    assert result.status == 206 and result.data == b"2345"
    assert result.etag == f'"{digest}"' and result.content_range == "bytes 2-5/10"
    head = client.head_object("obj-1", byte_range=(2, 5))
    assert head.status == 206 and calls[-1][0] == "HEAD"


def test_invalid_range_is_rejected_before_transport() -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (_ for _ in ()).throw(AssertionError("called")))
    try:
        client.get_object("obj", byte_range=(5, 2))
    except ValueError as exc:
        assert "range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_generated_run_events_preserve_event_page_contract() -> None:
    event = {
        "event_id": "1", "sequence": 1, "cursor": "1",
        "event_type": "task.admitted", "aggregate_type": "run",
        "aggregate_id": "run-1", "payload": {},
        "occurred_at": "2026-01-01T00:00:00Z",
    }

    def transport(method, path, headers, body):
        assert method == "GET" and path == "/v1/runs/run-1/events"
        return 200, {}, json.dumps({"items": [event], "next_cursor": None}).encode()

    items, cursor = WorkspaceClient("http://runtime", transport=transport).list_run_events("run-1")
    assert items[0].event_id == "1"
    assert cursor is None


def test_api_error_preserves_conflict_and_version_details() -> None:
    def transport(*args):
        return 409, {}, json.dumps({"code": "version_conflict", "message": "stale", "request_id": "req-1", "details": {"expected": 2, "actual": 3}}).encode()

    try:
        WorkspaceClient("http://runtime", transport=transport).get_project("p")
    except ApiError as exc:
        assert exc.status == 409 and exc.code == "version_conflict" and exc.details["actual"] == 3
    else:
        raise AssertionError("expected ApiError")


def test_client_correlates_transport_timeout_and_http_failure() -> None:
    observed_request_ids = []

    def timed_out(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        raise TimeoutError("late")

    with pytest.raises(ApiError) as timeout_error:
        WorkspaceClient("http://runtime", transport=timed_out, timeout=0.25).health()
    assert timeout_error.value.code == "transport_timeout"
    assert timeout_error.value.request_id == observed_request_ids[0]

    def rejected(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        return 503, {}, json.dumps({"code": "registration_failed", "message": "terminal"}).encode()

    with pytest.raises(ApiError) as rejected_error:
        WorkspaceClient("http://runtime", transport=rejected).health()
    assert rejected_error.value.code == "registration_failed"
    assert rejected_error.value.request_id == observed_request_ids[1]


def test_client_applies_bounded_timeout_to_stdlib_transport(monkeypatch) -> None:
    observed = {}

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1, "runtime_session_id": "runtime-session-1", "runtime_instance_id": "runtime-instance-1", "identity": {"release": 0, "managed_by": None}}).encode()

    def urlopen(request, *, timeout):
        observed["timeout"] = timeout
        observed["request_id"] = request.headers["X-request-id"]
        return Response()

    _patch_opener(monkeypatch, urlopen)
    client = WorkspaceClient("http://127.0.0.1:9", timeout=1.5)
    assert client.health().status == "ok"
    assert client.health().runtime_instance_id == "runtime-instance-1"
    assert observed["timeout"] == 1.5
    assert observed["request_id"].startswith("request-")
    with pytest.raises(ValueError, match="finite and positive"):
        WorkspaceClient("http://127.0.0.1:9", timeout=0)


def test_claim_capability_unavailable_is_typed_waiting_result() -> None:
    digest = "sha256:" + "a" * 64
    task = {
        "task_id": "task-1", "run_id": "run-1", "state": "queued", "version": 1,
        "capability_id": "render.gpu", "capability_digest": digest,
        "idempotency_key": "admit-1", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "runtime_epoch": 1,
        "waiting_reason": "capability_unavailable",
    }

    def transport(method, path, headers, body):
        assert method == "POST" and path == "/v1/tasks/claim"
        return 200, {}, json.dumps({"task": task, "waiting_reason": "capability_unavailable"}).encode()

    result = WorkspaceClient("http://runtime", transport=transport).claim_task(
        executor_id="worker-1", capability_ids=["render.gpu"],
        idempotency_key="claim-1", runtime_epoch=1,
    )
    assert isinstance(result, ClaimWaiting)
    assert result.waiting_reason == "capability_unavailable"
    assert result.task.task_id == "task-1"


def test_generated_task_lease_fields_decode_from_get_and_project_list() -> None:
    digest = "sha256:" + "a" * 64
    expired = "2026-01-01T00:00:00+00:00"
    deadline = "2026-01-02T00:00:00+00:00"

    def task(task_id: str, **lease_fields):
        return {
            "task_id": task_id,
            "run_id": "run-1",
            "project_id": "project-1",
            "state": "running",
            "version": 2,
            "capability_id": "render.basic",
            "capability_digest": digest,
            "idempotency_key": f"admit-{task_id}",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "runtime_epoch": 3,
            "input_object_ids": [],
            "spec": {},
            **lease_fields,
        }

    listed = [
        task("listed-task", lease_fence=8, lease_expires_at=deadline),
        task("missing-lease-task"),
        task("null-lease-task", lease_fence=None, lease_expires_at=None),
    ]

    def transport(method, path, headers, body):
        assert method == "GET"
        if path == "/v1/tasks/get-task":
            return 200, {}, json.dumps(task("get-task", lease_fence=7, lease_expires_at=expired)).encode()
        if path == "/v1/projects/project-1/tasks?limit=50":
            return 200, {}, json.dumps({"items": listed, "next_cursor": None}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", transport=transport)
    fetched = client.get_task("get-task")
    tasks, next_cursor = client.list_project_tasks("project-1")

    assert (fetched.lease_fence, fetched.lease_expires_at) == (7, expired)
    assert next_cursor is None
    assert [(item.task_id, item.lease_fence, item.lease_expires_at) for item in tasks] == [
        ("listed-task", 8, deadline),
        ("missing-lease-task", None, None),
        ("null-lease-task", None, None),
    ]


def test_distinct_tasks_reader_retains_expired_task_custody_with_fence(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(
        realm,
        support_root=tmp_path / "support",
    ).start()
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        executor_spec = {
            "executor_id": "executor-a",
            "max_concurrency": 1,
            "resource_keys": [],
            "capabilities": ["lease-projection"],
            "protocol": "workspace.v1",
        }
        registered = owner.register_executor(
            executor_spec,
            idempotency_key="lease-projection-register",
        )
        owner.register_executor(
            {**executor_spec, "executor_id": "executor-b"},
            idempotency_key="lease-projection-register-b",
        )
        capability = registered.capabilities[0]
        admitted = owner.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="lease-projection-admit",
        )
        executor_a_token, _ = daemon.credentials.provision(
            "executor-a", ["handshake", "worker:execute", "tasks:read"]
        )
        executor_a = WorkspaceClient(daemon.endpoint, executor_a_token)
        claimed = executor_a.claim_task(
            executor_id="executor-a",
            capability_ids=[capability.capability_id],
            idempotency_key="lease-projection-claim",
            runtime_epoch=executor_a.health().runtime_epoch,
        )
        assert claimed is not None and not isinstance(claimed, ClaimWaiting)

        expired = "2000-01-01T00:00:00+00:00"
        daemon.service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at=? WHERE id=?",
            (expired, admitted["task_id"]),
        )
        daemon.service.store.conn.execute(
            "UPDATE attempts SET lease_expires_at=? WHERE id=?",
            (expired, claimed.attempt_id),
        )
        daemon.service.store.conn.commit()

        reader_token, _ = daemon.credentials.provision("executor-b", ["tasks:read"])
        reader_identity = daemon.credentials.actor_metadata("executor-b")
        assert reader_identity["actor"] == "executor-b"
        assert "tasks:read" in reader_identity["scopes"]
        assert "admin" not in reader_identity["scopes"]
        assert reader_identity["actor"] != "executor-a"

        readback = WorkspaceClient(daemon.endpoint, reader_token).get_task(admitted["task_id"])
        # Expiry ends publication authority but does not prove executor stop.
        # A distinct reader preserves the exact running attempt and deadline.
        assert readback.state == "running"
        assert readback.lease_fence == claimed.fence
        assert readback.lease_expires_at == expired
        task = daemon.service.store.conn.execute(
            "SELECT status, attempt_id, executor_id, lease_fence, lease_expires_at FROM tasks WHERE id=?",
            (admitted["task_id"],),
        ).fetchone()
        assert tuple(task) == ("running", claimed.attempt_id, "executor-a", claimed.fence, expired)
        assert daemon.service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (claimed.attempt_id,),
        ).fetchone()[0] == 0
    finally:
        daemon.stop()


def test_generated_child_authority_client_preserves_legacy_shape_and_forwards_d18_descriptors() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body)))
        return 200, {}, b"{}"

    client = WorkspaceClient("http://runtime", transport=transport)
    client.issue_child_authority("attempt-1", lease_id="lease-1", fence=2, runtime_epoch=7)
    assert calls[-1][3] == {"lease_id": "lease-1", "fence": 2, "runtime_epoch": 7}

    child = {
        "child_id": "child-1",
        "capability_id": "render.child",
        "capability_digest": "sha256:" + "a" * 64,
    }
    derived_inputs = [{
        "name": "source-frame",
        "output_port": "frame",
        "filename": "source-frame.bin",
        "object_id": "sha256:" + "b" * 64,
        "size": 4096,
        "media_type": "application/octet-stream",
    }]
    client.issue_child_authority(
        "attempt-1",
        lease_id="lease-1",
        fence=2,
        runtime_epoch=7,
        child=child,
        derived_inputs=derived_inputs,
    )
    assert calls[-1][3] == {
        "lease_id": "lease-1",
        "fence": 2,
        "runtime_epoch": 7,
        "child": child,
        "derived_inputs": derived_inputs,
    }


def test_generator_is_reproducible() -> None:
    # --check proves the committed output is exactly what the generator produces,
    # without rewriting tracked files during a test run (testing plan UR.3).
    root = Path(__file__).parents[1]
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--check"], check=True, cwd=root)


def test_python_client_source_is_tracked_and_generated_check_is_not_self_referential(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    component = json.loads((root / "contract" / "component-manifest.json").read_text())
    python_component = next(item for item in component["clients"] if item["generator"] == "GENERATOR-PYTHON-INREPO")
    template = root / "generators" / "python_client_template.py"
    output = root / "packages" / "python" / "astrid_runtime_client" / "generated.py"
    assert (root / python_component["source"]).is_file()
    assert (root / python_component["output"]).resolve() == output.resolve()
    assert template.is_file()
    assert "__SCHEMA_DIGEST__" in template.read_text()
    original = output.read_bytes()
    isolated = tmp_path / "generated.py"
    isolated.write_bytes(original + b"\n# mutation\n")
    check = subprocess.run(
        [sys.executable, str(root / "generators" / "generate.py"), "--check", "--python-output", str(isolated)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert check.returncode != 0
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--python-output", str(isolated)], check=True, cwd=root)
    assert isolated.read_bytes() == output.read_bytes() == original


def _preference_fixture(name: str = "preferences-user.json") -> dict:
    return json.loads((Path(__file__).parents[1] / "conformance" / "fixtures" / name).read_text())


def test_preferences_generated_client_typed_user_result_and_encoded_project_selector() -> None:
    from astrid_runtime_client import PreferenceMutationResult, PreferenceResource

    resource = _preference_fixture()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body) if body else None))
        data = dict(resource)
        if "project" in path:
            data.update(scope="project", actor_id=None, project_id="p /?", document_id="preferences:project:p /?")
        if method == "GET":
            return 200, {}, json.dumps(data).encode()
        return 200, {}, json.dumps({"data": data, "receipt": {"receipt_id": "committed-project"} if data["scope"] == "project" else None}).encode()

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert isinstance(client.get_preferences("user"), PreferenceResource)
    user = client.update_preferences("user", resource["content"], 0, "user-write")
    assert isinstance(user, PreferenceMutationResult)
    assert isinstance(user.data, PreferenceResource)
    assert user.content == resource["content"] and user.receipt is None
    assert calls[-1][3] == {"content": resource["content"], "expected_version": 0}
    assert calls[-1][2]["Idempotency-Key"] == "user-write"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    project = client.update_preferences("project", "text", 1, "project-write", "p /?")
    assert project.receipt == {"receipt_id": "committed-project"}
    assert calls[-1][1] == "/v1/preferences/project?project_id=p%20%2F%3F"
    client.get_preferences("project")
    assert calls[-1][1] == "/v1/preferences/project"


@pytest.mark.parametrize("scope,selector", [("user", "p"), ("invalid", None)])
def test_preferences_generated_client_rejects_invalid_scope_and_user_project_selector(scope, selector) -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: pytest.fail("transport called"))
    with pytest.raises(ValueError):
        client.get_preferences(scope, selector)
    with pytest.raises(ValueError):
        client.update_preferences(scope, "content", 0, "key", selector)


@pytest.mark.parametrize("response", [
    {"data": _preference_fixture(), "receipt": {}},
    {"data": _preference_fixture()},
    {"data": {**_preference_fixture(), "content": {}}, "receipt": None},
    {"data": {**_preference_fixture(), "version": True}, "receipt": None},
    {"data": {**_preference_fixture(), "actor_id": None}, "receipt": None},
    {"data": {**_preference_fixture(), "project_id": "forged"}, "receipt": None},
    {"data": {**_preference_fixture(), "document_id": "other"}, "receipt": None},
    {"data": {key: value for key, value in _preference_fixture().items() if key != "version"}, "receipt": None},
])
def test_preferences_user_null_receipt_decoder_validates_known_fields(response) -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (200, {}, json.dumps(response).encode()))
    with pytest.raises(ApiError, match="invalid_response"):
        client.update_preferences("user", "content", 0, "key")


def test_python_response_extensions_are_tolerated_and_opaque_payloads_survive() -> None:
    resource = _preference_fixture()
    future_payload = {"nested": [1, {"opaque": True}]}
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, json.loads(body) if body else None))
        if path == "/v1/projects":
            data = {
                "project_id": "p", "realm_id": "r", "name": "Project",
                "version": 1, "created_at": "t", "updated_at": "t",
                "future_payload": future_payload,
            }
            return 201, {}, json.dumps({
                "data": data, "receipt": {"receipt_id": "receipt-1"},
                "future_envelope": future_payload,
            }).encode()
        data = {**resource, "future_payload": future_payload}
        return 200, {}, json.dumps({
            "data": data, "receipt": None, "future_envelope": future_payload,
        }).encode()

    client = WorkspaceClient("http://runtime", transport=transport)
    mutation = client.create_project("Project", idempotency_key="create-1")
    assert mutation.future_payload == future_payload
    assert mutation.receipt == {"receipt_id": "receipt-1"}
    assert calls[0][2] == {"name": "Project"}
    preference = client.update_preferences("user", resource["content"], 1, "write-1")
    assert preference.content == resource["content"]
    assert preference.data.content == resource["content"]
    assert calls[1][2] == {"content": resource["content"], "expected_version": 1}


def test_preferences_get_tolerates_extensions_but_validates_known_fields() -> None:
    invalid_resource = {
        **_preference_fixture(),
        "version": True,
        "future_extension": {"opaque": [1, 2, 3]},
    }
    client = WorkspaceClient(
        "http://runtime",
        transport=lambda *args: (200, {}, json.dumps(invalid_resource).encode()),
    )
    with pytest.raises(ApiError, match="invalid_response"):
        client.get_preferences("user")


@pytest.mark.parametrize("data,receipt", [({}, "committed"), ({}, []), ([], {}), ("project", {})])
def test_ordinary_mutation_extensions_do_not_bypass_known_field_types(data, receipt) -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (201, {}, json.dumps({
        "data": data, "receipt": receipt, "future_envelope": True,
    }).encode()))
    with pytest.raises(ApiError, match="invalid_response"):
        client.create_project("Project", idempotency_key="key")


def test_preferences_project_and_ordinary_mutations_still_require_receipts() -> None:
    resource = {**_preference_fixture(), "scope": "project", "actor_id": None, "project_id": "p", "document_id": "preferences:project:p"}
    client = WorkspaceClient("http://runtime", transport=lambda *args: (200, {}, json.dumps({"data": resource, "receipt": None}).encode()))
    with pytest.raises(ApiError, match="committed receipt"):
        client.update_preferences("project", "content", 0, "key")
    with pytest.raises(ApiError, match="committed receipt"):
        client.update_document("p", "doc", expected_version=1, idempotency_key="key", content="content")


def test_update_document_distinguishes_omitted_content_from_json_null() -> None:
    payloads = []

    def transport(method, path, headers, body):
        assert method == "PATCH" and path == "/v1/projects/p/documents/doc"
        payload = json.loads(body)
        payloads.append(payload)
        resource = {
            "document_id": "doc", "project_id": "p", "kind": "pack.note",
            "content": payload.get("content", "previous"), "version": 2,
            "created_at": "2026-10-02T00:00:00Z", "updated_at": "2026-10-02T00:00:01Z",
        }
        return 200, {}, json.dumps({"data": resource, "receipt": {}}).encode()

    client = WorkspaceClient("http://runtime", transport=transport)
    client.update_document("p", "doc", expected_version=1, idempotency_key="null", content=None)
    client.update_document("p", "doc", expected_version=1, idempotency_key="omitted")
    assert payloads == [
        {"expected_version": 1, "content": None},
        {"expected_version": 1},
    ]


def test_list_documents_generated_client_kind_filter_is_encoded() -> None:
    def transport(method, path, headers, body):
        assert method == "GET"
        assert path == "/v1/projects/p%20%2F/documents?limit=5&cursor=next%2Fpage&kind=astrid.note%20%2F%3F"
        return 200, {}, b'{"items": [], "next_cursor": null}'
    assert WorkspaceClient("http://runtime", transport=transport).list_documents("p /", cursor="next/page", limit=5, kind="astrid.note /?") == ([], None)


@pytest.mark.parametrize("name", ["kind", "model", "target", "tag"])
def test_list_project_objects_generated_client_forwards_each_filter(name):
    def transport(method, path, headers, body):
        assert method == "GET"
        assert path == f"/v1/projects/p/objects?limit=50&{name}=value"
        return 200, {}, b'{"items": [], "next_cursor": "next"}'

    assert getattr(WorkspaceClient("http://runtime", transport=transport), "list_project_objects")("p", **{name: "value"}) == ([], "next")


def test_list_project_objects_generated_client_forwards_combined_filters_and_encodes_values():
    from urllib.parse import parse_qs, urlsplit

    filters = {
        "kind": "astrid.video /?",
        "model": "vendor/model&variant=fast",
        "target": "runpod+gpu=1",
        "tag": "scene #1",
    }

    def transport(method, path, headers, body):
        parsed = urlsplit(path)
        assert method == "GET"
        assert parsed.path == "/v1/projects/p%20%2F/objects"
        assert parse_qs(parsed.query, keep_blank_values=True) == {"limit": ["50"], **{key: [value] for key, value in filters.items()}}
        return 200, {}, b'{"items": [], "next_cursor": null}'

    assert WorkspaceClient("http://runtime", transport=transport).list_project_objects("p /", **filters) == ([], None)


def test_list_project_objects_generated_client_without_filters_preserves_request_and_response():
    def transport(method, path, headers, body):
        assert method == "GET"
        assert path == "/v1/projects/p%20%2F/objects?limit=50"
        return 200, {}, b'{"items": [], "next_cursor": "existing-cursor"}'

    assert WorkspaceClient("http://runtime", transport=transport).list_project_objects("p /") == ([], "existing-cursor")


def test_stream_project_object_upload_sets_length_digest_and_does_not_buffer_or_close(monkeypatch) -> None:
    import astrid_runtime_client.generated as generated

    raw = b"prepared timeline bytes"
    digest = hashlib.sha256(raw).hexdigest()

    class ReadProbe(io.BytesIO):
        max_read = 0

        def read(self, size=-1):
            self.max_read = max(self.max_read, size)
            return super().read(size)

    stream = ReadProbe(raw)
    seen = {}

    class Response:
        status = 201
        headers = {}

        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def read(self): return b'{"data":{"object_id":"sha256:' + digest.encode() + b'"},"receipt":{}}'

    def open_request(request, *, timeout):
        seen["request"] = request
        seen["timeout"] = timeout
        chunks = []
        while True:
            chunk = request.data.read(7)
            if not chunk:
                break
            chunks.append(chunk)
        seen["uploaded"] = b"".join(chunks)
        return Response()

    monkeypatch.setattr(generated, "_urlopen_loopback", open_request)
    result = WorkspaceClient("http://runtime").ingest_project_object_stream(
        "p", stream, size=len(raw), media_type="application/json", idempotency_key="stream-import",
        filename="prepared.json", expected_digest=digest,
    )
    request = seen["request"]
    assert request.data is stream
    assert request.get_header("Content-length") == str(len(raw))
    assert request.get_header("X-expected-digest") == digest
    assert request.get_header("X-original-name") == "prepared.json"
    assert seen["uploaded"] == raw and stream.max_read == 7
    assert not stream.closed
    assert result["object_id"] == "sha256:" + digest

def test_generated_recoverable_snapshot_client_and_server_route_shape() -> None:
    from types import SimpleNamespace
    from runtime_protocol.server import RuntimeHandler

    calls = []
    authenticated = []
    output = {"name": "draft", "output_port": "state_result", "filename": "draft.json",
              "object_id": "sha256:" + "b" * 64, "size": 4, "media_type": "application/json"}
    data = {"association_id": "snapshot-1", "role": "recoverable_snapshot"}
    result = {"data": data, "receipt": {"receipt_id": "receipt-1", "command_kind": "attempt.recoverable_snapshot.publish",
        "idempotency_key": "save-1", "request_hash": "sha256:" + "a" * 64, "project_id": "project-1",
        "project_seq": [1, 1], "event_ids": ["1"], "result": data, "created_at": "2026-01-01T00:00:00Z"}}
    def publish(attempt_id, body, *, idempotency_key, identity):
        calls.append((attempt_id, body, idempotency_key, identity))
        return result
    def transport(method, path, headers, body):
        handler = object.__new__(RuntimeHandler)
        handler.server = SimpleNamespace(runtime=SimpleNamespace(publish_recoverable_snapshot=publish))
        handler.command = method
        handler.path = path
        handler._identity = lambda scope: authenticated.append(scope) or {"actor": "reviewer"}
        handler._project_mutation_body = lambda: json.loads(body)
        handler._idempotency_key = lambda: headers["Idempotency-Key"]
        handler._send = lambda status, value: (status, {}, json.dumps(value).encode())
        return handler._route()
    client = WorkspaceClient("http://runtime", "reviewer-token", transport=transport)
    saved = client.publish_recoverable_snapshot("attempt-1", lease_id="lease-1", fence=2, runtime_epoch=7,
        revision=3, output=output, idempotency_key="save-1")
    assert saved["association_id"] == data["association_id"] and saved["role"] == "recoverable_snapshot"
    assert saved.receipt["receipt_id"] == "receipt-1"
    assert authenticated == ["worker:execute"]
    assert calls == [("attempt-1", {"lease_id": "lease-1", "fence": 2, "runtime_epoch": 7, "revision": 3,
                      "output": output}, "save-1", {"actor": "reviewer"})]


def test_create_timeline_view_sends_explicit_key_and_preserves_view_response():
    result = {"inspection": {"revision_id": "r1"}, "artifacts": {"md": {"object_id": "view-object"}}}
    options = {"formats": ["md"], "revision_id": "r1"}
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body)))
        return 200, {}, json.dumps(result).encode()

    client = WorkspaceClient("http://runtime", "writer", transport=transport)
    with pytest.raises(TypeError, match="idempotency_key"):
        client.create_timeline_view("p/one", "t/two", options)
    assert calls == []
    assert client.create_timeline_view("p/one", "t/two", options, idempotency_key="view-retry") == result
    method, path, headers, body = calls[0]
    assert method == "POST"
    assert path == "/v1/projects/p%2Fone/timelines/t%2Ftwo/views"
    assert headers["Authorization"] == "Bearer writer"
    assert headers["Idempotency-Key"] == "view-retry"
    assert body == options
