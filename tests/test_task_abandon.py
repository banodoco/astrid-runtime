from __future__ import annotations

import base64
import copy
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.daemon import WORKER_ACTOR
from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.lifecycle import _interruption_report
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api


CAP = "test.abandon.render"
CAP_DIGEST = "sha256:" + hashlib.sha256(CAP.encode()).hexdigest()
TARGET = {"kind": "runpod", "pod_id": "abandon-pod", "provider_account_ref": "acct-a"}
OWNER = {"actor": "owner", "scopes": ["admin"]}
WORKER_IDENTITY = {
    "actor": "external-worker", "scopes": ["worker:execute", "objects:write"],
    "execution_binding": {
        "actual": TARGET, "executor_incarnation": "external-worker/inc-1",
        "verification": {"method": "credential_claim", "verified": True,
                          "evidence_digest": "sha256:" + "a" * 64},
    },
}


def _service(root):
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_capability({"capability_id": CAP, "definition_digest": CAP_DIGEST,
                                 "required_resource_keys": ["gpu-0"]})
    service.register_executor({
        "executor_id": "external-worker", "capabilities": [CAP],
        "max_concurrency": 4, "resource_keys": ["gpu-0"],
    }, idempotency_key="register-external")
    return service


def _active(service, key="active", *, cancel=True):
    admitted = service.create_task({
        "capability_id": CAP, "capability_digest": CAP_DIGEST,
        "input_object_ids": [], "spec": {}, "idempotency_key": "create-" + key,
        "execution_request": {"schema_version": 1, "target": TARGET, "inputs": []},
    }, enforce_readiness=True)
    attempt = service.claim_next({
        "executor_id": "external-worker", "capability_ids": [CAP],
        "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET,
    }, idempotency_key="claim-" + key, identity=WORKER_IDENTITY)
    assert attempt["task_id"] == admitted["task"]["id"]
    if cancel:
        _cancel(service, admitted, key)
        assert service.task(attempt["task_id"])["task"]["waiting_reason"] == "provider_state_unknown"
    return admitted, attempt


def _cancel(service, admitted, key):
    current_task = service.task(admitted["task"]["id"])["task"]
    return service.cancel_task_canonical(
        admitted["task"]["id"], {"expected_version": int(current_task.get("attempt", 0)) + 1},
        idempotency_key="cancel-" + key,
    )


def _body(service, admitted, attempt, **changes):
    observed = service.task(attempt["task_id"])
    body = {
        "expected_task_version": int(observed["task"].get("attempt", 0)) + 1,
        "attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"],
        "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
        "execution_binding": copy.deepcopy(observed.get("execution_binding") or {}),
        "reason": "provider outcome could not be confirmed",
    }
    body.update(changes)
    return body


def _abandon(service, admitted, attempt, *, key="abandon"):
    return service.abandon_task(
        attempt["task_id"], _body(service, admitted, attempt),
        idempotency_key=key, identity=OWNER,
    )


def _event_rows(service, run_id):
    return service.store.conn.execute(
        "SELECT kind, payload_json, previous_hash, event_hash FROM events WHERE run_id=? ORDER BY id",
        (run_id,),
    ).fetchall()


def _database_snapshot(service):
    """Stable logical SQLite snapshot for exact no-mutation assertions."""
    return tuple(service.store.conn.iterdump())


def test_abandon_lost_disposition_releases_resources_and_preserves_history(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "abandon-history", "name": "Abandon history"})
        admitted = service.create_task({
            "capability_id": CAP, "capability_digest": CAP_DIGEST, "project": project["id"],
            "input_object_ids": [], "spec": {}, "idempotency_key": "abandon-history-task",
            "execution_request": {"schema_version": 1, "target": TARGET, "inputs": []},
        }, enforce_readiness=True)
        first = service.claim_next({
            "executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET,
        }, idempotency_key="abandon-history-claim-1", identity=WORKER_IDENTITY)
        prior_bytes = b"output from historical attempt"
        service.settle_attempt(first["attempt_id"], {
            "lease_id": first["lease_id"], "fence": first["fence"],
            "runtime_epoch": first["runtime_epoch"], "outputs": [{
                "name": "historical", "kind": "object",
                "digest": "sha256:" + hashlib.sha256(prior_bytes).hexdigest(),
                "media_type": "application/octet-stream", "size": len(prior_bytes),
                "data_base64": base64.b64encode(prior_bytes).decode("ascii"),
                "filename": "historical.bin", "output_port": "historical",
            }],
        }, idempotency_key="abandon-history-settle", identity=WORKER_IDENTITY)
        service.retry_task(admitted["task"]["id"], {"expected_version": 2}, idempotency_key="abandon-history-retry")
        attempt = service.claim_next({
            "executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET,
        }, idempotency_key="abandon-history-claim-2", identity=WORKER_IDENTITY)
        _cancel(service, admitted, "history")
        task_id, run_id, attempt_id = attempt["task_id"], admitted["run"]["id"], attempt["attempt_id"]
        provenance = service.managed_outputs(task_id)
        assert provenance and provenance[0]["attempt_id"] == first["attempt_id"]
        before_events = _event_rows(service, run_id)

        result = _abandon(service, admitted, attempt)

        assert result["data"]["task_id"] == task_id
        assert result["data"]["run_id"] == run_id
        assert result["data"]["attempt_id"] == attempt_id
        assert result["data"]["disposition"] == "lost"
        assert result["data"]["reason"] == "provider outcome could not be confirmed"
        assert result["data"]["remote_stop_confirmed"] is False
        assert result["data"]["billing_stop_confirmed"] is False
        assert result["data"]["task"]["state"] == "failed"
        assert result["receipt"]
        stored = service.task(task_id)
        assert stored["task"]["status"] == stored["run"]["status"] == "failed"
        assert stored["task"]["result"]["disposition"] == "lost"
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt_id,)).fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()[0] == 0
        binding = service.store.execution_binding(task_id)
        assert binding["status"] in {"released", "stale"}
        assert service.managed_outputs(task_id) == provenance
        after_events = _event_rows(service, run_id)
        assert len(after_events) == len(before_events) + 1
        abandoned = after_events[-1]
        assert abandoned["kind"] == "task.abandoned"
        assert abandoned["previous_hash"] == before_events[-1]["event_hash"]
        assert abandoned["event_hash"] != before_events[-1]["event_hash"]
        report = _interruption_report(service.store.conn)
        assert not any(row["task_id"] == task_id for row in report["blockers"])
        assert service.store.integrity_report()["checks"]["event_chain"]["ok"] is True
    finally:
        service.close()


@pytest.mark.parametrize("identity", [
    {"actor": "external-worker", "scopes": ["worker:execute"]},
    {"actor": "browser", "scopes": ["admin"]},
    {"actor": "operator", "scopes": ["admin"]},
    {"actor": "owner", "scopes": []},
    None,
])
def test_service_abandon_requires_exact_owner_admin(tmp_path, identity):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "auth")
        with pytest.raises((AuthorizationError, ConflictError)):
            service.abandon_task(attempt["task_id"], _body(service, admitted, attempt),
                                 idempotency_key="auth-abandon", identity=identity)
        assert service.task(attempt["task_id"])["task"]["status"] == "cancel_requested"
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 0
    finally:
        service.close()


@pytest.mark.parametrize("field,value", [
    ("expected_task_version", 99), ("attempt_id", "other-attempt"),
    ("lease_id", "other-lease"), ("fence", 99), ("runtime_epoch", 99),
    ("binding_id", "other-binding"), ("placement_version", 99),
    ("actual_target", {"kind": "runpod", "pod_id": "other-pod", "provider_account_ref": "acct-a"}),
    ("executor_incarnation", "external-worker/other"),
    ("qualification", {"method": "credential_claim", "verified": True, "evidence_digest": "sha256:" + "c" * 64}),
])
def test_stale_identity_dimensions_refuse_without_mutation(tmp_path, field, value):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "stale-" + field)
        body = _body(service, admitted, attempt)
        if field in {"expected_task_version", "attempt_id", "lease_id", "fence", "runtime_epoch"}:
            body[field] = value
        elif field == "qualification":
            body["execution_binding"]["verification"] = value
        else:
            body["execution_binding"][field] = value
        before = _database_snapshot(service)
        with pytest.raises((ConflictError, ValidationError, AuthorizationError)):
            service.abandon_task(attempt["task_id"], body, idempotency_key="stale-abandon", identity=OWNER)
        assert _database_snapshot(service) == before
    finally:
        service.close()


@pytest.mark.parametrize("body_change", [
    {"reason": "  "}, {"reason": "x" * 4097}, {"expected_task_version": True},
    {"runtime_epoch": 0}, {"unexpected": "field"}, {"execution_binding": None},
])
def test_abandon_rejects_malformed_or_non_strict_bodies_atomically(tmp_path, body_change):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "bad-body")
        before = _database_snapshot(service)
        with pytest.raises((ValidationError, ConflictError)):
            service.abandon_task(attempt["task_id"], _body(service, admitted, attempt, **body_change),
                                 idempotency_key="bad-body-abandon", identity=OWNER)
        assert _database_snapshot(service) == before
    finally:
        service.close()


def test_abandon_requires_canonical_cancel_and_an_outstanding_verified_attempt(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "cancel-required", cancel=False)
        before_running = _database_snapshot(service)
        with pytest.raises(ConflictError):
            service.abandon_task(attempt["task_id"], _body(service, admitted, attempt),
                                 idempotency_key="before-cancel", identity=OWNER)
        assert _database_snapshot(service) == before_running

        # A normal runtime-owned task with no attempt cannot be declared lost.
        queued = service.create_task({"capability_id": CAP, "capability_digest": CAP_DIGEST,
                                      "input_object_ids": [], "spec": {}, "idempotency_key": "no-attempt"})
        no_attempt = {
            "expected_task_version": 1, "attempt_id": "missing-attempt", "lease_id": "missing-lease",
            "fence": 1, "runtime_epoch": service.health()["runtime_epoch"],
            "execution_binding": {}, "reason": "cannot identify a claimed external attempt",
        }
        before_no_attempt = _database_snapshot(service)
        with pytest.raises((ConflictError, ValidationError)):
            service.abandon_task(queued["task"]["id"], no_attempt,
                                 idempotency_key="no-attempt-abandon", identity=OWNER)
        assert _database_snapshot(service) == before_no_attempt
    finally:
        service.close()


def test_unverified_external_attempt_cannot_be_abandoned(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted = service.create_task({
            "capability_id": CAP, "capability_digest": CAP_DIGEST,
            "input_object_ids": [], "spec": {}, "idempotency_key": "unverified-external",
        }, enforce_readiness=True)
        unverified = {"actor": "external-worker", "scopes": ["worker:execute"]}
        attempt = service.claim_next({
            "executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": service.health()["runtime_epoch"],
        }, idempotency_key="claim-unverified", identity=unverified)
        assert attempt["task_id"] == admitted["task"]["id"]
        observed = service.store.execution_binding(attempt["task_id"])
        assert not (isinstance(observed, dict) and isinstance(observed.get("verification"), dict)
                    and observed["verification"].get("verified") is True)
        _cancel(service, admitted, "unverified-external")
        before = _database_snapshot(service)
        with pytest.raises((AuthorizationError, ConflictError)):
            service.abandon_task(attempt["task_id"], _body(service, admitted, attempt),
                                 idempotency_key="unverified-abandon", identity=OWNER)
        assert _database_snapshot(service) == before
    finally:
        service.close()


def test_local_worker_actor_cannot_be_abandoned_even_with_verified_placement(tmp_path):
    # Use the existing local generation fixture so the attempt carries real
    # owner verified generation evidence for WORKER_ACTOR.
    from tests.test_local_worker_handover import _daemon, _launch, _owned_cancel_claim

    daemon, _preparer, _proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        service = daemon.service
        task_id, attempt = _owned_cancel_claim(daemon, key="abandon-local-worker")
        binding = service.store.execution_binding(task_id)
        assert binding["executor_id"] == WORKER_ACTOR
        assert binding["verification"]["verified"] is True
        assert binding["executor_incarnation"]
        before = _database_snapshot(service)
        with pytest.raises((AuthorizationError, ConflictError)):
            service.abandon_task(task_id, _body(service, {}, attempt),
                                 idempotency_key="local-worker-abandon", identity=OWNER)
        assert _database_snapshot(service) == before
    finally:
        daemon.stop()


def test_identical_replay_lost_response_and_changed_payload_conflict(tmp_path):
    root = tmp_path / "realm"
    service = _service(root)
    try:
        admitted, attempt = _active(service, "replay")
        body = _body(service, admitted, attempt)
        first = service.abandon_task(attempt["task_id"], body, idempotency_key="same-key", identity=OWNER)
        event_count = len(_event_rows(service, admitted["run"]["id"]))
        assert service.abandon_task(attempt["task_id"], body, idempotency_key="same-key", identity=OWNER) == first
        before_conflict = _database_snapshot(service)
        with pytest.raises(ConflictError):
            service.abandon_task(attempt["task_id"], {**body, "reason": "changed"},
                                 idempotency_key="same-key", identity=OWNER)
        assert _database_snapshot(service) == before_conflict
        assert len(_event_rows(service, admitted["run"]["id"])) == event_count
        assert service.task(attempt["task_id"])["task"]["result"]["disposition"] == "lost"
        service.close()
        service = RuntimeService(root)
        assert service.abandon_task(attempt["task_id"], body, idempotency_key="same-key", identity=OWNER) == first
        before_restart_conflict = _database_snapshot(service)
        with pytest.raises(ConflictError):
            service.abandon_task(attempt["task_id"], {**body, "reason": "changed after restart"},
                                 idempotency_key="same-key", identity=OWNER)
        assert _database_snapshot(service) == before_restart_conflict
        assert len(_event_rows(service, admitted["run"]["id"])) == event_count
    finally:
        service.close()


def test_cancelled_external_attempt_can_be_abandoned_after_restart_with_old_epoch(tmp_path):
    root = tmp_path / "realm"
    service = _service(root)
    admitted, attempt = _active(service, "restart-abandon")
    old_epoch = attempt["runtime_epoch"]
    try:
        service.close()
        service = RuntimeService(root)
        assert service.health()["runtime_epoch"] > old_epoch
        fresh_owner_observation = service.task(attempt["task_id"])
        assert fresh_owner_observation["task"]["attempt_id"] == attempt["attempt_id"]
        assert fresh_owner_observation["execution_binding"] == service.store.execution_binding(attempt["task_id"])
        body = _body(service, admitted, attempt)
        assert body["runtime_epoch"] == old_epoch
        assert body["execution_binding"] == fresh_owner_observation["execution_binding"]
        committed = service.abandon_task(attempt["task_id"], body,
                                        idempotency_key="restart-abandon", identity=OWNER)
        assert committed["data"]["disposition"] == "lost"
        assert committed["data"]["attempt_id"] == attempt["attempt_id"]
        assert service.store.conn.execute("SELECT runtime_epoch FROM attempts WHERE id=?",
                                          (attempt["attempt_id"],)).fetchone()[0] == old_epoch
    finally:
        service.close()


def test_receipt_recording_failure_rolls_back_abandon_event_and_resources(tmp_path, monkeypatch):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "rollback")
        body = _body(service, admitted, attempt)
        before = _database_snapshot(service)
        original_record = service._command_record

        def record_then_fail(*args, **kwargs):
            original_record(*args, **kwargs)
            raise RuntimeError("injected receipt recording failure")

        monkeypatch.setattr(service, "_command_record", record_then_fail)
        with pytest.raises(RuntimeError, match="injected receipt recording failure"):
            service.abandon_task(attempt["task_id"], body,
                                 idempotency_key="rollback-abandon", identity=OWNER)
        assert _database_snapshot(service) == before
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?",
                                          (attempt["attempt_id"],)).fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL",
                                          (attempt["task_id"],)).fetchone()[0] == 1
    finally:
        service.close()


def test_abandon_http_is_owner_only_and_requires_idempotency(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        service.register_capability({"capability_id": CAP, "definition_digest": CAP_DIGEST,
                                     "required_resource_keys": ["gpu-0"]})
        service.register_executor({"executor_id": "external-worker", "capabilities": [CAP],
                                   "max_concurrency": 4, "resource_keys": ["gpu-0"]},
                                  idempotency_key="http-external-register")
        admitted, attempt = _active(service, "http")
        (tmp_path / "support" / "credentials").mkdir(exist_ok=True)
        owner = Api(daemon.endpoint, daemon.token)
        worker = Api(daemon.endpoint, daemon.worker_token)
        browser_token, _ = daemon.credentials.provision("browser", ["admin"])
        operator_token, _ = daemon.credentials.provision("operator", ["admin"])
        browser = Api(daemon.endpoint, browser_token)
        operator = Api(daemon.endpoint, operator_token)
        path = f"/v1/control/tasks/{attempt['task_id']}/abandon"
        body = _body(service, admitted, attempt)
        for api in (Api(daemon.endpoint, None), worker, browser, operator):
            with pytest.raises(RuntimeError):
                api.request("POST", path, body, headers={"Idempotency-Key": "http-denied"})
        malformed = [
            (None, b"{"),
            (None, b"[]"),
            ({key: value for key, value in body.items() if key != "reason"}, None),
            ({**body, "reason": ""}, None),
            ({**body, "reason": 17}, None),
            ({**body, "unexpected": True}, None),
        ]
        for index, (value, raw) in enumerate(malformed):
            before = _database_snapshot(service)
            with pytest.raises(RuntimeError):
                owner.request("POST", path, value, raw=raw, headers={
                    "Content-Type": "application/json",
                    "Idempotency-Key": f"http-malformed-{index}",
                })
            assert _database_snapshot(service) == before
        with pytest.raises(RuntimeError):
            owner.request("POST", path, body)
        committed = owner.request("POST", path, body, headers={"Idempotency-Key": "http-abandon"})
        assert committed["data"]["disposition"] == "lost"
    finally:
        daemon.stop()


def test_old_attempt_reports_are_fenced_before_and_after_restart_and_retry(tmp_path):
    root = tmp_path / "realm"
    service = _service(root)
    admitted, attempt = _active(service, "late", cancel=False)
    prepared = service.prepare_reboot({
        "attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"],
        "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
    }, identity=WORKER_IDENTITY)
    checkpoint = service.checkpoint_attempt(attempt["attempt_id"], {
        "lease_id": attempt["lease_id"], "fence": attempt["fence"],
        "runtime_epoch": attempt["runtime_epoch"], "nonce": prepared["nonce"],
        "authorization": prepared["nonce"], "state": {"step": 4},
    }, identity=WORKER_IDENTITY)
    _cancel(service, admitted, "late")
    _abandon(service, admitted, attempt, key="late-abandon")
    old_lease = {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}
    operations = [
        ("heartbeat", lambda s: s.heartbeat_attempt(attempt["attempt_id"], old_lease, idempotency_key="late-heartbeat", identity=WORKER_IDENTITY)),
        ("settle", lambda s: s.settle_attempt(attempt["attempt_id"], {**old_lease, "outputs": []}, idempotency_key="late-settle", identity=WORKER_IDENTITY)),
        ("fail", lambda s: s.fail_attempt(attempt["attempt_id"], {**old_lease, "error": {"code": "late"}}, idempotency_key="late-fail", identity=WORKER_IDENTITY)),
        ("checkpoint", lambda s: s.checkpoint_attempt(attempt["attempt_id"], {**old_lease, "nonce": "old", "authorization": "old", "state": {}}, identity=WORKER_IDENTITY)),
        ("resume", lambda s: s.resume_attempt({
            "checkpoint_id": checkpoint["checkpoint_id"], "attempt_id": attempt["attempt_id"],
            "nonce": prepared["nonce"], "authorization": prepared["nonce"],
            "runtime_epoch": s.health()["runtime_epoch"],
        }, identity=WORKER_IDENTITY)),
        ("claim-replay", lambda s: s.claim_next({
            "executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": attempt["runtime_epoch"], "target": TARGET,
        }, idempotency_key="claim-late", identity=WORKER_IDENTITY)),
        ("output", lambda s: s.ingest_object(b"late", original_name="late.bin", idempotency_key="late-output",
                                  identity=WORKER_IDENTITY, upload_binding={
                                      "project_id": admitted["run"]["project_id"], "run_id": admitted["run"]["id"],
                                      "task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"],
                                      "executor_id": "external-worker", **old_lease, "output_key": "late",
                                      "output_port": "late", "filename": "late.bin",
                                      "digest": "sha256:" + hashlib.sha256(b"late").hexdigest(), "size": 4,
                                      "media_type": "application/octet-stream"})),
    ]
    def assert_fenced(name, operation):
        try:
            operation(service)
        except (ConflictError, AuthorizationError):
            return
        pytest.fail(f"late {name} unexpectedly succeeded")

    try:
        for name, operation in operations:
            assert_fenced(name, operation)
        assert service.managed_outputs(attempt["task_id"]) == []
        service.close()
        service = RuntimeService(root)
        for name, operation in operations:
            assert_fenced(name, operation)
        snapshot = service.task(attempt["task_id"])
        retry = service.retry_task(attempt["task_id"], {"expected_version": snapshot["task"]["attempt"] + 1}, idempotency_key="explicit-retry")
        assert retry["data"]["state"] == "queued"
        newer = service.claim_next({
            "executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET,
        }, idempotency_key="claim-new-generation", identity=WORKER_IDENTITY)
        assert newer["task_id"] == attempt["task_id"]
        assert newer["attempt_id"] != attempt["attempt_id"]
        assert newer["fence"] > attempt["fence"]
        newer_snapshot = service.store.get_task(attempt["task_id"])
        for name, operation in operations:
            assert_fenced(name, operation)
        assert service.store.get_task(attempt["task_id"]) == newer_snapshot
        latest = service.task(attempt["task_id"])
        assert latest["task"]["status"] == latest["run"]["status"] == "running"
        assert latest["task"]["attempt_id"] == newer["attempt_id"]
        assert service.managed_outputs(attempt["task_id"]) == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL", (attempt["task_id"],)).fetchone()[0] == 1
    finally:
        service.close()


def test_abandon_settlement_barrier_race_has_one_terminal_winner(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "race", cancel=False)
        barrier = threading.Barrier(2)

        def abandon():
            barrier.wait()
            try:
                _cancel(service, admitted, "race")
                return ("abandoned", service.abandon_task(attempt["task_id"], _body(service, admitted, attempt),
                          idempotency_key="race-abandon", identity=OWNER))
            except (ConflictError, AuthorizationError) as exc:
                return ("refused", exc)

        def settle():
            barrier.wait()
            try:
                return ("settled", service.settle_attempt(attempt["attempt_id"], {
                    "lease_id": attempt["lease_id"], "fence": attempt["fence"],
                    "runtime_epoch": attempt["runtime_epoch"], "outputs": [],
                }, idempotency_key="race-settle", identity=WORKER_IDENTITY))
            except (ConflictError, AuthorizationError) as exc:
                return ("refused", exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(abandon), pool.submit(settle)]
            outcomes = [future.result(timeout=10) for future in results]
        final = service.task(attempt["task_id"])
        assert final["task"]["status"] == final["run"]["status"]
        assert final["task"]["status"] in {"failed", "completed"}
        assert sum(kind == "abandoned" for kind, _ in outcomes) + sum(kind == "settled" for kind, _ in outcomes) == 1
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
        assert not any(row["task_id"] == attempt["task_id"] for row in _interruption_report(service.store.conn)["blockers"])
        terminal_events = service.store.conn.execute(
            "SELECT kind FROM events WHERE task_id=? AND kind IN ('task.completed','task.failed','task.abandoned','task.cancelled') ORDER BY id",
            (attempt["task_id"],),
        ).fetchall()
        assert [row["kind"] for row in terminal_events] == [
            "task.completed" if final["task"]["status"] == "completed" else "task.abandoned"
        ]
    finally:
        service.close()


@pytest.mark.parametrize("winner", ["settlement", "abandon"])
def test_abandon_settlement_barrier_forces_each_valid_winner(tmp_path, winner):
    service = _service(tmp_path / "realm")
    try:
        admitted, attempt = _active(service, "forced-" + winner, cancel=False)
        barrier = threading.Barrier(2)
        winner_finished = threading.Event()

        def settle():
            barrier.wait()
            if winner == "abandon":
                winner_finished.wait(timeout=5)
            try:
                return service.settle_attempt(attempt["attempt_id"], {
                    "lease_id": attempt["lease_id"], "fence": attempt["fence"],
                    "runtime_epoch": attempt["runtime_epoch"], "outputs": [],
                }, idempotency_key="forced-settle-" + winner, identity=WORKER_IDENTITY)
            finally:
                if winner == "settlement":
                    winner_finished.set()

        def abandon():
            barrier.wait()
            if winner == "settlement":
                winner_finished.wait(timeout=5)
            try:
                _cancel(service, admitted, "forced-" + winner)
                return service.abandon_task(attempt["task_id"], _body(service, admitted, attempt),
                    idempotency_key="forced-abandon-" + winner, identity=OWNER)
            finally:
                if winner == "abandon":
                    winner_finished.set()

        with ThreadPoolExecutor(max_workers=2) as pool:
            settle_future = pool.submit(settle)
            abandon_future = pool.submit(abandon)
            if winner == "settlement":
                settle_future.result(timeout=10)
                with pytest.raises((ConflictError, AuthorizationError)):
                    abandon_future.result(timeout=10)
            else:
                abandon_future.result(timeout=10)
                with pytest.raises((ConflictError, AuthorizationError)):
                    settle_future.result(timeout=10)

        final = service.task(attempt["task_id"])
        assert final["task"]["status"] == ("completed" if winner == "settlement" else "failed")
        assert final["run"]["status"] == final["task"]["status"]
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
        assert not any(row["task_id"] == attempt["task_id"] for row in _interruption_report(service.store.conn)["blockers"])
        terminal_events = service.store.conn.execute(
            "SELECT kind FROM events WHERE task_id=? AND kind IN ('task.completed','task.failed','task.abandoned','task.cancelled') ORDER BY id",
            (attempt["task_id"],),
        ).fetchall()
        assert [row["kind"] for row in terminal_events] == [
            "task.completed" if winner == "settlement" else "task.abandoned"
        ]
    finally:
        service.close()


def test_active_delegated_child_ids_refuse_parent_abandon_atomically(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        # Child capability and delegation policy use the same verified target.
        child_cap = "test.abandon.child"
        child_digest = "sha256:" + hashlib.sha256(child_cap.encode()).hexdigest()
        service.register_capability({"capability_id": child_cap, "definition_digest": child_digest})
        service.register_executor({"executor_id": "child-worker", "capabilities": [child_cap],
                                   "max_concurrency": 2, "resource_keys": ["gpu-0"]},
                                  idempotency_key="child-worker-register")
        child_identity = {
            "actor": "child-worker", "scopes": ["worker:execute"],
            "execution_binding": {
                "actual": TARGET, "executor_incarnation": "child-worker/inc-1",
                "verification": {"method": "credential_claim", "verified": True,
                                  "evidence_digest": "sha256:" + "b" * 64},
            },
        }
        parent = service.create_task({
            "capability_id": CAP, "capability_digest": CAP_DIGEST, "input_object_ids": [],
            "spec": {}, "idempotency_key": "delegated-parent",
            "execution_request": {"schema_version": 1, "target": TARGET, "inputs": []},
            "child_delegation": {"capabilities": [{"capability_id": child_cap, "capability_digest": child_digest}], "targets": [TARGET], "input_object_ids": []},
        }, enforce_readiness=True)
        attempt = service.claim_next({"executor_id": "external-worker", "capability_ids": [CAP],
            "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET},
            idempotency_key="delegated-claim", identity=WORKER_IDENTITY)
        authority = service.issue_child_authority(attempt["attempt_id"], {
            "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
        }, identity=WORKER_IDENTITY)
        child = service.admit_delegated_child({"authority": authority["authority"], "task": {
            "capability_id": child_cap, "capability_digest": child_digest, "input_object_ids": [], "spec": {},
            "execution_request": {"schema_version": 1, "target": TARGET, "inputs": []},
        }}, idempotency_key="delegated-child", identity=WORKER_IDENTITY)
        child_attempt = service.claim_next({"executor_id": "child-worker", "capability_ids": [child_cap],
            "runtime_epoch": service.health()["runtime_epoch"], "target": TARGET},
            idempotency_key="claim-delegated-child", identity=child_identity)
        assert child_attempt["task_id"] == child["task"]["id"]
        current_parent = service.task(parent["task"]["id"])["task"]
        service.cancel_task_canonical(parent["task"]["id"], {"expected_version": int(current_parent.get("attempt", 0)) + 1}, idempotency_key="delegated-cancel")
        assert service.task(child["task"]["id"])["task"]["waiting_reason"] == "provider_state_unknown"
        before = service.task(parent["task"]["id"])
        with pytest.raises(ConflictError) as refused:
            service.abandon_task(parent["task"]["id"], _body(service, parent, attempt),
                                 idempotency_key="parent-abandon", identity=OWNER)
        assert child["task"]["id"] in str(refused.value.details)
        assert service.task(parent["task"]["id"]) == before
        assert service.task(child["task"]["id"])["task"]["status"] == "cancel_requested"
        blockers_before_resolution = _interruption_report(service.store.conn)["blockers"]
        assert any(row["task_id"] == child["task"]["id"] for row in blockers_before_resolution)
        service.abandon_task(child["task"]["id"], _body(service, child, child_attempt),
                             idempotency_key="abandon-delegated-child", identity=OWNER)
        service.abandon_task(parent["task"]["id"], _body(service, parent, attempt),
                             idempotency_key="abandon-parent-after-child", identity=OWNER)
        with pytest.raises((AuthorizationError, ConflictError)):
            service.admit_delegated_child({"authority": authority["authority"], "task": {
                "capability_id": child_cap, "capability_digest": child_digest,
                "input_object_ids": [], "spec": {},
                "execution_request": {"schema_version": 1, "target": TARGET, "inputs": []},
            }}, idempotency_key="delegated-child-after-abandon", identity=WORKER_IDENTITY)
        assert not _interruption_report(service.store.conn)["blockers"]
        assert service.store.integrity_report()["checks"]["event_chain"]["ok"] is True
    finally:
        service.close()
