"""G28: existing attempt settlement and reaper enforce hard terminal bounds."""
from __future__ import annotations

import hashlib
import base64
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.server import RuntimeHTTPServer, RuntimeHandler
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import MAX_TASK_ATTEMPTS, TASK_DEADLINE_SECONDS, RealmStore

pytestmark = pytest.mark.timeout(9)
CAP = "test.g28"
DIGEST = "sha256:" + hashlib.sha256(CAP.encode()).hexdigest()


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    value.register_capability({"capability_id": CAP, "definition_digest": DIGEST, "required_resource_keys": ["gpu"]})
    value.register_executor({"executor_id": "worker", "capabilities": [CAP], "resource_keys": ["gpu"]}, idempotency_key="register")
    try:
        yield value
    finally:
        value.close()


def _admit(service):
    return service.create_task({"capability_id": CAP, "capability_digest": DIGEST, "idempotency_key": "task"})["task"]["id"]


def _claim(service, key="claim"):
    return service.claim_next({"executor_id": "worker", "capability_ids": [CAP], "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key=key)


def _binding(attempt):
    return {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}


def _expire_lease(service, task_id, attempt):
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, task_id))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (past, attempt["attempt_id"]))


def _deadline(service, task_id, *, remaining=-1):
    admitted = datetime.now(timezone.utc) - timedelta(seconds=TASK_DEADLINE_SECONDS - remaining)
    service.store.conn.execute("UPDATE runs SET created_at=? WHERE id=(SELECT run_id FROM tasks WHERE id=?)", (admitted.isoformat(), task_id))
    return admitted + timedelta(seconds=TASK_DEADLINE_SECONDS)


def _assert_failed(service, task_id, code, *, attempt=None):
    value = service.store.get_task(task_id)
    assert value["task"]["status"] == value["run"]["status"] == "failed"
    assert value["task"]["result"]["error"]["code"] == code
    assert value["task"]["lease_expires_at"] is None
    assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()[0] == 0
    if attempt is not None:
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
    return value


@pytest.mark.parametrize("error,code", [
    ({"message": "failure handler broke"}, "executor_failed"),
    ({"code": "executor_exception", "message": "boom"}, "executor_exception"),
    ("executor exited", "executor_failed"),
])
def test_failure_is_coded_terminal_replayable_and_releases_resources(service, error, code):
    task_id = _admit(service)
    attempt = _claim(service)
    body = {**_binding(attempt), "error": error}
    failed = service.fail_attempt(attempt["attempt_id"], body, idempotency_key="fail")
    assert failed["data"]["state"] == "failed"
    _assert_failed(service, task_id, code, attempt=attempt)
    assert service.fail_attempt(attempt["attempt_id"], body, idempotency_key="fail") == failed
    with pytest.raises(LeaseError):
        service.heartbeat_attempt(attempt["attempt_id"], _binding(attempt), idempotency_key="late-heartbeat")


def test_lease_lost_owner_can_cede_only_its_exact_retained_attempt(service):
    task_id = _admit(service)
    attempt = _claim(service)
    _expire_lease(service, task_id, attempt)
    service.fail_attempt(attempt["attempt_id"], {**_binding(attempt), "error": {"code": "lease_lost"}}, idempotency_key="lease-lost")
    _assert_failed(service, task_id, "lease_lost", attempt=attempt)


def test_expired_owner_failure_cannot_mutate_successor(service):
    task_id = _admit(service)
    old = _claim(service)
    _expire_lease(service, task_id, old)
    assert _claim(service, "before-cession") is None
    service.fail_attempt(old["attempt_id"], {**_binding(old), "error": {"code": "lease_lost"}}, idempotency_key="cede-old")
    _assert_failed(service, task_id, "lease_lost", attempt=old)
    service.retry_task(task_id, {}, idempotency_key="retry-after-cession")
    successor = _claim(service, "successor")
    with pytest.raises(LeaseError):
        service.fail_attempt(old["attempt_id"], {**_binding(old), "error": {"code": "lease_lost"}}, idempotency_key="old-fail")
    assert service.task(task_id)["task"]["status"] == "running"
    assert service.task(task_id)["task"]["attempt_id"] == successor["attempt_id"]


@pytest.mark.parametrize("action", ["read", "heartbeat", "settle", "claim"])
def test_absolute_deadline_terminalizes_live_attempt_without_renew_or_publish(service, action):
    task_id = _admit(service)
    attempt = _claim(service)
    _deadline(service, task_id)
    if action == "read":
        service.task(task_id)
    elif action == "claim":
        assert _claim(service, "after-deadline") is None
    else:
        method = service.heartbeat_attempt if action == "heartbeat" else service.settle_attempt
        with pytest.raises(LeaseError):
            method(attempt["attempt_id"], _binding(attempt), idempotency_key="after-deadline")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)
    assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0


def test_absolute_deadline_applies_to_unclaimed_task(service):
    task_id = _admit(service)
    _deadline(service, task_id)
    assert _claim(service) is None
    _assert_failed(service, task_id, "task_deadline_exceeded")
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_claim_and_renewal_are_clamped_to_absolute_deadline(service):
    task_id = _admit(service)
    deadline = _deadline(service, task_id, remaining=5)
    attempt = _claim(service)
    assert datetime.fromisoformat(attempt["lease_expires_at"]) <= deadline
    renewed = service.heartbeat_attempt(attempt["attempt_id"], {**_binding(attempt), "lease_seconds": 3600, "progress": {"phase": "working"}}, idempotency_key="progress")
    expires = renewed["data"]["lease_expires_at"]
    assert datetime.fromisoformat(expires) <= deadline
    assert service.store.conn.execute("SELECT lease_expires_at FROM reservations WHERE task_id=?", (task_id,)).fetchone()[0] == expires
    _deadline(service, task_id)
    with pytest.raises(LeaseError):
        service.heartbeat_attempt(attempt["attempt_id"], {**_binding(attempt), "progress": {"phase": "late"}}, idempotency_key="late")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)


def test_attempt_cap_terminalizes_expiry_and_prevents_fourth_claim(service):
    task_id = _admit(service)
    for number in range(MAX_TASK_ATTEMPTS):
        attempt = _claim(service, f"claim-{number}")
        assert attempt["task_id"] == task_id
        _expire_lease(service, task_id, attempt)
        service.task(task_id)
        if number < MAX_TASK_ATTEMPTS - 1:
            # Below the hard cap, expiry retains custody. Only an explicit
            # owner cession and retry can make the next attempt claimable.
            assert service.store.get_task(task_id)["task"]["status"] == "running"
            assert _claim(service, f"before-cession-{number}") is None
            service.fail_attempt(attempt["attempt_id"], {**_binding(attempt), "error": {"code": "lease_lost"}}, idempotency_key=f"cede-{number}")
            _assert_failed(service, task_id, "lease_lost", attempt=attempt)
            service.retry_task(task_id, {}, idempotency_key=f"retry-{number}")
    _assert_failed(service, task_id, "attempt_limit_exceeded", attempt=attempt)
    assert _claim(service, "beyond-cap") is None
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)).fetchone()[0] == MAX_TASK_ATTEMPTS


def test_explicit_retries_preserve_absolute_deadline_and_attempt_cap(service):
    task_id = _admit(service)
    admission = service.task(task_id)["run"]["created_at"]
    for number in range(MAX_TASK_ATTEMPTS):
        attempt = _claim(service, f"claim-{number}")
        service.fail_attempt(attempt["attempt_id"], {**_binding(attempt), "error": {"code": "executor_failed"}}, idempotency_key=f"fail-{number}")
        service.retry_task(task_id, {}, idempotency_key=f"retry-{number}")
        assert service.store.get_task(task_id)["run"]["created_at"] == admission
    assert _claim(service, "beyond-cap") is None
    _assert_failed(service, task_id, "attempt_limit_exceeded")


def test_deadline_crossed_during_output_staging_is_failed_after_rollback(service, monkeypatch):
    task_id = _admit(service)
    attempt = _claim(service)
    original = service._stage_outputs

    def stage(*args, **kwargs):
        result = original(*args, **kwargs)
        # Model time passing after the pre-settlement deadline check without
        # sleeping or mutating admission inside the rolled-back transaction.
        monkeypatch.setattr("runtime_protocol.store.TASK_DEADLINE_SECONDS", 0)
        return result

    monkeypatch.setattr(service, "_stage_outputs", stage)
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], _binding(attempt), idempotency_key="late-stage")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)


def test_success_replay_remains_idempotent_after_deadline(service):
    task_id = _admit(service)
    attempt = _claim(service)
    body = _binding(attempt)
    settled = service.settle_attempt(attempt["attempt_id"], body, idempotency_key="settle")
    _deadline(service, task_id)
    assert service.settle_attempt(attempt["attempt_id"], body, idempotency_key="settle") == settled
    assert service.store.get_task(task_id)["task"]["status"] == "completed"


def test_deadline_crossed_during_publication_rolls_back_success_and_objects(service, monkeypatch):
    task_id = _admit(service)
    attempt = _claim(service)
    payload = b"g28 late publication"
    digest = hashlib.sha256(payload).hexdigest()
    output = {"name": "late.bin", "digest": "sha256:" + digest, "media_type": "application/octet-stream",
              "size": len(payload), "data_base64": base64.b64encode(payload).decode()}
    original = service.store._associate_managed_outputs

    def associate(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr("runtime_protocol.store.TASK_DEADLINE_SECONDS", 0)
        return result

    monkeypatch.setattr(service.store, "_associate_managed_outputs", associate)
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {**_binding(attempt), "outputs": [output]}, idempotency_key="late-publish")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)
    assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    assert service.managed_outputs(task_id) == []
    assert not service.cas.path_for(digest).exists()


@pytest.mark.parametrize("admitted", ["garbage", "2020-01-01T00:00:00", "2999-01-01T00:00:00+00:00"])
def test_invalid_or_future_admission_time_fails_closed(service, admitted):
    task_id = _admit(service)
    service.store.conn.execute("UPDATE runs SET created_at=? WHERE id=(SELECT run_id FROM tasks WHERE id=?)", (admitted, task_id))
    service.task(task_id)
    _assert_failed(service, task_id, "invalid_task_deadline")


@pytest.mark.parametrize("bound", ["deadline", "attempt_cap"])
def test_verified_external_provider_uncertainty_cannot_bypass_hard_bounds(tmp_path, bound):
    from test_execution_binding_contract import _admit, _claim, _service
    service = _service(tmp_path / "targeted", resource_keys=["gpu"])
    target = {"kind": "runpod", "pod_id": "pod-g28", "provider_account_ref": "account-g28"}
    try:
        task_id = _admit(service, "external", target)["task"]["id"]
        attempt = _claim(service, "external-claim", target)
        if bound == "deadline":
            _deadline(service, task_id)
            code = "task_deadline_exceeded"
        else:
            service.store.conn.execute("UPDATE tasks SET attempt=? WHERE id=?", (MAX_TASK_ATTEMPTS, task_id))
            _expire_lease(service, task_id, attempt)
            code = "attempt_limit_exceeded"
        service.task(task_id)
        value = _assert_failed(service, task_id, code, attempt=attempt)
        assert value["task"]["result"]["error"]["remote_stop_confirmed"] is False
        assert value["execution_binding"]["status"] == "released"
    finally:
        service.close()


@pytest.mark.parametrize("bound", ["deadline", "attempt_cap"])
def test_restart_preserves_original_task_bounds(service, bound):
    task_id = _admit(service)
    attempt = _claim(service)
    if bound == "deadline":
        _deadline(service, task_id)
        code = "task_deadline_exceeded"
    else:
        service.store.conn.execute("UPDATE tasks SET attempt=? WHERE id=?", (MAX_TASK_ATTEMPTS, task_id))
        code = "attempt_limit_exceeded"
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.task(task_id)
        _assert_failed(restarted, task_id, code, attempt=attempt)
    finally:
        restarted.close()


def test_existing_server_poll_terminalizes_without_client_reads(service):
    task_id = _admit(service)
    _deadline(service, task_id, remaining=0.1)
    server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = service
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        limit = time.monotonic() + 2
        # Raw observation cannot trigger the read reaper.
        while service.store.get_task(task_id)["task"]["status"] != "failed" and time.monotonic() < limit:
            time.sleep(0.01)
        _assert_failed(service, task_id, "task_deadline_exceeded")
    finally:
        server.shutdown()
        thread.join(1)
        server.server_close()
    assert not thread.is_alive()


def _admit_bounded(service):
    target = {"kind": "machine", "id": "g28-machine"}
    task_id = service.create_task({"capability_id": CAP, "capability_digest": DIGEST,
        "idempotency_key": "bounded-task", "execution_request": {"schema_version": 1,
        "target": target, "inputs": [], "limits": {"max_runtime_seconds": 1}}})["task"]["id"]
    return task_id, target


def _claim_bounded(service, target, key="bounded-claim"):
    from test_execution_binding_contract import _identity
    identity = _identity(target)
    identity["actor"] = "worker"
    return service.claim_next({"executor_id": "worker", "capability_ids": [CAP],
        "runtime_epoch": service.health()["runtime_epoch"], "target": target},
        idempotency_key=key, identity=identity)


def test_admitted_runtime_deadline_crossed_during_staging_rejects_late_settlement(service, monkeypatch):
    task_id, target = _admit_bounded(service)
    attempt = _claim_bounded(service, target)
    original_stage = service._stage_outputs
    clock = datetime.now(timezone.utc)

    class AdvancedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            advanced = clock + timedelta(seconds=2)
            return advanced.astimezone(tz) if tz else advanced.replace(tzinfo=None)

    def stage(*args, **kwargs):
        value = original_stage(*args, **kwargs)
        # Runtime holds its real mutex and settlement transaction here. The
        # host's competing fail RPC cannot win this race; Runtime must enforce
        # the carried attempt limit itself before making output reachable.
        assert service.store._mutex._is_owned()
        monkeypatch.setattr("runtime_protocol.store.datetime", AdvancedClock)
        return value

    monkeypatch.setattr(service, "_stage_outputs", stage)
    payload = b"attempt deadline output"
    digest = hashlib.sha256(payload).hexdigest()
    output = {"name": "late.bin", "digest": "sha256:" + digest, "media_type": "application/octet-stream",
              "size": len(payload), "data_base64": base64.b64encode(payload).decode()}
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {**_binding(attempt), "outputs": [output]}, idempotency_key="bounded-settle")
    _assert_failed(service, task_id, "timeout", attempt=attempt)
    assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    assert service.managed_outputs(task_id) == []
    assert not service.cas.path_for(digest).exists()


@pytest.mark.parametrize("origin", [None, "garbage", "2999-01-01T00:00:00+00:00"])
def test_current_attempt_runtime_origin_fails_closed(service, origin):
    task_id, target = _admit_bounded(service)
    attempt = _claim_bounded(service, target)
    if origin is None:
        service.store.conn.execute("DELETE FROM events WHERE task_id=? AND kind='task.claimed'", (task_id,))
    else:
        service.store.conn.execute("UPDATE events SET created_at=? WHERE task_id=? AND kind='task.claimed'", (origin, task_id))
    service.task(task_id)
    _assert_failed(service, task_id, "invalid_task_deadline", attempt=attempt)


def test_attempt_runtime_clamps_lease_and_old_claim_does_not_poison_retry(service):
    task_id, target = _admit_bounded(service)
    old = _claim_bounded(service, target)
    started = service.store.conn.execute("SELECT created_at FROM events WHERE task_id=? AND kind='task.claimed'", (task_id,)).fetchone()[0]
    deadline = datetime.fromisoformat(started) + timedelta(seconds=1)
    assert datetime.fromisoformat(old["lease_expires_at"]) <= deadline
    renewed = service.heartbeat_attempt(old["attempt_id"], {**_binding(old), "lease_seconds": 3600,
        "progress": {"phase": "working"}}, idempotency_key="bounded-heartbeat")
    assert datetime.fromisoformat(renewed["data"]["lease_expires_at"]) <= deadline
    service.fail_attempt(old["attempt_id"], {**_binding(old), "error": {"code": "executor_failed"}}, idempotency_key="bounded-fail")
    service.retry_task(task_id, {}, idempotency_key="bounded-retry")
    past = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    service.store.conn.execute("UPDATE events SET created_at=? WHERE task_id=? AND kind='task.claimed'", (past, task_id))
    successor = _claim_bounded(service, target, "bounded-successor")
    assert successor["fence"] > old["fence"]
    assert service.task(task_id)["task"]["status"] == "running"


@pytest.mark.parametrize("action", ["claim", "heartbeat", "settle"])
def test_absolute_deadline_boundary_is_exclusive(service, monkeypatch, action):
    task_id = _admit(service)
    attempt = _claim(service) if action != "claim" else None
    boundary = _deadline(service, task_id, remaining=0)

    class BoundaryClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return boundary.astimezone(tz) if tz else boundary.replace(tzinfo=None)

    monkeypatch.setattr("runtime_protocol.store.datetime", BoundaryClock)
    if action == "claim":
        assert _claim(service) is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    else:
        method = service.heartbeat_attempt if action == "heartbeat" else service.settle_attempt
        with pytest.raises(LeaseError):
            method(attempt["attempt_id"], _binding(attempt), idempotency_key="at-boundary")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)


@pytest.mark.parametrize("preflight_ending", ["ready", "unavailable", "error"])
def test_deadline_crossed_during_claim_preflight_is_durable_without_attempt(service, monkeypatch, preflight_ending):
    task_id = _admit(service)
    boundary = _deadline(service, task_id, remaining=5)
    original = service.store.storage_preflight

    class LateClock(datetime):
        @classmethod
        def now(cls, tz=None):
            late = boundary + timedelta(seconds=1)
            return late.astimezone(tz) if tz else late.replace(tzinfo=None)

    def preflight(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr("runtime_protocol.store.datetime", LateClock)
        if preflight_ending == "error":
            raise OSError("preflight failed after deadline")
        return {**result, "ok": preflight_ending == "ready"}

    monkeypatch.setattr(service.store, "storage_preflight", preflight)
    if preflight_ending == "error":
        with pytest.raises(OSError, match="preflight failed after deadline"):
            _claim(service)
    else:
        assert _claim(service) is None
    _assert_failed(service, task_id, "task_deadline_exceeded")
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    assert service.store.get_task(task_id)["task"]["attempt"] == 0


def test_claim_deadline_is_original_admission_bound_and_client_compatible(service):
    import json
    from pathlib import Path

    from astrid_runtime_client import AttemptFence
    from jsonschema import Draft202012Validator, FormatChecker

    task_id = _admit(service)
    expected = datetime.fromisoformat(service.task(task_id)["run"]["created_at"]) + timedelta(seconds=TASK_DEADLINE_SECONDS)
    old = _claim(service)
    assert datetime.fromisoformat(old["deadline_at"]) == expected
    assert AttemptFence.from_json(old).deadline_at == old["deadline_at"]
    # Existing retained claim receipts remain valid for older Runtime servers.
    legacy = {key: value for key, value in old.items() if key != "deadline_at"}
    assert AttemptFence.from_json(legacy).deadline_at is None
    schema = json.loads((Path(__file__).parents[1] / "contract/schemas/worker.json").read_text())
    validator = Draft202012Validator(schema["definitions"]["AttemptFence"], format_checker=FormatChecker())
    validator.validate(old)
    validator.validate(legacy)
    service.fail_attempt(old["attempt_id"], {**_binding(old), "error": {"code": "executor_failed"}}, idempotency_key="deadline-fail")
    service.retry_task(task_id, {}, idempotency_key="deadline-retry")
    successor = _claim(service, "deadline-successor")
    assert successor["deadline_at"] == old["deadline_at"]
