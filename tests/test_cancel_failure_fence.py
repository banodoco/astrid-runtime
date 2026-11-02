"""Cancellation must compare the real stored state at its write boundary."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from test_fail_closed_g28 import (
    _admit, _assert_failed, _binding, _claim, _deadline, service,
)
from runtime_protocol.store import TASK_DEADLINE_SECONDS


ERROR = {"code": "provider_failed", "message": "producer failed before cancellation",
         "fix": "inspect the producer failure"}


def _fail(service, attempt, key="failure"):
    return service.fail_attempt(attempt["attempt_id"],
        {**_binding(attempt), "error": ERROR}, idempotency_key=key)


def _cancel_body(attempt, *, stop_observed):
    return {**_binding(attempt), "attempt_id": attempt["attempt_id"],
            "stop_observed": stop_observed}


def _cancel_events(service, task_id):
    return service.store.conn.execute(
        "SELECT kind FROM events WHERE task_id=? AND kind IN ('task.cancelled', 'task.cancel_requested')",
        (task_id,),
    ).fetchall()


def _before_cancel_transaction(monkeypatch, service, task_id, transition):
    """Schedule a real committed transition after the store's initial read."""
    original = service.store._transaction
    called = []

    @contextmanager
    def interposed():
        # Restore before invoking real service operations and their transactions.
        monkeypatch.setattr(service.store, "_transaction", original)
        assert not service.store.conn.in_transaction
        transition()
        assert not service.store.conn.in_transaction
        with service.store._read_snapshot() as reader:
            row = reader.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            called.append(dict(row))
        with original():
            yield

    monkeypatch.setattr(service.store, "_transaction", interposed)
    return called


def test_failure_before_cancel_preserves_error_version_and_replay(service):
    task_id = _admit(service)
    attempt = _claim(service)
    version = service.store.get_task(task_id)["task"]["attempt"] + 1
    failed = _fail(service, attempt)
    body = {"expected_version": version}
    cancelled = service.cancel_task_canonical(task_id, body, idempotency_key="cancel-failed")
    assert cancelled["data"] == failed["data"]
    assert cancelled["data"]["version"] == version
    assert service.cancel_task_canonical(task_id, body, idempotency_key="cancel-failed") == cancelled
    assert _assert_failed(service, task_id, ERROR["code"], attempt=attempt)["task"]["result"]["error"] == ERROR
    assert not _cancel_events(service, task_id)


@pytest.mark.parametrize("failure,caller", [
    ("executor", "owner"), ("executor", "worker_observed"),
    ("executor", "worker_unobserved"), ("deadline", "owner"),
])
def test_failure_committed_after_cancel_read_cannot_be_overwritten(service, monkeypatch, failure, caller):
    task_id = _admit(service)
    attempt = _claim(service)
    code = ERROR["code"] if failure == "executor" else "task_deadline_exceeded"

    def fail():
        if failure == "executor":
            _fail(service, attempt)
        else:
            _deadline(service, task_id)
            service.reap_task_lifetimes()
        _assert_failed(service, task_id, code, attempt=attempt)

    committed = _before_cancel_transaction(monkeypatch, service, task_id, fail)
    outcome = None
    try:
        if caller == "owner":
            outcome = service.cancel(task_id)
        else:
            outcome = service.store.cancel_task(task_id,
                **_cancel_body(attempt, stop_observed=caller == "worker_observed"))
    except ConflictError as exc:
        outcome = exc
    assert len(committed) == 1 and committed[0]["status"] == "failed"
    value = _assert_failed(service, task_id, code, attempt=attempt)
    if failure == "executor":
        assert value["task"]["result"]["error"] == ERROR
        assert _fail(service, attempt)["data"]["state"] == "failed"
    assert not _cancel_events(service, task_id)
    assert isinstance(outcome, ConflictError)
    assert outcome.details["actual"]["status"] == "failed"
    assert outcome.details["expected_attempt_id"] == attempt["attempt_id"]


@pytest.mark.parametrize("stop_observed", [False, True])
def test_stale_cancel_snapshot_cannot_mutate_successor_attempt(service, monkeypatch, stop_observed):
    task_id = _admit(service)
    old = _claim(service)
    successor = []

    def replace_attempt():
        _fail(service, old)
        service.retry_task(task_id, {}, idempotency_key="retry")
        successor.append(_claim(service, "successor"))

    committed = _before_cancel_transaction(monkeypatch, service, task_id, replace_attempt)
    outcome = None
    try:
        outcome = service.store.cancel_task(task_id, **_cancel_body(old, stop_observed=stop_observed))
    except ConflictError as exc:
        outcome = exc
    current = service.store.get_task(task_id)["task"]
    assert committed[0]["status"] == current["status"] == "running"
    assert current["attempt_id"] == successor[0]["attempt_id"] != old["attempt_id"]
    assert current["lease_token"] == successor[0]["lease_id"]
    assert current["lease_fence"] == successor[0]["fence"] > old["fence"]
    assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (successor[0]["attempt_id"],)).fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()[0] == 1
    assert not _cancel_events(service, task_id)
    assert isinstance(outcome, ConflictError)


def test_stale_owner_cancel_cannot_mark_successor_binding_stop_pending(tmp_path, monkeypatch):
    from test_execution_binding_contract import (
        _admit as admit_targeted, _claim as claim_targeted, _service as targeted_service,
    )

    service = targeted_service(tmp_path / "targeted", resource_keys=["gpu"])
    target = {"kind": "machine", "id": "cancel-fence-machine"}
    try:
        task_id = admit_targeted(service, "targeted-task", target)["task"]["id"]
        old = claim_targeted(service, "first-claim", target)
        successor = []

        def replace_attempt():
            _fail(service, old)
            service.retry_task(task_id, {}, idempotency_key="retry")
            successor.append(claim_targeted(service, "successor", target))
            assert service.store.execution_binding(task_id)["status"] == "claimed"

        committed = _before_cancel_transaction(monkeypatch, service, task_id, replace_attempt)
        outcome = None
        try:
            outcome = service.cancel(task_id)
        except ConflictError as exc:
            outcome = exc
        current = service.store.get_task(task_id)["task"]
        assert committed[0]["status"] == current["status"] == "running"
        assert current["attempt_id"] == successor[0]["attempt_id"]
        assert service.store.execution_binding(task_id)["status"] == "claimed"
        assert not _cancel_events(service, task_id)
        assert isinstance(outcome, ConflictError)
    finally:
        service.close()


@pytest.mark.parametrize("claimed", [False, True])
def test_current_version_owner_cancellation_remains_replayable(service, claimed):
    task_id = _admit(service)
    attempt = _claim(service) if claimed else None
    body = {"expected_version": 2 if claimed else 1}
    result = service.cancel_task_canonical(task_id, body, idempotency_key="owner-cancel")
    assert result["data"]["state"] == "cancelled"
    assert service.cancel_task_canonical(task_id, body, idempotency_key="owner-cancel") == result
    value = service.store.get_task(task_id)
    assert value["task"]["status"] == value["run"]["status"] == "cancelled"
    assert value["task"]["attempt_id"] is None
    if attempt is not None:
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1


@pytest.mark.parametrize("stale", ["version", "fence"])
def test_stale_canonical_cancel_cannot_mutate_successor(service, stale):
    task_id = _admit(service)
    old = _claim(service)
    _fail(service, old)
    service.retry_task(task_id, {}, idempotency_key="retry")
    current = _claim(service, "successor")
    body = {"expected_version": 2} if stale == "version" else _cancel_body(old, stop_observed=True)
    with pytest.raises(ConflictError):
        service.cancel_task_canonical(task_id, body, idempotency_key="stale-cancel")
    stored = service.store.get_task(task_id)["task"]
    assert stored["status"] == "running" and stored["attempt_id"] == current["attempt_id"]
    assert not _cancel_events(service, task_id)


def test_deadline_after_cancel_request_remains_failed_after_late_cancel(service):
    task_id = _admit(service)
    attempt = _claim(service)
    request = service.cancel_task_canonical(task_id,
        _cancel_body(attempt, stop_observed=False), idempotency_key="request-stop")
    assert request["data"]["state"] == "cancel_requested"
    assert service.store.get_task(task_id)["task"]["attempt_id"] == attempt["attempt_id"]
    _deadline(service, task_id)
    late = service.cancel_task_canonical(task_id, {"expected_version": request["data"]["version"]},
        idempotency_key="late-owner-cancel")
    failed = _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)
    assert late["data"]["state"] == "failed"
    assert late["data"]["result"] == failed["task"]["result"]
    with pytest.raises(LeaseError):
        service.cancel_task_canonical(task_id, _cancel_body(attempt, stop_observed=True),
            idempotency_key="late-worker-cancel")
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)
    assert [row[0] for row in _cancel_events(service, task_id)] == ["task.cancel_requested"]


def test_deadline_crossed_after_cancel_request_is_checked_at_final_write(service, monkeypatch):
    task_id = _admit(service)
    attempt = _claim(service)
    service.cancel_task_canonical(task_id, _cancel_body(attempt, stop_observed=False),
        idempotency_key="request-stop")
    assert service.store.get_task(task_id)["task"]["status"] == "cancel_requested"
    original = service.store.contain_delegated_children
    future = datetime.now(timezone.utc) + timedelta(seconds=TASK_DEADLINE_SECONDS + 1)
    crossed = []

    class LateClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future.astimezone(tz) if tz else future.replace(tzinfo=None)

    def contain(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr("runtime_protocol.store.datetime", LateClock)
        crossed.append(True)
        return result

    monkeypatch.setattr(service.store, "contain_delegated_children", contain)
    outcome = None
    try:
        outcome = service.cancel_task_canonical(task_id, _cancel_body(attempt, stop_observed=True),
            idempotency_key="late-observed-stop")
    except LeaseError as exc:
        outcome = exc
    assert crossed
    _assert_failed(service, task_id, "task_deadline_exceeded", attempt=attempt)
    assert isinstance(outcome, LeaseError)
    assert [row[0] for row in _cancel_events(service, task_id)] == ["task.cancel_requested"]
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM command_idempotency WHERE command_kind='task.cancel' AND idempotency_key='late-observed-stop'",
    ).fetchone()[0] == 0
