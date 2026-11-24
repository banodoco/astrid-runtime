"""RN-8: claims and ordinary renewals share Runtime's lease policy."""
from __future__ import annotations

import multiprocessing
import time
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol import store as runtime_store
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import LeaseError
from astrid_runtime_client import WorkspaceClient
from tests.runtime_credentials import provision_executor_token
from tests.test_runtime_lease_expiry_reads import _claimed_task, _custody, service


def _binding(attempt):
    return {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}


def _assert_expiry_window(expires, before, after, seconds):
    actual = datetime.fromisoformat(expires)
    # Runtime persists milliseconds, so allow only that rounding at the lower bound.
    assert before + timedelta(seconds=seconds, milliseconds=-1) <= actual
    assert actual <= after + timedelta(seconds=seconds)


@pytest.mark.parametrize("seconds", [30, 2])
def test_claim_and_default_renewal_share_runtime_lease_policy(service, monkeypatch, seconds):
    monkeypatch.setattr(runtime_store, "LEASE_SECONDS", seconds)
    before_claim = datetime.now(timezone.utc)
    task_id, attempt = _claimed_task(service)
    after_claim = datetime.now(timezone.utc)
    _assert_expiry_window(attempt["lease_expires_at"], before_claim, after_claim, seconds)

    before_renew = datetime.now(timezone.utc)
    renewed = service.heartbeat_attempt(attempt["attempt_id"], _binding(attempt),
                                        idempotency_key="rn8-renew")["data"]
    after_renew = datetime.now(timezone.utc)

    _assert_expiry_window(renewed["lease_expires_at"], before_renew, after_renew, seconds)
    assert renewed["attempt_id"] == attempt["attempt_id"]
    assert renewed["fence"] == attempt["fence"]
    custody = _custody(service, task_id, attempt)
    assert custody["task"]["lease_expires_at"] == renewed["lease_expires_at"]
    assert custody["attempt"]["lease_expires_at"] == renewed["lease_expires_at"]
    assert {row["lease_expires_at"] for row in custody["reservations"]} == {renewed["lease_expires_at"]}


@pytest.mark.parametrize("field", ["fence", "lease_id", "runtime_epoch"])
def test_default_renewal_refuses_stale_authority_without_extending_lease(service, field):
    task_id, attempt = _claimed_task(service)
    before = _custody(service, task_id, attempt)
    body = _binding(attempt)
    body[field] = "stale-lease" if field == "lease_id" else body[field] + 1

    with pytest.raises(LeaseError):
        service.heartbeat_attempt(attempt["attempt_id"], body, idempotency_key="rn8-stale-" + field)

    assert _custody(service, task_id, attempt) == before


def _heartbeat_worker(endpoint, credential, attempt, acknowledgements):
    """A disposable real HTTP worker; the Runtime alone chooses its lease length."""
    client = WorkspaceClient(endpoint, credential)
    sequence = 0
    try:
        while True:
            sequence += 1
            result = client.heartbeat_attempt(
                attempt["attempt_id"], **_binding(attempt),
                idempotency_key=f"rn8-worker-{sequence}",
            )
            acknowledgements.send(dict(result))
            time.sleep(0.1)
    finally:
        acknowledgements.close()


def test_killed_renewing_worker_lease_expires_and_cannot_publish(tmp_path, monkeypatch):
    # Shorten only the server policy to keep a real process-death proof focused.
    # The separate default-policy case above verifies the production 30 s value.
    monkeypatch.setattr(runtime_store, "LEASE_SECONDS", 2)
    root = tmp_path / "realm"
    runtime_store.RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    worker = None
    receiver = sender = None
    try:
        task_id, attempt = _claimed_task(daemon.service)
        first_expiry = datetime.fromisoformat(attempt["lease_expires_at"])
        credential = provision_executor_token(daemon, "worker")
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        worker = context.Process(target=_heartbeat_worker,
                                 args=(daemon.endpoint, credential, attempt, sender))
        worker.start()
        sender.close()

        acknowledgements = []
        while datetime.now(timezone.utc) <= first_expiry + timedelta(seconds=0.2):
            assert receiver.poll(5), "worker did not acknowledge a real HTTP renewal"
            acknowledged = receiver.recv()
            assert acknowledged["attempt_id"] == attempt["attempt_id"]
            assert acknowledged["fence"] == attempt["fence"]
            acknowledgements.append(acknowledged)
        assert len(acknowledgements) >= 2
        assert datetime.fromisoformat(acknowledgements[-1]["lease_expires_at"]) > first_expiry

        worker.kill()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert worker.exitcode not in (None, 0)
        retained = _custody(daemon.service, task_id, attempt)
        expires = datetime.fromisoformat(retained["attempt"]["lease_expires_at"])
        wait_until = time.monotonic() + 4
        while datetime.now(timezone.utc) <= expires and time.monotonic() < wait_until:
            time.sleep(0.02)
        assert datetime.now(timezone.utc) > expires, "a dead worker retained an extended lease"

        with pytest.raises(LeaseError):
            daemon.service.heartbeat_attempt(attempt["attempt_id"], _binding(attempt),
                                               idempotency_key="rn8-after-worker-kill")
        with pytest.raises(LeaseError):
            daemon.service.settle_attempt(attempt["attempt_id"],
                                            {**_binding(attempt), "outputs": []},
                                            idempotency_key="rn8-dead-worker-settle")
        # Lease expiry fences publication; it is not proof of custody cleanup.
        assert _custody(daemon.service, task_id, attempt) == retained
        assert retained["attempt"]["settled"] == 0
        assert all(row["released_at"] is None for row in retained["reservations"])
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    finally:
        if worker is not None and worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        if receiver is not None:
            receiver.close()
        if sender is not None:
            sender.close()
        daemon.stop()
