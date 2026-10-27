from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_service(root):
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def _attempt(service: RuntimeService):
    capability_digest = _digest(b"identity-capability")
    service.register_capability({"capability_id": "identity.render", "definition_digest": capability_digest})
    service.register_executor({"executor_id": "identity-executor", "capabilities": ["identity.render"]}, idempotency_key="identity-register")
    task = service.create_task({"capability_id": "identity.render", "capability_digest": capability_digest, "idempotency_key": "identity-task"})
    attempt = service.claim_next(
        {"executor_id": "identity-executor", "capability_ids": ["identity.render"], "runtime_epoch": service.health()["runtime_epoch"]},
        idempotency_key="identity-claim",
    )
    return task, attempt


def test_executor_identity_is_migrated_persisted_and_reregistration_is_idempotent(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        digest = _digest(b"executor-source")
        body = {
            "executor_id": "provenance-executor",
            "capabilities": [],
            "source_digest": digest,
            "dependency_digest": _digest(b"executor-dependencies"),
            "source_epoch": "source-epoch-1",
            "schema_digest": service.health()["schema_digest"],
        }
        first = service.register_executor(body, idempotency_key="provenance-register")
        replay = service.register_executor(body, idempotency_key="provenance-register")
        assert replay == first
        assert first["source_digest"] == digest
        row = service.store.conn.execute(
            "SELECT source_digest, dependency_digest, source_epoch FROM executors WHERE id=?",
            ("provenance-executor",),
        ).fetchone()
        assert tuple(row) == (digest, body["dependency_digest"], "source-epoch-1")

        refreshed = {**body, "source_digest": _digest(b"executor-source-v2"), "source_epoch": "source-epoch-2", "runtime_epoch": service.health()["runtime_epoch"]}
        updated = service.register_executor(refreshed, idempotency_key="provenance-refresh")
        assert updated["source_digest"] == refreshed["source_digest"]
        with pytest.raises(ConflictError):
            service.register_executor({**refreshed, "source_epoch": "different"}, idempotency_key="provenance-refresh")
    finally:
        service.close()


def test_settlement_persists_flat_result_and_rejects_reserved_outputs(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        _task, attempt = _attempt(service)
        payload = b"identity-output"
        output = {
            "name": "output",
            "kind": "object",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
        }
        base = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [output]}
        with pytest.raises(ValidationError, match="reserved"):
            service.settle_attempt(attempt["attempt_id"], {**base, "result": {"outputs": []}}, idempotency_key="reserved-result")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0

        settled = service.settle_attempt(attempt["attempt_id"], {**base, "result": {"answer": 42}}, idempotency_key="flat-result")
        data = settled["data"]
        assert data["result"] == {"answer": 42, "outputs": [{"name": "output", "kind": "object", "digest": output["digest"], "media_type": output["media_type"], "size": len(payload)}]}
        assert service.settle_attempt(attempt["attempt_id"], {**base, "result": {"answer": 42}}, idempotency_key="flat-result") == settled
    finally:
        service.close()


def test_settlement_preserves_output_descriptors(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        task, attempt = _attempt(service)
        payload = b"descriptor-output"
        output = {
            "name": "primary",
            "kind": "object",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
            "ordinal": 0,
            "role": "primary_render",
            "is_primary": True,
        }
        settled = service.settle_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [output],
                "result": {"answer": 7},
            },
            idempotency_key="descriptor-settle",
        )
        expected = {key: output[key] for key in ("name", "kind", "digest", "media_type", "size", "ordinal", "role", "is_primary")}
        assert settled["data"]["result"]["outputs"] == [expected]
        assert service.task(task["task"]["id"])["task"]["result"]["outputs"] == [expected]
    finally:
        service.close()


def test_abandon_settles_evidenced_checkpoint_ancestors_and_fences_consumed_resume_receipt(tmp_path):
    from tests.test_execution_binding_contract import CAPABILITY, _admit, _claim, _identity, _service
    from runtime_protocol.errors import LeaseError
    from runtime_protocol.lifecycle import _interruption_report

    root = tmp_path / "realm"
    target = {"kind": "runpod", "pod_id": "checkpoint-pod", "provider_account_ref": "account-a"}
    service = _service(root)
    try:
        admitted = _admit(service, "ancestor-task", target)
        old = _claim(service, "ancestor-claim", target)
        lease = {key: old[key] for key in ("lease_id", "fence", "runtime_epoch")}
        prepared = service.prepare_reboot({**lease, "attempt_id": old["attempt_id"]}, identity=_identity(target))
        checkpoint = service.checkpoint_attempt(old["attempt_id"], {**lease, "nonce": prepared["nonce"],
            "authorization": prepared["nonce"], "state": {"provider_id": "retained"}}, identity=_identity(target))
        service.close()

        service = RuntimeService(root)
        epoch = service.health()["runtime_epoch"]
        service.register_executor({"executor_id": "executor-a", "capabilities": [CAPABILITY],
            "runtime_epoch": epoch}, idempotency_key="ancestor-register-restart")
        resume = {"checkpoint_id": checkpoint["checkpoint_id"], "nonce": prepared["nonce"],
                  "authorization": prepared["nonce"], "runtime_epoch": epoch}
        current = service.resume_attempt(resume, identity=_identity(target))["attempt"]
        task_id = current["task_id"]
        assert current["attempt_id"] != old["attempt_id"]
        assert service.resume_attempt(resume, identity=_identity(target))["attempt"]["attempt_id"] == current["attempt_id"]
        service.cancel_task_canonical(task_id, {}, idempotency_key="ancestor-cancel")
        observed = service._task_resource(service.store.get_task(task_id))
        result = service.abandon_task(task_id, {
            "expected_task_version": observed["version"], "attempt_id": current["attempt_id"],
            "lease_id": current["lease_id"], "fence": current["fence"], "runtime_epoch": current["runtime_epoch"],
            "execution_binding": observed["execution_binding"], "reason": "owner loses recovered provider work",
        }, idempotency_key="ancestor-abandon", identity={"actor": "owner", "scopes": ["admin"]})
        assert result["data"]["disposition"] == "lost"
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=? AND settled=0", (task_id,)).fetchone()[0] == 0
        assert _interruption_report(service.store.conn)["safe"] is True
        before = list(service.store.conn.iterdump())
        with pytest.raises(LeaseError, match="abandoned"):
            service.resume_attempt(resume, identity=_identity(target))
        with pytest.raises(LeaseError, match="abandoned"):
            service.heartbeat_attempt(old["attempt_id"], lease, idempotency_key="ancestor-late-heartbeat", identity=_identity(target))
        assert list(service.store.conn.iterdump()) == before
        # Historical checkpoint bytes, receipt, and attempt identities survive.
        assert service.store.conn.execute("SELECT state FROM recovery_checkpoints WHERE id=?", (checkpoint["checkpoint_id"],)).fetchone()[0] == "resumed"
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)).fetchone()[0] == 2
        service.close()
        service = RuntimeService(root)
        service.retry_task(task_id, {}, idempotency_key="ancestor-explicit-retry")
        resume["runtime_epoch"] = service.health()["runtime_epoch"]
        before = list(service.store.conn.iterdump())
        with pytest.raises(LeaseError, match="abandoned"):
            service.resume_attempt(resume, identity=_identity(target))
        assert list(service.store.conn.iterdump()) == before
    finally:
        service.close()


@pytest.mark.parametrize("unaccounted", ["attempt", "reservation"])
def test_abandon_refuses_unaccounted_outstanding_identities_atomically(tmp_path, unaccounted):
    from tests.test_execution_binding_contract import _admit, _claim, _service
    service = _service(tmp_path / "realm", resource_keys=["gpu"])
    try:
        target = {"kind": "runpod", "pod_id": "exact-pod", "provider_account_ref": "account-a"}
        admitted = _admit(service, "unaccounted-task", target)
        attempt = _claim(service, "unaccounted-claim", target)
        task_id = admitted["task"]["id"]
        service.cancel_task_canonical(task_id, {}, idempotency_key="unaccounted-cancel")
        observed = service._task_resource(service.store.get_task(task_id))
        if unaccounted == "attempt":
            service.store.conn.execute("INSERT INTO attempts(id,task_id,lease_id,fence,executor_id,lease_expires_at,settled,runtime_epoch) "
                "SELECT 'unaccounted-attempt',task_id,'unaccounted-lease',fence+50,executor_id,lease_expires_at,0,runtime_epoch "
                "FROM attempts WHERE id=?", (attempt["attempt_id"],))
        else:
            service.store.conn.execute("UPDATE reservations SET lease_token='unaccounted-lease' WHERE task_id=?", (task_id,))
        before = list(service.store.conn.iterdump())
        with pytest.raises(ConflictError, match="additional unsettled|reservation identity"):
            service.abandon_task(task_id, {"expected_task_version": observed["version"],
                "attempt_id": attempt["attempt_id"], **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
                "execution_binding": observed["execution_binding"], "reason": "owner clears exact attempt"},
                idempotency_key="unaccounted-abandon", identity={"actor": "owner", "scopes": ["admin"]})
        assert list(service.store.conn.iterdump()) == before
    finally:
        service.close()
