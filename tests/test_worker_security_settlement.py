from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_service(root: Path, **kwargs):
    RealmStore.initialize(root).close()
    return RuntimeService(root, **kwargs)


def _new_daemon(root: Path, **kwargs):
    RealmStore.initialize(root).close()
    return RuntimeDaemon(root, **kwargs)


def _service_attempt(tmp_path: Path):
    service = _new_service(tmp_path / "realm")
    definition = _digest(b"render-settlement-v1")
    service.register_capability({"capability_id": "render.settlement", "definition_digest": definition})
    service.register_executor(
        {"executor_id": "worker", "capabilities": ["render.settlement"]},
        idempotency_key="settlement-worker-register",
    )
    task = service.create_task(
        {
            "capability_id": "render.settlement",
            "capability_digest": definition,
            "idempotency_key": "settlement-task",
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": "worker",
            "capability_ids": ["render.settlement"],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key="settlement-worker-claim",
    )
    return service, task, attempt


def test_default_startup_uses_scoped_worker_credential(tmp_path: Path) -> None:
    daemon = _new_daemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        assert daemon.worker_token != daemon.token
        assert daemon.credentials.load(daemon.worker_token) == {
            "actor": WORKER_ACTOR,
            "scopes": sorted(WORKER_SCOPES),
        }

        owner = Api(daemon.endpoint, daemon.token)
        worker = Api(daemon.endpoint, daemon.worker_token)
        assert owner.request("GET", "/v1/export")
        with pytest.raises(RuntimeError) as denied:
            worker.request("GET", "/v1/export")
        assert denied.value.status == 401
    finally:
        daemon.stop()


def test_two_worker_credentials_cannot_cross_claim_or_mutate_attempt(tmp_path: Path) -> None:
    daemon = _new_daemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        capability = "render.security"
        definition = _digest(b"render-security-v1")
        owner.request("POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": definition})
        for executor_id in ("worker-a", "worker-b"):
            owner.request(
                "POST", "/v1/executors",
                {"executor_id": executor_id, "capabilities": [{"capability_id": capability, "definition_digest": definition, "status": "ready", "required_resource_keys": []}]},
                headers={"Idempotency-Key": executor_id},
            )
        token_a, _ = daemon.credentials.provision("worker-a", ["handshake", "worker:execute", "tasks:read"])
        token_b, _ = daemon.credentials.provision("worker-b", ["handshake", "worker:execute", "tasks:read"])
        worker_a, worker_b = Api(daemon.endpoint, token_a), Api(daemon.endpoint, token_b)
        owner.request("POST", "/v1/tasks", {"capability_id": capability, "capability_digest": definition, "input_object_ids": []}, headers={"Idempotency-Key": "security-task"})
        epoch = owner.health()["runtime_epoch"]

        with pytest.raises(RuntimeError) as wrong_claim:
            worker_b.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "wrong-claim"})
        assert wrong_claim.value.status == 401

        attempt = worker_a.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "right-claim"})
        for action, body in (
            ("heartbeat", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch}),
            ("checkpoint", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "nonce": "forged", "authorization": "forged", "state": {}}),
            ("fail", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "error": {"code": "forged"}}),
            ("settle", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": []}),
        ):
            with pytest.raises(RuntimeError) as wrong_action:
                worker_b.request("POST", f"/v1/attempts/{attempt['attempt_id']}/{action}", body, headers={"Idempotency-Key": f"wrong-{action}"})
            assert wrong_action.value.status == 401
    finally:
        daemon.stop()


def test_settlement_stages_all_outputs_before_fenced_publication(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        definition = _digest(b"render-settlement-v1")
        service.register_capability({"capability_id": "render.settlement", "definition_digest": definition})
        service.register_executor(
            {"executor_id": "worker", "capabilities": ["render.settlement"]},
            idempotency_key="settlement-worker-register",
        )
        project = service.create_project({"slug": "settlement", "name": "Settlement"})
        task = service.create_task({"capability_id": "render.settlement", "capability_digest": definition, "project": project["id"], "idempotency_key": "settlement-task"})
        attempt = service.claim_next(
            {"executor_id": "worker", "capability_ids": ["render.settlement"], "runtime_epoch": service.health()["runtime_epoch"]},
            idempotency_key="settlement-worker-claim",
        )
        payload = b"first-output"
        valid = {"digest": _digest(payload), "data_base64": base64.b64encode(payload).decode("ascii"), "size": len(payload), "media_type": "application/octet-stream", "kind": "object", "name": "first"}
        with pytest.raises(ValidationError):
            service.settle_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid, {"digest": "malformed"}]},
                idempotency_key="settlement-invalid",
            )
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert list((service.store.cas_root).glob("*/*")) == []

        service.settle_attempt(
            attempt["attempt_id"],
            {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid]},
            idempotency_key="settlement-valid",
        )
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)).fetchone()[0] == 1
        assert service.task(task["task"]["id"])["task"]["status"] == "completed"
        assert not (service.store.staging_root / "settlements" / attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_staged_bytes_are_reverified_before_cas_promotion(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"immutable-output"
    digest = _digest(payload).removeprefix("sha256:")
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [
            {
                "digest": "sha256:" + digest,
                "data_base64": base64.b64encode(payload).decode("ascii"),
                "size": len(payload),
                "media_type": "application/octet-stream",
                "kind": "object",
                "name": "output",
            }
        ],
    )
    try:
        staged["items"][0]["path"].write_bytes(b"IMMUTABLE-output")
        with pytest.raises(ConflictError, match="hash or size"):
            with service.store._transaction():
                service._publish_staged_outputs(staged)
        service._recover_cas_publication_journals()
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
    finally:
        service._discard_staged_outputs(staged)
        service.close()


def test_stale_fence_rejects_output_before_any_staging_or_publication(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"fenced-output"
    digest = _digest(payload).removeprefix("sha256:")
    try:
        with pytest.raises(LeaseError):
            service.settle_attempt(
                attempt["attempt_id"],
                {
                    "lease_id": attempt["lease_id"],
                    "fence": attempt["fence"] - 1,
                    "runtime_epoch": attempt["runtime_epoch"],
                    "outputs": [
                        {
                            "digest": "sha256:" + digest,
                            "data_base64": base64.b64encode(payload).decode("ascii"),
                            "size": len(payload),
                            "media_type": "application/octet-stream",
                            "kind": "object",
                            "name": "output",
                        }
                    ],
                },
                idempotency_key="stale-fence-settle",
            )
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert not (service.store.staging_root / "settlements" / attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_attempt_staging_rejects_path_escape_ids(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        with pytest.raises(ValidationError, match="attempt_id is invalid"):
            service._stage_outputs("../outside", [])
        assert not (tmp_path / "outside").exists()
    finally:
        service.close()


def test_staged_cleanup_pins_directory_before_unlinking(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"staged-cleanup"
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [{"digest": _digest(payload), "data_base64": base64.b64encode(payload).decode("ascii")}],
    )
    stage_dir = staged["stage_dir"]
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "must-survive"
    external.write_bytes(b"external")
    real_stage = stage_dir.with_name(stage_dir.name + "-real")
    try:
        stage_dir.rename(real_stage)
        stage_dir.symlink_to(outside, target_is_directory=True)
        service._discard_staged_outputs(staged)
        assert external.read_bytes() == b"external"
    finally:
        if stage_dir.is_symlink():
            stage_dir.unlink()
        if real_stage.exists():
            service._discard_staged_outputs({"stage_dir": real_stage, "items": []})
        service.close()


def test_promotion_uses_open_source_identity_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"trusted-staged-bytes"
    digest = _digest(payload).removeprefix("sha256:")
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [{"digest": "sha256:" + digest, "data_base64": base64.b64encode(payload).decode("ascii")}],
    )
    source = staged["items"][0]["path"]
    replacement = source.with_name(source.name + "-original")
    attacker = b"attacker-bytes"
    swapped = False
    original_verify = service._verify_open_file

    def replace_after_verify(file_fd, expected_digest, expected_size, *, label):
        nonlocal swapped
        result = original_verify(file_fd, expected_digest, expected_size, label=label)
        if label == "staged output" and not swapped:
            swapped = True
            source.rename(replacement)
            source.write_bytes(attacker)
        return result

    monkeypatch.setattr(service, "_verify_open_file", replace_after_verify)
    try:
        with service.store._transaction():
            service._publish_staged_outputs(staged)
        assert swapped
        assert service.cas.path_for(digest).read_bytes() == payload
        staged["committed"] = True
    finally:
        service._discard_staged_outputs(staged)
        service.close()


def test_journal_recovery_pins_cas_prefix_before_unlinking(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    payload = b"journal-recovery"
    digest = _digest(payload).removeprefix("sha256:")
    service = _new_service(root)
    service._begin_cas_publication_journal("ingest", [{"digest": digest}], project_id="unscoped")
    service.cas.put(payload)
    destination = service.cas.path_for(digest)
    prefix = destination.parent
    service.close()

    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "must-survive"
    external.write_bytes(b"external")
    real_prefix = prefix.with_name(prefix.name + "-real")
    try:
        prefix.rename(real_prefix)
        prefix.symlink_to(outside, target_is_directory=True)
        recovered = RuntimeService(root)
        try:
            assert external.read_bytes() == b"external"
            assert prefix.is_symlink()
            assert (real_prefix / digest[2:]).read_bytes() == payload
        finally:
            recovered.close()
    finally:
        if prefix.is_symlink():
            prefix.unlink()
        if real_prefix.exists():
            real_prefix.rename(prefix)


def test_retained_external_worker_token_is_fenced_after_abandon_restart_and_new_claim(tmp_path):
    from tests.test_tasks_clear import _external_cli_task
    from tests.test_execution_binding_contract import CAPABILITY, _admit, _identity

    root, support = tmp_path / "realm", tmp_path / "support"
    daemon = _new_daemon(root, support_root=support).start()
    try:
        task_id, old = _external_cli_task(daemon)
        placement = _identity(old["execution_binding"]["actual_target"])["execution_binding"]
        token, _ = daemon.credentials.provision("executor-a", ["worker:execute", "tasks:read", "objects:write"],
            metadata={"execution_binding": placement})
        owner, worker = Api(daemon.endpoint, daemon.token), Api(daemon.endpoint, token)
        lease = {key: old[key] for key in ("lease_id", "fence", "runtime_epoch")}
        worker.request("POST", f"/v1/attempts/{old['attempt_id']}/heartbeat", lease,
                       headers={"Idempotency-Key": "retained-heartbeat"})
        owner.request("POST", f"/v1/tasks/{task_id}/cancel", {}, headers={"Idempotency-Key": "retained-cancel"})
        observed = owner.request("GET", f"/v1/control/tasks/{task_id}/settlement")["task"]
        abandon_body = {
            "expected_task_version": observed["version"], "attempt_id": old["attempt_id"], **lease,
            "execution_binding": observed["execution_binding"], "reason": "owner loses provider attempt",
        }
        abandoned = owner.request("POST", f"/v1/control/tasks/{task_id}/abandon", abandon_body,
                                  headers={"Idempotency-Key": "retained-abandon"})

        def reject_old_reports():
            before = list(daemon.service.store.conn.iterdump())
            for action, body, key in (
                ("heartbeat", lease, "retained-heartbeat"),  # previously successful replay
                ("heartbeat", lease, "retained-heartbeat-new-key"),
                ("settle", {**lease, "outputs": [{"digest": _digest(b"late-output"), "size": 11,
                    "data_base64": base64.b64encode(b"late-output").decode(), "name": "late"}]}, "retained-settle"),
                ("fail", {**lease, "error": {"code": "late"}}, "retained-fail"),
            ):
                with pytest.raises(RuntimeError) as denied:
                    worker.request("POST", f"/v1/attempts/{old['attempt_id']}/{action}", body,
                                   headers={"Idempotency-Key": key})
                assert denied.value.status in {401, 409}
            assert list(daemon.service.store.conn.iterdump()) == before

        reject_old_reports()
        daemon.stop()
        daemon = RuntimeDaemon(root, support_root=support).start()
        worker = Api(daemon.endpoint, token)  # retain actual original credential bytes
        owner = Api(daemon.endpoint, daemon.token)
        assert daemon.credentials.load(token)["actor"] == "executor-a"
        reject_old_reports()
        owner.request("POST", f"/v1/tasks/{task_id}/retry", {}, headers={"Idempotency-Key": "retained-retry"})
        epoch = daemon.service.health()["runtime_epoch"]
        daemon.service.register_executor({"executor_id": "executor-a", "capabilities": [CAPABILITY],
            "resource_keys": ["external-gpu"], "runtime_epoch": epoch}, idempotency_key="retained-refresh")
        fresh = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor-a", "capability_ids": [CAPABILITY],
            "runtime_epoch": epoch, "target": placement["actual"]}, headers={"Idempotency-Key": "retained-fresh-claim"})
        assert fresh["attempt_id"] != old["attempt_id"] and fresh["fence"] > old["fence"]
        reject_old_reports()
        before_replay = list(daemon.service.store.conn.iterdump())
        assert owner.request("POST", f"/v1/control/tasks/{task_id}/abandon", abandon_body,
                             headers={"Idempotency-Key": "retained-abandon"}) == abandoned
        assert list(daemon.service.store.conn.iterdump()) == before_replay
        worker.request("POST", f"/v1/attempts/{fresh['attempt_id']}/settle", {
            **{key: fresh[key] for key in ("lease_id", "fence", "runtime_epoch")}, "outputs": [],
        }, headers={"Idempotency-Key": "retained-fresh-settle"})
        assert daemon.service.store.get_task(task_id)["task"]["status"] == "completed"
        independent = _admit(daemon.service, "retained-independent-task", placement["actual"])
        independent_attempt = worker.request("POST", "/v1/tasks/claim", {
            "executor_id": "executor-a", "capability_ids": [CAPABILITY], "runtime_epoch": epoch,
            "target": placement["actual"]}, headers={"Idempotency-Key": "retained-independent-claim"})
        assert independent_attempt["task_id"] == independent["task"]["id"] != task_id
        worker.request("POST", f"/v1/attempts/{independent_attempt['attempt_id']}/settle", {
            **{key: independent_attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}, "outputs": [],
        }, headers={"Idempotency-Key": "retained-independent-settle"})
        assert daemon.service.store.get_task(independent_attempt["task_id"])["task"]["status"] == "completed"
    finally:
        daemon.stop()
