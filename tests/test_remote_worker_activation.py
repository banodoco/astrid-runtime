from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR
from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.remote_worker_activation import (
    ParkedRemoteHost,
    QualifiedRemoteWorkerLauncher,
    RemotePreparationCheckpoint,
    RemotePreparationLaunch,
    _digest,
)
from runtime_protocol.remote_worker_deployment import (
    ArtifactReference, DeploymentReference, deployment_binding_from_task, project_launch,
)
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api


CAPABILITY = "pack.render"
CAPABILITY_DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()
OLD = {"kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a"}
NEW = {"kind": "runpod", "pod_id": "pod-new", "provider_account_ref": "account-a"}
MACHINE = {"kind": "machine", "id": "machine-a"}
OWNER = {"actor": "owner", "scopes": ["admin"]}


def _service(tmp_path: Path, *, child_delegation: bool = False, target=OLD, capacity=2):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST})
    service.register_executor(
        {"executor_id": "host", "capabilities": [CAPABILITY], "max_concurrency": capacity},
        idempotency_key="host-register",
    )
    project = service.create_project(
        {"slug": "remote-activation", "name": "Remote activation"},
        idempotency_key="remote-activation-project",
    )
    source = service.ingest(
        project["id"],
        b"remote-worker-activation-input",
        media_type="application/octet-stream",
        original_name="source.bin",
        idempotency_key="remote-activation-input",
    )
    input_digest = source["data"]["digest"]
    admission = {
        "capability_id": CAPABILITY,
        "capability_digest": CAPABILITY_DIGEST,
        "project": project["id"],
        "input_object_ids": [input_digest],
        "spec": {"inputs": {"source": input_digest}},
        "execution_request": {
            "schema_version": 1,
            "target": target,
            "inputs": [{"name": "source", "object_id": input_digest}],
        },
        "idempotency_key": "same-canonical-admission",
    }
    if target.get("kind") == "runpod":
        admission["execution_request"]["remote_activation_required"] = True
    if child_delegation:
        admission["child_delegation"] = {
            "capabilities": [{"capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST}],
            "targets": [target],
            "input_object_ids": [],
        }
    admitted = service.create_task(admission, enforce_readiness=True)
    task_id = admitted["task"]["id"]
    return service, task_id


def _reference(tmp_path: Path, service: RuntimeService, task_id: str) -> DeploymentReference:
    task = service._task_resource(service.store.get_task(task_id))
    binding = deployment_binding_from_task(task)
    executable = ArtifactReference("python", tmp_path / "python", "sha256:" + "2" * 64)
    target = binding.placement.effective_target
    return DeploymentReference(
        deployment_id="deployment-1", revision="revision-1",
        task_id=task_id, run_id=binding.admission_identity.run_id,
        target_ref=target["kind"] + ":" + binding.placement.original_target.get("pod_id", binding.placement.original_target.get("id", "")),
        effective_target_ref=target["kind"] + ":" + target.get("pod_id", target.get("id", "")),
        executable=executable, dependency_closure=(executable,),
        source_closure_digest="sha256:" + "3" * 64,
        data_root=tmp_path / "data", support_root=tmp_path / "data" / "runtime",
        runtime_endpoint="http://127.0.0.1:59683",
        runtime_instance_id="instance-1", runtime_epoch=service.health()["runtime_epoch"],
        runtime_schema_digest="sha256:" + "4" * 64,
        model_root=tmp_path / "models", capacity=1, session_ref="session-1",
        session_config_digest="sha256:" + "5" * 64,
        output_root=tmp_path / "outputs", credential_ref=str(tmp_path / "credentials" / "host.token"),
        executor_id="host", boot_manifest_path=tmp_path / "data" / "runtime" / "boot.json",
        boot_manifest_hash="sha256:" + "6" * 64,
        readiness_profile_path=tmp_path / "data" / "runtime" / "ready.json",
        readiness_profile_hash="sha256:" + "7" * 64,
        admission_identity=binding.admission_identity,
        capability_identity=binding.capability_identity,
        input_bindings=binding.input_bindings,
        original_target=binding.placement.original_target,
        effective_target=target,
        placement_version=binding.placement.placement_version,
        recovery_decision_digest=binding.placement.recovery_decision_digest,
        execution_target=target,
    )


def _observation(ref: DeploymentReference, service: RuntimeService):
    value = {
        "target": dict(ref.effective_target),
        "process": {"pid": 12345, "birth_id": "birth-1", "pgid": 12345, "sid": 12345},
        "runtime_instance_id": ref.runtime_instance_id,
        "runtime_epoch": ref.runtime_epoch,
        "runtime_session_id": service.runtime_session_id,
        "source_closure_digest": ref.source_closure_digest,
        "dependency_closure_digest": _digest([
            {"name": item.name, "path": str(item.path), "digest": item.digest}
            for item in ref.dependency_closure
        ]),
        "model_root": str(ref.model_root), "session_ref": ref.session_ref,
        "data_root": str(ref.data_root), "support_root": str(ref.support_root),
        "output_root": str(ref.output_root),
        "capacity": ref.capacity, "model_inventory_digest": "sha256:" + "8" * 64,
        "session_config_digest": ref.session_config_digest,
    }
    if ref.effective_target["kind"] == "runpod":
        value["child"] = {"attached": True, "lanes": ["orchestration", "executor"],
                           "birth_id": "child-1"}
        value["provider_identity"] = {"account_ref": ref.effective_target["provider_account_ref"],
                                      "pod_id": ref.effective_target["pod_id"]}
    else:
        value["machine_identity"] = {"id": ref.effective_target["id"], "uid": 501}
        value["process"].update(uid=501, executable=str(ref.executable.path), artifact_digest=ref.executable.digest)
    return value


class Preparer:
    def __init__(self):
        self.calls = []
        self.bad_ack = False
        self.accepted_process = {"pid": 12345, "birth_id": "birth-1"}

    def prepare(self, launch):
        self.calls.append("prepare")
        return object()

    def acknowledge(self, handle, grant, *, accept):
        if not self.bad_ack:
            accept(dict(grant), dict(self.accepted_process))
        self.calls.append("private_ack")
        return {"activation_id": "wrong" if self.bad_ack else grant["activation_id"],
                "executor_incarnation": grant["executor_incarnation"],
                "evidence_digest": grant["evidence_digest"]}

    def await_ready(self, handle):
        self.calls.append("await_ready")

    def abort(self, handle):
        self.calls.append("abort")


class CheckpointPreparer(Preparer):
    def __init__(self):
        super().__init__()
        self.checkpoints = []
        self.fail_stage = None

    def checkpoint(self, parked, stage, details):
        self.checkpoints.append((parked, stage, copy.deepcopy(details)))
        if stage == self.fail_stage:
            raise OSError("checkpoint unavailable")

    def restore(self, reference):
        parked = next(host for host, stage, _details in self.checkpoints if stage == "parked")
        assert parked.target == reference.effective_target
        return RemotePreparationCheckpoint(
            parked.handle, copy.deepcopy(parked.target), copy.deepcopy(parked.observation),
            parked.evidence_digest, parked.executor_incarnation,
        )


class Inspector:
    def __init__(self, observation):
        self.current = observation
        self.calls = 0
        self.ready_calls = 0

    def observe_ready(self, handle):
        self.ready_calls += 1
        return copy.deepcopy(self.current)

    def observe(self, handle):
        self.calls += 1
        return copy.deepcopy(self.current)


def _fixture(tmp_path):
    service, task_id = _service(tmp_path)
    reference = _reference(tmp_path, service, task_id)
    credentials = CredentialStore(tmp_path / "credentials")
    preparer = Preparer()
    inspector = Inspector(_observation(reference, service))
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    return service, task_id, reference, credentials, preparer, inspector, launcher


def test_resident_credential_control_lifecycle_uses_callback_without_local_store(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, _launcher = _fixture(tmp_path)
    calls = []

    def control(control_task, value):
        assert control_task == task_id
        action = value["action"]
        calls.append(action)
        if action == "provision":
            _token, path = credentials.provision(
                "host", ["worker:execute"], rotate=True, enabled=False,
                metadata={"execution_binding": value["placement"],
                          "qualified_activation": value["qualification"]},
            )
            return {"credential_actor": "host", "credential_file": str(path)}
        if action == "enable":
            credentials.enable_actor("host")
            return {"enabled": True}
        if action == "verify":
            metadata = credentials.actor_metadata("host")
            return {"fresh": bool(metadata and service._remote_activation_matches(
                task_id, metadata, metadata["execution_binding"],
            ))}
        if action == "revoke":
            credentials.revoke("host")
            return {"revoked": True}
        pytest.fail(f"unexpected resident control: {action}")

    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=None, credential_control=control,
        preparer=preparer, inspector=inspector,
    )
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        assert launcher.activation_state == "active"
        assert calls == ["provision", "enable"]
        launcher.assert_fresh(service._task_resource(service.store.get_task(task_id)), ref, parked, qualification)
        assert calls[-1] == "verify"
        restored = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=None, credential_control=control,
            preparer=preparer, inspector=inspector,
        )
        restored.restore_activation(task, ref, parked, qualification)
        assert restored.activation_state == "unknown"
        assert restored.activation_credential_digest is None
        assert restored.reconcile_activation(task, ref, parked, qualification) == qualification
        credentials.revoke("host")
        with pytest.raises(ConflictError, match="revoked or expired"):
            launcher.assert_fresh(service._task_resource(service.store.get_task(task_id)), ref, parked, qualification)
    finally:
        service.close()


@pytest.mark.parametrize(
    ("lose_cleanup_reply", "commit_during_cleanup"),
    [(False, False), (True, False), (False, True)],
)
def test_http_owner_precommit_failure_retires_exact_generation_before_abort(
        tmp_path, lose_cleanup_reply, commit_during_cleanup):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(
        root, support_root=tmp_path / "support"
    ).start()
    try:
        service = daemon.service
        service.register_capability({
            "capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST,
        })
        task_id = service.create_task({
            "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [], "spec": {},
            "execution_request": {
                "schema_version": 1, "target": OLD, "remote_activation_required": True,
            },
            "idempotency_key": "http-precommit-failure",
        }, enforce_readiness=True)["task"]["id"]
        reference = replace(_reference(tmp_path, service, task_id), executor_id=WORKER_ACTOR)
        observation = _observation(reference, service)
        preparer = Preparer()
        preparer.bad_ack = True
        inspector = Inspector(observation)
        owner_http = Api(daemon.endpoint, daemon.token)
        calls = []
        attempted = []

        def credential_control(control_task, body):
            assert control_task == task_id
            attempted.append(body["action"])
            if body["action"] == "revoke-uncommitted" and commit_during_cleanup:
                service.record_remote_activation(task_id, body["qualification"], identity=OWNER)
            response = owner_http.request(
                "POST", f"/v1/tasks/{task_id}/remote-credential", body,
            )
            calls.append((body["action"], response))
            if body["action"] == "revoke-uncommitted" and lose_cleanup_reply:
                raise TimeoutError("owner cleanup reply lost")
            return response

        # This caller facade deliberately has no RuntimeService private
        # history methods. The resident HTTP owner must prove noncommit and
        # tombstone/revoke before the launcher may abort its process handle.
        facade = SimpleNamespace(
            runtime_session_id=service.runtime_session_id,
            store=SimpleNamespace(_current_runtime_epoch=service.store._current_runtime_epoch),
        )
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=facade, credentials=None, credential_control=credential_control,
            preparer=preparer, inspector=inspector,
        )
        original_abort = preparer.abort

        def abort(handle):
            assert calls[-1] == ("revoke-uncommitted", {"revoked": True})
            assert not lose_cleanup_reply and not commit_during_cleanup
            original_abort(handle)

        preparer.abort = abort
        parked = launcher.park(reference, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        if commit_during_cleanup:
            with pytest.raises(RuntimeError) as denied:
                launcher.activate(task, reference, parked)
            assert denied.value.status == 409
            assert launcher.activation_state == "unknown"
            assert "abort" not in preparer.calls
        elif lose_cleanup_reply:
            with pytest.raises(TimeoutError, match="reply lost"):
                launcher.activate(task, reference, parked)
            assert launcher.activation_state == "unknown"
            assert "abort" not in preparer.calls
        else:
            with pytest.raises(ConflictError, match="acknowledgement"):
                launcher.activate(task, reference, parked)
            assert launcher.activation_state == "inactive"
            assert preparer.calls[-1] == "abort"
        activation_id = launcher.activation_qualification["activation_id"]
        history = service._remote_activation_history(task_id, activation_id)
        if commit_during_cleanup:
            assert any(kind == "task.remote_activation_qualified" for kind, _ in history)
            assert not any(kind == "task.remote_activation_revoked" for kind, _ in history)
            assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        else:
            assert any(kind == "task.remote_activation_revoked" and value.get("unqualified") is True
                       for kind, value in history)
            assert not any(kind == "task.remote_activation_qualified" for kind, _ in history)
            assert daemon.credentials.actor_metadata(WORKER_ACTOR) is None
            assert calls[-1][1] == {"revoked": True}
        assert attempted == ["provision", "revoke-uncommitted"]
    finally:
        daemon.stop()


@pytest.mark.parametrize("both", [False, True])
def test_resident_credential_control_requires_exactly_one_authority(tmp_path, both):
    service, _task_id, _ref, credentials, preparer, inspector, _launcher = _fixture(tmp_path)
    try:
        with pytest.raises(ValidationError, match="exactly one"):
            QualifiedRemoteWorkerLauncher(
                runtime=service, credentials=credentials if both else None,
                credential_control=(lambda *_args: {}) if both else None,
                preparer=preparer, inspector=inspector,
            )
    finally:
        service.close()


def test_preparation_receives_exact_reference_and_projected_launch(tmp_path, monkeypatch):
    service, _task_id, ref, _credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    received = []

    def prepare(bundle):
        assert isinstance(bundle, RemotePreparationLaunch)
        received.append(bundle)
        return object()

    monkeypatch.setattr(preparer, "prepare", prepare)
    try:
        with pytest.raises(ConflictError, match="preparation target"):
            launcher.park(ref, target=NEW)
        assert received == []
        launcher.park(ref, target=OLD)
        assert received[0].reference is ref
        assert received[0].launch == project_launch(ref)
    finally:
        service.close()


@pytest.mark.parametrize("field,bad", [
    ("provider_identity", {"account_ref": "account-a", "pod_id": "foreign"}),
    ("process", {"pid": True, "birth_id": "birth", "pgid": True, "sid": True}),
    ("runtime_epoch", True),
    ("runtime_session_id", ""),
    ("model_inventory_digest", "unmeasured"),
    ("output_root", "relative/outputs"),
    ("child", {"ready": True}),
    ("lanes", 2),
])
def test_independent_observation_rejects_incomplete_or_synthetic_evidence(tmp_path, field, bad):
    service, _task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        inspector.current[field] = bad
        with pytest.raises(ConflictError):
            launcher.park(ref, target=OLD)
        assert preparer.calls[-1] == "abort"
        assert credentials.actor_metadata("host") is None
    finally:
        service.close()


def test_park_abort_ambiguity_retains_process_handle(tmp_path, monkeypatch):
    service, _task_id, ref, _credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        inspector.current["model_inventory_digest"] = "unmeasured"
        def abort_unconfirmed(_handle):
            raise OSError("remote stop reply lost")
        monkeypatch.setattr(preparer, "abort", abort_unconfirmed)
        with pytest.raises(ConflictError, match="readiness digest"):
            launcher.park(ref, target=OLD)
        assert launcher.activation_state == "unknown"
        assert launcher.preparation_handle is not None
        with pytest.raises(ConflictError, match="custody is unresolved"):
            launcher.park(ref, target=OLD)
    finally:
        service.close()


def test_locked_process_incarnation_is_the_runtime_qualification(tmp_path, monkeypatch):
    service, task_id, ref, _credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        locked_incarnation = "locked-process-owner-1"
        inspector.current["process"]["birth_id"] = "os-birth-1"
        handle = SimpleNamespace(incarnation=locked_incarnation)
        monkeypatch.setattr(preparer, "prepare", lambda _bundle: handle)
        preparer.accepted_process = {
            "pid": inspector.current["process"]["pid"],
            "birth_id": inspector.current["process"]["birth_id"],
        }
        parked = launcher.park(ref, target=OLD)
        assert parked.handle is handle
        assert parked.observation["process"]["birth_id"] == "os-birth-1"
        assert parked.executor_incarnation == locked_incarnation
        qualification = launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert qualification["executor_incarnation"] == locked_incarnation
        assert service._latest_remote_activation(task_id)["executor_incarnation"] == locked_incarnation
    finally:
        service.close()


def test_preparer_checkpoints_exact_process_and_activation_stages(tmp_path, monkeypatch):
    service, task_id, ref, credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    provision = credentials.provision

    def provision_after_qualification(*args, **kwargs):
        assert [stage for _parked, stage, _details in preparer.checkpoints] == [
            "parked", "qualification",
        ]
        return provision(*args, **kwargs)

    monkeypatch.setattr(credentials, "provision", provision_after_qualification)
    try:
        parked = launcher.park(ref, target=OLD)
        qualification = launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert [stage for _parked, stage, _details in preparer.checkpoints] == [
            "parked", "qualification", "credential", "acknowledged", "enabled", "ready", "committed",
        ]
        assert all(saved is parked for saved, _stage, _details in preparer.checkpoints)
        assert preparer.checkpoints[0][2] == {"schema_version": 1}
        assert preparer.checkpoints[0][0].observation["process"] == {
            "pid": 12345, "birth_id": "birth-1", "pgid": 12345, "sid": 12345,
        }
        assert preparer.checkpoints[0][0].executor_incarnation == qualification["executor_incarnation"]
        assert all(details["qualification"] == qualification
                   for _saved, _stage, details in preparer.checkpoints[1:])
        assert preparer.checkpoints[2][2]["credential_file"] == str(credentials.path_for("host"))
        assert preparer.checkpoints[3][2]["acknowledgement"] == {
            "activation_id": qualification["activation_id"],
            "executor_incarnation": parked.executor_incarnation,
            "evidence_digest": parked.evidence_digest,
        }
        assert preparer.checkpoints[5][2]["ready_observation"] == parked.observation
        assert credentials.path_for("host").read_text().strip() not in repr(preparer.checkpoints)
    finally:
        service.close()


@pytest.mark.parametrize("stage", ["qualification", "credential", "acknowledged", "enabled", "ready"])
def test_precommit_checkpoint_failure_retires_exact_generation(tmp_path, stage):
    service, task_id, ref, credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    preparer.fail_stage = stage
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        if stage in {"qualification", "credential"}:
            with pytest.raises(OSError, match="checkpoint unavailable"):
                launcher.activate(task, ref, parked)
            assert launcher.activation_state == "inactive"
            assert service._latest_remote_activation(task_id) is None
            assert credentials.actor_metadata("host") is None
            assert preparer.calls[-1] == "abort"
        else:
            launcher.activate(task, ref, parked)
            assert launcher.activation_state == "active"
            assert service._latest_remote_activation(task_id) is not None
            token = credentials.path_for("host").read_text().strip()
            credentials.require(token, "worker:execute")
            assert "abort" not in preparer.calls
    finally:
        service.close()


def test_park_checkpoint_failure_aborts_the_owned_process(tmp_path):
    service, _task_id, ref, _credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    preparer.fail_stage = "parked"
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=CredentialStore(tmp_path / "checkpoint-credentials"),
        preparer=preparer, inspector=inspector,
    )
    try:
        with pytest.raises(OSError, match="checkpoint unavailable"):
            launcher.park(ref, target=OLD)
        assert launcher.activation_state == "inactive"
        assert preparer.calls[-1] == "abort"
    finally:
        service.close()


def _claim(service, target, identity, key):
    return service.claim_next({
        "executor_id": "host", "capability_ids": [CAPABILITY],
        "runtime_epoch": service.health()["runtime_epoch"], "target": target,
    }, idempotency_key=key, identity=identity)


def _identity(credentials):
    return credentials.load(credentials.path_for("host").read_text().strip())


def _expired_identity(service, credentials, task_id):
    expired = copy.deepcopy(_identity(credentials)["qualified_activation"])
    expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    service.store.conn.execute(
        "UPDATE events SET payload_json=? WHERE task_id=? AND kind='task.remote_activation_qualified'",
        (json.dumps(expired, sort_keys=True, separators=(",", ":")), str(task_id)),
    )
    identity = _identity(credentials)
    identity["qualified_activation"] = expired
    return identity


def test_parked_host_remains_unclaimable_until_private_ack_and_owner_activation(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        assert service._task_requires_remote_activation(task_id)
        assert service.task(task_id)["task"]["execution_request"]["remote_activation_required"] is True
        missing = _claim(service, OLD, {"actor": "host", "scopes": ["worker:execute"]}, "missing")
        assert missing["waiting_reason"] in {"execution_binding_missing", "remote_activation_missing"}
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        assert preparer.calls == ["prepare", "private_ack", "await_ready"]
        assert inspector.calls == 5
        assert credentials.actor_metadata("host")["qualified_activation"] == qualification
        launcher.assert_fresh(task, ref, parked, qualification)
        claimed = _claim(service, OLD, _identity(credentials), "qualified-claim")
        assert claimed["task_id"] == task_id
        assert claimed["execution_binding"]["executor_incarnation"] == parked.executor_incarnation
        assert claimed["execution_binding"]["actual_target"] == OLD
    finally:
        service.close()


@pytest.mark.parametrize("target", [None, {"kind": "machine", "id": "local-worker"}, OLD])
def test_unmarked_executor_tasks_do_not_require_remote_activation(tmp_path, target):
    service, _task_id = _service(tmp_path)
    try:
        body = {
            "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [], "spec": {}, "idempotency_key": "local-admission",
        }
        if target is not None:
            body["execution_request"] = {"schema_version": 1, "target": target}
        task_id = service.create_task(body)["task"]["id"]
        assert service._task_requires_remote_activation(task_id) is False
    finally:
        service.close()


@pytest.mark.parametrize("failure", [None, "grant", "process", "missing", "duplicate", "lost_reply", "cleanup"])
def test_acceptance_callback_commits_before_ack_and_keeps_credential_disabled(tmp_path, failure):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        deliveries = []

        def acknowledge(handle, grant, *, accept):
            deliveries.append(handle)
            token = Path(grant["credential_file"]).read_text().strip()
            assert service._latest_remote_activation(task_id) is None
            with pytest.raises(AuthorizationError):
                credentials.require(token, "worker:execute")
            received = dict(grant)
            process = {"pid": 12345, "birth_id": "birth-1"}
            if failure == "grant":
                received["activation_id"] = "foreign"
            if failure == "process":
                process["birth_id"] = "foreign"
            if failure != "missing":
                accept(received, process)
                assert [kind for kind, _ in service._remote_activation_history(task_id)] == [
                    "task.remote_activation_qualified", "task.remote_activation_accepted",
                ]
                with pytest.raises(AuthorizationError):
                    credentials.require(token, "worker:execute")
            if failure == "duplicate":
                accept(received, process)
            if failure == "lost_reply":
                raise EOFError("final reply lost after resident commit")
            if failure == "cleanup":
                raise ConflictError("final acknowledgement was not returned")
            return {key: grant[key] for key in ("activation_id", "executor_incarnation", "evidence_digest")}

        preparer.acknowledge = acknowledge
        task = service._task_resource(service.store.get_task(task_id))
        if failure in {None, "lost_reply"}:
            launcher.activate(task, ref, parked)
            assert launcher.activation_state == "active"
            assert credentials.require(credentials.path_for("host").read_text().strip(), "worker:execute")
        elif failure in {"duplicate", "cleanup"}:
            with pytest.raises(ConflictError):
                launcher.activate(task, ref, parked)
            assert launcher.activation_state == "unknown"
            assert credentials.actor_metadata("host") is not None
            assert service._latest_remote_activation(task_id) is not None
            assert "abort" not in preparer.calls
        else:
            with pytest.raises(ConflictError):
                launcher.activate(task, ref, parked)
            assert launcher.activation_state == "inactive"
            assert credentials.actor_metadata("host") is None
            assert service._latest_remote_activation(task_id) is None
            assert preparer.calls[-1] == "abort"
        assert deliveries == [parked.handle]
    finally:
        service.close()


@pytest.mark.parametrize("target,marker", [
    ({"kind": "machine", "id": "local-worker"}, True),
    (OLD, "true"),
    (OLD, 1),
])
def test_remote_activation_intent_requires_runpod_and_a_boolean(tmp_path, target, marker):
    service, _task_id = _service(tmp_path)
    try:
        with pytest.raises(ValidationError, match="remote_activation_required|RunPod"):
            service.create_task({
                "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
                "input_object_ids": [], "spec": {},
                "execution_request": {"schema_version": 1, "target": target,
                                      "remote_activation_required": marker},
                "idempotency_key": "invalid-remote-intent",
            })
    finally:
        service.close()


@pytest.mark.parametrize("target,field,change", [
    (OLD, "provider_identity", {"account_ref": "account-a", "pod_id": "foreign-pod"}),
    (OLD, "child", {"attached": False}),
    (MACHINE, "machine_identity", {"id": "foreign-machine", "uid": 501}),
    (MACHINE, "machine_identity", {"id": "machine-a", "uid": 502}),
])
def test_placement_witness_cannot_substitute_provider_machine_or_child(tmp_path, target, field, change):
    service, task_id = _service(tmp_path, target=target)
    try:
        ref = _reference(tmp_path, service, task_id)
        observation = _observation(ref, service)
        observation[field] = change
        with pytest.raises(ConflictError):
            QualifiedRemoteWorkerLauncher._validate_observation(observation, target)
    finally:
        service.close()


def test_preparer_wait_error_does_not_override_independent_readiness(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def not_ready(_handle):
            preparer.calls.append("await_ready")
            raise ConflictError("preparer wait ended early")

        preparer.await_ready = not_ready
        qualification = launcher.activate(
            service._task_resource(service.store.get_task(task_id)), ref, parked,
        )
        assert launcher.activation_state == "active"
        assert service._latest_remote_activation(task_id) == qualification
        credentials.require(credentials.path_for("host").read_text().strip(), "worker:execute")
        assert "abort" not in preparer.calls
    finally:
        service.close()


def test_activation_order_commits_acceptance_before_ack_and_enables_after_ack(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    task = service._task_resource(service.store.get_task(task_id))
    order = []
    provision = credentials.provision
    enable = credentials.enable_actor
    record = service.record_remote_activation
    parked_holder = []

    def disabled_provision(*args, **kwargs):
        assert kwargs["enabled"] is False
        order.append("disabled-provision")
        return provision(*args, **kwargs)

    def acknowledge(_handle, grant, *, accept):
        order.append("private-acceptance-request")
        token = Path(grant["credential_file"]).read_text().strip()
        with pytest.raises(AuthorizationError):
            credentials.require(token, "worker:execute")
        accept(dict(grant), {"pid": 12345, "birth_id": "birth-1"})
        order.append("private-ack")
        assert service._latest_remote_activation(task_id) == launcher.activation_qualification
        with pytest.raises(AuthorizationError):
            credentials.require(token, "worker:execute")
        return {field: grant[field] for field in (
            "activation_id", "executor_incarnation", "evidence_digest",
        )}

    def enable_exact(actor):
        order.append("enable-exact")
        assert service._latest_remote_activation(task_id) == launcher.activation_qualification
        enable(actor)

    def accepted_record(*args, **kwargs):
        order.append("acceptance-commit")
        assert launcher.activation_state == "unknown"
        return record(*args, **kwargs)

    def initialize_register(_handle):
        order.append("initialize-register")
        identity = _identity(credentials)
        assert service._remote_activation_matches(task_id, identity, identity["execution_binding"])

    def independent_ready(_handle):
        order.append("independent-ready")
        assert service._latest_remote_activation(task_id) == launcher.activation_qualification
        return copy.deepcopy(inspector.current)

    monkeypatch.setattr(credentials, "provision", disabled_provision)
    monkeypatch.setattr(credentials, "enable_actor", enable_exact)
    monkeypatch.setattr(preparer, "acknowledge", acknowledge)
    monkeypatch.setattr(preparer, "await_ready", initialize_register)
    monkeypatch.setattr(inspector, "observe_ready", independent_ready)
    monkeypatch.setattr(service, "record_remote_activation", accepted_record)
    try:
        parked = launcher.park(ref, target=OLD)
        parked_holder.append(parked)
        launcher.activate(task, ref, parked)
        assert order == ["disabled-provision", "private-acceptance-request", "acceptance-commit",
                         "private-ack", "enable-exact", "initialize-register", "independent-ready"]
        assert _claim(service, OLD, _identity(credentials), "postcommit-claim")["task_id"] == task_id
    finally:
        service.close()


@pytest.mark.parametrize("phase", ["delivery", "enable", "wait", "readiness"])
@pytest.mark.parametrize("interruption", [OSError, KeyboardInterrupt])
def test_activation_interruption_preserves_exact_custody(
    tmp_path, monkeypatch, phase, interruption,
):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        original_enable = credentials.enable_actor

        def interrupt(*args, **kwargs):
            if phase == "enable":
                original_enable(*args, **kwargs)
            raise interruption("activation interrupted")

        owner, method = {
            "delivery": (preparer, "acknowledge"),
            "enable": (credentials, "enable_actor"),
            "wait": (preparer, "await_ready"),
            "readiness": (inspector, "observe_ready"),
        }[phase]
        monkeypatch.setattr(owner, method, interrupt)
        activate = lambda: launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        if phase in {"delivery", "enable", "readiness"} or interruption is KeyboardInterrupt:
            with pytest.raises(interruption):
                activate()
        else:
            activate()
        if phase == "delivery":
            assert launcher.activation_state == "inactive"
            assert launcher.activation_host is parked
            assert service._latest_remote_activation(task_id) is None
            assert credentials.actor_metadata("host") is None
            assert preparer.calls[-1] == "abort"
            with pytest.raises(ConflictError, match="permanently revoked"):
                service.record_remote_activation(task_id, launcher.activation_qualification, identity=OWNER)
        elif phase == "wait" and interruption is OSError:
            assert launcher.activation_state == "active"
            assert service._latest_remote_activation(task_id) == launcher.activation_qualification
            assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
            assert "abort" not in preparer.calls
        else:
            assert launcher.activation_state in {"unknown", "active"}
            assert service._latest_remote_activation(task_id) == launcher.activation_qualification
            assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
            assert "abort" not in preparer.calls
    finally:
        service.close()


@pytest.mark.parametrize("ready_failure", [
    "missing-inspector", "changed-runtime", "changed-epoch", "changed-runtime-session",
    "changed-source", "changed-dependencies", "changed-model-root", "changed-model",
    "changed-session-ref", "changed-session", "changed-output", "changed-capacity",
])
def test_wait_response_cannot_attest_host_readiness(tmp_path, monkeypatch, ready_failure):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        if ready_failure == "missing-inspector":
            monkeypatch.setattr(inspector, "observe_ready", None)
        else:
            ready = copy.deepcopy(inspector.current)
            field, value = {
                "changed-runtime": ("runtime_instance_id", "foreign-runtime"),
                "changed-epoch": ("runtime_epoch", ref.runtime_epoch + 1),
                "changed-runtime-session": ("runtime_session_id", "foreign-runtime-session"),
                "changed-source": ("source_closure_digest", "sha256:" + "9" * 64),
                "changed-dependencies": ("dependency_closure_digest", "sha256:" + "9" * 64),
                "changed-model-root": ("model_root", "/foreign/models"),
                "changed-output": ("output_root", "/foreign/outputs"),
                "changed-model": ("model_inventory_digest", "sha256:" + "9" * 64),
                "changed-session-ref": ("session_ref", "foreign-session"),
                "changed-session": ("session_config_digest", "sha256:" + "9" * 64),
                "changed-capacity": ("capacity", 2),
            }[ready_failure]
            ready[field] = value
            monkeypatch.setattr(inspector, "observe_ready", lambda _handle: ready)
        monkeypatch.setattr(preparer, "await_ready", lambda _handle: {"ready": True})
        with pytest.raises(ConflictError, match="readiness|capacity"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert launcher.activation_state == "unknown"
        assert service._latest_remote_activation(task_id) == launcher.activation_qualification
        assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
        assert "abort" not in preparer.calls
    finally:
        service.close()


@pytest.mark.parametrize("interruption", [OSError, KeyboardInterrupt])
def test_lost_commit_reply_reconciles_exact_activation_with_running_claim(tmp_path, monkeypatch, interruption):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        commit = service.record_remote_activation
        calls = 0

        def lost_reply(*args, **kwargs):
            nonlocal calls
            calls += 1
            assert launcher.activation_state == "unknown"
            result = commit(*args, **kwargs)
            if calls == 1:
                token = credentials.path_for("host").read_text().strip()
                with pytest.raises(AuthorizationError):
                    credentials.require(token, "worker:execute")
                raise interruption("commit reply lost")
            return result

        monkeypatch.setattr(service, "record_remote_activation", lost_reply)
        if interruption is KeyboardInterrupt:
            with pytest.raises(ConflictError, match="may have admitted work"):
                launcher.activate(task, ref, parked)
            assert launcher.activation_state == "unknown"
            assert launcher.activation_host is parked
            assert service._latest_remote_activation(task_id) == launcher.activation_qualification
            assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
            assert "abort" not in preparer.calls
            assert calls == 1
        else:
            assert launcher.activate(task, ref, parked) == launcher.activation_qualification
            assert launcher.activation_state == "active"
            assert "abort" not in preparer.calls
            assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
            assert calls == 2
            credentials.require(credentials.path_for("host").read_text().strip(), "worker:execute")
    finally:
        service.close()


def test_recreated_launcher_restores_exact_custody_and_replays_after_claim(tmp_path, monkeypatch):
    service, task_id, ref, credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        commit = service.record_remote_activation
        calls = 0

        def lost_reply(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                commit(*args, **kwargs)
                token = credentials.path_for("host").read_text().strip()
                with pytest.raises(AuthorizationError):
                    credentials.require(token, "worker:execute")
            raise OSError("commit reply lost")

        monkeypatch.setattr(service, "record_remote_activation", lost_reply)
        with pytest.raises(ConflictError, match="may have admitted work"):
            launcher.activate(task, ref, parked)
        assert launcher.activation_state == "unknown"
        assert calls == 2
        saved = next(details["qualification"] for _host, stage, details in preparer.checkpoints
                     if stage == "qualification")
        assert preparer.checkpoints[-1][1] == "credential"
        token = credentials.path_for("host").read_text().strip()
        restored = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
        )
        rehydrated = restored.restore_prepared_activation(task, ref, saved)
        assert isinstance(rehydrated, ParkedRemoteHost)
        assert restored.activation_state == "unknown"
        assert restored.activation_host is rehydrated
        assert rehydrated is not parked
        assert rehydrated.observation == parked.observation
        assert restored.activation_credential_digest == hashlib.sha256(token.encode()).hexdigest()
        monkeypatch.setattr(service, "record_remote_activation", commit)
        assert restored.reconcile_activation(task, ref, rehydrated, saved) == saved
        assert restored.activation_state == "active"
        assert service.task(task_id)["task"]["status"] == "queued"
        assert preparer.checkpoints[-1][1] == "committed"
        assert credentials.path_for("host").read_text().strip() == token
        assert "abort" not in preparer.calls
    finally:
        service.close()


def test_committed_checkpoint_failure_keeps_custody_for_exact_replay(tmp_path):
    service, task_id, ref, credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    preparer.fail_stage = "committed"
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        with pytest.raises(OSError, match="checkpoint unavailable"):
            launcher.activate(task, ref, parked)
        qualification = launcher.activation_qualification
        assert service._latest_remote_activation(task_id) == qualification
        assert launcher.activation_state == "unknown"
        assert credentials.actor_metadata("host")["qualified_activation"] == qualification
        assert "abort" not in preparer.calls
        preparer.fail_stage = None
        assert launcher.reconcile_activation(task, ref, parked, qualification) == qualification
        assert launcher.activation_state == "active"
    finally:
        service.close()


@pytest.mark.parametrize("alter", ["process", "incarnation"])
def test_restore_prepared_rejects_foreign_process_checkpoint(tmp_path, monkeypatch, alter):
    service, task_id, ref, credentials, _preparer, inspector, _launcher = _fixture(tmp_path)
    preparer = CheckpointPreparer()
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        actual_restore = preparer.restore

        def foreign_restore(reference):
            checkpoint = actual_restore(reference)
            if alter == "incarnation":
                return replace(checkpoint, executor_incarnation="foreign-process")
            observation = copy.deepcopy(checkpoint.observation)
            observation["process"]["birth_id"] = "foreign-birth"
            return replace(checkpoint, observation=observation)

        monkeypatch.setattr(preparer, "restore", foreign_restore)
        restored = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
        )
        with pytest.raises(ConflictError, match="foreign|observation changed"):
            restored.restore_prepared_activation(task, ref, qualification)
        assert restored.activation_state == "inactive"
        assert restored.activation_host is None
    finally:
        service.close()


@pytest.mark.parametrize("field,foreign", [
    ("activation_id", "foreign-generation"),
    ("credential_actor", "other-host"),
    ("deployment_digest", "sha256:" + "9" * 64),
    ("executor_incarnation", "foreign-process"),
    ("observation_digest", "sha256:" + "9" * 64),
    ("task_id", "foreign-task"),
])
def test_restore_rejects_foreign_persisted_generation(tmp_path, monkeypatch, field, foreign):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        restored = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
        )
        bad = {**qualification, field: foreign}

        def forbidden_commit(*_args, **_kwargs):
            pytest.fail("foreign generation must not reach Runtime commit")

        monkeypatch.setattr(service, "record_remote_activation", forbidden_commit)
        with pytest.raises(ConflictError, match="foreign or incomplete|credential generation changed"):
            restored.restore_activation(task, ref, parked, bad)
        assert restored.activation_state == "inactive"
        assert restored.activation_host is None
    finally:
        service.close()


@pytest.mark.parametrize("cut", ["before-record", "replay-unavailable", "ready-unavailable", "foreign-replay"])
def test_uncertain_commit_retains_custody_until_exact_ready_reconciliation(tmp_path, monkeypatch, cut):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        commit = service.record_remote_activation
        ready = inspector.observe_ready
        calls = 0

        def unavailable(*_args):
            raise OSError("readback unavailable")

        def lost_reply(*args, **kwargs):
            nonlocal calls
            calls += 1
            assert launcher.activation_state == "unknown"
            if cut != "before-record" and calls == 1:
                commit(*args, **kwargs)
            if cut == "ready-unavailable" and calls == 1:
                monkeypatch.setattr(inspector, "observe_ready", unavailable)
            if cut == "foreign-replay" and calls > 1:
                foreign = {**args[1], "activation_id": "foreign-generation"}
                return foreign
            raise OSError("commit reply lost")

        monkeypatch.setattr(service, "record_remote_activation", lost_reply)
        if cut == "before-record":
            with pytest.raises(OSError, match="commit reply lost"):
                launcher.activate(task, ref, parked)
        elif cut == "foreign-replay":
            with pytest.raises(ConflictError, match="activation|commit"):
                launcher.activate(task, ref, parked)
        else:
            with pytest.raises(ConflictError, match="may have admitted|uncommitted"):
                launcher.activate(task, ref, parked)
        qualification = launcher.activation_qualification
        assert launcher.activation_host is parked
        if cut == "before-record":
            assert launcher.activation_state == "inactive"
            assert service._latest_remote_activation(task_id) is None
            assert credentials.actor_metadata("host") is None
            assert preparer.calls[-1] == "abort"
            monkeypatch.setattr(service, "record_remote_activation", commit)
            with pytest.raises(ConflictError, match="permanently revoked"):
                service.record_remote_activation(task_id, qualification, identity=OWNER)
            return
        token = credentials.path_for("host").read_bytes()
        with pytest.raises(ConflictError, match="unresolved"):
            launcher.activate(task, ref, parked)
        assert launcher.activation_state == "unknown"
        assert service._latest_remote_activation(task_id) == qualification
        assert credentials.actor_metadata("host")["qualified_activation"] == qualification
        assert "abort" not in preparer.calls
        monkeypatch.setattr(inspector, "observe_ready", ready)
        monkeypatch.setattr(service, "record_remote_activation", commit)
        assert launcher.reconcile_activation(task, ref, parked, qualification) == qualification
        assert launcher.activation_state == "active"
        assert credentials.path_for("host").read_bytes() == token
        assert "abort" not in preparer.calls
    finally:
        service.close()


def test_precommit_cleanup_retains_host_when_activation_absence_cannot_be_proven(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        preparer.bad_ack = True

        def unknown_history(*_args):
            raise OSError("activation history unavailable")

        monkeypatch.setattr(service, "_remote_activation_history", unknown_history)
        with pytest.raises(OSError, match="history unavailable"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert launcher.activation_state == "unknown"
        assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
        assert "abort" not in preparer.calls
    finally:
        service.close()


def test_precommit_cleanup_does_not_revoke_a_rotated_credential_generation(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        acknowledge = preparer.acknowledge

        def rotate_before_reply(handle, grant, *, accept):
            metadata = credentials.actor_metadata("host")
            credentials.provision("host", ["worker:execute"], rotate=True, enabled=False,
                                  metadata={"execution_binding": metadata["execution_binding"],
                                            "qualified_activation": metadata["qualified_activation"]})
            return acknowledge(handle, grant, accept=accept)

        monkeypatch.setattr(preparer, "acknowledge", rotate_before_reply)
        with pytest.raises(ConflictError, match="generation changed"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert launcher.activation_state == "unknown"
        assert launcher.activation_host is parked
        assert credentials.actor_metadata("host")["qualified_activation"] == launcher.activation_qualification
        assert service._latest_remote_activation(task_id) == launcher.activation_qualification
        assert "abort" not in preparer.calls
    finally:
        service.close()


def test_abort_failure_retains_unknown_process_custody_after_exact_revocation(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        preparer.bad_ack = True

        def abort_unconfirmed(_handle):
            raise OSError("remote stop reply lost")

        monkeypatch.setattr(preparer, "abort", abort_unconfirmed)
        with pytest.raises(OSError, match="stop reply lost"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert launcher.activation_state == "unknown"
        assert launcher.activation_host is parked
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert service._remote_activation_history(task_id, launcher.activation_qualification["activation_id"])[-1][0] == "task.remote_activation_revoked"
    finally:
        service.close()


@pytest.mark.parametrize("field,bad", [
    ("process", {"pid": 12345, "birth_id": "changed", "pgid": 12345, "sid": 12345}),
    ("model_root", "/wrong/models"),
    ("session_ref", "other-session"),
    ("data_root", "/wrong/data"),
    ("capacity", 2),
])
def test_changed_observation_blocks_activation_before_credential(tmp_path, field, bad):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        inspector.current[field] = bad
        with pytest.raises(ConflictError):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert "private_ack" not in preparer.calls
    finally:
        service.close()


def test_private_ack_failure_revokes_disabled_credential_and_leaves_task_queued(tmp_path):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        preparer.bad_ack = True
        with pytest.raises(ConflictError, match="acknowledgement"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert service.task(task_id)["task"]["status"] == "queued"
    finally:
        service.close()


def test_revocation_expiry_and_replay_fail_closed(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        claimed = _claim(service, OLD, identity, "one-claim")
        assert claimed["task_id"] == task_id
        service.revoke_remote_activation(task_id, qualification["activation_id"], identity=OWNER)
        with pytest.raises(AuthorizationError, match="activation"):
            _claim(service, OLD, identity, "one-claim")
        with pytest.raises(AuthorizationError, match="activation"):
            service._assert_attempt_identity({"task_id": task_id, "executor_id": "host"}, identity)
    finally:
        service.close()


def test_exact_committed_activation_replay_returns_receipt_after_expiry(tmp_path):
    service, task_id, ref, _credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        qualification = launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        expired = copy.deepcopy(qualification)
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute(
            "UPDATE events SET payload_json=? WHERE task_id=? AND kind='task.remote_activation_qualified'",
            (json.dumps(expired, sort_keys=True, separators=(",", ":")), task_id),
        )
        assert service.record_remote_activation(task_id, expired, identity=OWNER) == expired
        new_generation = {**expired, "activation_id": "new-expired-generation"}
        with pytest.raises(ConflictError, match="expired"):
            service.record_remote_activation(task_id, new_generation, identity=OWNER)
    finally:
        service.close()


def test_expired_qualification_allows_replay_of_bound_claim_but_not_new_claim(tmp_path):
    service, task_id = _service(tmp_path)
    try:
        task = service._task_resource(service.store.get_task(task_id))
        second = service.create_task({
            "capability_id": CAPABILITY,
            "capability_digest": CAPABILITY_DIGEST,
            "project": task["project_id"],
            "input_object_ids": task["input_object_ids"],
            "spec": {"inputs": {"source": task["input_object_ids"][0]}},
            "execution_request": task["execution_request"],
            "idempotency_key": "second-canonical-admission",
        }, enforce_readiness=True)
        # The first task's activation is the only qualified generation. The
        # second queued task must not inherit it merely because the worker and
        # target are otherwise identical.
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(_reference(tmp_path, service, task_id), service)),
        )
        reference = _reference(tmp_path, service, task_id)
        parked_host = launcher.park(reference, target=OLD)
        qualification = launcher.activate(task, reference, parked_host)
        identity = _identity(credentials)
        first = _claim(service, OLD, identity, "bound-claim")
        assert first["task_id"] == task_id
        expired_identity = _expired_identity(service, credentials, task_id)
        replay = _claim(service, OLD, expired_identity, "bound-claim")
        assert replay["attempt_id"] == first["attempt_id"]
        new_claim = _claim(service, OLD, expired_identity, "new-claim-after-expiry")
        assert new_claim["task"]["task_id"] == second["task"]["id"]
        assert new_claim["waiting_reason"] == "remote_activation_missing"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (second["task"]["id"],)
        ).fetchone()[0] == 0
        assert qualification["activation_id"] == expired_identity["qualified_activation"]["activation_id"]
    finally:
        service.close()


@pytest.mark.parametrize("operation", ["heartbeat", "settle", "fail"])
def test_expired_qualification_remains_authoritative_for_bound_attempt(tmp_path, operation):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        claim = _claim(service, OLD, identity, f"expired-{operation}-claim")
        identity = _expired_identity(service, credentials, task_id)
        lease = {
            "lease_id": claim["lease_id"], "fence": claim["fence"],
            "runtime_epoch": claim["runtime_epoch"],
        }
        if operation == "heartbeat":
            result = service.heartbeat_attempt(
                claim["attempt_id"], {**lease, "progress": {"phase": "still-running"}},
                idempotency_key="expired-heartbeat", identity=identity,
            )
            assert result["data"]["attempt_id"] == claim["attempt_id"]
        elif operation == "settle":
            result = service.settle_attempt(
                claim["attempt_id"], {**lease, "outputs": []},
                idempotency_key="expired-settle", identity=identity,
            )
            assert result["data"]["task_id"] == task_id
        else:
            result = service.fail_attempt(
                claim["attempt_id"], {**lease, "error": {"code": "expired-proof-test"}},
                idempotency_key="expired-fail", identity=identity,
            )
            assert result["data"]["task_id"] == task_id
    finally:
        service.close()


@pytest.mark.parametrize("capacity", [1, 2])
def test_qualified_machine_parent_and_exact_child_obey_registered_slots(tmp_path, capacity):
    service, task_id = _service(tmp_path, child_delegation=True, target=MACHINE, capacity=capacity)
    try:
        ref = replace(_reference(tmp_path, service, task_id), capacity=capacity)
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(ref, service)),
        )
        parked = launcher.park(ref, target=MACHINE)
        qualification = launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        identity = _identity(credentials)
        parent = _claim(service, MACHINE, identity, "slot-parent")
        authority = service.issue_child_authority(
            parent["attempt_id"],
            {key: parent[key] for key in ("lease_id", "fence", "runtime_epoch")},
            identity=identity,
        )["authority"]

        def admit_child(key):
            return service.admit_delegated_child({
                "authority": authority,
                "task": {
                    "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
                    "input_object_ids": [], "spec": {},
                    "execution_request": {"schema_version": 1, "target": MACHINE, "inputs": []},
                },
            }, idempotency_key=key, identity=identity)["task"]["id"]

        def claim_child(child, key):
            return service.claim_delegated_child(child, {
                "executor_id": "host", "capability_ids": [CAPABILITY],
                "runtime_epoch": parent["runtime_epoch"], "target": MACHINE, "authority": authority,
            }, idempotency_key=key, identity=identity)

        child = admit_child("slot-child")
        blocked = child
        if capacity == 2:
            claimed = claim_child(child, "slot-child-claim")
            assert claim_child(child, "slot-child-claim")["attempt_id"] == claimed["attempt_id"]
            for attempt in (parent, claimed):
                binding = attempt["execution_binding"]
                assert binding["actual_target"] == MACHINE
                assert binding["executor_incarnation"] == qualification["executor_incarnation"]
                assert binding["verification"] == {
                    "method": "credential_claim", "verified": True,
                    "evidence_digest": qualification["evidence_digest"],
                }
            blocked = admit_child("slot-third")
        before = service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        with pytest.raises(ConflictError, match="preflight") as error:
            claim_child(blocked, "slot-over-limit")
        assert error.value.details["waiting_reason"] == "waiting_for_worker"
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == before == capacity
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE executor_id='host' AND status='running'",
        ).fetchone()[0] == capacity
        assert service.store.conn.execute(
            "SELECT max_concurrency FROM executors WHERE id='host'",
        ).fetchone()[0] == capacity
        assert service.store.get_task(blocked)["task"]["status"] == "queued"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (blocked,),
        ).fetchone()[0] == 0
    finally:
        service.close()


@pytest.mark.parametrize("capacity,observed", [(1, 2), (2, 1)])
def test_initial_observation_capacity_must_equal_deployment(tmp_path, capacity, observed):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        ref = replace(ref, capacity=capacity)
        inspector.current["capacity"] = observed
        parked = launcher.park(ref, target=OLD)
        with pytest.raises(ConflictError, match="capacity evidence changed"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert "private_ack" not in preparer.calls
    finally:
        service.close()


@pytest.mark.parametrize("capacity", [0, 3, -1, True, 2.0, "2"])
def test_observation_rejects_unsupported_slot_counts(tmp_path, capacity):
    service, _task_id, _ref, _credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        inspector.current["capacity"] = capacity
        with pytest.raises(ConflictError, match="capacity"):
            launcher.park(_ref, target=OLD)
        assert preparer.calls == ["prepare", "abort"]
    finally:
        service.close()


@pytest.mark.parametrize("target", [OLD, MACHINE])
@pytest.mark.parametrize("finish", [False, True])
def test_qualified_credential_is_scoped_to_authorized_child_lineage(tmp_path, target, finish):
    service, task_id = _service(tmp_path, child_delegation=True, target=target)
    try:
        ref = _reference(tmp_path, service, task_id)
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(ref, service)),
        )
        parked = launcher.park(ref, target=target)
        task = service._task_resource(service.store.get_task(task_id))
        launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        parent = _claim(service, target, identity, "qualified-parent")
        authority = service.issue_child_authority(
            parent["attempt_id"], {
                "lease_id": parent["lease_id"], "fence": parent["fence"],
                "runtime_epoch": parent["runtime_epoch"],
            }, identity=identity,
        )["authority"]
        child = service.admit_delegated_child({
            "authority": authority,
            "task": {
                "capability_id": CAPABILITY,
                "capability_digest": CAPABILITY_DIGEST,
                "input_object_ids": [],
                "spec": {"params": {"child": "authorized"}},
                "execution_request": {"schema_version": 1, "target": target, "inputs": []},
            },
        }, idempotency_key="authorized-child", identity=identity)
        claimed_child = _claim(service, target, identity, "authorized-child-claim")
        assert claimed_child["task_id"] == child["task"]["id"]
        replayed_child = _claim(service, target, identity, "authorized-child-claim")
        assert replayed_child["attempt_id"] == claimed_child["attempt_id"]
        heartbeat = service.heartbeat_attempt(
            claimed_child["attempt_id"], {
                "lease_id": claimed_child["lease_id"],
                "fence": claimed_child["fence"],
                "runtime_epoch": claimed_child["runtime_epoch"],
            }, idempotency_key="authorized-child-heartbeat", identity=identity,
        )
        assert heartbeat["data"]["attempt_id"] == claimed_child["attempt_id"]
        # Two actual resident attempts make progress while the parent's lease
        # remains live. Machine evidence carries no invented remote child.
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE executor_id='host' AND settled=0"
        ).fetchone()[0] == 2
        parent_lease = {key: parent[key] for key in ("lease_id", "fence", "runtime_epoch")}
        progress = service.heartbeat_attempt(
            parent["attempt_id"], {**parent_lease, "progress": {"phase": "child-running"}},
            idempotency_key="parent-with-live-child", identity=identity,
        )
        assert progress["data"]["attempt_id"] == parent["attempt_id"]
        if finish:
            child_lease = {key: claimed_child[key] for key in ("lease_id", "fence", "runtime_epoch")}
            service.settle_attempt(
                claimed_child["attempt_id"], {**child_lease, "outputs": []},
                idempotency_key="child-progress-completed", identity=identity,
            )
            service.heartbeat_attempt(
                parent["attempt_id"], {**parent_lease, "progress": {"phase": "child-completed"}},
                idempotency_key="parent-after-child-completed", identity=identity,
            )
            service.settle_attempt(
                parent["attempt_id"], {**parent_lease, "outputs": []},
                idempotency_key="parent-progress-completed", identity=identity,
            )
            assert service.task(child["task"]["id"])["task"]["status"] == "completed"
            assert service.task(task_id)["task"]["status"] == "completed"
        service.revoke_remote_activation(
            task_id, identity["qualified_activation"]["activation_id"], identity=OWNER,
        )
        with pytest.raises(AuthorizationError, match="remote activation"):
            service.heartbeat_attempt(
                claimed_child["attempt_id"], {
                    "lease_id": claimed_child["lease_id"],
                    "fence": claimed_child["fence"],
                    "runtime_epoch": claimed_child["runtime_epoch"],
                }, idempotency_key="revoked-child-heartbeat", identity=identity,
            )

        foreign = copy.deepcopy(identity)
        foreign["qualified_activation"]["authorized_child_lineage"]["parent_task_id"] = "foreign-parent"
        with pytest.raises(AuthorizationError, match="remote activation"):
            service._assert_attempt_identity(
                {"task_id": child["task"]["id"], "executor_id": "host"}, foreign,
            )
    finally:
        service.close()


def test_revoked_activation_generation_is_tombstoned_and_replacement_needs_new_generation(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        service.revoke_remote_activation(task_id, qualification["activation_id"], identity=OWNER)
        with pytest.raises(ConflictError, match="permanently revoked"):
            service.record_remote_activation(task_id, qualification, identity=OWNER)
        replacement = copy.deepcopy(qualification)
        replacement["activation_id"] = "replacement-generation"
        assert service.record_remote_activation(task_id, replacement, identity=OWNER) == replacement
    finally:
        service.close()


def test_recovered_placement_requires_matching_new_qualification(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        original_binding = deployment_binding_from_task(task)
        old_activation = launcher.activate(task, ref, parked)
        old_identity = _identity(credentials)
        claimed = _claim(service, OLD, old_identity, "old-claim")
        service.fail_attempt(claimed["attempt_id"], {
            "lease_id": claimed["lease_id"], "fence": claimed["fence"],
            "runtime_epoch": claimed["runtime_epoch"], "error": {"code": "old-pod-lost"},
        }, idempotency_key="old-fail", identity=old_identity)
        with pytest.raises(ConflictError, match="queued task or exact recovered"):
            service.assert_remote_activation_admissible(task_id, old_activation)
        new_ref = replace(ref, effective_target=NEW, execution_target=NEW,
                          effective_target_ref="runpod:pod-new")
        new_inspector = Inspector(_observation(new_ref, service))
        new_launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(), inspector=new_inspector,
        )
        new_parked = new_launcher.park(new_ref, target=NEW)
        before = service._task_resource(service.store.get_task(task_id))
        recovery = service.recover_task_placement(task_id, {
            "schema_version": 1, "expected_task_version": before["version"],
            "expected_placement_version": 0, "expected_original_target": OLD,
            "expected_current_target": OLD, "replacement_target": NEW,
            "reason": "old exact pod absent", "loss_evidence": {
                "source": "independent-provider", "status": "absent", "target": OLD,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "evidence_digest": "sha256:" + "9" * 64, "no_active_work": True,
            }, "qualification": new_parked.recovery_qualification(),
        }, idempotency_key="recover-once", identity=OWNER)
        assert recovery["data"]["placement_recovery"]["placement_version"] == 1
        assert service._latest_remote_activation(task_id) is None
        fresh = service._task_resource(service.store.get_task(task_id))
        recovered_ref = _reference(tmp_path, service, task_id)
        candidate = {**old_activation, "binding_digest": recovered_ref.deployment_binding.digest(),
                     "effective_target": NEW, "evidence_digest": new_parked.evidence_digest,
                     "executor_incarnation": new_parked.executor_incarnation,
                     "authorized_child_lineage": {**old_activation["authorized_child_lineage"],
                                                  "effective_target": NEW, "placement_version": 1}}
        service.assert_remote_activation_admissible(task_id, candidate)
        for field, bad in (("binding_digest", old_activation["binding_digest"]),
                           ("effective_target", OLD), ("evidence_digest", "sha256:" + "0" * 64),
                           ("executor_incarnation", "foreign"),
                           ("authorized_child_lineage", {**candidate["authorized_child_lineage"], "placement_version": 0})):
            with pytest.raises(ConflictError):
                service.assert_remote_activation_admissible(task_id, {**candidate, field: bad})
        service.store.conn.execute("UPDATE attempts SET settled=0 WHERE id=?", (claimed["attempt_id"],))
        with pytest.raises(ConflictError, match="unknown active work"):
            service.assert_remote_activation_admissible(task_id, candidate)
        service.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (claimed["attempt_id"],))
        service.store.conn.execute(
            "INSERT INTO reservations(task_id,resource_key,lease_token,created_at,released_at,executor_id,fence,lease_expires_at,runtime_epoch) "
            "VALUES (?, 'recovery-test', ?, ?, NULL, 'host', ?, ?, ?)",
            (task_id, claimed["lease_id"], datetime.now(timezone.utc).isoformat(), claimed["fence"],
             datetime.now(timezone.utc).isoformat(), claimed["runtime_epoch"]),
        )
        with pytest.raises(ConflictError, match="active reservation"):
            service.assert_remote_activation_admissible(task_id, candidate)
        service.store.conn.execute("DELETE FROM reservations WHERE task_id=? AND resource_key='recovery-test'", (task_id,))
        new_activation = new_launcher.activate(fresh, recovered_ref, new_parked)
        assert new_activation["binding_digest"] != old_activation["binding_digest"]
        assert fresh["run_id"] == task["run_id"]
        assert fresh["input_object_ids"] == task["input_object_ids"]
        assert fresh["execution_request"] == task["execution_request"]
        recovered_binding = deployment_binding_from_task(fresh)
        assert recovered_binding.admission_identity == original_binding.admission_identity
        assert recovered_binding.capability_identity == original_binding.capability_identity
        assert recovered_binding.input_bindings == original_binding.input_bindings
    finally:
        service.close()

