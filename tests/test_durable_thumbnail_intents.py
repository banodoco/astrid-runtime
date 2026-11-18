"""LS-6: primary settlement owns durable, bounded enhancement admission."""
import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from tests.test_generation_thumbnail_settlement import (
    CAPABILITY, _create_effect, _digest, _output, _seed_generation, _service, _settle, _task,
)

THUMBNAIL = "generation.thumbnail_backfill"


def register(service, executor):
    service.register_executor({"executor_id": executor, "runtime_epoch": service.health()["runtime_epoch"],
        "capabilities": [{"capability_id": name, "definition_digest": _digest(name),
                          "status": "ready", "required_resource_keys": [],
                          "estimated_scratch_bytes": 2 * 1024 * 1024, "estimated_output_bytes": 512 * 1024}
                         for name in (CAPABILITY, THUMBNAIL)]},
        idempotency_key=f"register-{executor}-{service.health()['runtime_epoch']}")


def worker(service, executor):
    return {"executor_id": executor, "runtime_epoch": service.health()["runtime_epoch"]}


def pending(service, executor):
    return service.pending_thumbnail_intents(worker(service, executor),
        identity={"actor": executor, "scopes": ["worker:execute"]})


def test_primary_reply_precedes_admission_and_restart_admits_once(tmp_path):
    service, project = _service(tmp_path, "restart-intent")
    executor = "restart-intent-worker"
    root = service.store.root
    try:
        seeded = _seed_generation(service, project, key="main", with_thumbnail=False)
        parent_id = seeded["task"]["task"]["id"]
        main = service.store.get_task(parent_id)["task"]
        assert main["status"] == "completed"
        intent, = main["result"]["thumbnail_intents"]
        assert intent["attempt_id"] == main["attempt_id"]
        assert intent["source_object_id"] == seeded["source_object_id"]
        assert intent["project_id"] == project["id"]
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        service.close()
    service = RuntimeService(root)
    try:
        register(service, executor)
        assert pending(service, executor)["items"] == [intent]
        identity = {"actor": executor, "scopes": ["worker:execute"]}
        first = service.admit_thumbnail_intent(parent_id, intent["intent_id"], worker(service, executor), identity=identity)
        # Repeating after the first response was lost reuses ordinary task identity.
        second = service.admit_thumbnail_intent(parent_id, intent["intent_id"], worker(service, executor), identity=identity)
        assert first["task"]["id"] == second["task"]["id"]
        assert first["task"]["expected_effect"]["payload"]["source_object_id"] == seeded["source_object_id"]
        assert first["task"]["spec"]["input_object_ids"] == [seeded["source_object_id"]]
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 2
        assert pending(service, executor)["items"] == []
        assert service.store.get_task(parent_id)["task"]["status"] == "completed"
    finally:
        service.close()


def test_existing_thumbnail_does_not_create_pending_intent(tmp_path):
    service, project = _service(tmp_path, "already-ready")
    try:
        seeded = _seed_generation(service, project, key="ready", with_thumbnail=True)
        assert "thumbnail_intents" not in service.store.get_task(seeded["task"]["task"]["id"])["task"]["result"]
        assert pending(service, "already-ready-worker")["items"] == []
    finally:
        service.close()


@pytest.mark.parametrize("change", ["actor", "epoch", "extra", "source-change"])
def test_intent_admission_cannot_change_owner_epoch_or_source(tmp_path, change):
    service, project = _service(tmp_path, "guard-intent")
    executor = "guard-intent-worker"
    try:
        seeded = _seed_generation(service, project, key="guard", with_thumbnail=False)
        register(service, executor)
        intent, = pending(service, executor)["items"]
        body = worker(service, executor)
        identity = {"actor": executor, "scopes": ["worker:execute"]}
        if change == "actor":
            identity["actor"] = "foreign-worker"
        elif change == "epoch":
            body["runtime_epoch"] += 1
        elif change == "extra":
            body["source_object_id"] = _digest(b"substitute")
        else:
            # A later primary change cannot turn the old intent into a new source.
            service.ingest(project["id"], b"substitute", media_type="video/mp4", idempotency_key="substitute")
            service.store.conn.execute("UPDATE generation_variants SET object_id=? WHERE id=?",
                                       (_digest(b"substitute").removeprefix("sha256:"), seeded["variant_id"]))
        with pytest.raises((AuthorizationError, ConflictError, ValidationError)):
            service.admit_thumbnail_intent(intent["task_id"], intent["intent_id"], body, identity=identity)
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        service.close()


def test_worker_cannot_supply_a_thumbnail_intent(tmp_path):
    service, project = _service(tmp_path, "forged-intent")
    try:
        effect = _create_effect(project["id"])
        source = service.ingest(project["id"], b"admitted source", media_type="image/png",
                                idempotency_key="forged-input")["data"]["digest"]
        task, attempt = _task(service, project["id"], effect, key="forged", inputs=[source])
        with pytest.raises(ValidationError, match="reserved"):
            service.settle_attempt(attempt["attempt_id"], {
                "lease_id": attempt["lease_id"], "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [_output(b"video", name="video", media_type="video/mp4", ordinal=0)], "effect": effect,
                "result": {"thumbnail_intents": [{"source_object_id": _digest(b"unrelated")}]}},
                idempotency_key="forged-settlement")
        assert service.store.get_task(task["task"]["id"])["task"]["status"] == "running"
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
    finally:
        service.close()


def test_effect_rollback_leaves_no_thumbnail_intent(tmp_path, monkeypatch):
    service, project = _service(tmp_path, "rollback-intent")
    try:
        effect = _create_effect(project["id"])
        source = service.ingest(project["id"], b"admitted source", media_type="image/png",
                                idempotency_key="rollback-input")["data"]["digest"]
        task, attempt = _task(service, project["id"], effect, key="rollback", inputs=[source])
        append = service.store._append_event
        def refuse(*args, **kwargs):
            if len(args) > 2 and args[2] == "task.completed":
                raise OSError("commit interrupted")
            return append(*args, **kwargs)
        monkeypatch.setattr(service.store, "_append_event", refuse)
        with pytest.raises(OSError, match="commit interrupted"):
            _settle(service, attempt, effect, [_output(b"video", name="video", media_type="video/mp4", ordinal=0)])
        assert service.store.get_task(task["task"]["id"])["task"]["status"] == "running"
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert pending(service, "rollback-intent-worker")["items"] == []
    finally:
        service.close()


def test_failed_thumbnail_remains_retryable_without_repeating_generation(tmp_path):
    service, project = _service(tmp_path, "retry-intent")
    executor = "retry-intent-worker"
    try:
        seeded = _seed_generation(service, project, key="primary", with_thumbnail=False)
        register(service, executor)
        intent, = pending(service, executor)["items"]
        admitted = service.admit_thumbnail_intent(intent["task_id"], intent["intent_id"], worker(service, executor))
        task_id = admitted["task"]["id"]
        claim = service.claim_next({**worker(service, executor), "capability_ids": [THUMBNAIL]},
                                   idempotency_key="thumbnail-claim")
        assert claim["task_id"] == task_id
        service.fail_attempt(claim["attempt_id"], {**{key: claim[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "error": {"code": "thumbnail_extraction_failed", "message": "decoder refused"}}, idempotency_key="thumbnail-failed")
        failed = service._task_resource(service.task(task_id))
        assert failed["state"] == "failed"
        assert pending(service, executor)["items"] == []
        assert service.admit_thumbnail_intent(intent["task_id"], intent["intent_id"], worker(service, executor))["task"]["id"] == task_id
        service.retry_task(task_id, {"expected_version": failed["version"]}, idempotency_key="retry-thumbnail")
        retried = service.claim_next({**worker(service, executor), "capability_ids": [THUMBNAIL]},
                                     idempotency_key="thumbnail-retry-claim")
        assert retried["task_id"] == task_id and retried["attempt_id"] != claim["attempt_id"]
        assert service.store.get_task(seeded["task"]["task"]["id"])["task"]["status"] == "completed"
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 2
    finally:
        service.close()


def test_scoped_http_worker_admits_only_its_stored_intent(tmp_path):
    from astrid_runtime_client import ApiError, WorkspaceClient
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.store import RealmStore

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        executor = "intent-worker"
        register(service, executor)
        project = service.create_project({"slug": "http-intent", "name": "HTTP intent"}, idempotency_key="project")
        _seed_generation(service, project, key="primary", with_thumbnail=False)
        token, _ = daemon.credentials.provision(executor, ["handshake", "worker:execute", "tasks:read"])
        client = WorkspaceClient(daemon.endpoint, token)
        epoch = service.health()["runtime_epoch"]
        intent, = client.pending_thumbnail_intents(executor_id=executor, runtime_epoch=epoch)["items"]
        with pytest.raises(ApiError) as denied:
            client.admit_task(capability_id=THUMBNAIL, capability_digest=_digest(THUMBNAIL),
                              input_object_ids=[], idempotency_key="arbitrary")
        assert denied.value.status == 401
        admitted = client.admit_thumbnail_intent(intent["task_id"], intent["intent_id"],
                                                executor_id=executor, runtime_epoch=epoch)
        assert admitted.receipt is not None
        assert admitted["capability_id"] == THUMBNAIL
        assert client.pending_thumbnail_intents(executor_id=executor, runtime_epoch=epoch)["items"] == []
        other, _ = daemon.credentials.provision("foreign", ["handshake", "worker:execute", "tasks:read"])
        foreign = WorkspaceClient(daemon.endpoint, other)
        with pytest.raises(ApiError) as denied:
            foreign.admit_thumbnail_intent(intent["task_id"], intent["intent_id"], executor_id=executor, runtime_epoch=epoch)
        assert denied.value.status == 401
    finally:
        daemon.stop()
