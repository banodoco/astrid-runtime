"""R14-FIX-12: ordinary task retries retain each attempt's durable logs."""
from __future__ import annotations

import base64
from copy import deepcopy
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore
from tests.test_managed_output_public_api import CAPABILITY, _digest, _output


def _logs(label: str) -> list[dict]:
    return [
        _output(
            f"{label} {name}\n".encode(), name=name, filename=name + ".log",
            media_type="text/plain", output_port="logs", group_key="default",
            variant_key=name, ordinal=0, role="log", durability="durable",
        )
        for name in ("job.stdout", "job.stderr")
    ]


@pytest.fixture
def ordinary(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        executor = "ordinary-log-worker"
        service.register_executor(
            {"executor_id": executor, "capabilities": [CAPABILITY]},
            idempotency_key="executor",
        )
        project = service.create_project(
            {"slug": "ordinary-logs", "name": "Ordinary logs"}, idempotency_key="project",
        )
        task = service.create_task({
            "capability_id": CAPABILITY, "capability_digest": _digest(CAPABILITY),
            "project": project["id"], "input_object_ids": [], "idempotency_key": "task",
        })
        token, _ = daemon.credentials.provision(
            executor, ["handshake", "worker:execute", "tasks:read", "objects:read"],
        )
        yield SimpleNamespace(
            service=service, owner=WorkspaceClient(daemon.endpoint, daemon.token),
            worker=WorkspaceClient(daemon.endpoint, token), executor=executor,
            project=project, task_id=task["task"]["id"],
        )
    finally:
        daemon.stop()


def _claim(ordinary, key):
    return ordinary.service.claim_next({
        "executor_id": ordinary.executor, "capability_ids": [CAPABILITY],
        "runtime_epoch": ordinary.service.health()["runtime_epoch"],
    }, idempotency_key=key)


def _fence(attempt):
    return {name: attempt[name] for name in ("lease_id", "fence", "runtime_epoch")}


def _assert_public_reads(ordinary, attempt, expected):
    rows, cursor = ordinary.owner.list_managed_outputs(ordinary.task_id)
    assert cursor is None
    logs = {row.variant_key: row for row in rows
            if row.role == "log" and row.attempt_id == attempt["attempt_id"]}
    assert set(logs) == {"job.stdout", "job.stderr"}
    for output in expected:
        row = logs[output["name"]]
        assert ordinary.owner.get_managed_output(row.association_id) == row
        assert ordinary.owner.get_object(row.object_id).data == base64.b64decode(output["data_base64"])
        assert row.task_id == ordinary.task_id and row.project_id == ordinary.project["id"]
        assert row.durability == "durable" and row.media_type == "text/plain"
        assert row.filename == output["filename"] and row.size == output["size"]
        assert row.provenance["task_id"] == ordinary.task_id
        assert row.provenance["attempt_id"] == attempt["attempt_id"]
        assert row.provenance["executor_id"] == ordinary.executor
        assert row.provenance["capability_id"] == CAPABILITY
        assert row.provenance["fence"] == attempt["fence"]
        assert row.provenance["runtime_epoch"] == attempt["runtime_epoch"]
    return logs


@pytest.mark.parametrize("same_bytes", [True, False])
def test_owner_retry_keeps_both_attempts_logs_readable_over_public_http(ordinary, same_bytes):
    first = _claim(ordinary, "first-claim")
    first_logs = _logs("first")
    failed = ordinary.worker.fail_attempt(
        first["attempt_id"], **_fence(first), outputs=first_logs,
        error={"code": "native_exit", "message": "exited 23"}, idempotency_key="first-fail",
    )
    assert failed.state == "failed"
    saved = _assert_public_reads(ordinary, first, first_logs)
    task = ordinary.owner.get_task(ordinary.task_id)
    with pytest.raises(ApiError) as denied:
        ordinary.worker.retry_task(ordinary.task_id, expected_version=task.version,
                                  idempotency_key="worker-retry-denied")
    assert denied.value.status == 401
    ordinary.owner.retry_task(ordinary.task_id, expected_version=task.version,
                             idempotency_key="owner-retry")
    second = _claim(ordinary, "second-claim")
    assert second["task_id"] == first["task_id"]
    assert second["attempt_id"] != first["attempt_id"] and second["fence"] > first["fence"]
    second_logs = _logs("first" if same_bytes else "second")
    result = _output(b"ordinary result", name="answer", filename="answer.txt", media_type="text/plain")
    body = {**_fence(second), "outputs": [result, *second_logs]}
    settled = ordinary.worker.settle_attempt(second["attempt_id"], body, idempotency_key="second-settle")
    assert settled["state"] == "succeeded"
    assert ordinary.owner.get_task(ordinary.task_id).state == "succeeded"
    current = _assert_public_reads(ordinary, second, second_logs)
    assert _assert_public_reads(ordinary, first, first_logs) == saved
    assert {row.association_id for row in saved.values()}.isdisjoint(
        row.association_id for row in current.values()
    )
    rows, cursor = ordinary.owner.list_managed_outputs(ordinary.task_id)
    assert cursor is None and len(rows) == 5
    assert ordinary.worker.settle_attempt(second["attempt_id"], body, idempotency_key="second-settle") == settled
    assert ordinary.owner.list_managed_outputs(ordinary.task_id) == (rows, cursor)
    assert ordinary.owner.get_object(result["digest"]).data == b"ordinary result"
    assert ordinary.service.store.integrity_report()["ok"]


@pytest.mark.parametrize("role", ["result", "log"])
def test_successful_associations_still_refuse_changed_bytes_and_attempt_ownership(ordinary, role):
    attempt = _claim(ordinary, "success-claim")
    output = _logs("success")[0] if role == "log" else _output(
        b"successful output", name="answer", filename="answer.txt", role="result",
    )
    ordinary.worker.settle_attempt(
        attempt["attempt_id"], {**_fence(attempt), "outputs": [output]},
        idempotency_key="successful-settle",
    )
    saved, _ = ordinary.owner.list_managed_outputs(ordinary.task_id)
    assert len(saved) == 1
    row = saved[0]
    normalized = deepcopy(ordinary.service.store.get_task(ordinary.task_id)["task"]["result"]["outputs"][0])
    # Exercise the immutable-association guard directly, as the existing
    # generic-publication test does; public terminal replay also remains fenced.
    for changed in (
        {**normalized, "digest": _digest(b"changed bytes"), "size": len(b"changed bytes")},
        {**normalized, "filename": "changed.txt"},
    ):
        with pytest.raises(ConflictError, match="immutable output"):
            with ordinary.service.store._transaction():
                ordinary.service.store._associate_managed_outputs(
                    {"outputs": [changed]}, task_id=ordinary.task_id,
                    attempt_id=attempt["attempt_id"], project_id=ordinary.project["id"],
                )
    if role == "result":
        another = ordinary.service.create_task({
            "capability_id": CAPABILITY, "capability_digest": _digest(CAPABILITY),
            "project": ordinary.project["id"], "idempotency_key": "other-task",
        })
        foreign = _claim(ordinary, "foreign-claim")
        assert foreign["task_id"] == another["task"]["id"]
        with pytest.raises(ConflictError, match="immutable output"):
            with ordinary.service.store._transaction():
                ordinary.service.store._associate_managed_outputs(
                    {"outputs": [normalized]}, task_id=ordinary.task_id,
                    attempt_id=foreign["attempt_id"], project_id=ordinary.project["id"],
                )
    assert ordinary.owner.get_managed_output(row.association_id) == row
    assert ordinary.owner.get_object(row.object_id).data == base64.b64decode(output["data_base64"])
    assert ordinary.service.store.integrity_report()["ok"]
