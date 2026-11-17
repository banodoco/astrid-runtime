"""The generated wait transport remains read-only and is promptly closable."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from test_ls7_thin_resolution import descriptor, registration, request


def test_generated_wait_can_close_without_mutating_task(tmp_path, monkeypatch):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    try:
        daemon.service.register_executor(registration(daemon.service), idempotency_key="register")
        first = client.admit_thin_task(request()["thin_request"], idempotency_key="thin-create")
        task_id = first["task_id"]
        snapshot = client.wait_for_task(task_id, timeout_seconds=0)
        entered = threading.Event()
        changes = daemon.service._changes()
        wait = changes.condition.wait
        def observed_wait(seconds):
            entered.set()
            return wait(seconds)
        monkeypatch.setattr(changes.condition, "wait", observed_wait)
        with ThreadPoolExecutor() as pool:
            pending = pool.submit(client.wait_for_task, task_id, cursor=snapshot["cursor"], timeout_seconds=25)
            assert entered.wait(1)
            client.cancel_waits()
            with pytest.raises(ApiError) as error:
                pending.result(1)
            assert error.value.code == "wait_cancelled"
        assert daemon.service.store.get_task(task_id)["task"]["status"] == "queued"
        # A reconnect resumes the durable task without admitting a second one.
        reader = WorkspaceClient(daemon.endpoint, daemon.token)
        assert reader.wait_for_task(task_id, cursor=snapshot["cursor"], timeout_seconds=0)["task"]["state"] == "queued"
        assert reader.admit_thin_task(request()["thin_request"], idempotency_key="thin-create") == first
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        daemon.stop()


def test_generated_wait_transport_preserves_typed_scope_refusal(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        token, _ = daemon.credentials.provision("reader", ["tasks:read"])
        client = WorkspaceClient(daemon.endpoint, token)
        with pytest.raises(ApiError) as error:
            client.wait_for_work(executor_id="reader", capability_ids=[], runtime_epoch=daemon.service._runtime_state["runtime_epoch"], timeout_seconds=0)
        assert error.value.status == 401 and error.value.code == "unauthorized"
    finally:
        daemon.stop()
