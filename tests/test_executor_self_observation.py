from __future__ import annotations

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError
from runtime_protocol.store import RealmStore
from runtime_protocol.service import RuntimeService


def test_executor_observation_http_authority(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        for executor in ("worker-a", "worker-b"):
            owner.register_executor(executor, [], idempotency_key=f"register-{executor}")
        expected = owner.request("GET", "/v1/executors/worker-a")
        assert expected["executor_id"] == "worker-a"
        assert expected["runtime_session_id"] == daemon.service.runtime_session_id
        assert owner.request("GET", "/v1/executors/worker-b")["executor_id"] == "worker-b"

        def actor(name, scopes):
            token, _ = daemon.credentials.provision(name, scopes)
            return Api(daemon.endpoint, token)

        worker = actor("worker-a", ["worker:execute"])
        assert worker.request("GET", "/v1/executors/worker-a") == expected
        for api, path, headers in (
            (worker, "/v1/executors/worker-b", None),
            (worker, "/v1/executors/worker-b", {"X-Actor": "worker-b"}),
            (actor("worker-b", ["tasks:read"]), "/v1/executors/worker-b", None),
            (actor("other-admin", ["admin"]), "/v1/executors/worker-a", None),
            (actor("worker-admin", ["admin"]), "/v1/executors/worker-admin", None),
            (Api(daemon.endpoint, None), "/v1/executors/worker-a", None),
            (Api(daemon.endpoint, "invalid"), "/v1/executors/worker-a", None),
        ):
            with pytest.raises(RuntimeError) as denied:
                api.request("GET", path, headers=headers)
            assert denied.value.status == 401

        owner_token, _ = daemon.credentials.provision("owner", ["admin"], rotate=True)
        assert Api(daemon.endpoint, owner_token).request("GET", "/v1/executors/worker-a") == expected
    finally:
        daemon.stop()


def test_executor_observation_service_rejects_missing_and_forged_authority(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root, support_root=tmp_path / "support")
    try:
        for identity in (
            None, {}, {"actor": None, "scopes": ["worker:execute"]},
            {"actor": "worker-a", "scopes": "worker:execute"},
            {"actor": "worker-a", "scopes": None},
            {"actor": "worker-a", "scopes": []},
            {"actor": "worker-a", "scopes": ["admin"]},
            {"actor": "other", "scopes": ["admin", "worker:execute"]},
            {"actor": "owner", "scopes": ["worker:execute"]},
        ):
            with pytest.raises(AuthorizationError):
                service.executor_observation("worker-a", identity=identity)
    finally:
        service.close()
