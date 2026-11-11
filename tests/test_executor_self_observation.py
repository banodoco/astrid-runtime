from __future__ import annotations

import hashlib
import json

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
        digest = "sha256:" + hashlib.sha256(b"self-observation").hexdigest()
        owner.request("POST", "/v1/capabilities", {
            "capability_id": "render.observation", "definition_digest": digest,
        })
        for executor in ("worker-a", "worker-b"):
            owner.request("POST", "/v1/executors", {
                "executor_id": executor, "capabilities": ["render.observation"],
                "resource_keys": ["gpu"], "max_concurrency": 2,
                "readiness": "not_ready", "readiness_reason": "warming",
                "source_digest": digest, "dependency_digest": digest,
                "source_epoch": "revision-1",
            }, headers={"Idempotency-Key": f"register-{executor}"})
        before = dict(daemon.service.store.conn.execute(
            "SELECT * FROM executors WHERE id=?", ("worker-a",),
        ).fetchone())
        expected = owner.request("GET", "/v1/executors/worker-a")
        assert set(expected) == {
            "executor_id", "max_concurrency", "resource_keys", "capabilities",
            "protocol", "runtime_epoch", "readiness", "readiness_reason",
            "last_seen_at", "source_digest", "dependency_digest", "source_epoch",
            "runtime_session_id",
        }
        assert expected["max_concurrency"] == 2
        assert expected["resource_keys"] == ["gpu"]
        assert expected["capabilities"][0]["definition_digest"] == digest
        assert expected["readiness"] == "not_ready"
        assert expected["readiness_reason"] == "warming"
        assert expected["source_digest"] == expected["dependency_digest"] == digest
        assert expected["source_epoch"] == "revision-1"
        assert expected["executor_id"] == "worker-a"
        assert expected["runtime_session_id"] == daemon.service.runtime_session_id
        assert owner.request("GET", "/v1/executors/worker-b")["executor_id"] == "worker-b"

        def actor(name, scopes):
            token, _ = daemon.credentials.provision(name, scopes)
            return Api(daemon.endpoint, token)

        worker = actor("worker-a", ["worker:execute"])
        assert worker.request("GET", "/v1/executors/worker-a") == expected
        assert worker.credential not in json.dumps(expected)
        assert daemon.token not in json.dumps(expected)
        after = dict(daemon.service.store.conn.execute(
            "SELECT * FROM executors WHERE id=?", ("worker-a",),
        ).fetchone())
        assert after == before
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

        daemon.credentials.disable_actor("worker-a")
        with pytest.raises(RuntimeError) as disabled:
            worker.request("GET", "/v1/executors/worker-a")
        assert disabled.value.status == 401
        daemon.credentials.revoke("worker-a")
        with pytest.raises(RuntimeError) as revoked:
            worker.request("GET", "/v1/executors/worker-a")
        assert revoked.value.status == 401

        owner_token, _ = daemon.credentials.provision("owner", ["admin"], rotate=True)
        assert Api(daemon.endpoint, owner_token).request("GET", "/v1/executors/worker-a") == expected
    finally:
        daemon.stop()


def test_executor_observation_service_rejects_missing_and_forged_authority(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root, support_root=tmp_path / "support")
    try:
        for executor in ("worker-a", "worker-b"):
            service.register_executor({"executor_id": executor}, idempotency_key=executor)
        owner = {"actor": "owner", "scopes": ["admin"]}
        worker = {"actor": "worker-a", "scopes": ["worker:execute"]}
        expected = service.executor_observation("worker-a", identity=owner)
        assert service.executor_observation("worker-a", identity=worker) == expected
        assert service.executor_observation("worker-b", identity=owner)["executor_id"] == "worker-b"
        with pytest.raises(AuthorizationError):
            service.executor_observation("worker-b", identity=worker)
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
