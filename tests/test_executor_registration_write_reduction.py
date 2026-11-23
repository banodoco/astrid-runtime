from __future__ import annotations

import copy
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import EXECUTOR_LIVENESS_SECONDS, RealmStore


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    yield runtime
    runtime.close()


def registration(service):
    return {
        "executor_id": "worker", "runtime_epoch": service.health()["runtime_epoch"],
        "capabilities": [{"capability_id": "render", "definition_digest": "sha256:" + "a" * 64,
                          "required_resource_keys": ["gpu"], "status": "ready",
                          "estimated_scratch_bytes": 5, "estimated_output_bytes": 10}],
        "resource_keys": ["gpu"], "max_concurrency": 2,
        "source_digest": "source", "dependency_digest": "dependency", "source_epoch": "one",
        "verified_facts": {"exact": {"driver": "one"}, "minimum": {"vram_bytes": 10}},
    }


def durable_writes(service, body, key):
    writes = []
    def authorizer(action, name, column, database, trigger):
        if database == "main" and action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
            writes.append((action, name, column))
        return sqlite3.SQLITE_OK
    service.store.conn.set_authorizer(authorizer)
    try:
        result = service.register_executor(body, idempotency_key=key)
    finally:
        service.store.conn.set_authorizer(None)
    return result, writes


def set_age(service, seconds):
    timestamp = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(timespec="milliseconds")
    service.store.conn.execute("UPDATE executors SET last_seen_at=? WHERE id='worker'", (timestamp,))
    return timestamp


def row(service):
    return service.store.conn.execute("SELECT * FROM executors WHERE id='worker'").fetchone()


def test_fresh_identical_registration_has_no_durable_writes(service):
    body = registration(service)
    first = service.register_executor(body, idempotency_key="first")
    before = dict(row(service))
    result, writes = durable_writes(service, body, "second")
    assert result == first
    assert writes == []
    assert dict(row(service)) == before
    assert service.store.matching_live_executor("render", body["capabilities"][0]["definition_digest"], include_storage=False)


def test_half_ttl_refresh_and_liveness(service):
    body = registration(service)
    service.register_executor(body, idempotency_key="first")
    young = set_age(service, EXECUTOR_LIVENESS_SECONDS / 2 - 2)
    _, writes = durable_writes(service, body, "young")
    assert writes == []
    assert row(service)["last_seen_at"] == young
    old = set_age(service, EXECUTOR_LIVENESS_SECONDS / 2 + 2)
    _, writes = durable_writes(service, body, "old")
    assert writes
    assert row(service)["last_seen_at"] > old
    assert service.store.matching_live_executor("render", body["capabilities"][0]["definition_digest"], include_storage=False)


@pytest.mark.parametrize("change", [
    {"max_concurrency": 3}, {"resource_keys": ["gpu", "cpu"]},
    {"readiness": "not_ready", "readiness_reason": "busy"},
    {"source_digest": "source2"}, {"dependency_digest": "dependency2"}, {"source_epoch": "two"},
    {"verified_facts": {"exact": {"driver": "two"}, "minimum": {"vram_bytes": 10}}},
])
def test_changed_executor_fields_propagate(service, change):
    body = registration(service)
    service.register_executor(body, idempotency_key="first")
    updated = copy.deepcopy(body)
    updated.update(change)
    _, writes = durable_writes(service, updated, "changed")
    assert writes
    actual = service.store._executor_result(row(service))
    for key, value in change.items():
        assert actual[key] == value


@pytest.mark.parametrize("field,value", [
    ("definition_digest", "sha256:" + "b" * 64), ("status", "unavailable"),
    ("required_resource_keys", ["gpu", "cpu"]), ("estimated_scratch_bytes", 7),
    ("estimated_output_bytes", 11), ("unavailable_reason", "changed"),
])
def test_changed_capability_descriptor_propagates(service, field, value):
    body = registration(service)
    service.register_executor(body, idempotency_key="first")
    updated = copy.deepcopy(body)
    updated["capabilities"][0][field] = value
    result, writes = durable_writes(service, updated, "changed")
    assert writes
    assert result["capabilities"][0][field] == value


def test_shared_capability_change_is_restored(service):
    body = registration(service)
    service.register_executor(body, idempotency_key="first")
    service.register_capability({"capability_id": "render", "definition_digest": "sha256:" + "b" * 64})
    result, writes = durable_writes(service, body, "again")
    assert writes
    assert result["capabilities"][0]["definition_digest"] == body["capabilities"][0]["definition_digest"]


def test_replay_epoch_and_heartbeat_fences(service):
    body = registration(service)
    first = service.register_executor(body, idempotency_key="first")
    old = set_age(service, EXECUTOR_LIVENESS_SECONDS - 2)
    replay, writes = durable_writes(service, body, "first")
    assert replay == first
    assert writes == []
    assert row(service)["last_seen_at"] == old
    changed = {**body, "max_concurrency": 3}
    with pytest.raises(ConflictError):
        service.register_executor(changed, idempotency_key="first")
    with pytest.raises(LeaseError):
        service.register_executor({**body, "runtime_epoch": body["runtime_epoch"] + 1}, idempotency_key="stale")
    service.store.heartbeat_executor("worker", runtime_epoch=body["runtime_epoch"])
    assert row(service)["last_seen_at"] > old
    assert service.store.matching_live_executor("render", body["capabilities"][0]["definition_digest"], include_storage=False)


def test_exact_half_ttl_requires_refresh(service, monkeypatch):
    import runtime_protocol.store as store_module

    body = registration(service)
    service.register_executor(body, idempotency_key="first")
    fixed = datetime.now(timezone.utc).replace(microsecond=0)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz else fixed.replace(tzinfo=None)

    monkeypatch.setattr(store_module, "datetime", FixedDateTime)
    cutoff = (fixed - timedelta(seconds=EXECUTOR_LIVENESS_SECONDS / 2)).isoformat()
    service.store.conn.execute("UPDATE executors SET last_seen_at=? WHERE id='worker'", (cutoff,))
    _, writes = durable_writes(service, body, "boundary")
    assert writes
    assert row(service)["last_seen_at"] != cutoff


def test_missing_string_capability_is_created(service):
    body = registration(service)
    body["capabilities"] = ["simple"]
    service.register_executor(body, idempotency_key="first")
    service.store.conn.execute("DELETE FROM capabilities WHERE id='simple'")
    result, writes = durable_writes(service, body, "again")
    assert writes
    assert result["capabilities"][0]["capability_id"] == "simple"


def test_fresh_string_capability_registration_has_no_durable_writes(service):
    body = registration(service)
    body["capabilities"] = ["simple"]
    body.pop("verified_facts")
    service.register_executor(body, idempotency_key="first")
    _, writes = durable_writes(service, body, "again")
    assert writes == []
