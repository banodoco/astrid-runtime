from __future__ import annotations

import io
import json
import threading

import pytest
from http_helpers import Api

from astrid_runtime import runtime_boundary
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol import platform
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


def test_boundary_marks_exact_identity_reads_and_preserves_realm_authentication(tmp_path, monkeypatch):
    credential = tmp_path / "owner.token"
    credential.write_text("test-owner-credential")
    platform.owner_only(credential)
    endpoint = "http://127.0.0.1:17410"
    requests = []

    def read(request, *, timeout):
        requests.append((request.full_url, request.get_method(),
                         {key.lower(): value for key, value in request.header_items()}))
        assert timeout == LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS
        value = ({"realm_id": "selected-realm"} if request.full_url.endswith("/v1/realm") else
                 {"status": "ok", "protocol": "workspace.v1", "runtime_instance_id": "selected-owner"})
        return io.BytesIO(json.dumps(value).encode())

    monkeypatch.setattr(runtime_boundary, "urlopen_loopback", read)
    result = LocalRuntimeBoundary().endpoint_metadata(endpoint=endpoint, credential_file=credential)
    assert result["realm_id"] == "selected-realm"
    assert result["runtime_instance_id"] == "selected-owner"
    assert [url for url, _, _ in requests] == [endpoint + "/v1/health", endpoint + "/v1/realm"]
    assert all(method == "GET" for _, method, _ in requests)
    assert all(headers["x-astrid-owner-identity"] == "1" for _, _, headers in requests)
    assert "authorization" not in requests[0][2]
    assert requests[1][2]["authorization"] == "Bearer test-owner-credential"


def test_endpoint_metadata_rejects_conflicting_realm_instance_identity(tmp_path, monkeypatch):
    credential = tmp_path / "owner.token"
    credential.write_text("test-owner-credential")
    platform.owner_only(credential)
    endpoint = "http://127.0.0.1:17410"

    def read(request, *, timeout):
        value = ({"realm_id": "selected-realm", "runtime_instance_id": "other-owner"}
                 if request.full_url.endswith("/v1/realm") else
                 {"status": "ok", "runtime_instance_id": "selected-owner"})
        return io.BytesIO(json.dumps(value).encode())

    monkeypatch.setattr(runtime_boundary, "urlopen_loopback", read)
    assert LocalRuntimeBoundary().endpoint_metadata(
        endpoint=endpoint, credential_file=credential,
    ) == {}


@pytest.mark.parametrize("method,path,body,marker", [
    ("GET", "/v1/projects", None, "1"),
    ("POST", "/v1/projects", {"slug": "guarded", "name": "Guarded"}, "1"),
    ("GET", "/v1/realm", None, "01"),
])
def test_identity_header_cannot_bypass_other_routes_or_mutation_guard(tmp_path, monkeypatch, method, path, body, marker):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    mutex = daemon.service.store._mutex
    operator = threading.get_ident()
    waiting, done = threading.Event(), threading.Event()
    results, failures = [], []

    class ObservedMutex:
        def __enter__(self):
            if threading.get_ident() != operator:
                waiting.set()
            return mutex.__enter__()

        def __exit__(self, *args):
            return mutex.__exit__(*args)

    def request():
        try:
            results.append(Api(daemon.endpoint, daemon.token).request(method, path, body, headers={
                "X-Astrid-Owner-Identity": marker, "Idempotency-Key": "guarded-request",
            }))
        except Exception as error:
            failures.append(error)
        finally:
            done.set()

    monkeypatch.setattr(daemon.service.store, "_mutex", ObservedMutex())
    worker = threading.Thread(target=request)
    try:
        with daemon.service.store._mutex:
            worker.start()
            assert waiting.wait(2), "request bypassed the shared store guard"
            assert not done.is_set()
        worker.join(5)
        assert not worker.is_alive()
        assert not failures
        assert len(results) == 1
        projects = daemon.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        assert projects == (1 if method == "POST" else 0)
    finally:
        if worker.ident is not None:
            worker.join(5)
        daemon.stop()
