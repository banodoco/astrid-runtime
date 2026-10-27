"""Transport contract of the browser door: admission, CORS, preflight, bodies, caching, limits, cancellation, audit.

Every test starts its own daemon with a door on an ephemeral port (see tests/door_helpers.py).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import time
import urllib.parse

import pytest

from tests.door_helpers import HOSTED, start_door_world

API_RUNTIME = "/api/runtime"
EXPOSED = ["content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified"]
EVIL = "https://evil.test"


def _unwrap(value):
    return value["data"] if isinstance(value, dict) and "data" in value else value


def _new_project(world, key="project-1", name="Door"):
    status, body = world.owner("POST", "/v1/projects", {"name": name}, headers={"Idempotency-Key": key})
    assert status == 201, body
    return _unwrap(json.loads(body))["project_id"]


def _ingest(world, project_id, data, key="ingest-1"):
    status, body = world.owner(
        "POST", f"/v1/projects/{project_id}/objects", raw=data,
        headers={"Content-Type": "application/octet-stream", "Idempotency-Key": key},
    )
    assert status == 201, body
    return _unwrap(json.loads(body))


def _assert_health_answers(world):
    """Hang guard only: the door must answer health again after the abandoned connection."""
    for _ in range(100):
        reply = world.call(f"{API_RUNTIME}/v1/health")
        if reply.status == 200:
            return
        time.sleep(0.1)
    raise AssertionError("door did not answer health after the abandoned connection")


# 1. Admission order -----------------------------------------------------------

def test_admission_order_host_origin_and_route(tmp_path):
    world = start_door_world(tmp_path)
    try:
        port = world.port
        path = f"{API_RUNTIME}/v1/health"

        reply = world.call(path, origin=None)
        assert reply.status == 403
        assert reply.json() == {"error": "hosted_origin_required"}

        reply = world.call(path, origin=EVIL)
        assert reply.status == 403
        assert reply.json() == {"error": "hosted_origin_required"}
        assert "access-control-allow-origin" not in reply.headers

        for host in ["evil.test", f"localhost:{port}", f"[::1]:{port}", f"127.0.0.1:{port + 1}", "127.0.0.1",
                     f"127.0.0.1.evil.test:{port}"]:
            reply = world.call(path, origin=HOSTED, host=host)
            assert reply.status == 403, host
            assert reply.json() == {"error": "invalid_host"}, host

        for unlisted in ["/session/abc/api/runtime/v1/health", "/v1/health", "/api/runtime/v1/doctor",
                         "/api/astrid/generation/compose", "/api/other/v1/health", "/"]:
            reply = world.call(unlisted, origin=EVIL)
            assert reply.status == 403, unlisted
            assert reply.json() == {"error": "hosted_origin_required"}, unlisted

            reply = world.call(unlisted, origin=None)
            assert reply.status == 403, unlisted

            # Control: with the hosted Origin the same path is a 404 from the door itself, with CORS.
            reply = world.call(unlisted, origin=HOSTED)
            assert reply.status == 404, unlisted
            assert reply.json() == {"error": "route_not_allowed"}, unlisted
            assert reply.headers.get("access-control-allow-origin") == HOSTED, unlisted
    finally:
        world.stop()


# 2. Allowed reads -------------------------------------------------------------

@pytest.mark.parametrize("prefix", ["/api/runtime", "/api/astrid"])
def test_allowed_health_read_and_response_headers(tmp_path, prefix):
    world = start_door_world(tmp_path)
    try:
        reply = world.call(f"{prefix}/v1/health")
        assert reply.status == 200
        body = reply.json()
        assert body["status"] == "ok"
        assert body["protocol"] == "workspace.v1"
        assert body.get("runtime_instance_id") or body.get("runtime_session_id")

        headers = reply.headers
        assert headers["access-control-allow-origin"] == HOSTED
        assert headers["vary"] == "Origin"
        exposed = [item.strip() for item in headers["access-control-expose-headers"].split(",")]
        assert set(EXPOSED) <= set(exposed)
        assert headers["cache-control"] == "no-store"
        for hidden in ("x-request-id", "server", "set-cookie"):
            assert hidden not in headers
    finally:
        world.stop()


def test_health_reports_pinokio_only_as_a_door_extension(tmp_path, monkeypatch):
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    world = start_door_world(tmp_path)
    try:
        reply = world.call(f"{API_RUNTIME}/v1/health")
        assert reply.status == 200
        assert "install" not in reply.json()

        # The live door follows the owner's startup snapshot; changing the
        # process environment after startup cannot change its marker.
        monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "8")
        monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
        reply = world.call(f"{API_RUNTIME}/v1/health")
        assert reply.status == 200
        assert "install" not in reply.json()

        pinokio_root = tmp_path / "pinokio"
        pinokio_root.mkdir()
        monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
    finally:
        world.stop()

    pinokio_world = start_door_world(pinokio_root)
    try:
        reply = pinokio_world.call(f"{API_RUNTIME}/v1/health")
        assert reply.status == 200
        assert reply.json()["install"] == {"managed_by": "pinokio"}

        monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "other")
        reply = pinokio_world.call(f"{API_RUNTIME}/v1/health")
        assert reply.status == 200
        assert reply.json()["install"] == {"managed_by": "pinokio"}

        status, body = pinokio_world.owner("GET", "/v1/health")
        assert status == 200
        assert "install" not in json.loads(body)
    finally:
        pinokio_world.stop()


def test_realm_read_through_the_door(tmp_path):
    world = start_door_world(tmp_path)
    try:
        reply = world.call(f"{API_RUNTIME}/v1/realm")
        assert reply.status == 200
        assert reply.json()["realm_id"] == world.daemon.service.realm["id"]
    finally:
        world.stop()


# 3. Browser credentials -------------------------------------------------------

def test_browser_credentials_are_refused(tmp_path):
    world = start_door_world(tmp_path)
    try:
        path = f"{API_RUNTIME}/v1/health"
        reply = world.call(path, headers={"Authorization": f"Bearer {world.product_token}"})
        assert reply.status == 403
        assert reply.json() == {"error": "browser_credentials_forbidden"}

        reply = world.call(path, headers={"Cookie": "a=b"})
        assert reply.status == 403
        assert reply.json() == {"error": "browser_credentials_forbidden"}

        object_path = f"{API_RUNTIME}/v1/objects/sha256:{'0' * 64}"
        for method in ("GET", "HEAD"):
            reply = world.call(object_path, method, origin=None, headers={"Referer": HOSTED + "/"})
            assert reply.status == 403, method
            if method == "GET":
                assert reply.json() == {"error": "hosted_origin_required"}
    finally:
        world.stop()


# 4. Preflight -----------------------------------------------------------------

def test_preflight_allows_listed_request(tmp_path):
    world = start_door_world(tmp_path)
    try:
        reply = world.call(
            f"{API_RUNTIME}/v1/projects", "OPTIONS",
            headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, idempotency-key",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        assert reply.status == 204
        assert reply.headers["access-control-allow-methods"] == "POST"
        assert reply.headers["access-control-allow-headers"] == "content-type, idempotency-key"
        assert reply.headers["access-control-allow-private-network"] == "true"
        assert reply.headers["access-control-max-age"] == "300"
        assert reply.headers["access-control-allow-origin"] == HOSTED
    finally:
        world.stop()


def test_preflight_refusals(tmp_path):
    world = start_door_world(tmp_path)
    try:
        projects = f"{API_RUNTIME}/v1/projects"
        method_header = {"Access-Control-Request-Method": "POST"}

        reply = world.call(projects, "OPTIONS", origin=EVIL, headers=method_header)
        assert reply.status == 403

        reply = world.call(projects, "OPTIONS", headers={"Access-Control-Request-Method": "DELETE"})
        assert reply.status == 404
        assert reply.json() == {"error": "route_not_allowed"}

        reply = world.call(f"{API_RUNTIME}/v1/doctor", "OPTIONS", headers={"Access-Control-Request-Method": "GET"})
        assert reply.status == 404

        for header in ("authorization", "x-output-binding"):
            reply = world.call(projects, "OPTIONS", headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": f"content-type, {header}",
            })
            assert reply.status == 403, header
            assert reply.json() == {"error": "header_not_allowed"}, header

        reply = world.call("/api/astrid/acp/connect", "OPTIONS", headers={
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        })
        assert reply.status == 204
    finally:
        world.stop()


# 5. Projects and renameTimeline -----------------------------------------------

def test_project_create_and_timeline_rename_through_the_door(tmp_path):
    world = start_door_world(tmp_path)
    try:
        reply = world.call(
            f"{API_RUNTIME}/v1/projects", "POST",
            headers={"Content-Type": "application/json", "Idempotency-Key": "door-project"},
            body=json.dumps({"name": "Door"}).encode(),
        )
        assert reply.status == 201, reply.body
        project_id = _unwrap(reply.json())["project_id"]

        status, body = world.owner(
            "POST", f"/v1/projects/{project_id}/timelines", {"timeline_id": "t1", "name": "First"},
            headers={"Idempotency-Key": "timeline-t1"},
        )
        assert status == 201, body

        patch_headers = {"Content-Type": "application/json", "Idempotency-Key": "rename-1"}
        reply = world.call(f"{API_RUNTIME}/v1/projects/{project_id}/timelines/t1", "PATCH",
                           headers=patch_headers, body=json.dumps({"name": "Renamed"}).encode())
        assert reply.status == 200, reply.body

        status, body = world.owner("GET", f"/v1/projects/{project_id}/timelines/t1")
        assert status == 200, body
        assert _unwrap(json.loads(body))["name"] == "Renamed"

        for origin in (None, EVIL):
            reply = world.call(f"{API_RUNTIME}/v1/projects/{project_id}/timelines/t1", "PATCH", origin=origin,
                               headers={**patch_headers, "Idempotency-Key": f"rename-refused-{origin}"},
                               body=json.dumps({"name": "Refused"}).encode())
            assert reply.status == 403, origin

        status, body = world.owner("GET", f"/v1/projects/{project_id}/timelines/t1")
        assert _unwrap(json.loads(body))["name"] == "Renamed"
    finally:
        world.stop()


# 6. Objects, Range and caching ------------------------------------------------

def test_object_reads_range_head_and_caching(tmp_path):
    world = start_door_world(tmp_path)
    try:
        data = os.urandom(100 * 1024)
        project_id = _new_project(world)
        ingested = _ingest(world, project_id, data)
        object_id = ingested["object_id"]
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", object_id)
        size = len(data)
        path = f"{API_RUNTIME}/v1/objects/" + urllib.parse.quote(object_id, safe="")

        reply = world.call(path)
        assert reply.status == 200
        assert reply.body == data
        assert "etag" in reply.headers
        assert reply.headers["cache-control"] == "private, max-age=31536000, immutable"
        assert "x-content-digest" not in reply.headers

        reply = world.call(path, headers={"Range": "bytes=10-19"})
        assert reply.status == 206
        assert reply.body == data[10:20]
        assert reply.headers["content-range"] == f"bytes 10-19/{size}"

        reply = world.call(path, headers={"Range": "bytes=999999999-"})
        assert reply.status == 416

        reply = world.call(path, "HEAD")
        assert reply.status == 200
        assert int(reply.headers["content-length"]) == size
        assert reply.body == b""

        reply = world.call(f"{API_RUNTIME}/v1/projects")
        assert reply.status == 200
        assert reply.headers["cache-control"] == "no-store"
    finally:
        world.stop()


# 7. Limits -------------------------------------------------------------------

def test_json_and_acp_body_limits(tmp_path):
    world = start_door_world(tmp_path)
    try:
        reply = world.call(f"{API_RUNTIME}/v1/projects", "POST",
                           headers={"Content-Type": "application/json", "Idempotency-Key": "too-big"},
                           body=b"x" * (1024 * 1024 + 1))
        assert reply.status == 413
        assert reply.json() == {"error": "payload_too_large"}

        reply = world.call("/api/astrid/acp/connect", "POST",
                           headers={"Content-Type": "application/json"}, body=b"x" * (128 * 1024 + 1))
        assert reply.status == 413
    finally:
        world.stop()


def test_lowered_object_cap_for_fixed_and_chunked_bodies(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNTIME_MAX_OBJECT_BYTES", "4096")
    world = start_door_world(tmp_path)
    try:
        project_id = _new_project(world)
        path = f"{API_RUNTIME}/v1/projects/{project_id}/objects"
        upload = {"Content-Type": "application/octet-stream", "Idempotency-Key": "cap"}

        reply = world.call(path, "POST", headers={**upload, "Idempotency-Key": "cap-fixed"}, body=b"a" * 4097)
        assert reply.status == 413
        assert reply.json() == {"error": "payload_too_large"}

        data = b"b" * 4097
        chunked = b"1001\r\n" + data + b"\r\n0\r\n\r\n"
        reply = world.call(path, "POST", headers={**upload, "Idempotency-Key": "cap-chunked", "Transfer-Encoding": "chunked"},
                           body=chunked)
        assert reply.status == 413
        assert reply.json() == {"error": "payload_too_large"}

        reply = world.call(path, "POST", headers={**upload, "Idempotency-Key": "cap-exact"}, body=b"c" * 4096)
        assert reply.status == 201
    finally:
        world.stop()


def test_large_object_above_old_json_cap_is_accepted(tmp_path):
    world = start_door_world(tmp_path)
    try:
        data = os.urandom(65 * 1024 * 1024)
        project_id = _new_project(world)
        reply = world.call(f"{API_RUNTIME}/v1/projects/{project_id}/objects", "POST",
                           headers={"Content-Type": "application/octet-stream", "Idempotency-Key": "large"}, body=data)
        assert reply.status == 201, reply.body
        assert _unwrap(reply.json())["digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
    finally:
        world.stop()


# 8. Cancellation --------------------------------------------------------------

def test_cancelled_upload_leaves_door_serving(tmp_path):
    world = start_door_world(tmp_path)
    try:
        project_id = _new_project(world)
        head = (
            f"POST {API_RUNTIME}/v1/projects/{project_id}/objects HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{world.port}\r\n"
            f"Origin: {HOSTED}\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Idempotency-Key: cancelled-upload\r\n"
            f"Content-Length: {10 * 1024 * 1024}\r\n\r\n"
        ).encode()
        sock = socket.create_connection(("127.0.0.1", world.port), timeout=10)
        try:
            sock.sendall(head + b"x" * (64 * 1024))
        finally:
            sock.close()
        _assert_health_answers(world)
    finally:
        world.stop()


def test_cancelled_download_leaves_door_serving(tmp_path):
    world = start_door_world(tmp_path)
    try:
        project_id = _new_project(world)
        object_id = _ingest(world, project_id, os.urandom(4 * 1024 * 1024))["object_id"]
        path = f"{API_RUNTIME}/v1/objects/" + urllib.parse.quote(object_id, safe="")
        request = (
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{world.port}\r\nOrigin: {HOSTED}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock = socket.create_connection(("127.0.0.1", world.port), timeout=10)
        try:
            sock.sendall(request)
            received = sock.recv(1024)
            assert received.split(b"\r\n", 1)[0].split(b" ")[1:2] == [b"200"]
        finally:
            sock.close()
        _assert_health_answers(world)
    finally:
        world.stop()


# 9. Audit ---------------------------------------------------------------------

def test_audit_lines_without_credentials(tmp_path):
    audit = tmp_path / "audit.jsonl"
    world = start_door_world(tmp_path, audit_log=audit)
    try:
        data = os.urandom(2048)
        project_id = _new_project(world)
        object_id = _ingest(world, project_id, data)["object_id"]
        object_path = f"{API_RUNTIME}/v1/objects/" + urllib.parse.quote(object_id, safe="")

        assert world.call(f"{API_RUNTIME}/v1/health").status == 200
        assert world.call(object_path).status == 200
        assert world.call(f"{API_RUNTIME}/v1/health", origin=EVIL).status == 403

        deadline = time.monotonic() + 10
        while True:
            audit_text = audit.read_text(encoding="utf-8") if audit.exists() else ""
            audit_lines = audit_text.splitlines()
            if audit_text.count("\n") >= 3:
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"expected 3 audit lines within 10 seconds, found {len(audit_lines)}")
            time.sleep(0.01)

        lines = [json.loads(line) for line in audit_lines]
        for entry in lines:
            assert set(entry) == {"at", "method", "path", "origin", "status", "response_bytes"}

        # Each request is audited on its own handler thread after its response,
        # so rows can land in any order; identify them by content.
        assert len(lines) == 3
        (obj,) = [entry for entry in lines if entry["path"].startswith("/v1/objects/")]
        (foreign,) = [entry for entry in lines if entry["origin"] == EVIL]
        (health,) = [entry for entry in lines if entry is not obj and entry is not foreign]
        assert health["path"] == "/v1/health"
        assert health["status"] == 200 and health["method"] == "GET"
        assert obj["path"] == f"/v1/objects/{object_id}"
        assert obj["status"] == 200
        assert obj["response_bytes"] == len(data)
        assert foreign["status"] == 403
        assert foreign["origin"] == EVIL

        assert world.product_token not in audit.read_text(encoding="utf-8")
    finally:
        world.stop()


# 10. Preflight refuses what a browser would never send, rather than reading it as nothing.


def _raw_options(world, headers):
    """OPTIONS with repeatable headers, as (name, value) pairs."""
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=30)
    try:
        connection.putrequest("OPTIONS", f"{API_RUNTIME}/v1/projects", skip_host=True, skip_accept_encoding=True)
        for name, value in [("Host", f"127.0.0.1:{world.port}"), ("Origin", HOSTED), ("Access-Control-Request-Method", "POST"), *headers]:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        return response.status, json.loads(response.read() or b"null")
    finally:
        connection.close()


def test_preflight_refuses_repeated_request_headers_and_browser_credentials(tmp_path):
    world = start_door_world(tmp_path)
    try:
        assert _raw_options(world, [("Access-Control-Request-Headers", "content-type")])[0] == 204
        for repeated in ([("Access-Control-Request-Headers", "content-type"), ("Access-Control-Request-Headers", "authorization")],
                         [("Access-Control-Request-Headers", "content-type"), ("Access-Control-Request-Headers", "content-type")]):
            assert _raw_options(world, repeated) == (403, {"error": "header_not_allowed"}), repeated
        for credential in [("Authorization", "Bearer browser"), ("Cookie", "a=b")]:
            assert _raw_options(world, [("Access-Control-Request-Headers", "content-type"), credential]) == (403, {"error": "browser_credentials_forbidden"}), credential
    finally:
        world.stop()
