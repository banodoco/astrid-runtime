"""Chat forwarding on the browser door (runtime_protocol/door.py, /api/astrid/acp/*).

The chat service is a fake HTTP server on loopback that announces itself through
the owner-only ``<support>/chat.json``. The door is exercised the way the hosted
page uses it, through raw HTTP on its own port.

Ported from app-door: scripts/astrid-loopback-gateway.test.ts, test 3.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.door_helpers import HOSTED, start_door_world, write_owner_only

CHAT_TOKEN = "chat-token"
GUARD_SECONDS = 30
RPC_BODY = b'{"id": 7, "method": "session/prompt", "params": {"text": "hi"}}'
AGENTS = "/api/astrid/acp/agents"


def _json_reply(handler, status: int, value, extra_headers=()):
    body = json.dumps(value).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    for name, value_ in extra_headers:
        handler.send_header(name, value_)
    handler.end_headers()
    handler.wfile.write(body)


class FakeChat:
    """A loopback chat service that records every request and answers the door's routes."""

    def __init__(self):
        self.requests: list[dict] = []
        self.hooks: dict[tuple[str, str], object] = {}
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_class(self))
        self.port = self._server.server_port
        self.endpoint = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, name="fake-chat", daemon=True)
        self._thread.start()

    def record(self, entry: dict) -> None:
        with self._lock:
            self.requests.append(entry)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=GUARD_SECONDS)


def _handler_class(chat: FakeChat):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            chat.record({
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "bridge": self.headers.get("X-Astrid-Bridge-Version"),
                "local_media": self.headers.get("X-Astrid-Local-Media-Only"),
                "content_type": self.headers.get("Content-Type"),
                "body": body,
            })
            hook = chat.hooks.get((self.command, self.path))
            if hook is not None:
                hook(self)
                return
            if (self.command, self.path) == ("GET", "/agents"):
                _json_reply(self, 200, {"agents": []})
            elif (self.command, self.path) == ("POST", "/connect"):
                _json_reply(self, 200, {"connection_id": "connection-1", "initialize": {}})
            elif (self.command, self.path) == ("POST", "/connection-1/rpc"):
                _json_reply(self, 200, {"result": {"ok": True}})
            else:
                _json_reply(self, 404, {"error": "not_found"})

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_OPTIONS = do_HEAD = _serve

    return Handler


@pytest.fixture
def chat():
    service = FakeChat()
    try:
        yield service
    finally:
        service.close()


@pytest.fixture
def make_world(tmp_path):
    worlds = []

    def start(**door_options):
        world = start_door_world(tmp_path, **door_options)
        worlds.append(world)
        return world

    try:
        yield start
    finally:
        for world in worlds:
            world.stop()


def _point_chat_at(world, endpoint: str, token: str = CHAT_TOKEN) -> None:
    write_owner_only(world.support / "chat.json", {"endpoint": endpoint, "token": token})


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


# 1. Forwarding ---------------------------------------------------------------


def test_forwards_typed_acp_routes_with_bridge_credential(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)

    agents = world.call("/api/astrid/acp/agents")
    connect = world.call("/api/astrid/acp/connect", "POST", headers={"Content-Type": "application/json"}, body=b"{}")
    rpc = world.call(
        "/api/astrid/acp/connection-1/rpc", "POST",
        headers={"Content-Type": "application/json"}, body=RPC_BODY,
    )

    assert (agents.status, agents.json()) == (200, {"agents": []})
    assert (connect.status, connect.json()) == (200, {"connection_id": "connection-1", "initialize": {}})
    assert (rpc.status, rpc.json()) == (200, {"result": {"ok": True}})
    for reply in (agents, connect, rpc):
        assert reply.headers["access-control-allow-origin"] == HOSTED
        assert reply.headers["cache-control"] == "no-store"

    assert [(entry["method"], entry["path"]) for entry in chat.requests] == [
        ("GET", "/agents"),
        ("POST", "/connect"),
        ("POST", "/connection-1/rpc"),
    ]
    for entry in chat.requests:
        assert entry["authorization"] == f"Bearer {CHAT_TOKEN}"
        assert entry["bridge"] == "v1"
        assert entry["local_media"] == "1"
    assert chat.requests[1]["content_type"] == "application/json"
    assert chat.requests[1]["body"] == b"{}"
    assert chat.requests[2]["content_type"] == "application/json"
    assert chat.requests[2]["body"] == RPC_BODY


# 2. Refusals that never reach the chat service -------------------------------


def test_refusals_never_reach_chat_service(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)

    browser_credentials = world.call(
        "/api/astrid/acp/connect", "POST",
        headers={"Authorization": "Bearer browser", "Content-Type": "application/json"}, body=b"{}",
    )
    wrong_method = world.call("/api/astrid/acp/connection-1/rpc")
    delete_agents = world.call("/api/astrid/acp/agents", "DELETE")
    foreign_origin = world.call(
        "/api/astrid/acp/connect", "POST",
        headers={"Content-Type": "application/json"}, body=b"{}", origin="https://evil.test",
    )

    assert (browser_credentials.status, browser_credentials.json()) == (403, {"error": "browser_credentials_forbidden"})
    assert (wrong_method.status, wrong_method.json()) == (404, {"error": "route_not_allowed"})
    assert (delete_agents.status, delete_agents.json()) == (404, {"error": "route_not_allowed"})
    assert foreign_origin.status == 403
    assert foreign_origin.json() == {"error": "hosted_origin_required"}
    assert chat.requests == []


# 3. No chat service ----------------------------------------------------------


def test_no_chat_file_answers_acp_unavailable_and_preflight_passes(make_world):
    world = make_world()
    assert not (world.support / "chat.json").exists()

    health = world.call("/api/astrid/acp/health")
    preflight = world.call(
        "/api/astrid/acp/connect", "OPTIONS",
        headers={"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
    )

    assert (health.status, health.json()) == (503, {"error": "acp_unavailable"})
    assert health.headers["access-control-allow-origin"] == HOSTED
    assert preflight.status == 204
    assert preflight.headers["access-control-allow-origin"] == HOSTED
    assert "post" in preflight.headers["access-control-allow-methods"].lower()


# 4. Unusable chat.json -------------------------------------------------------


@pytest.mark.parametrize("case", ["not-owner-only", "localhost-endpoint", "non-loopback-endpoint", "no-token", "not-json"])
def test_unusable_chat_file_is_acp_unavailable(make_world, chat, case):
    world = make_world()
    path = world.support / "chat.json"
    port = chat.port
    if case == "not-owner-only":
        write_owner_only(path, {"endpoint": chat.endpoint, "token": CHAT_TOKEN}, mode=0o644)
    elif case == "localhost-endpoint":
        _point_chat_at(world, f"http://localhost:{port}")
    elif case == "non-loopback-endpoint":
        _point_chat_at(world, f"http://10.0.0.1:{port}")
    elif case == "no-token":
        write_owner_only(path, {"endpoint": chat.endpoint})
    else:
        path.write_text("{not json", encoding="utf-8")
        os.chmod(path, 0o600)

    reply = world.call(AGENTS)

    assert (reply.status, reply.json()) == (503, {"error": "acp_unavailable"})
    assert chat.requests == []


# 5. Dead endpoint, then recovery without restart -----------------------------


def test_dead_endpoint_is_unavailable_then_recovers_on_rewrite(make_world, chat):
    world = make_world()
    _point_chat_at(world, f"http://127.0.0.1:{_free_port()}")

    dead = world.call(AGENTS)
    assert (dead.status, dead.json()) == (503, {"error": "acp_unavailable"})

    _point_chat_at(world, chat.endpoint)
    recovered = world.call(AGENTS)

    assert (recovered.status, recovered.json()) == (200, {"agents": []})
    assert [entry["path"] for entry in chat.requests] == ["/agents"]


# 6. Stalled chat service -----------------------------------------------------


def test_stalled_chat_service_times_out_and_door_keeps_serving(make_world, chat):
    world = make_world(acp_idle_timeout=0.5)
    _point_chat_at(world, chat.endpoint)
    release = threading.Event()

    def stall(handler):
        release.wait(GUARD_SECONDS)
        try:
            _json_reply(handler, 200, {"models": []})
        except OSError:
            pass

    chat.hooks[("GET", "/models")] = stall
    try:
        stalled = world.call("/api/astrid/acp/models")
        assert (stalled.status, stalled.json()) == (504, {"error": "upstream_timeout"})
        assert stalled.headers["access-control-allow-origin"] == HOSTED

        after = world.call(AGENTS)
        assert (after.status, after.json()) == (200, {"agents": []})
    finally:
        release.set()


@pytest.mark.parametrize("path,body", [
    ("/projects/project-1/chat/prompt", b'{"prompt": [{"type": "text", "text": "hi"}]}'),
    ("/connection-1/rpc", RPC_BODY),
])
def test_prompt_completion_outlives_chat_timeout(make_world, chat, path, body):
    world = make_world(acp_idle_timeout=0.05)
    _point_chat_at(world, chat.endpoint)
    started, release = threading.Event(), threading.Event()

    def prompt(handler):
        started.set()
        release.wait(GUARD_SECONDS)
        _json_reply(handler, 200, {"result": {"stopReason": "end_turn"}})

    chat.hooks[("POST", path)] = prompt
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(world.call, "/api/astrid/acp" + path, "POST",
                              headers={"Content-Type": "application/json"}, body=body)
        try:
            assert started.wait(GUARD_SECONDS)
            with pytest.raises(FutureTimeout):
                pending.result(timeout=0.2)
            assert world.call(AGENTS).status == 200
        finally:
            release.set()
        reply = pending.result(timeout=GUARD_SECONDS)
    assert (reply.status, reply.json()) == (200, {"result": {"stopReason": "end_turn"}})
    assert sum(entry["path"] == path for entry in chat.requests) == 1


@pytest.mark.parametrize("body", [b'{"method": "session/load"}', b'[]', b'not json'])
def test_non_prompt_rpc_keeps_chat_timeout(make_world, chat, body):
    world = make_world(acp_idle_timeout=0.05)
    _point_chat_at(world, chat.endpoint)
    release = threading.Event()

    def stall(handler):
        release.wait(GUARD_SECONDS)

    chat.hooks[("POST", "/connection-1/rpc")] = stall
    try:
        reply = world.call("/api/astrid/acp/connection-1/rpc", "POST",
                           headers={"Content-Type": "application/json"}, body=body)
        assert (reply.status, reply.json()) == (504, {"error": "upstream_timeout"})
    finally:
        release.set()


@pytest.mark.parametrize("close_listener", [False, True], ids=["browser-disconnect", "listener-shutdown"])
def test_pending_prompt_connection_closes_without_cancelling_work(make_world, chat, close_listener):
    world = make_world(acp_idle_timeout=0.05)
    _point_chat_at(world, chat.endpoint)
    started, upstream_closed = threading.Event(), threading.Event()

    def prompt(handler):
        started.set()
        handler.connection.settimeout(GUARD_SECONDS)
        assert handler.rfile.read(1) == b""
        upstream_closed.set()

    chat.hooks[("POST", "/connection-1/rpc")] = prompt
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=GUARD_SECONDS)
    try:
        connection.request("POST", "/api/astrid/acp/connection-1/rpc", body=RPC_BODY,
                           headers={"Origin": HOSTED, "Content-Type": "application/json"})
        assert started.wait(GUARD_SECONDS)
        if close_listener:
            world.daemon.stop()
        else:
            connection.close()
        assert upstream_closed.wait(GUARD_SECONDS), "pending prompt HTTP connection leaked"
        assert [entry["path"] for entry in chat.requests] == ["/connection-1/rpc"]
    finally:
        connection.close()


def test_prompt_upstream_disconnect_is_unavailable(make_world, chat):
    world = make_world(acp_idle_timeout=0.05)
    _point_chat_at(world, chat.endpoint)

    def disconnect(handler):
        handler.connection.shutdown(socket.SHUT_RDWR)

    chat.hooks[("POST", "/connection-1/rpc")] = disconnect
    reply = world.call("/api/astrid/acp/connection-1/rpc", "POST",
                       headers={"Content-Type": "application/json"}, body=RPC_BODY)
    assert (reply.status, reply.json()) == (503, {"error": "acp_unavailable"})


# 7. Redirect -----------------------------------------------------------------


def test_upstream_redirect_is_refused(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)

    def redirect(handler):
        handler.send_response(302)
        handler.send_header("Location", "https://remote.test/x")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    chat.hooks[("GET", "/health")] = redirect

    reply = world.call("/api/astrid/acp/health")

    assert (reply.status, reply.json()) == (502, {"error": "upstream_redirect_forbidden"})
    assert [entry["path"] for entry in chat.requests] == ["/health"]


# 8. Streaming ----------------------------------------------------------------


def test_event_stream_is_forwarded_before_upstream_finishes(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)
    release = threading.Event()

    def events(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.end_headers()
        handler.wfile.write(b"data: one\n\n")
        handler.wfile.flush()
        release.wait(GUARD_SECONDS)
        handler.wfile.write(b"data: two\n\n")
        handler.wfile.flush()

    chat.hooks[("GET", "/connection-1/events")] = events
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=GUARD_SECONDS)
    try:
        connection.putrequest("GET", "/api/astrid/acp/connection-1/events", skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", f"127.0.0.1:{world.port}")
        connection.putheader("Origin", HOSTED)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 200

        received = b""
        while b"data: one" not in received:
            chunk = response.read1(4096)
            assert chunk, "the door closed the stream before the first event arrived"
            received += chunk

        release.set()
        received += response.read()
    finally:
        release.set()
        connection.close()

    assert b"data: one\n\n" in received
    assert b"data: two\n\n" in received
    assert received.index(b"data: one") < received.index(b"data: two")


# 9. Response header allowlist ------------------------------------------------


def test_response_headers_are_allowlisted(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)

    def agents_with_extras(handler):
        _json_reply(handler, 200, {"agents": []}, extra_headers=[("Set-Cookie", "s=1"), ("X-Secret", "1")])

    chat.hooks[("GET", "/agents")] = agents_with_extras

    reply = world.call(AGENTS)

    assert (reply.status, reply.json()) == (200, {"agents": []})
    assert "set-cookie" not in reply.headers
    assert "x-secret" not in reply.headers


# 10. Chat is behind the same product authority and readiness as every other route.


def test_chat_needs_the_product_credential_and_a_ready_runtime(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)
    assert world.call(AGENTS).status == 200
    forwarded = len(chat.requests)

    credential = world.credential_file.read_bytes()
    world.credential_file.unlink()
    reply = world.call(AGENTS)
    assert (reply.status, reply.json()) == (503, {"error": "runtime_unavailable"})
    world.credential_file.write_bytes(credential)
    os.chmod(world.credential_file, 0o600)

    world.daemon.service._verified = False
    reply = world.call(AGENTS)
    assert (reply.status, reply.json()) == (503, {"error": "runtime_unavailable"})
    assert len(chat.requests) == forwarded, "nothing reached the chat service while the product could not act"


# 11. Closing the listener closes the chat streams it forwards.


def test_listener_shutdown_closes_inflight_chat_streams(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)
    upstream_closed = threading.Event()
    first_event_sent = threading.Event()

    def events(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.end_headers()
        handler.wfile.write(b"data: one\n\n")
        handler.wfile.flush()
        first_event_sent.set()
        # Blocks until the door closes its end of this connection.
        handler.rfile.read(1)
        upstream_closed.set()

    chat.hooks[("GET", "/connection-1/events")] = events
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=GUARD_SECONDS)
    try:
        connection.putrequest("GET", "/api/astrid/acp/connection-1/events", skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", f"127.0.0.1:{world.port}")
        connection.putheader("Origin", HOSTED)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 200
        assert first_event_sent.wait(GUARD_SECONDS)

        world.daemon.stop()

        assert upstream_closed.wait(GUARD_SECONDS), "the chat stream outlived the listener that forwarded it"
    finally:
        connection.close()


# 12. The registration is read once, bounded.


def test_an_oversized_registration_is_ignored(make_world, chat):
    world = make_world()
    padded = json.dumps({"endpoint": chat.endpoint, "token": CHAT_TOKEN}) + " " * (65 * 1024)
    path = world.support / "chat.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(padded)

    reply = world.call(AGENTS)

    assert (reply.status, reply.json()) == (503, {"error": "acp_unavailable"})
    assert chat.requests == []


def test_forwards_astrid_api_key_route_and_keeps_astrid_out_of_connection_ids(make_world, chat):
    world = make_world()
    _point_chat_at(world, chat.endpoint)
    key_body = b'{"provider":"openrouter","key":"sk-or-test-key"}'

    def saved(handler):
        _json_reply(handler, 200, {"provider": "openrouter", "signedIn": True, "currentModel": None})

    chat.hooks[("POST", "/astrid/api-key")] = saved
    reply = world.call("/api/astrid/acp/astrid/api-key", "POST", headers={"Content-Type": "application/json"}, body=key_body)
    as_connection = world.call("/api/astrid/acp/astrid", "DELETE")

    assert (reply.status, reply.json()) == (200, {"provider": "openrouter", "signedIn": True, "currentModel": None})
    assert [(entry["method"], entry["path"], entry["body"]) for entry in chat.requests] == [
        ("POST", "/astrid/api-key", key_body),
    ]
    assert as_connection.status == 404
