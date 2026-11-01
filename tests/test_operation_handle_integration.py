"""Direct owned TS transport against real startup-loaded Agent and Runtime SQL.

Response gates delay only observation of real server output, after acceptance;
they never substitute a provider, client, credential authority or wire DTO.
"""
from __future__ import annotations

import json
import queue
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path

import pytest

from door_helpers import DoorWorld
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.server import RuntimeHandler
from test_timeline_commit_integration import Editing, agent, film, positions, rows  # noqa: F401

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def compiled_client(tmp_path_factory):
    output = tmp_path_factory.mktemp("operation-client")
    (output / "package.json").write_text('{"type":"module"}\n')
    # Override only the output directory; read the normal package sources and
    # compiler without writing build products or caches in shared dependencies.
    subprocess.run([
        shutil.which("tsc") or "tsc", "-p", str(ROOT / "packages/typescript/tsconfig.json"),
        "--outDir", str(output / "dist"),
    ], check=True, capture_output=True, text=True)
    return output / "dist/index.js"


class NodeSession:
    def __init__(self, compiled, config):
        self.process = subprocess.Popen(
            [shutil.which("node") or "node", str(ROOT / "tests/fixtures/operation-handle-live.mjs")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.events = queue.Queue()

        def read():
            for line in self.process.stdout:
                self.events.put(json.loads(line))
            self.events.put({"event": "closed"})

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        # Credentials travel on a private pipe, never argv, stdout or logs.
        self.send({"client": str(compiled), **config})

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def expect(self, event):
        value = self.events.get(timeout=30)
        assert value["event"] == event, (value, self.process.stderr.read() if value["event"] == "closed" else "")
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        self.reader.join(timeout=10)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()

    def finish(self):
        self.expect("done")
        self.process.stdin.close()
        assert self.process.wait(timeout=10) == 0, self.process.stderr.read()


class ResponseGate:
    def __init__(self, method, path, wait):
        self.method, self.path, self.wait = method, path, wait
        self.entered, self.release = threading.Event(), threading.Event()
        self.payload = None

    def pause(self):
        self.entered.set()
        if not self.release.wait(timeout=30):
            raise TimeoutError("test did not release real HTTP response")


@pytest.fixture
def live(film, agent, tmp_path, monkeypatch):
    daemon = RuntimeDaemon(
        film.fixture.duplicate_root, support_root=tmp_path / "support", authoring_profile="astrid",
    ).start()
    world = DoorWorld(tmp_path, daemon, tmp_path / "product.json")
    world.provision()
    editing = Editing(daemon.service, film, agent)
    editing.assert_baseline()
    gates, responses = [], []
    send = RuntimeHandler._send

    def delayed(handler, status, payload=None, **kwargs):
        if not getattr(handler, "_defer_response", False):
            responses.append((handler.command, handler.path, status, kwargs.get("error")))
            for gate in list(gates):
                if (handler.command, handler.path) != (gate.method, gate.path):
                    continue
                gates.remove(gate)
                gate.payload = payload
                if gate.wait == "response":
                    gate.pause()
                else:
                    end_headers = handler.end_headers

                    def headers_then_pause():
                        end_headers()
                        gate.pause()

                    handler.end_headers = headers_then_pause
                break
        return send(handler, status, payload, **kwargs)

    monkeypatch.setattr(RuntimeHandler, "_send", delayed)
    try:
        yield world, editing, gates, responses
    finally:
        for gate in gates:
            gate.release.set()
        world.stop()


@pytest.mark.parametrize("wait", ["response", "body"])
def test_durable_lost_ack_rebind_exact_retry_and_dispose(live, compiled_client, wait):
    world, edit, gates, _ = live
    body = edit.body([edit.move("music-bed", 1)])
    before_history = edit.history()
    ack = ResponseGate("POST", edit.path, wait)
    read = ResponseGate("GET", edit.path.removesuffix("/commit"), wait)
    gates.append(ack)
    node = NodeSession(compiled_client, {
        "mode": "recovery", "base": world.daemon.endpoint, "token": world.product_token,
        "body": body, "key": "connector-lost-ack", "wait": wait,
    })
    try:
        node.expect("ready")
        assert ack.entered.wait(timeout=30)
        if wait == "body":
            node.expect("body-await")
        # A separate SQLite connection sees the commit before any client ACK.
        accepted = ack.payload
        durable = sqlite3.connect(f"{edit.service.store.db_path.as_uri()}?mode=ro", uri=True)
        try:
            assert durable.execute(
                "SELECT COUNT(*) FROM timeline_commit_history WHERE project_id=? AND timeline_id=?",
                (edit.project, edit.timeline),
            ).fetchone()[0] == len(before_history) + 1
            stored, = durable.execute(
                "SELECT result_json FROM command_idempotency WHERE txn_id=? AND command_kind='timeline.commit'",
                (accepted["receipt"]["receipt_id"],),
            ).fetchone()
            assert json.loads(stored) == accepted["data"]
        finally:
            durable.close()
        assert accepted["data"]["status"] == "accepted"
        assert accepted["data"]["publisher"] == "astrid-door-product"
        assert positions(accepted["data"]["canonical_document"])["music-bed"] == 1
        edit.assert_readback(accepted)
        after = rows(edit.service)
        fresh_token = world.provision()
        node.send({"token": fresh_token})
        node.expect("rebound")
        ack.release.set()
        replay = node.expect("replayed")["result"]
        assert replay == accepted
        assert rows(edit.service) == after
        assert len(edit.history()) == len(before_history) + 1
        assert edit.history()[-1]["publication_id"] == accepted["receipt"]["receipt_id"]
        gates.append(read)
        node.send({"read": True})
        assert read.entered.wait(timeout=30)
        if wait == "body":
            node.expect("body-await")
        node.send({"dispose": True})
        node.expect("disposed")
        read.release.set()
        node.finish()
        assert rows(edit.service) == after
        edit.assert_baseline()
    finally:
        ack.release.set()
        read.release.set()
        node.close()


def test_real_credentials_and_scope_refusals(live, compiled_client):
    world, edit, _, responses = live
    reader, _ = world.daemon.credentials.provision("connector-reader", ["handshake", "projects:read"])
    body = edit.body([edit.move("music-bed", 1)])
    before = rows(edit.service)
    node = NodeSession(compiled_client, {
        "mode": "auth", "base": world.daemon.endpoint, "token": reader,
        "body": body, "key": "connector-refused",
    })
    try:
        node.finish()
        refused = [(path, error) for _, path, status, error in responses if status == 401]
        assert [path for path, _ in refused] == [
            "/v1/handshake", edit.path, "/v1/handshake", edit.path,
        ]
        assert refused[0][1]["message"] == "invalid bearer credential"
        assert refused[1][1]["message"] == "invalid bearer credential"
        assert refused[2][1]["details"]["scopes"] == ["projects:write"]
        assert refused[3][1]["details"]["scope"] == "projects:write"
        assert rows(edit.service) == before
    finally:
        node.close()
