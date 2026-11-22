from __future__ import annotations

import errno
import sqlite3
import threading

import pytest

from runtime_protocol.server import RuntimeHandler, _ReplyWriter
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


class _FlakySocket:
    def __init__(self, fail, error, accept=10**9):
        self.fail, self.error, self.accept = fail, error, accept
        self.data = bytearray()
        self.sizes = []

    def send(self, view):
        if self.fail:
            self.fail -= 1
            raise self.error
        chunk = bytes(view[: self.accept])
        self.sizes.append(len(chunk))
        self.data += chunk
        return len(chunk)

    def fileno(self):
        return -1


@pytest.fixture
def writable(monkeypatch):
    monkeypatch.setattr("runtime_protocol.server.select.select", lambda r, w, x, t: ([], w, []))


def test_enobufs_then_full_reply_in_64k_pieces(writable):
    sock = _FlakySocket(2, OSError(errno.ENOBUFS, "No buffer space available"))
    payload = b"x" * (200 * 1024)
    assert _ReplyWriter(sock, 30).write(payload) == len(payload)
    assert bytes(sock.data) == payload
    assert max(sock.sizes) == 64 * 1024


def test_eagain_waits_and_continues(writable):
    sock = _FlakySocket(1, BlockingIOError(errno.EAGAIN, "again"))
    _ReplyWriter(sock, 30).write(b"hello")
    assert bytes(sock.data) == b"hello"


def test_other_errors_propagate_unchanged(writable):
    sock = _FlakySocket(1, ConnectionResetError(errno.ECONNRESET, "reset"))
    with pytest.raises(ConnectionResetError):
        _ReplyWriter(sock, 30).write(b"hello")


def test_enobufs_beyond_timeout_times_out(writable):
    sock = _FlakySocket(10**6, OSError(errno.ENOBUFS, "No buffer space available"))
    with pytest.raises(TimeoutError):
        _ReplyWriter(sock, 0.05).write(b"hello")


def test_health_is_served_without_the_store_mutex_and_returns_while_it_is_held(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        handler = RuntimeHandler.__new__(RuntimeHandler)
        handler.command, handler.path, handler.headers = "GET", "/v1/health", {}
        assert handler._is_health_probe()
        result = {}
        with service.store._mutex:
            thread = threading.Thread(target=lambda: result.update(service.health()))
            thread.start()
            thread.join(5)
            assert not thread.is_alive()
        assert result["status"] == "ok"
    finally:
        service.close()


def test_missing_realm_path_preserves_ordinary_health_but_identity_probe_revokes(tmp_path):
    root = tmp_path / "realm"
    moved = tmp_path / "moved"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        root.rename(moved)
        assert service.health()["status"] == "ok"
        assert service.health(identity_probe=True)["status"] == "degraded"
        assert service._admission_failure == {"reason": "runtime_liveness_failed"}
        moved.rename(root)
        assert service.health()["status"] == "degraded"
    finally:
        if moved.exists():
            moved.rename(root)
        service.close()


@pytest.mark.parametrize("failure", ["wrong-identity", "corrupt-schema", "corrupt-read", "closed-handle"])
def test_missing_realm_path_rejects_broken_primary_handle(tmp_path, failure):
    root = tmp_path / "realm"
    moved = tmp_path / "moved"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        root.rename(moved)
        if failure == "closed-handle":
            service.store.conn.close()
        elif failure == "corrupt-read":
            class CorruptConnection:
                def __init__(self, connection):
                    self.connection = connection

                def execute(self, _query):
                    raise sqlite3.DatabaseError("database disk image is malformed")

                def __getattr__(self, name):
                    return getattr(self.connection, name)

            service.store.conn = CorruptConnection(service.store.conn)
        else:
            service.store.conn.execute("PRAGMA foreign_keys=OFF")
            if failure == "wrong-identity":
                service.store.conn.execute("UPDATE realm SET id = 'wrong-realm'")
            else:
                service.store.conn.execute("DROP TABLE realm")
        assert service.health()["status"] == "degraded"
        assert service._admission_failure == {"reason": "runtime_liveness_failed"}
        moved.rename(root)
        assert service.health()["status"] == "degraded"
    finally:
        if moved.exists():
            moved.rename(root)
        service.store.close(orderly=False)


@pytest.mark.parametrize("replacement", ["file", "symlink-loop"])
def test_unresolvable_realm_ancestor_revokes_admission(tmp_path, replacement):
    parent = tmp_path / "parent"
    root = parent / "realm"
    moved = tmp_path / "moved"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        parent.rename(moved)
        if replacement == "file":
            parent.write_text("replacement", encoding="utf-8")
        else:
            parent.symlink_to(parent, target_is_directory=True)
        assert service.health()["status"] == "degraded"
        assert service._admission_failure == {"reason": "runtime_liveness_failed"}
        parent.unlink()
        moved.rename(parent)
        assert service.health()["status"] == "degraded"
    finally:
        if moved.exists():
            parent.unlink(missing_ok=True)
            moved.rename(parent)
        service.close()
