"""The existing HTTP poll hook must never wait for lifetime maintenance."""
import threading
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import RealmAdmissionError
from runtime_protocol.server import RuntimeHTTPServer, RuntimeHandler


def test_poll_maintenance_is_nonblocking_serialized_and_rescheduled():
    entered, release = threading.Event(), threading.Event()
    calls = []

    def reap():
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(2)

    server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = SimpleNamespace(reap_task_lifetimes=reap)
    try:
        server.service_actions()
        assert entered.wait(1)
        for _ in range(5):
            server.service_actions()
        assert len(calls) == 1
        assert calls[0] != threading.get_ident()
        release.set()
        server._maintenance_thread.join(2)
        assert not server._maintenance_thread.is_alive()
        server.service_actions()
        server._maintenance_thread.join(2)
        assert len(calls) == 2
    finally:
        release.set()
        server.server_close()


@pytest.mark.parametrize("error", [RealmAdmissionError("admission lost"), ValueError("unexpected maintenance failure")])
def test_maintenance_preserves_admission_and_unexpected_error_handling(error):
    calls = []

    def reap():
        calls.append(True)
        if len(calls) == 1:
            raise error

    server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = SimpleNamespace(reap_task_lifetimes=reap)
    try:
        server.service_actions()
        server._maintenance_thread.join(2)
        assert not server._maintenance_thread.is_alive()
        if isinstance(error, ValueError):
            with pytest.raises(ValueError) as observed:
                server.service_actions()
            assert observed.value is error
            assert len(calls) == 1
        server.service_actions()
        server._maintenance_thread.join(2)
        assert calls == [True, True]
    finally:
        server.server_close()


def test_server_close_drains_admitted_maintenance_before_store_teardown(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    joining, closed = threading.Event(), threading.Event()
    calls = []

    def reap():
        calls.append(True)
        entered.set()
        assert release.wait(2)

    server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = SimpleNamespace(reap_task_lifetimes=reap)
    closer = threading.Thread(target=lambda: (server.server_close(), closed.set()))
    try:
        server.service_actions()
        assert entered.wait(1)
        join = server._maintenance_thread.join

        def observed_join(*args, **kwargs):
            joining.set()
            return join(*args, **kwargs)

        monkeypatch.setattr(server._maintenance_thread, "join", observed_join)
        closer.start()
        assert joining.wait(1)
        assert not closed.is_set()
        assert not server.accepting_authenticated_requests
        release.set()
        closer.join(2)
        assert closed.is_set()
        server.service_actions()
        assert calls == [True]
    finally:
        release.set()
        if closer.ident is not None:
            closer.join(2)
        server.server_close()


def test_failed_maintenance_thread_start_releases_gate_and_allows_close(monkeypatch):
    server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    server.runtime = SimpleNamespace(reap_task_lifetimes=lambda: None)

    def failed_start(self):
        raise RuntimeError("cannot start maintenance thread")

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    try:
        with pytest.raises(RuntimeError, match="cannot start maintenance thread"):
            server.service_actions()
        assert not server._maintenance_lock.locked()
    finally:
        server.server_close()
