"""Connection bursts cannot change the automatic lifetime-reaper cadence."""
from types import SimpleNamespace

import pytest

from runtime_protocol import server as module


def test_connection_turns_keep_the_idle_reaper_cadence_and_explicit_pumps(monkeypatch):
    clock = [0.0]
    calls = []
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    server = module.RuntimeHTTPServer(('127.0.0.1', 0), module.RuntimeHandler)
    server.runtime = SimpleNamespace(reap_task_lifetimes=lambda: calls.append(clock[0]))

    def accept_loop(self, poll_interval):
        assert poll_interval == 0.2
        for now, expected in [(0, 0), (0.19, 0), (0.2, 1), (0.39, 1), (0.4, 2)]:
            clock[0] = now
            # A burst of accepted connections runs many service_actions turns.
            for _ in range(20):
                self.service_actions()
                if self._maintenance_thread is not None:
                    self._maintenance_thread.join(2)
                    assert not self._maintenance_thread.is_alive()
            assert len(calls) == expected

    monkeypatch.setattr(module.ThreadingHTTPServer, 'serve_forever', accept_loop)
    try:
        server.serve_forever(poll_interval=0.2)
        assert calls == [0.2, 0.4]
        # Explicit recovery/handover callers can still request immediate work.
        server.service_actions()
        server._maintenance_thread.join(2)
        assert calls == [0.2, 0.4, 0.4]
    finally:
        server.server_close()


def test_automatic_maintenance_error_is_observed_before_the_next_tick(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    server = module.RuntimeHTTPServer(('127.0.0.1', 0), module.RuntimeHandler)

    def reap():
        raise ValueError('maintenance failure')

    server.runtime = SimpleNamespace(reap_task_lifetimes=reap)

    def accept_loop(self, poll_interval):
        clock[0] = poll_interval
        self.service_actions()
        self._maintenance_thread.join(2)
        # The previous failure must surface even though the clock did not move.
        with pytest.raises(ValueError, match='maintenance failure'):
            self.service_actions()

    monkeypatch.setattr(module.ThreadingHTTPServer, 'serve_forever', accept_loop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
