"""Runtime request timing logs stay compact and off the response contract."""
import hashlib
import json
import logging
import threading
from types import SimpleNamespace

import runtime_protocol.server as runtime_server
from runtime_protocol.server import RuntimeHandler


def test_dispatch_logs_request_over_one_second_as_bounded_json(monkeypatch, caplog):
    # A deterministic monotonic clock makes the slow-request boundary cheap to
    # exercise without sleeping or changing the response path.
    ticks = iter((0, 10, 20, 1_000_000_020))
    monkeypatch.setattr(runtime_server.time, "monotonic_ns", lambda: next(ticks))

    class Handler(RuntimeHandler):
        def _route(self):
            pass

    handler = object.__new__(Handler)
    handler.server = SimpleNamespace(runtime=SimpleNamespace(store=SimpleNamespace(_mutex=threading.RLock())))
    handler.headers = {}
    handler.command = "GET"
    handler.path = "/v1/projects/example"
    handler._runtime_request_id = "request-for-test"

    with caplog.at_level(logging.INFO, logger=runtime_server.__name__):
        handler._dispatch()

    records = [record for record in caplog.records if record.getMessage().startswith("runtime.request.slow ")]
    assert len(records) == 1
    encoded = records[0].getMessage().removeprefix("runtime.request.slow ")
    payload = json.loads(encoded)
    assert payload == {
        "event": "request_slow",
        "method": "GET",
        "path": "/v1/projects/example",
        "request_id_sha256": hashlib.sha256(b"request-for-test").hexdigest(),
        "store_lock_wait_ms": 0,
        "total_ms": 1000,
    }
    assert len(encoded.encode("utf-8")) < 2048


def test_slow_request_diagnostic_ignores_malformed_path():
    handler = object.__new__(RuntimeHandler)
    handler.path = "//[malformed"
    handler.command = "GET"
    handler._runtime_request_id = "request-for-test"

    # urlsplit rejects this network-path reference's malformed IPv6 authority.
    # Diagnostic parsing must never become a request-processing failure.
    handler._log_slow_request(1_000_000_001, 0)
