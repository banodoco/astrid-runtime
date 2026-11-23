"""Per-request covers diagnostics stay isolated and leave exceptions intact."""
import io
import json
import logging

import pytest

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol import timeline_commit_execution as execution
from runtime_protocol.timeline_commit_producer import value_equal


def _capture_timing(callback):
    root = logging.getLogger()
    logger = execution._LOGGER
    previous_handlers = root.handlers[:]
    previous_root_level = root.level
    previous_logger_level = logger.level
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    try:
        root.handlers[:] = [handler]
        root.setLevel(logging.INFO)
        logger.setLevel(logging.NOTSET)
        callback()
        line = stream.getvalue().strip()
        assert line.startswith("runtime.timeline_commit.timing ")
        return json.loads(line.split(" ", 1)[1])
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_root_level)
        logger.setLevel(previous_logger_level)
        handler.close()


def test_covers_and_value_equal_counts_are_request_local_and_emitted():
    def request():
        timing, token = execution.start_commit_timing()
        try:
            assert auth.covers([{"kind": "field", "ref": "x", "path": ["a"]}],
                               {"kind": "field", "ref": "x", "path": ["a"]})
            assert value_equal({"a": [1]}, {"a": [1]})
        finally:
            execution.finish_commit_timing(timing, token)

    first = _capture_timing(request)["covers"]
    second = _capture_timing(request)["covers"]
    assert first["calls"] == 1
    assert first["elapsed_ns"] >= 0
    assert first["value_equal_calls"] == 8
    assert second["calls"] == first["calls"]
    assert second["elapsed_ns"] >= 0
    assert second["value_equal_calls"] == first["value_equal_calls"]


def test_covers_exception_counts_and_cleans_request_context():
    timing, token = execution.start_commit_timing()
    try:
        with pytest.raises(KeyError):
            auth.covers([{}], {"kind": "field", "ref": "x", "path": []})
    finally:
        execution.finish_commit_timing(timing, token)
    assert execution.current_commit_timing() is None
    assert timing.covers_calls == 1
    assert timing.covers_elapsed_ns >= 0


def test_off_commit_counts_are_noops():
    assert execution.current_commit_timing() is None
    assert auth.covers([], {"kind": "field", "ref": "x", "path": []}) is False
    assert value_equal(1, 1)
