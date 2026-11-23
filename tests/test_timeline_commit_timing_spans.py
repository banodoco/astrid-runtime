"""The permanent commit timing record keeps bounded stage spans and sizes."""
import io
import json
import logging
import time

from runtime_protocol import timeline_commit_execution as execution


def test_commit_timing_emits_stage_spans_and_byte_sizes():
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
        timing = execution.CommitTiming()
        timing.begin("total")
        for name in execution._TIMING_FIELDS:
            if name == "total":
                continue
            timing.begin(name)
            timing.end(name)
        timing.end("total")
        timing.set_size("request_body", 1234)
        timing.set_size("response_body", 567)
        timing.emit()

        line = stream.getvalue().strip()
        assert line.startswith("runtime.timeline_commit.timing ")
        payload = json.loads(line.split(" ", 1)[1])
        assert set(payload["stage_spans_ms"]) == set(execution._TIMING_FIELDS)
        for name, span in payload["stage_spans_ms"].items():
            assert set(span) == {"start_ms", "end_ms", "duration_ms"}
            assert 0 <= span["start_ms"] <= span["end_ms"]
            assert span["duration_ms"] == payload["timings_ms"][name]
        assert payload["sizes_bytes"] == {"request_body": 1234, "response_body": 567}
        assert sum(payload["exclusive_timings_ms"].values()) == payload["runtime_wall_ms"]
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_root_level)
        logger.setLevel(previous_logger_level)
        handler.close()


def test_exclusive_partition_assigns_nested_stages_once_and_accounts_for_gaps():
    timing = execution.CommitTiming()
    timing._origin_ns = 0
    timing._ended_ns = 10_000_000
    timing._span_ns = {
        "handler": (0, 9_000_000),
        "service_admission": (2_000_000, 4_000_000),
        "provider_commit": (3_000_000, 7_000_000),
        "port_store_accept": (4_000_000, 5_000_000),
    }

    exclusive = timing._exclusive_timings()
    assert exclusive == {
        "handler": 4,
        "service_admission": 1,
        "provider_commit": 3,
        "port_store_accept": 1,
        "unattributed": 1,
    }
    assert sum(exclusive.values()) == 10


def test_normal_finish_emits_nonzero_runtime_wall_and_exclusive_stages():
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
        timing, token = execution.start_commit_timing()
        timing.begin("handler")
        time.sleep(0.003)
        timing.end("handler")
        execution.finish_commit_timing(timing, token)

        line = stream.getvalue().strip()
        payload = json.loads(line.split(" ", 1)[1])
        assert payload["timings_ms"]["total"] > 0
        assert payload["stage_spans_ms"]["total"]["duration_ms"] > 0
        assert payload["exclusive_timings_ms"]["handler"] > 0
        assert payload["runtime_wall_ms"] > 0
        assert sum(payload["exclusive_timings_ms"].values()) == payload["runtime_wall_ms"]
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_root_level)
        logger.setLevel(previous_logger_level)
        handler.close()
