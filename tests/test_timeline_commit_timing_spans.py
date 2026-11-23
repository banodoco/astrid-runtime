"""The permanent commit timing record keeps bounded stage spans and sizes."""
import io
import json
import logging

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
        for name in execution._TIMING_FIELDS:
            timing.begin(name)
            timing.end(name)
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
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_root_level)
        logger.setLevel(previous_logger_level)
        handler.close()
