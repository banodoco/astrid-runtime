"""Commit timing records must reach the Runtime's INFO log sink."""
import io
import logging

from runtime_protocol import timeline_commit_execution as execution


def test_commit_timing_reaches_info_sink_with_default_child_level():
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

        execution.CommitTiming().emit()

        record = stream.getvalue()
        assert record.startswith("runtime.timeline_commit.timing ")
        assert '"event":"timeline_commit_timing"' in record
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_root_level)
        logger.setLevel(previous_logger_level)
        handler.close()
