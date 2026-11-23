"""Rotating UTF-8 logs shared by the Runtime and its profile services."""

from __future__ import annotations

import contextlib
import json
import io
import logging
import sys
import threading
from pathlib import Path

from . import platform


def _replace(source, destination):
    def operation():
        return source.replace(destination)
    if sys.platform == "win32":
        return platform._retry_windows_sharing_violation(operation)
    return operation()


class RotatingLog(io.TextIOBase):
    def __init__(self, path, *, max_bytes=5 * 1024 * 1024, backups=3):
        super().__init__()
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        platform.owner_only(self.path.parent)
        self._file = None
        self._open()

    @property
    def encoding(self):
        return "utf-8"

    def _open(self):
        self._file = self.path.open("ab", buffering=0)
        try:
            platform.owner_only(self.path)
        except BaseException:
            self._file.close()
            raise
        self._size = self._file.tell()

    def write(self, value):
        encoded = value.encode("utf-8", "replace")
        with self._lock:
            if self.closed:
                raise ValueError("write to closed log")
            if self._size and self._size + len(encoded) > self.max_bytes:
                self._file.close()
                try:
                    for index in range(self.backups, 0, -1):
                        source = self.path if index == 1 else self.path.with_name(self.path.name + f".{index - 1}")
                        if source.exists():
                            _replace(source, self.path.with_name(self.path.name + f".{index}"))
                finally:
                    self._open()
            self._file.write(encoded)
            self._size += len(encoded)
        return len(value)

    def flush(self):
        with self._lock:
            if self._file is not None and not self._file.closed:
                self._file.flush()

    def close(self):
        with self._lock:
            try:
                super().close()
            finally:
                if self._file is not None:
                    self._file.close()


class CommitStageTimingHandler(logging.Handler):
    """Write only the structured commit timing payloads to a bounded JSONL file."""

    PREFIX = "runtime.timeline_commit.timing "
    MAX_RECORD_BYTES = 16 * 1024

    def __init__(self, path):
        super().__init__(level=logging.INFO)
        self._log = RotatingLog(path, max_bytes=1024 * 1024, backups=3)

    def emit(self, record):
        try:
            message = record.getMessage()
            if record.name != "runtime_protocol.timeline_commit_execution" or not message.startswith(self.PREFIX):
                return
            payload = message[len(self.PREFIX):]
            encoded = (payload + "\n").encode("utf-8")
            if len(encoded) > self.MAX_RECORD_BYTES:
                return
            # The producer emits JSON, but validate before making this a JSONL sink.
            json.loads(payload)
            self._log.write(payload + "\n")
        except Exception:
            # Diagnostics must not change the outcome of a commit.
            return

    def close(self):
        try:
            self._log.close()
        finally:
            super().close()


@contextlib.contextmanager
def commit_stage_timing_sink(path):
    """Attach the JSONL sink directly so root logger configuration is irrelevant."""
    logger = logging.getLogger("runtime_protocol.timeline_commit_execution")
    previous_level = logger.level
    handler = CommitStageTimingHandler(path)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        handler.close()
