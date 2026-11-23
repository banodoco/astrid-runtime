"""The daemon start entrypoint owns a bounded JSONL timing sink."""
import json
import logging

import pytest

from runtime_protocol import cli
from runtime_protocol.timeline_commit_execution import CommitExecutionCoordinator
from test_timeline_commit_acceptance import context, prepared, realm as _commit_realm


@pytest.fixture
def timing_realm(tmp_path):
    yield from _commit_realm.__wrapped__(tmp_path)


class _Port:
    def __init__(self, commits, ctx, candidate):
        self.commits, self.ctx, self.candidate = commits, ctx, candidate

    def accept(self):
        return self.commits.accept(self.ctx, self.candidate, authorize=lambda: None)

    def close(self):
        pass


class _Provider:
    def commit(self, ctx, port):
        return port.accept()


def test_daemon_start_writes_one_json_timing_record_per_commit_with_root_warning(
    tmp_path, monkeypatch, timing_realm,
):
    service, commits, project, head, _ = timing_realm

    root = logging.getLogger()
    logger = logging.getLogger("runtime_protocol.timeline_commit_execution")
    previous_level = root.level
    previous_logger_level = logger.level
    root.setLevel(logging.WARNING)
    try:
        def daemon_start(_args):
            request = context(service, project, head, "daemon-timing-sink")
            candidate = prepared(commits, request)
            CommitExecutionCoordinator(commits).execute(
                request, _Provider(), lambda bound: _Port(commits, bound, candidate),
                authorize=lambda: None,
            )
            return 0

        monkeypatch.setattr(cli, "_main", daemon_start)
        data_root = tmp_path / "data"
        support_root = data_root / "runtime"
        log_file = tmp_path / "os-logs" / "runtime.log"
        assert cli.main([
            "start", "--root", str(tmp_path / "realm"),
            "--support-root", str(support_root), "--log-file", str(log_file),
        ]) == 0

        sink = data_root / "logs" / "commit-stage-timings.jsonl"
        lines = sink.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event"] == "timeline_commit_timing"
        assert record["outcome"] == "accepted"
        assert "timings_ms" in record and "stage_spans_ms" in record
        assert set(record) <= {
            "event", "request_id", "outcome", "timings_ms", "stage_spans_ms",
            "exclusive_timings_ms", "runtime_wall_ms", "sizes_bytes",
            "public_request_id_hash", "idempotency_key_sha256",
        }
        assert str(tmp_path) not in lines[0]
        assert (sink.parent / "commit-stage-timings.jsonl.1").exists() is False
    finally:
        root.setLevel(previous_level)
        logger.setLevel(previous_logger_level)


def test_timing_handler_rotates_with_bounded_backups(tmp_path):
    from runtime_protocol.logs import CommitStageTimingHandler

    path = tmp_path / "logs" / "commit-stage-timings.jsonl"
    handler = CommitStageTimingHandler(path)
    logger = logging.getLogger("runtime_protocol.timeline_commit_execution")
    record = logging.LogRecord(
        logger.name, logging.INFO, __file__, 1,
        "runtime.timeline_commit.timing {\"event\":\"timeline_commit_timing\",\"padding\":\"%s\"}" % ("x" * 8000,),
        (), None,
    )
    try:
        for _ in range(540):
            handler.emit(record)
        assert path.exists()
        rotated = [path.with_name(path.name + f".{index}") for index in range(1, 4)]
        assert all(item.exists() for item in rotated)
        assert not path.with_name(path.name + ".4").exists()
        for item in [path, *rotated]:
            assert item.stat().st_size <= 1024 * 1024
            for line in item.read_text(encoding="utf-8").splitlines():
                assert json.loads(line)["event"] == "timeline_commit_timing"
    finally:
        handler.close()
