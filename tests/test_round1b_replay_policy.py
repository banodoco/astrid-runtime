from types import SimpleNamespace

import pytest

from runtime_protocol import service as service_module
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService


@pytest.mark.parametrize("kind,table,created,window", [
    ("timeline.commit", "command_idempotency", None, service_module.IDEMPOTENCY_RESULT_WINDOW_SECONDS),
    ("task.claim_delegated_child", "session_command_replay", "old", service_module.SESSION_IDEMPOTENCY_WINDOW_SECONDS),
    ("task.claim", "session_command_replay", "old", service_module.SESSION_IDEMPOTENCY_WINDOW_SECONDS),
    ("project.create", "command_idempotency", "old", service_module.IDEMPOTENCY_RESULT_WINDOW_SECONDS),
])
def test_replay_selects_correct_table_and_expiry(monkeypatch, kind, table, created, window):
    calls = []
    row = {"request_hash": "digest", "result_json": "{}", "created_at": "old"}
    class Connection:
        def execute(self, query, args):
            calls.append((query, args))
            return SimpleNamespace(fetchone=lambda: row)
    conn = Connection()
    instance = object.__new__(RuntimeService)
    instance.store = SimpleNamespace(conn=conn)
    def decode(data, **kwargs):
        calls.append(kwargs)
        return {"ok": True}
    monkeypatch.setattr(service_module, "command_result", decode)
    assert instance._command_replay_state(kind, "item", "replay-key", "digest") == (True, {"ok": True})
    assert table in calls[0][0]
    assert calls[1]["created_at"] == created
    assert calls[1]["window_seconds"] == window
    with pytest.raises(ConflictError):
        instance._command_replay_state(kind, "item", "replay-key", "different")
