"""Clean restart replay checkpoint proofs through the ordinary Runtime service."""
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest
import test_timeline_commit_port as port_tests
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, rows

from runtime_protocol import platform, timeline_commit_store
from runtime_protocol.errors import AuthorizationError, RealmAdmissionError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_store import TimelineCommitStore

service = port_tests.service
_CHECKPOINT = "timeline_replay_checkpoint"


def _history(service, project):
    return service.list_timeline_commits(project, "main", limit=1, authorize=lambda: None)


def _next(service, *, prior="opening", note="second"):
    change_body = body(service)
    change = change_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": {"org.example.timeline": {"note": prior}}}
    change["value"] = {"org.example.timeline": {"note": note}}
    change_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    return change_body


def _seed(service):
    provider(service)
    first = commit(service, body(service))
    last = commit(service, _next(service), key="edit-2")
    project = service.test_project
    expected = _history(service, project)
    root = service.store.root
    service.close()
    return root, project, first["receipt"]["receipt_id"], last["receipt"]["receipt_id"], expected


def _replays(monkeypatch):
    original = TimelineCommitStore._verify_accepted_replay
    calls = []

    def verify(commits, row, edge, *args):
        calls.append((commits.store.db_path, edge["publication_id"]))
        return original(commits, row, edge, *args)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", verify)
    return calls


def _state(root):
    return root / "admission-state.json"


def _uncheckpoint(root):
    path = _state(root)
    state = json.loads(path.read_text())
    state.pop(_CHECKPOINT, None)
    path.write_text(json.dumps(state))


def test_clean_restart_rederives_live_history_without_semantic_replay(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)
    admitted = []
    verify = TimelineCommitStore._verify_accepted_record

    def checked(commits, row, edge, **kwargs):
        admitted.append((commits.store.db_path, edge["publication_id"]))
        return verify(commits, row, edge, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_record", checked)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert any(path != root / "realm.sqlite3" and published == head for path, published in admitted)
    assert (root / "realm.sqlite3", head) in admitted
    assert calls == []


@pytest.mark.parametrize("change", ["version", "realm", "truncated", "stale", "unprotected", "missing"])
def test_invalid_checkpoint_replays_healthy_history(service, monkeypatch, change):
    root, project, first, head, expected = _seed(service)
    path = _state(root)
    state = json.loads(path.read_text())
    checkpoint = state[_CHECKPOINT]
    if change == "version":
        checkpoint["version"] = "unknown"
    elif change == "realm":
        checkpoint["realm_id"] = "another-realm"
    elif change == "stale":
        # Keep the old proof intact while advancing the real SQLite generation.
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE projects SET updated_at='changed' WHERE id=?", (project,))
    elif change == "unprotected":
        if sys.platform == "win32":
            pytest.skip("this case changes POSIX permission bits")
        path.chmod(0o644)
    elif change == "missing":
        del state[_CHECKPOINT]
    path.write_text(json.dumps(state) if change != "truncated" else '{"timeline_replay_checkpoint":')
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert {published for path, published in calls if path != root / "realm.sqlite3"} == {first, head}


def test_full_admission_can_publish_next_checkpoint_without_a_history_request(service, monkeypatch):
    root, project, first, head, expected = _seed(service)
    _uncheckpoint(root)
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)):
        assert {published for _, published in calls} == {first, head}
    calls.clear()
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert calls == []


@pytest.mark.parametrize("change", ["modified", "deleted", "reordered"])
def test_changed_history_has_same_startup_refusal_as_full_replay(service, monkeypatch, change):
    root, _, first, head, _ = _seed(service)
    with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
        if change == "modified":
            conn.execute("UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?", (head,))
        elif change == "deleted":
            conn.execute("DELETE FROM timeline_commit_history WHERE publication_id=?", (head,))
        else:
            old, new = [conn.execute("SELECT project_seq FROM timeline_commit_history WHERE publication_id=?",
                                     (published,)).fetchone()[0] for published in (first, head)]
            for published, ordinal in ((first, new + 100), (head, old), (first, new)):
                conn.execute("UPDATE timeline_commit_history SET project_seq=? WHERE publication_id=?", (ordinal, published))
    calls = _replays(monkeypatch)
    with pytest.raises(RealmAdmissionError) as retained:
        RuntimeService(root)
    retained_calls = calls.copy()
    _uncheckpoint(root)
    calls.clear()
    with pytest.raises(RealmAdmissionError) as uncached:
        RuntimeService(root)
    assert retained.value.details["checks"]["revisions"] == uncached.value.details["checks"]["revisions"]
    assert [published for _, published in retained_calls] == [published for _, published in calls]


def test_installed_verifier_change_cannot_relabel_earlier_proofs(service, monkeypatch):
    original = timeline_commit_store.version
    timeline_commit_store.replay_checkpoint_version.cache_clear()
    try:
        provider(service)
        commit(service, body(service))
        _history(service, service.test_project)
        monkeypatch.setattr(timeline_commit_store, "version",
                            lambda name: "changed" if name == "jsonschema" else original(name))
        service.close()
        assert _CHECKPOINT not in json.loads(_state(service.store.root).read_text())
    finally:
        timeline_commit_store.replay_checkpoint_version.cache_clear()


def test_interrupted_replacement_leaves_no_usable_checkpoint(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    project = service.test_project
    expected = _history(service, project)
    root = service.store.root
    path = _state(root)
    active = path.read_bytes()
    replace = platform.durable_replace
    attempted = []

    def crash(temporary, destination):
        if destination == path:
            attempted.append(json.loads(Path(temporary).read_bytes()))
            raise OSError("interrupted before admission replacement")
        return replace(temporary, destination)

    with monkeypatch.context() as patch:
        patch.setattr(platform, "durable_replace", crash)
        with pytest.raises(OSError, match="interrupted before admission replacement"):
            service.close()
    assert path.read_bytes() == active
    assert attempted[0]["clean_shutdown"] is True
    assert attempted[0][_CHECKPOINT]
    assert not tuple(root.glob(".admission-state-*"))
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert calls[0][1] == accepted["receipt"]["receipt_id"]


def test_process_crash_after_sync_never_admits_temporary_proof(service, monkeypatch):
    root, project, first, head, expected = _seed(service)
    code = """
import os
import sys
from runtime_protocol import platform, timeline_commit_store
from runtime_protocol.service import RuntimeService

service = RuntimeService(sys.argv[1])
replace = platform.durable_replace

def interrupted(source, destination):
    if destination.name == "admission-state.json":
        os._exit(77)
    return replace(source, destination)

platform.durable_replace = interrupted
service.close()
"""
    result = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 77, result.stderr
    assert json.loads(_state(root).read_text())["clean_shutdown"] is False
    orphans = tuple(root.glob(".admission-state-*"))
    assert len(orphans) == 1
    assert json.loads(orphans[0].read_text())[_CHECKPOINT]
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert {published for path, published in calls if path != root / "realm.sqlite3"} == {first, head}


def test_writer_between_copied_admission_and_live_open_forces_new_admission(service, monkeypatch):
    root, _, _, head, _ = _seed(service)
    original = RealmStore._open

    def change(store, **kwargs):
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (head,))
        return original(store, **kwargs)

    monkeypatch.setattr(RealmStore, "_open", change)
    with pytest.raises(RealmAdmissionError) as refused:
        RuntimeService(root)
    assert not refused.value.details["checks"]["revisions"]["ok"]


def test_first_refused_read_clears_live_checkpoint(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)

    def denied():
        raise AuthorizationError("read denied")

    with closing(RuntimeService(root)) as reopened:
        assert calls == []
        with pytest.raises(AuthorizationError, match="read denied"):
            reopened.list_timeline_commits(project, "main", limit=1, authorize=denied)
        assert _history(reopened, project) == expected
    assert (root / "realm.sqlite3", head) in calls


def test_external_unrelated_writer_also_clears_live_checkpoint(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
        assert calls == []
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE projects SET updated_at='external' WHERE id=?", (project,))
        assert _history(reopened, project) == expected
    assert (root / "realm.sqlite3", head) in calls


@pytest.mark.parametrize("retain", [True, False])
def test_external_history_write_before_commit_still_refuses(service, retain):
    root, project, _, head, expected = _seed(service)
    if not retain:
        _uncheckpoint(root)
    with closing(RuntimeService(root)) as reopened:
        reopened.test_project = project
        reopened.test_provider = port_tests.PreparedProvider()
        reopened.register_timeline_commit_provider(reopened.test_provider)
        provider(reopened)
        request = _next(reopened, prior="second", note="third")
        assert _history(reopened, project) == expected
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (head,))
        before = rows(reopened)
        with pytest.raises((CommitRejected, RuntimeErrorBase), match="corrupt|history"):
            commit(reopened, request, key="must-refuse")
        assert rows(reopened) == before
