"""Process replay reuse never replaces fresh authority reads."""
from __future__ import annotations

import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest
import test_timeline_commit_authentication as auth
from test_timeline_commit_port import commit

from runtime_protocol.errors import ProtocolError
from runtime_protocol.util import canonical_json

service = auth.service


def accepted(service, monkeypatch):
    auth.provider(service)
    result = commit(service, auth.body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    publication = result["receipt"]["receipt_id"]
    calls = Counter()
    original = commits._verify_accepted_replay

    def verify(row, edge, *args):
        calls[(threading.get_ident(), edge["project_seq"])] += 1
        return original(row, edge, *args)

    monkeypatch.setattr(commits, "_verify_accepted_replay", verify)
    return commits, publication, calls


def read(service, commits, publication):
    return commits.history_entry(service.test_project, "main", publication)


def test_replay_reused_across_evaluations_and_returns_detached_values(service, monkeypatch):
    commits, publication, calls = accepted(service, monkeypatch)
    with commits.verification_scope():
        expected = read(service, commits, publication)
        for _ in range(3):
            value = read(service, commits, publication)
            assert value == expected
            value["records"]["steps"].clear()
        assert list(calls.values()) == [1]
        outer = commits._verification.current
        with commits.verification_scope():
            read(service, commits, publication)
            assert list(calls.values()) == [1]
        assert commits._verification.current is outer
        read(service, commits, publication)
        assert list(calls.values()) == [1]
    assert commits._verification.current is None
    assert not outer["verified"] and not outer["active"]
    read(service, commits, publication)
    read(service, commits, publication)
    assert list(calls.values()) == [1]


def test_concurrent_evaluations_share_replay_but_keep_independent_scopes(service, monkeypatch):
    commits, publication, calls = accepted(service, monkeypatch)
    barrier = threading.Barrier(2)

    def evaluate():
        with commits.verification_scope():
            barrier.wait(timeout=5)
            for _ in range(2):
                read(service, commits, publication)
        assert commits._verification.current is None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(evaluate) for _ in range(2)]
        for future in futures:
            future.result(timeout=10)
    assert list(calls.values()) == [1]


def test_failure_never_memoized_and_baseexception_cleans_scope(service, monkeypatch):
    commits, publication, calls = accepted(service, monkeypatch)
    original = commits._verify_accepted_replay
    failures = []

    def fail(*args):
        failures.append(True)
        raise ValueError("bad retained suffix")

    monkeypatch.setattr(commits, "_verify_accepted_replay", fail)
    with pytest.raises(KeyboardInterrupt), commits.verification_scope():
        current = commits._verification.current
        for _ in range(2):
            with pytest.raises(ProtocolError):
                read(service, commits, publication)
            assert not current["verified"] and not current["active"]
        monkeypatch.setattr(commits, "_verify_accepted_replay", original)
        read(service, commits, publication)
        raise KeyboardInterrupt()
    assert len(failures) == 2
    assert commits._verification.current is None
    assert not current["verified"] and not current["active"]
    read(service, commits, publication)
    assert list(calls.values()) == [2]


@pytest.mark.parametrize("target", ["metadata", "event", "source", "owner", "abi", "records", "ledger"])
def test_same_head_mutation_is_detected_inside_and_after_scope(service, monkeypatch, target):
    commits, publication, _ = accepted(service, monkeypatch)
    conn = service.store.conn
    edge = conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=?", (publication,)).fetchone()
    if target == "owner":
        service.create_timeline(service.test_project, "other", idempotency_key="other")
    with commits.verification_scope():
        read(service, commits, publication)
        if target in {"metadata", "abi", "records"}:
            import json
            column = "records_json" if target == "records" else "metadata_json"
            changed = json.loads(edge[column])
            if target == "abi":
                changed["recorder_abi"] = 1
            elif target == "metadata":
                changed["label"] = "forged"
            else:
                changed["steps"][0]["patch"] = []
            conn.execute(f"UPDATE timeline_commit_history SET {column}=? WHERE publication_id=?",
                         (canonical_json(changed), publication))
        elif target == "event":
            conn.execute("UPDATE timeline_events SET payload_json='{}' WHERE timeline_id=? AND kind='timeline.commit.accepted'",
                         ("main",))
        elif target == "source":
            conn.execute("UPDATE parent_composition_revisions SET content_digest=? WHERE id=?",
                         ("sha256:" + "0" * 64, edge["previous_revision_id"]))
        elif target == "owner":
            conn.execute("UPDATE parent_composition_revisions SET timeline_id='other' WHERE id=?",
                         (edge["previous_revision_id"],))
        else:
            conn.execute("UPDATE command_idempotency SET request_hash='forged' WHERE txn_id=?", (publication,))
        # A ledger hash alone has no pure replay check in an old fixture without
        # a retained capture, but the accepted event always authenticates it.
        with pytest.raises(ProtocolError):
            read(service, commits, publication)
    with pytest.raises(ProtocolError):
        read(service, commits, publication)


def test_recursive_accepted_history_is_rejected_and_cleans_active_set(service, monkeypatch):
    commits, publication, _ = accepted(service, monkeypatch)
    original = commits._accepted_replay

    def recurse(*args, **kwargs):
        read(service, commits, publication)
        return original(*args, **kwargs)

    monkeypatch.setattr(commits, "_accepted_replay", recurse)
    with commits.verification_scope():
        with pytest.raises(ProtocolError, match="cycle"):
            read(service, commits, publication)
        assert not commits._verification.current["active"]
        assert not commits._verification.current["verified"]
    monkeypatch.setattr(commits, "_accepted_replay", original)
    read(service, commits, publication)


def test_consistent_source_rewrite_invalidates_entry_only_digest(service, monkeypatch):
    import json

    from runtime_protocol.timeline_commit_validation import digest

    commits, publication, calls = accepted(service, monkeypatch)
    conn = service.store.conn
    entry = read(service, commits, publication)
    source_id = entry["previous"]["revision_id"]
    source = conn.execute("SELECT payload_json FROM parent_composition_revisions WHERE id=?", (source_id,)).fetchone()[0]
    with commits.verification_scope():
        read(service, commits, publication)
        payload = json.loads(source)
        payload["meta"] = {"org.example.source": {"changed": True}}
        conn.execute("UPDATE parent_composition_revisions SET payload_json=?, content_digest=? WHERE id=?",
                     (canonical_json(payload), digest(payload), source_id))
        # The rewritten source is internally consistent. The accepted edge,
        # ledger, head and event bytes have not moved, but its binding is stale.
        commits.revision_closure(service.test_project, "main", source_id)
        with pytest.raises(ProtocolError):
            read(service, commits, publication)
        assert list(calls.values()) == [2]


def test_nested_public_history_api_has_fresh_scope(service, monkeypatch):
    commits, publication, calls = accepted(service, monkeypatch)
    with commits.verification_scope():
        read(service, commits, publication)
        service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
        read(service, commits, publication)
        assert list(calls.values()) == [1]


def test_store_write_outside_accept_discards_successful_replay(service, monkeypatch):
    commits, publication, calls = accepted(service, monkeypatch)
    expected = read(service, commits, publication)
    assert commits._replay_memo
    service.create_timeline(service.test_project, "another", idempotency_key="another")
    assert read(service, commits, publication) == expected
    assert list(calls.values()) == [2]


def test_public_authorization_refusal_discards_successful_replay(service, monkeypatch):
    from runtime_protocol.errors import ForbiddenError

    commits, publication, calls = accepted(service, monkeypatch)
    expected = read(service, commits, publication)
    assert commits._replay_memo

    def refuse():
        raise ForbiddenError("authority changed")

    with pytest.raises(ForbiddenError):
        service.list_timeline_commits(service.test_project, "main", authorize=refuse)
    assert not commits._replay_memo
    assert read(service, commits, publication) == expected
    assert list(calls.values()) == [2]


def test_retained_rehashed_step_forgery_refuses_with_warm_memo(service, monkeypatch):
    # Reuse D88's retained security-test_d88_review.py witness unchanged in
    # substance. Only its withdrawn persisted attestation is absent here.
    import json

    from runtime_protocol.timeline_commit_validation import digest

    commits, publication, _ = accepted(service, monkeypatch)
    read(service, commits, publication)
    assert commits._replay_memo
    conn = service.store.conn
    row = conn.execute("SELECT * FROM command_idempotency WHERE txn_id=?", (publication,)).fetchone()
    edge = conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=?", (publication,)).fetchone()
    records = json.loads(edge["records_json"])
    result = json.loads(row["result_json"])
    records["steps"][0]["patch"] = []
    result["steps"][0]["patch"] = []
    conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                 (canonical_json(records), publication))
    conn.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?",
                 (canonical_json(result), publication))
    event_id = json.loads(row["event_ids_json"])[-1]
    event = conn.execute("SELECT * FROM timeline_events WHERE id=?", (event_id,)).fetchone()
    payload = json.loads(event["payload_json"])
    payload["records_digest"] = digest(records)
    hashed = {"timeline_id": "main", "kind": event["kind"], "payload": payload,
              "previous_hash": event["previous_hash"], "created_at": event["created_at"]}
    conn.execute("UPDATE timeline_events SET payload_json=?, event_hash=? WHERE id=?",
                 (canonical_json(payload), digest(hashed)[7:], event_id))
    before = list(conn.iterdump())
    with pytest.raises(ProtocolError):
        read(service, commits, publication)
    assert not commits._replay_memo
    assert list(conn.iterdump()) == before
