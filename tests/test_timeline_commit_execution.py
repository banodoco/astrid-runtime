from __future__ import annotations

import copy
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import AuthorizationError, ProtocolError, RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_execution import CommitExecutionCoordinator, CommitOutcomeUnknown
from runtime_protocol.timeline_commit_store import request_identity
from test_timeline_commit_acceptance import RECORD_CORRUPTIONS, accept, accepted_recorder, assert_corrupt_restart, context, corrupt_recorder, counts, prepared, realm


class Port:
    def __init__(self, commits, ctx, candidate, *, close_error=False):
        self.commits, self.ctx, self.candidate = commits, ctx, candidate
        self.closed = False
        self.close_error = close_error

    def accept(self):
        assert not self.closed
        return accept(self.commits, self.ctx, self.candidate)

    def close(self):
        self.closed = True
        if self.close_error:
            raise RuntimeError("hook failed after COMMIT")


class Provider:
    def __init__(self, call):
        self.call = call
        self.calls = 0

    def commit(self, ctx, port):
        self.calls += 1
        return self.call(ctx, port)


def _timing_payloads(caplog):
    prefix = "runtime.timeline_commit.timing "
    return [json.loads(record.getMessage()[len(prefix):]) for record in caplog.records
            if record.getMessage().startswith(prefix)]


def test_success_and_replay_keep_receipt_and_emit_bounded_stage_timings(realm, caplog):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head, "timing-replay")
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    provider = Provider(lambda _, port: port.accept())

    with caplog.at_level(logging.DEBUG, logger="runtime_protocol.timeline_commit_execution"):
        accepted = coordinator.execute(
            ctx, provider, lambda c: Port(commits, c, candidate), authorize=lambda: None,
        )
        replay = coordinator.execute(
            ctx, Provider(lambda *_: pytest.fail("exact replay reran provider")),
            lambda _: pytest.fail("exact replay constructed a port"), authorize=lambda: None,
        )

    assert replay == accepted
    assert replay["data"]["status"] == accepted["data"]["status"]
    assert replay["receipt"] == accepted["receipt"]
    assert provider.calls == 1
    payloads = _timing_payloads(caplog)
    assert [payload["outcome"] for payload in payloads] == ["accepted", "replay"]
    for payload in payloads:
        assert set(payload["timings_ms"]) == {
            "handler", "service_admission", "initial_replay_lookup", "provider_commit",
            "port_store_accept", "close", "durable_reconciliation", "wire_response", "total",
        }
        assert all(type(value) is int and 0 <= value <= 24 * 60 * 60 * 1000
                   for value in payload["timings_ms"].values())


def test_timing_is_redacted_and_durable_winner_still_wins(realm, caplog):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head, "timing-durable-winner")
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    durable = []

    def provider_call(_, port):
        durable.append(port.accept())
        raise RuntimeError("payload-secret-must-not-be-logged")

    with caplog.at_level(logging.DEBUG, logger="runtime_protocol.timeline_commit_execution"):
        result = coordinator.execute(
            ctx, Provider(provider_call), lambda c: Port(commits, c, candidate),
            authorize=lambda: None,
        )

    assert result == durable[0]
    assert result["data"]["status"] == "accepted"
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "payload-secret-must-not-be-logged" not in messages
    payloads = _timing_payloads(caplog)
    assert len(payloads) == 1
    line = next(record.getMessage() for record in caplog.records
                 if record.getMessage().startswith("runtime.timeline_commit.timing "))
    assert len((line + "\n").encode()) <= 4096
    assert all(type(value) is int and value >= 0
               for value in payloads[0]["timings_ms"].values())


def test_timing_covers_real_port_and_store_acceptance(realm, caplog):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    service, commits, project, head, _ = realm
    ctx = context(service, project, head, "timing-real-port")
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)

    with caplog.at_level(logging.DEBUG, logger="runtime_protocol.timeline_commit_execution"):
        result = coordinator.execute(
            ctx,
            Provider(lambda _, port: (port.head(), port.accept(candidate))[1]),
            lambda bound: RequestCommitPort(service, commits, bound, lambda: None),
            authorize=lambda: None,
        )

    assert result["data"]["status"] == "accepted"
    payload = _timing_payloads(caplog)[0]
    assert payload["timings_ms"]["provider_commit"] >= payload["timings_ms"]["port_store_accept"] >= 0


def test_commit_duplicate_move_winner_between_lookup_and_execution(realm):
    _winner_before_lock(realm, "clip.move")


def test_commit_duplicate_add_winner_between_lookup_and_execution(realm):
    _winner_before_lock(realm, "clip.add")


def test_mounted_service_forwards_full_v2_context_and_structured_invalid_reply(request):
    service, _, project, head, _ = request.getfixturevalue("realm")
    reads = [{"kind": "scope", "ref": "parent", "path": []}]
    patch = {
        "op": "set",
        "ref": "parent",
        "path": ["config", "title"],
        "before": {"state": "absent"},
        "value": "Opening",
    }
    body = {
        "api_version": 1,
        "project_id": project,
        "timeline_id": "main",
        "base_revision_id": head["revision_id"],
        "base_publication_id": head["publication_id"],
        "commands": [{
            "schema_version": 1,
            "op": "doc.patch",
            "version": "1",
            "select": None,
            "args": {"changes": [patch]},
        }],
        "label": "Opening title",
        "steps": [{
            "id": "opening",
            "label": "Opening title",
            "intent": "Set the opening title",
            "tags": ["title"],
            "command_ordinals": [0],
            "patch": [patch],
            "reads": reads,
        }],
        "merge": "fields",
        "reads": reads,
        "source": {"via": "app", "detail": "mounted-v2"},
    }
    seen = []

    class InvalidProvider:
        provider_id = "astrid-v1"
        interface_version = 1
        contract_digest = SCHEMA_DIGEST

        def commit(self, context, port):
            seen.append((copy.deepcopy(context), port._provider_context()))
            return {
                "http_status": 422,
                "code": "invalid_commit",
                "message": "fixture provider rejected the candidate",
                "details": {
                    "status": "invalid",
                    "reason": "fixture_rejection",
                    "base": None,
                    "current": None,
                    "conflicts": [],
                    "path": ["commands", 0, "args", "changes"],
                    "hint": "inspect the patch",
                    "suggested_command": "timeline show",
                },
            }

    service.register_timeline_commit_provider(InvalidProvider())
    with pytest.raises(RuntimeErrorBase) as error:
        service.commit_timeline(
            project,
            "main",
            body,
            idempotency_key="mounted-v2-invalid",
            publisher="authenticated-editor",
            invocation_path=f"/v1/projects/{project}/timelines/main/commit",
            authorize=lambda: None,
        )

    assert error.value.status == 422
    assert error.value.code == "invalid_commit"
    assert error.value.details["status"] == "invalid"
    assert error.value.details["path"] == ["commands", 0, "args", "changes"]
    assert len(seen) == 1
    context, provider_context = seen[0]
    assert context["request"] == body
    assert context["invocation"]["body"] == body
    assert provider_context == context
    assert context["publisher"] == "authenticated-editor"
    assert context["idempotency_key"] == "mounted-v2-invalid"
    assert "request_id" not in context


def _winner_before_lock(realm, op):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head, op=op)
    candidate = prepared(commits, ctx)
    if op == "clip.add":
        command = candidate["records"]["commands"][0]["command"]
        command["select"] = "parent"
        command["args"] = {"row": {"id": "clip", "clipType": "hold", "track": "picture", "at": 2, "hold": 1}}
        ctx["request"]["commands"][0] = copy.deepcopy(command)
        ctx["invocation"]["body"] = copy.deepcopy(ctx["request"])
        ctx["request_hash"] = request_identity(ctx)
        candidate["records"]["commands"][0]["command"] = copy.deepcopy(command)
        candidate["records"]["commands"][0]["created"] = [{"ref": "parent/clip:clip", "kind": "clip", "owner": "parent"}]
    coordinator = CommitExecutionCoordinator(commits)
    missed, resume = threading.Event(), threading.Event()
    def loser():
        assert commits.lookup(ctx, authorize=lambda: None) is None
        missed.set()
        assert resume.wait(10)
        provider = Provider(lambda *_: pytest.fail("loser executed provider after winner"))
        result = coordinator.execute(ctx, provider, lambda _: pytest.fail("loser constructed semantic port"), authorize=lambda: None)
        assert provider.calls == 0
        return result
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(loser)
        assert missed.wait(10)
        winner = coordinator.execute(ctx, Provider(lambda _, port: port.accept()), lambda c: Port(commits, c, candidate), authorize=lambda: None)
        resume.set()
        assert future.result(timeout=10) == winner
    assert commits.history(project, "main", commits.head(project, "main"))["items"][-1]["records"] == candidate["records"]
    assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'").fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 2
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE kind='timeline.commit.accepted'").fetchone()[0] == 1
    assert not coordinator._entries


def test_equal_waiters_share_entry_and_never_hold_store_mutex(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    entered, release = threading.Event(), threading.Event()
    def run_provider(_, port):
        entered.set()
        assert release.wait(10)
        return port.accept()
    provider = Provider(run_provider)
    def run():
        return coordinator.execute(ctx, provider, lambda c: Port(commits, c, candidate), authorize=lambda: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run)
        assert entered.wait(10)
        waiting = threading.Event()
        with coordinator._guard:
            entry = next(iter(coordinator._entries.values()))
            original_lock = entry.lock
            class WaitLock:
                def __enter__(self):
                    waiting.set()
                    original_lock.acquire()
                def __exit__(self, *args):
                    original_lock.release()
            entry.lock = WaitLock()
        second = pool.submit(run)
        assert waiting.wait(10)
        # The provider is paused with exclusion held. SQLite is still available.
        assert commits.head(project, "main") == head
        with coordinator._guard:
            assert next(iter(coordinator._entries.values())) is entry
            assert entry.users == 2
        release.set()
        assert first.result(timeout=10) == second.result(timeout=10)
    assert provider.calls == 1
    assert not coordinator._entries


@pytest.mark.parametrize("completion", ["conflict", "refused", "head_busy", "exception", "close_exception", "preview", "accepted"])
def test_all_provider_completions_reconcile_a_durable_winner(realm, completion):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    durable = []
    def run(_, port):
        durable.append(port.accept())
        if completion == "exception":
            raise RuntimeError("loser failed after COMMIT")
        if completion == "close_exception":
            return durable[0]
        if completion == "preview":
            return {"data": {"status": "preview"}, "receipt": None}
        if completion == "accepted":
            return durable[0]
        return {"http_status": 409, "code": "conflict", "message": "loser rejection", "details": {
            "status": "conflict" if completion == "conflict" else "refused", "reason": completion,
            "base": None, "current": None, "conflicts": []}}
    result = coordinator.execute(ctx, Provider(run), lambda c: Port(commits, c, candidate, close_error=completion == "close_exception"), authorize=lambda: None)
    assert result == durable[0]
    assert len(commits.history(project, "main", commits.head(project, "main"))["items"]) == 2
    assert not coordinator._entries


def test_active_hash_mismatch_does_no_provider_work(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    changed = copy.deepcopy(ctx)
    changed["invocation"]["body"]["rationale"] = "different"
    changed["request_hash"] = request_identity(changed)
    coordinator = CommitExecutionCoordinator(commits)
    entered, release = threading.Event(), threading.Event()
    def run(_, port):
        entered.set()
        assert release.wait(10)
        return port.accept()
    with ThreadPoolExecutor(max_workers=1) as pool:
        winner = pool.submit(coordinator.execute, ctx, Provider(run), lambda c: Port(commits, c, candidate), authorize=lambda: None)
        assert entered.wait(10)
        try:
            with pytest.raises(CommitRejected) as error:
                coordinator.execute(changed, Provider(lambda *_: pytest.fail("changed hash ran provider")), lambda _: None, authorize=lambda: None)
            assert error.value.failure["details"]["reason"] == "idempotency_mismatch"
        finally:
            release.set()
        winner.result(timeout=10)
    assert not coordinator._entries


def test_claimed_acceptance_without_ledger_is_protocol_failure(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    coordinator = CommitExecutionCoordinator(commits)
    before = counts(service)
    with pytest.raises(ProtocolError):
        coordinator.execute(ctx, Provider(lambda *_: {"data": {"status": "accepted"}, "receipt": {}}),
                            lambda c: Port(commits, c, None), authorize=lambda: None)
    assert counts(service) == before
    assert not coordinator._entries


def test_readback_failure_is_unknown_outcome(realm, monkeypatch):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    lookup = commits.lookup
    calls = 0
    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("storage read unavailable")
        return lookup(*args, **kwargs)
    monkeypatch.setattr(commits, "lookup", fail_second)
    with pytest.raises(CommitOutcomeUnknown) as error:
        coordinator.execute(ctx, Provider(lambda _, p: p.accept()), lambda c: Port(commits, c, candidate), authorize=lambda: None)
    assert error.value.status == 503
    monkeypatch.setattr(commits, "lookup", lookup)
    assert commits.lookup(ctx, authorize=lambda: None)["data"]["status"] == "accepted"
    assert not coordinator._entries


def test_authority_is_rechecked_before_disclosing_acceptance(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    allowed = True
    def authorize():
        if not allowed:
            raise AuthorizationError("credential revoked")
    def run(_, port):
        nonlocal allowed
        result = port.accept()
        allowed = False
        return result
    with pytest.raises(AuthorizationError):
        coordinator.execute(ctx, Provider(run), lambda c: Port(commits, c, candidate), authorize=authorize)
    assert commits.lookup(ctx, authorize=lambda: None) is not None
    assert not coordinator._entries


def test_concurrent_different_keys_cas_one_winner(realm):
    from runtime_protocol.timeline_commit import StaleHead
    service, commits, project, head, _ = realm
    contexts = [context(service, project, head, f"parallel-{i}") for i in range(2)]
    candidates = [prepared(commits, ctx, revision=f"parallel-parent-{i}") for i, ctx in enumerate(contexts)]
    barrier = threading.Barrier(2)
    coordinator = CommitExecutionCoordinator(commits)
    def execute(i):
        def run(_, port):
            barrier.wait(timeout=10)
            return port.accept()
        try:
            return coordinator.execute(contexts[i], Provider(run), lambda c: Port(commits, c, candidates[i]), authorize=lambda: None)
        except StaleHead:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, range(2)))
    assert sum(result is not None for result in results) == 1
    assert len(commits.history(project, "main", commits.head(project, "main"))["items"]) == 2
    assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.commit'").fetchone()[0] == 1
    assert not coordinator._entries


def test_durable_original_wins_while_changed_hash_is_active_before_lookup(realm, monkeypatch):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    coordinator = CommitExecutionCoordinator(commits)
    accepted = coordinator.execute(ctx, Provider(lambda _, p: p.accept()), lambda c: Port(commits, c, candidate), authorize=lambda: None)
    changed = copy.deepcopy(ctx)
    changed["request"]["rationale"] = "changed request"
    changed["invocation"]["body"] = copy.deepcopy(changed["request"])
    changed["request_hash"] = request_identity(changed)
    registered, resume = threading.Event(), threading.Event()
    lookup = commits.lookup
    def paused_lookup(value, **kwargs):
        if value["request_hash"] == changed["request_hash"]:
            registered.set()
            assert resume.wait(10)
        return lookup(value, **kwargs)
    monkeypatch.setattr(commits, "lookup", paused_lookup)
    must_not_run = Provider(lambda *_: pytest.fail("durable retry ran semantic provider"))
    with ThreadPoolExecutor(max_workers=1) as pool:
        loser = pool.submit(coordinator.execute, changed, must_not_run, lambda _: pytest.fail("changed request built port"), authorize=lambda: None)
        assert registered.wait(10)
        try:
            assert coordinator.execute(ctx, must_not_run, lambda _: pytest.fail("exact retry built port"), authorize=lambda: None) == accepted
        finally:
            resume.set()
        with pytest.raises(CommitRejected) as error:
            loser.result(timeout=10)
        assert error.value.failure["details"]["reason"] == "idempotency_mismatch"
    assert must_not_run.calls == 0
    assert not coordinator._entries


@pytest.mark.parametrize("path,replacement", RECORD_CORRUPTIONS)
def test_corrupt_durable_recorder_never_reruns_provider_even_after_restart(realm, path, replacement):
    service, commits, _, _, root = realm
    ctx, value, result = accepted_recorder(realm)
    corrupt_recorder(service, value, result, path, replacement)
    coordinator = CommitExecutionCoordinator(commits)
    provider = Provider(lambda *_: pytest.fail("corrupt accepted key reran provider"))
    before = counts(service)
    head = tuple(service.store.conn.execute("SELECT * FROM parent_composition_heads WHERE timeline_id='main'").fetchone())
    with pytest.raises(CommitOutcomeUnknown) as error:
        coordinator.execute(ctx, provider, lambda _: pytest.fail("corrupt accepted key constructed semantic port"), authorize=lambda: None)
    assert error.value.status == 503
    assert isinstance(error.value.__cause__, ProtocolError)
    assert provider.calls == 0
    assert not coordinator._entries
    assert counts(service) == before
    assert tuple(service.store.conn.execute("SELECT * FROM parent_composition_heads WHERE timeline_id='main'").fetchone()) == head
    assert_corrupt_restart(service, root)
