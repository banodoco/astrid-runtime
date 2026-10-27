from __future__ import annotations

import hashlib
import json

import pytest

from astrid_runtime import cli
from astrid_runtime.paths import RuntimePaths
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api


def _live_owner(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    daemon = RuntimeDaemon(realm_root, support_root=paths.runtime_support, realm_id="realm").start()
    (paths.runtime_support / "credentials").mkdir(parents=True, exist_ok=True)
    (paths.runtime_support / "credentials" / "owner.token").write_text(daemon.token, encoding="utf-8")
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    return paths, daemon


def _task(daemon, task_id="task-clear", *, capability="clear.fixture"):
    digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
    daemon.service.register_capability({
        "capability_id": capability, "definition_digest": digest, "status": "ready",
    })
    created = daemon.service.create_task({
        "capability_id": capability, "capability_digest": digest,
        "input_object_ids": [], "spec": {}, "idempotency_key": "create-" + task_id,
    })
    return created["task"]


def _settlement(daemon, task_id):
    return Api(daemon.endpoint, daemon.token).request("GET", f"/v1/control/tasks/{task_id}/settlement")


def _external_cli_task(daemon):
    from tests.test_execution_binding_contract import CAPABILITY, CAPABILITY_DIGEST, _admit, _claim
    service = daemon.service
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST,
                                 "required_resource_keys": ["external-gpu"]})
    service.register_executor({"executor_id": "executor-a", "capabilities": [CAPABILITY],
                               "resource_keys": ["external-gpu"], "max_concurrency": 2},
                              idempotency_key="cli-external-register")
    target = {"kind": "runpod", "pod_id": "cli-pod", "provider_account_ref": "account-a"}
    admitted = _admit(service, "cli-external", target)
    attempt = _claim(service, "cli-external-claim", target)
    return admitted["task"]["id"], attempt


@pytest.mark.parametrize("json_output", [True, False])
def test_real_cli_successful_worker_lost_result_is_already_settled(tmp_path, monkeypatch, capsys, json_output):
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, attempt = _external_cli_task(daemon)
        result = daemon.service.settle_attempt(attempt["attempt_id"], {
            **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "outputs": [], "result": {"disposition": "lost", "reason": "ordinary worker result"},
        }, idempotency_key="ordinary-worker-lost-result")
        assert result["data"]["state"] == "succeeded"
        observation = _settlement(daemon, task_id)
        assert observation["state"] == "succeeded" and observation["settled"] is True
        assert "lost_disposition" not in observation
        before = list(daemon.service.store.conn.iterdump())
        args = ["tasks", "clear", task_id] + (["--json"] if json_output else [])
        assert cli.main(args) == 0
        output = capsys.readouterr().out
        if json_output:
            row = json.loads(output)["outcomes"][0]
            assert row == {"task_id": task_id, "outcome": "already_settled", "state": "succeeded", "repeated": False}
        else:
            assert "already_settled" in output and "succeeded" in output
            assert "lost" not in output
        assert "remote_stop_confirmed" not in output and "billing_stop_confirmed" not in output
        assert "ordinary worker result" not in output
        assert not daemon.service.store.conn.execute(
            "SELECT 1 FROM events WHERE task_id=? AND kind='task.abandoned'", (task_id,),
        ).fetchone()
        assert list(daemon.service.store.conn.iterdump()) == before
    finally:
        daemon.stop()


@pytest.mark.parametrize("json_output", [True, False], ids=["json", "text"])
@pytest.mark.parametrize("path,value", [
    pytest.param(("valid",), None, id="valid-signal"),
    pytest.param(("lost_disposition",), {}, id="empty-signal"),
    pytest.param(("lost_disposition", "extra"), None, id="extra-property"),
    pytest.param(("lost_disposition", "remote_stop_confirmed"), True, id="extra-remote-stop"),
    pytest.param(("lost_disposition", "billing_stop_confirmed"), True, id="extra-billing-stop"),
    pytest.param(("lost_disposition", "remote_stop_confirmed"), False, id="extra-remote-stop-false"),
    pytest.param(("lost_disposition", "billing_stop_confirmed"), False, id="extra-billing-stop-false"),
    pytest.param(("lost_disposition", ""), None, id="extra-empty-key"),
    pytest.param(("task", "state"), "succeeded", id="nested-state-succeeded"),
    pytest.param(("task", "state"), "cancelled", id="nested-state-cancelled"),
    pytest.param(("task", "state"), None, id="nested-state-null"),
    pytest.param(("missing", "task", "state"), None, id="nested-state-missing"),
    pytest.param(("task", "result", "task_id"), "other-task", id="result-task-mismatch"),
    pytest.param(("task", "result", "task_id"), None, id="result-task-null"),
    pytest.param(("task", "result", "task_id"), "", id="result-task-empty"),
    pytest.param(("task", "result", "task_id"), 123, id="result-task-numeric"),
    pytest.param(("missing", "task", "result", "task_id"), None, id="result-task-missing"),
    pytest.param(("task", "result", "run_id"), "other-run", id="result-run-mismatch"),
    pytest.param(("task", "result", "run_id"), None, id="result-run-null"),
    pytest.param(("task", "result", "run_id"), "", id="result-run-empty"),
    pytest.param(("task", "result", "run_id"), 123, id="result-run-numeric"),
    pytest.param(("missing", "task", "result", "run_id"), None, id="result-run-missing"),
    pytest.param(("task", "run_id"), None, id="canonical-run-null"),
    pytest.param(("task", "run_id"), "", id="canonical-run-empty"),
    pytest.param(("task", "run_id"), " \t", id="canonical-run-blank"),
    pytest.param(("task", "run_id"), 123, id="canonical-run-numeric"),
    pytest.param(("missing", "task", "run_id"), None, id="canonical-run-missing"),
    pytest.param(("lost_disposition",), None, id="null-signal"),
    pytest.param(("lost_disposition",), [], id="nonmapping-signal"),
    pytest.param(("lost_disposition", "reason"), None, id="null-reason"),
    pytest.param(("lost_disposition", "reason"), "", id="empty-reason"),
    pytest.param(("lost_disposition", "reason"), " \t\n", id="blank-reason"),
    pytest.param(("lost_disposition", "reason"), "x" * 4097, id="long-reason"),
    pytest.param(("lost_disposition", "reason"), 123, id="numeric-reason"),
    pytest.param(("lost_disposition", "event_id"), 123, id="numeric-event"),
    pytest.param(("lost_disposition", "event_id"), True, id="boolean-event"),
    pytest.param(("lost_disposition", "event_id"), [], id="array-event"),
    pytest.param(("lost_disposition", "event_id"), {}, id="object-event"),
    pytest.param(("lost_disposition", "event_id"), None, id="null-event"),
    pytest.param(("lost_disposition", "event_id"), "", id="empty-event"),
    pytest.param(("lost_disposition", "event_id"), "event", id="nondecimal-event"),
    pytest.param(("lost_disposition", "attempt_id"), 123, id="numeric-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), True, id="boolean-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), [], id="array-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), {}, id="object-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), None, id="null-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), "", id="empty-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), " ", id="blank-attempt"),
    pytest.param(("lost_disposition", "attempt_id"), "other-attempt", id="mismatched-attempt"),
    pytest.param(("lost_disposition", "reason"), "other reason", id="mismatched-reason"),
    pytest.param(("task_id",), "other-task", id="mismatched-settlement-task"),
    pytest.param(("task", "result"), None, id="null-result"),
    pytest.param(("task", "result", "disposition"), "ordinary", id="ordinary-result"),
    pytest.param(("task", "result", "remote_stop_confirmed"), True, id="remote-stop-true"),
    pytest.param(("task", "result", "remote_stop_confirmed"), 0, id="remote-stop-numeric"),
    pytest.param(("task", "result", "billing_stop_confirmed"), None, id="billing-stop-null"),
    pytest.param(("task", "result", "billing_stop_confirmed"), 0, id="billing-stop-numeric"),
    # The "missing" path prefix removes a property rather than setting it to null.
    pytest.param(("missing", "lost_disposition", "reason"), None, id="missing-reason"),
    pytest.param(("missing", "lost_disposition", "event_id"), None, id="missing-event"),
    pytest.param(("missing", "lost_disposition", "attempt_id"), None, id="missing-attempt"),
    pytest.param(("missing", "task", "result", "remote_stop_confirmed"), None, id="missing-remote-stop"),
    pytest.param(("missing", "task", "result", "billing_stop_confirmed"), None, id="missing-billing-stop"),
])
def test_real_cli_lost_signal_validation(tmp_path, monkeypatch, capsys, json_output, path, value):
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, attempt = _external_cli_task(daemon)
        daemon.service.fail_attempt(attempt["attempt_id"], {
            **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "error": {"message": "ordinary worker failure"},
        }, idempotency_key="ordinary-worker-failure")
        observed = _settlement(daemon, task_id)
        assert observed["state"] == "failed" and observed["settled"] is True
        assert "lost_disposition" not in observed
        original = daemon.task_settlement
        injected = []

        def injected_settlement(requested_id, *, identity):
            response = original(requested_id, identity=identity)
            response["lost_disposition"] = {"event_id": "123", "attempt_id": attempt["attempt_id"],
                                            "reason": "owner clears provider uncertainty"}
            response["task"]["result"] = {"task_id": task_id, "run_id": response["task"]["run_id"],
                "disposition": "lost", "attempt_id": attempt["attempt_id"],
                "reason": "owner clears provider uncertainty", "remote_stop_confirmed": False,
                "billing_stop_confirmed": False}
            missing = path[0] == "missing"
            keys = path[1:] if missing else path
            target = response
            for key in keys[:-1]:
                target = target[key]
            if path == ("valid",):
                pass
            elif missing:
                del target[keys[-1]]
                if keys == ("task", "run_id"):
                    del response["task"]["result"]["run_id"]
            else:
                target[keys[-1]] = value
                # Keep both copies equal for malformed types so rejection
                # proves shape validation as well as cross-record matching.
                if keys == ("lost_disposition", "reason") and value != "other reason":
                    response["task"]["result"]["reason"] = value
                if keys == ("lost_disposition", "attempt_id") and value != "other-attempt":
                    response["task"]["result"]["attempt_id"] = value
                if keys == ("task", "run_id"):
                    response["task"]["result"]["run_id"] = value
            injected.append(requested_id)
            return response

        # Inject at the server response boundary; HTTP, the generated client,
        # owner authorization and the CLI output path remain real.
        monkeypatch.setattr(daemon, "task_settlement", injected_settlement)
        before = list(daemon.service.store.conn.iterdump())
        database_before = daemon.service.store.db_path.read_bytes()
        assert cli.main(["tasks", "clear", task_id] + (["--json"] if json_output else [])) == 0
        output = capsys.readouterr().out
        assert injected == [task_id]
        expected = {"task_id": task_id, "outcome": "already_settled", "state": "failed", "repeated": False}
        if path == ("valid",):
            expected.update(outcome="lost", disposition="lost", reason="owner clears provider uncertainty",
                            remote_stop_confirmed=False, billing_stop_confirmed=False)
        if json_output:
            assert json.loads(output)["outcomes"] == [expected]
        else:
            assert json.loads(output.split("outcomes: ", 1)[1]) == [expected]
        if path != ("valid",):
            assert "lost" not in output
            assert "remote_stop_confirmed" not in output and "billing_stop_confirmed" not in output
        assert not daemon.service.store.conn.execute(
            "SELECT 1 FROM events WHERE task_id=? AND kind='task.abandoned'", (task_id,),
        ).fetchone()
        assert list(daemon.service.store.conn.iterdump()) == before
        assert daemon.service.store.db_path.read_bytes() == database_before
    finally:
        daemon.stop()


@pytest.mark.parametrize("terminal_state", ["succeeded", "failed"])
def test_real_cli_retry_terminal_result_does_not_inherit_old_owner_abandon(tmp_path, monkeypatch, capsys, terminal_state):
    from tests.test_execution_binding_contract import _claim

    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, old_attempt = _external_cli_task(daemon)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["outcomes"][0]["outcome"] == "lost"
        lost = _settlement(daemon, task_id)["lost_disposition"]
        assert lost["attempt_id"] == old_attempt["attempt_id"]
        daemon.service.retry_task(task_id, idempotency_key="retry-abandoned-for-cli")
        assert "lost_disposition" not in _settlement(daemon, task_id)
        attempt = _claim(daemon.service, "retry-cli-claim", {
            "kind": "runpod", "pod_id": "cli-pod", "provider_account_ref": "account-a",
        })
        assert attempt["attempt_id"] != old_attempt["attempt_id"]
        body = {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}
        worker_result = {"disposition": "lost", "reason": "ordinary worker result"}
        if terminal_state == "succeeded":
            daemon.service.settle_attempt(attempt["attempt_id"], {
                **body, "outputs": [], "result": worker_result,
            }, idempotency_key="retry-cli-succeeded")
        else:
            daemon.service.fail_attempt(attempt["attempt_id"], {
                **body, "error": worker_result,
            }, idempotency_key="retry-cli-failed")
        observation = _settlement(daemon, task_id)
        assert observation["state"] == terminal_state and observation["settled"] is True
        assert "lost_disposition" not in observation
        before = list(daemon.service.store.conn.iterdump())
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        row = json.loads(capsys.readouterr().out)["outcomes"][0]
        assert row == {"task_id": task_id, "outcome": "already_settled", "state": terminal_state, "repeated": False}
        assert daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM events WHERE task_id=? AND kind='task.abandoned'", (task_id,),
        ).fetchone()[0] == 1
        assert list(daemon.service.store.conn.iterdump()) == before
    finally:
        daemon.stop()


def test_real_cli_external_lost_is_distinct_from_cancellation_and_retained_on_replay(tmp_path, monkeypatch, capsys):
    from runtime_protocol.lifecycle import _interruption_report
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        external_id, attempt = _external_cli_task(daemon)
        ordinary = _task(daemon, "ordinary-to-cancel")
        untouched = _task(daemon, "keep-running", capability="clear.keep-running")
        daemon.service.register_executor({"executor_id": "unrelated-worker", "capabilities": ["clear.keep-running"]})
        daemon.service.claim_next({"executor_id": "unrelated-worker", "capability_ids": ["clear.keep-running"],
                                   "runtime_epoch": daemon.service.health()["runtime_epoch"]}, idempotency_key="keep-claim")
        assert cli.main(["tasks", "clear", external_id, ordinary["id"], external_id, "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert [row["outcome"] for row in result["outcomes"]] == ["lost", "settled", "lost"]
        assert result["outcomes"][0]["remote_stop_confirmed"] is False
        assert result["outcomes"][0]["billing_stop_confirmed"] is False
        assert result["outcomes"][1]["state"] == "cancelled"
        assert _settlement(daemon, external_id)["settled"] is True
        assert daemon.service.store.get_task(external_id)["run"]["status"] == "failed"
        assert daemon.service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
        blockers = _interruption_report(daemon.service.store.conn)["blockers"]
        assert {row["task_id"] for row in blockers} == {untouched["id"]}
        before = list(daemon.service.store.conn.iterdump())
        assert cli.main(["tasks", "clear", external_id, "--json"]) == 0
        replay = json.loads(capsys.readouterr().out)
        assert replay["outcomes"][0]["outcome"] == "lost"
        assert list(daemon.service.store.conn.iterdump()) == before
    finally:
        daemon.stop()


def test_real_cli_lost_response_retry_observes_durable_lost_without_second_event(tmp_path, monkeypatch, capsys):
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, _attempt = _external_cli_task(daemon)
        original = daemon.service.abandon_task

        def lose_response(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("simulated response lost after abandon commit")

        monkeypatch.setattr(daemon.service, "abandon_task", lose_response)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 1
        assert json.loads(capsys.readouterr().out)["outcomes"][0]["outcome"] == "unresolved"
        assert _settlement(daemon, task_id)["settled"] is True
        monkeypatch.setattr(daemon.service, "abandon_task", original)
        lost = _settlement(daemon, task_id)["lost_disposition"]
        daemon.stop()
        daemon = RuntimeDaemon(_paths.realms_dir / "realm", support_root=_paths.runtime_support, realm_id="realm").start()
        _cli_paths_for_daemon(tmp_path, monkeypatch, daemon)
        assert _settlement(daemon, task_id)["lost_disposition"] == lost
        before = list(daemon.service.store.conn.iterdump())
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["outcomes"][0]["outcome"] == "lost"
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM events WHERE task_id=? AND kind='task.abandoned'", (task_id,)).fetchone()[0] == 1
        assert list(daemon.service.store.conn.iterdump()) == before
    finally:
        daemon.stop()


def test_external_clear_refuses_attempt_changed_after_canonical_cancellation(tmp_path, monkeypatch, capsys):
    import copy
    from astrid_runtime import task_clear
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, _attempt = _external_cli_task(daemon)
        original = task_clear._typed_control
        abandon_calls = []
        observations = 0

        def raced_control(client):
            request = original(client)

            def control(method, route, body=None):
                nonlocal observations
                if method == "POST" and route.endswith("/abandon"):
                    abandon_calls.append(body)
                value = request(method, route, body)
                if method == "GET" and route.endswith("/settlement"):
                    observations += 1
                    if observations >= 2:
                        value = copy.deepcopy(value)
                        value["task"]["attempt_id"] = "different-new-attempt"
                        value["task"]["execution_binding"]["attempt_id"] = "different-new-attempt"
                return value

            return control

        monkeypatch.setattr(task_clear, "_typed_control", raced_control)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 1
        row = json.loads(capsys.readouterr().out)["outcomes"][0]
        assert row["outcome"] == "unresolved" and "changed" in row["abandon_error"]
        assert abandon_calls == []
        assert daemon.service.store.get_task(task_id)["task"]["waiting_reason"] == "provider_state_unknown"
    finally:
        daemon.stop()


def test_new_canonical_cancel_keeps_lost_terminal_disposition(tmp_path, monkeypatch):
    from astrid_runtime_client import WorkspaceClient
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_id, _attempt = _external_cli_task(daemon)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        events = daemon.service.store.conn.execute("SELECT COUNT(*) FROM events WHERE task_id=?", (task_id,)).fetchone()[0]
        result = WorkspaceClient(daemon.endpoint, daemon.token).cancel_task(task_id, idempotency_key="new-cancel-after-lost")
        assert result["state"] == "failed" and result["result"]["disposition"] == "lost"
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM events WHERE task_id=?", (task_id,)).fetchone()[0] == events
        assert daemon.service.store.get_task(task_id)["run"]["status"] == "failed"
    finally:
        daemon.stop()


def test_parser_help_and_exact_ids():
    args = cli.parser().parse_args(["tasks", "clear", "task-a", "task-b", "--json"])
    assert args.command == "tasks"
    assert args.tasks_command == "clear"
    assert args.task_ids == ["task-a", "task-b"]
    assert args.json is True
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["tasks", "clear"])


def test_real_loopback_cancel_duplicate_retry_and_event_idempotency(tmp_path, monkeypatch, capsys):
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task = _task(daemon)
        assert cli.main(["tasks", "clear", task["id"], task["id"], "--json"]) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["ok"] is True
        assert [row["outcome"] for row in first["outcomes"]] == ["settled", "settled"]
        assert first["outcomes"][1]["repeated"] is True
        assert first["outcomes"][1]["first_occurrence"] == 0
        assert _settlement(daemon, task["id"])["settled"] is True
        assert daemon.service.store.get_task(task["id"])["run"]["status"] == "cancelled"
        events_before = daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM events WHERE task_id=?", (task["id"],)
        ).fetchone()[0]

        assert cli.main(["tasks", "clear", task["id"], "--json"]) == 0
        retry = json.loads(capsys.readouterr().out)
        assert retry["outcomes"][0]["outcome"] == "already_settled"
        events_after = daemon.service.store.conn.execute(
            "SELECT COUNT(*) FROM events WHERE task_id=?", (task["id"],)
        ).fetchone()[0]
        assert events_after == events_before
    finally:
        daemon.stop()


def test_unknown_mixed_ids_are_deterministic_and_known_task_is_cleared(tmp_path, monkeypatch, capsys):
    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task = _task(daemon)
        assert cli.main(["tasks", "clear", "missing-task", task["id"], "--json"]) == 1
        result = json.loads(capsys.readouterr().out)
        assert [row["outcome"] for row in result["outcomes"]] == ["unknown", "settled"]
        assert _settlement(daemon, task["id"])["settled"] is True
    finally:
        daemon.stop()


def test_unrelated_ordinary_task_remains_a_lifecycle_blocker(tmp_path, monkeypatch, capsys):
    from runtime_protocol.lifecycle import _interruption_report

    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        named = _task(daemon, "clear-this", capability="clear.named")
        unrelated = _task(daemon, "keep-this-running", capability="clear.unrelated")
        daemon.service.register_executor({
            "executor_id": "ordinary-worker", "capabilities": ["clear.unrelated"],
            "max_concurrency": 1,
        })
        claim = daemon.service.claim_next({
            "executor_id": "ordinary-worker", "capability_ids": ["clear.unrelated"],
            "runtime_epoch": daemon.service.store._current_runtime_epoch(),
        }, idempotency_key="claim-unrelated")
        assert claim["task_id"] == unrelated["id"]
        daemon.service.store.conn.execute(
            "UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?",
            (claim["attempt_id"],),
        )
        daemon.service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00Z' WHERE id=?",
            (unrelated["id"],),
        )
        assert cli.main(["tasks", "clear", named["id"], "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["outcomes"][0]["outcome"] == "settled"
        blockers = _interruption_report(daemon.service.store.conn)["blockers"]
        assert any(row["task_id"] == unrelated["id"] for row in blockers)
        assert daemon.service.store.get_task(unrelated["id"])["task"]["status"] == "running"
        assert daemon.service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (claim["attempt_id"],)
        ).fetchone()[0] == 0
    finally:
        daemon.stop()


def test_real_cli_cancellation_preserves_canonical_continuation_containment(tmp_path, monkeypatch, capsys):
    from tests.test_task_continuations import _child, _continuation_body, _setup

    _paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        project_id, continuation_digest = _setup(daemon.service, "cli-clear-continuation")
        first = _child(daemon.service, project_id, "cli-clear-first")
        second = _child(daemon.service, project_id, "cli-clear-second")
        continuation = daemon.service.create_task(
            _continuation_body(project_id, continuation_digest, [
                first["task"]["id"], second["task"]["id"],
            ])
        )
        assert continuation["task"]["waiting_reason"] == "waiting_for_dependencies"
        assert cli.main(["tasks", "clear", first["task"]["id"], "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["outcomes"][0]["outcome"] == "settled"
        assert daemon.service.task(first["task"]["id"])["task"]["status"] == "cancelled"
        assert daemon.service.task(second["task"]["id"])["task"]["status"] == "queued"
        assert daemon.service.task(continuation["task"]["id"])["task"]["waiting_reason"] == "dependency_cancelled"
        assert daemon.service.task(continuation["task"]["id"])["task"]["status"] == "queued"
    finally:
        daemon.stop()


def test_bad_owner_credential_preflights_all_ids_before_any_cancel(tmp_path, monkeypatch, capsys):
    paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task_a = _task(daemon, "task-a", capability="clear.a")
        task_b = _task(daemon, "task-b", capability="clear.b")
        (paths.runtime_support / "credentials" / "owner.token").write_text("not-an-owner", encoding="utf-8")
        assert cli.main(["tasks", "clear", task_a["id"], task_b["id"], "--json"]) == 1
        result = json.loads(capsys.readouterr().out)
        assert all(row["outcome"] == "failed" for row in result["outcomes"])
        assert daemon.service.task(task_a["id"])["task"]["status"] == "queued"
        assert daemon.service.task(task_b["id"])["task"]["status"] == "queued"
    finally:
        daemon.stop()


@pytest.mark.parametrize("credential", ["owner\nbad", "owner\u00e9"])
def test_malformed_credential_bytes_fail_without_exposing_them_or_cancelling(tmp_path, monkeypatch, capsys, credential):
    paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task = _task(daemon)
        (paths.runtime_support / "credentials" / "owner.token").write_text(credential, encoding="utf-8")
        assert cli.main(["tasks", "clear", task["id"], "--json"]) == 1
        output = capsys.readouterr().out
        assert credential not in output
        assert "malformed" in output
        result = json.loads(output)
        assert result["outcomes"][0]["outcome"] == "failed"
        assert daemon.service.task(task["id"])["task"]["status"] == "queued"
    finally:
        daemon.stop()


def test_missing_owner_credential_fails_all_ids_before_mutation(tmp_path, monkeypatch, capsys):
    paths, daemon = _live_owner(tmp_path, monkeypatch)
    try:
        task = _task(daemon)
        (paths.runtime_support / "credentials" / "owner.token").unlink()
        assert cli.main(["tasks", "clear", task["id"], "missing", "--json"]) == 1
        result = json.loads(capsys.readouterr().out)
        assert all(row["outcome"] == "failed" for row in result["outcomes"])
        assert daemon.service.task(task["id"])["task"]["status"] == "queued"
    finally:
        daemon.stop()


def test_no_owner_discovery_does_not_start_runtime_or_mutate(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    paths.ensure_support_dirs()
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    assert cli.main(["tasks", "clear", "wanted", "wanted", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert [row["outcome"] for row in result["outcomes"]] == ["failed", "failed"]
    assert result["outcomes"][1]["repeated"] is True
    assert not paths.discovery_path.exists()


def test_control_preflight_completes_for_every_unique_id_before_cancel(tmp_path):
    from astrid_runtime.task_clear import ControlError, clear_tasks

    calls = []
    class Client:
        def cancel_task(self, task_id, **kwargs):
            calls.append(("cancel", task_id))
    def control(method, route, body=None):
        calls.append(("control", method, route))
        if route.endswith("/missing/settlement"):
            raise ControlError("unknown", status=404)
        if route.endswith("/settlement"):
            task_id = route.split("/")[-2]
            return {"task_id": task_id, "state": "queued", "settled": False, "blockers": [],
                    "task": {"task_id": task_id, "state": "queued", "version": 1}}
        raise ControlError("no local Worker", status=404)
    paths = RuntimePaths.sandbox(tmp_path / "home")
    result = clear_tasks(paths, ["one", "missing", "one"], credential_reader=lambda _: "owner",
                         client_factory=lambda _: Client(), control_request=control)
    first_cancel = next(i for i, item in enumerate(calls) if item[0] == "cancel")
    preflight = [item for item in calls[:first_cancel] if item[0] == "control"]
    assert preflight == [
        ("control", "GET", "/v1/control/tasks/one/settlement"),
        ("control", "GET", "/v1/control/tasks/missing/settlement"),
    ]
    assert result["ok"] is False
    assert [row["outcome"] for row in result["outcomes"]] == ["unresolved", "unknown", "unresolved"]


def test_terminal_state_without_owner_settlement_proof_is_not_success(tmp_path):
    from astrid_runtime.task_clear import clear_tasks

    calls = []
    class Client:
        def cancel_task(self, task_id, **kwargs):
            calls.append(("cancel", task_id))
    def control(method, route, body=None):
        calls.append((method, route, body))
        if route.endswith("/settlement"):
            return {"task_id": "terminal-unsettled", "state": "cancelled", "settled": False,
                    "blockers": [{"task_id": "terminal-unsettled", "blocker_kind": "unsettled_attempt"}],
                    "task": {"task_id": "terminal-unsettled", "state": "cancelled", "version": 3}}
        raise AssertionError(route)
    result = clear_tasks(RuntimePaths.sandbox(tmp_path / "home"), ["terminal-unsettled"],
                         credential_reader=lambda _: "owner", client_factory=lambda _: Client(),
                         control_request=control)
    assert result["ok"] is False
    assert result["outcomes"][0]["outcome"] == "unresolved"
    assert result["outcomes"][0]["state"] == "cancelled"
    assert not any(item[0] == "cancel" for item in calls)


def test_worker_conflict_details_normalize_raw_and_typed_error_shapes():
    from astrid_runtime.task_clear import _control_details

    details = {"required_task_ids": ["worker-task"]}
    assert _control_details(details) == details
    assert _control_details({
        "code": "conflict", "message": "local Worker has unlisted outstanding tasks",
        "details": details,
    }) == details


def test_active_local_worker_handoff_is_exact_and_never_called_when_already_settled(tmp_path):
    from astrid_runtime.task_clear import clear_tasks

    calls = []
    execution_binding = {
        "executor_id": "astrid-pack-host", "executor_incarnation": "inc",
        "verification": {"evidence_digest": "digest"},
    }
    class Client:
        def cancel_task(self, task_id, **kwargs): calls.append(("cancel", task_id))
    settled = set()
    def control(method, route, body=None):
        calls.append((method, route, body))
        if route.endswith("/generation"):
            return {"executor_incarnation": "inc", "evidence_digest": "digest", "state": "active"}
        if route.endswith("/relinquish"):
            assert body["expected_task_ids"] == ["named", "other"]
            return {"state": "relinquished"}
        if route.endswith("/settlement"):
            task_id = route.split("/")[-2]
            if any(entry[0] == "POST" and entry[1].endswith("/relinquish") for entry in calls):
                settled.add(task_id)
            return {"task_id": task_id, "state": "cancelled", "settled": task_id in settled,
                    "blockers": [], "task": {"task_id": task_id, "state": "running", "version": 2,
                                               "execution_binding": execution_binding}}
        raise AssertionError(route)
    paths = RuntimePaths.sandbox(tmp_path / "home")
    result = clear_tasks(paths, ["named", "other"], credential_reader=lambda _: "owner",
                         client_factory=lambda _: Client(), control_request=control)
    assert result["ok"] is True
    handoff = [entry for entry in calls if entry[1].endswith("/relinquish")]
    assert len(handoff) == 1
    assert handoff[0][2]["expected_task_ids"] == ["named", "other"]


def test_unrelated_named_blocker_makes_exact_worker_handoff_refuse(tmp_path):
    from astrid_runtime.task_clear import ControlError, clear_tasks

    calls = []
    execution_binding = {
        "executor_id": "astrid-pack-host", "executor_incarnation": "inc",
        "verification": {"evidence_digest": "digest"},
    }
    class Client:
        def cancel_task(self, task_id, **_kwargs): calls.append(("cancel", task_id))
    def control(method, route, body=None):
        calls.append((method, route, body))
        if route.endswith("/generation"):
            return {"executor_incarnation": "inc", "evidence_digest": "digest", "state": "active"}
        if route.endswith("/relinquish"):
            raise ControlError("local Worker has unlisted outstanding tasks", status=409,
                               details={"required_task_ids": ["other-worker-task"]})
        if route.endswith("/settlement"):
            task_id = route.split("/")[-2]
            return {"task_id": task_id, "state": "cancel_requested", "settled": False,
                    "blockers": [{"task_id": task_id, "blocker_kind": "unsettled_attempt"}],
                    "task": {"task_id": task_id, "state": "running", "version": 1,
                             "execution_binding": execution_binding}}
        raise AssertionError(route)
    result = clear_tasks(RuntimePaths.sandbox(tmp_path / "home"), ["named"],
                         credential_reader=lambda _: "owner", client_factory=lambda _: Client(),
                         control_request=control)
    assert result["ok"] is False
    assert result["outcomes"][0]["outcome"] == "unresolved"
    assert "unlisted outstanding" in result["outcomes"][0]["worker_handoff_error"]


def _cli_paths_for_daemon(tmp_path, monkeypatch, daemon):
    paths = RuntimePaths.sandbox(tmp_path / "cli-home")
    paths.ensure_support_dirs()
    (paths.runtime_support / "credentials").mkdir(parents=True, exist_ok=True)
    (paths.runtime_support / "credentials" / "owner.token").write_text(daemon.token, encoding="utf-8")
    paths.discovery_path.write_text(json.dumps({"endpoint": daemon.endpoint}), encoding="utf-8")
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    return paths


def test_real_host_only_worker_task_is_cancelled_acknowledged_and_settled(tmp_path, monkeypatch, capsys):
    from tests.test_local_worker_handover import (
        _assert_owned_cancel_finalized, _daemon as worker_daemon, _launch, _owned_cancel_claim,
    )

    daemon, preparer, _proxy, workspace_uuid = worker_daemon(tmp_path / "worker", host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon, key="clear-worker-task", cancel=False)
        _cli_paths_for_daemon(tmp_path, monkeypatch, daemon)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["outcomes"][0]["outcome"] == "settled"
        assert result["outcomes"][0]["worker_relinquished"] is True
        _assert_owned_cancel_finalized(daemon, task_id, attempt)
        assert preparer.events.count("stop_owned") == 1
        assert daemon._local_relinquish_state()["state"] == "complete"
    finally:
        daemon.stop()


def test_real_worker_handoff_refuses_unnamed_worker_task_and_keeps_it_running(tmp_path, monkeypatch, capsys):
    from tests.test_local_worker_handover import _daemon as worker_daemon, _launch, _owned_cancel_claim
    daemon, preparer, _proxy, workspace_uuid = worker_daemon(tmp_path / "worker", host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        named_id, _attempt = _owned_cancel_claim(daemon, key="clear-named", cancel=False)
        unnamed_id, _unnamed_attempt = _owned_cancel_claim(
            daemon, key="clear-unnamed", cancel=False, resource_key="cpu2",
        )
        _cli_paths_for_daemon(tmp_path, monkeypatch, daemon)
        assert cli.main(["tasks", "clear", named_id, "--json"]) == 1
        result = json.loads(capsys.readouterr().out)
        row = result["outcomes"][0]
        assert row["outcome"] == "unresolved"
        assert "unlisted outstanding tasks" in row["worker_handoff_error"]
        assert row["worker_handoff_details"]["required_task_ids"] == [unnamed_id]
        assert daemon.service.task(unnamed_id)["task"]["status"] == "running"
        assert preparer.events.count("stop_owned") == 0
    finally:
        daemon.stop()


def test_stop_unknown_worker_clear_retries_exact_generation_and_settles(tmp_path, monkeypatch, capsys):
    from tests.test_local_worker_handover import (
        _assert_owned_cancel_finalized, _daemon as worker_daemon, _launch, _owned_cancel_claim,
    )

    daemon, preparer, _proxy, workspace_uuid = worker_daemon(tmp_path / "worker", host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon, key="clear-stop-unknown", cancel=False)
        _cli_paths_for_daemon(tmp_path, monkeypatch, daemon)
        preparer.fail_stop = True
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 1
        first = json.loads(capsys.readouterr().out)
        assert first["outcomes"][0]["outcome"] == "unresolved"
        assert daemon.service.task(task_id)["task"]["status"] == "cancel_requested"
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"

        preparer.fail_stop = False
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        retry = json.loads(capsys.readouterr().out)
        assert retry["outcomes"][0]["outcome"] == "settled"
        assert retry["outcomes"][0]["worker_relinquished"] is True
        assert daemon._local_relinquish_state()["state"] == "complete"
        _assert_owned_cancel_finalized(daemon, task_id, attempt)
        assert preparer.events.count("stop_owned") == 2
    finally:
        preparer.fail_stop = False
        daemon.stop()


def test_stopped_after_settlement_retry_replays_same_worker_task_set(tmp_path, monkeypatch, capsys):
    from tests.test_local_worker_handover import (
        _assert_owned_cancel_finalized, _daemon as worker_daemon, _launch, _owned_cancel_claim,
    )

    daemon, preparer, _proxy, workspace_uuid = worker_daemon(tmp_path / "worker", host_only=True)
    original_write = daemon._write_local_relinquish
    fail_complete_once = {"value": True}

    def fail_after_settlement(checkpoint):
        if checkpoint.get("state") == "complete" and fail_complete_once["value"]:
            fail_complete_once["value"] = False
            raise OSError("simulated lost completion response after settlement")
        return original_write(checkpoint)

    daemon._write_local_relinquish = fail_after_settlement
    try:
        _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon, key="clear-stopped-retry", cancel=False)
        _cli_paths_for_daemon(tmp_path, monkeypatch, daemon)
        assert cli.main(["tasks", "clear", task_id, "--json"]) == 1
        first = json.loads(capsys.readouterr().out)
        assert first["outcomes"][0]["outcome"] == "unresolved"
        assert _settlement(daemon, task_id)["settled"] is True
        assert daemon._local_relinquish_state()["state"] == "stopped"
        stop_calls = preparer.events.count("stop_owned")

        assert cli.main(["tasks", "clear", task_id, "--json"]) == 0
        retry = json.loads(capsys.readouterr().out)
        assert retry["outcomes"][0]["outcome"] == "already_settled"
        assert daemon._local_relinquish_state()["state"] == "complete"
        assert preparer.events.count("stop_owned") == stop_calls
        _assert_owned_cancel_finalized(daemon, task_id, attempt)
    finally:
        daemon.stop()
