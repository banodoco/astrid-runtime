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
