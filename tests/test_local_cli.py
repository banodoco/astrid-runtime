from __future__ import annotations

import json
from pathlib import Path

import pytest

from astrid_runtime import cli
from astrid_runtime.bootstrap import BootstrapError
from astrid_runtime.paths import RuntimePaths


class _TypedClient:
    def __init__(self):
        self.calls = []

    def checkpoint_attempt(self, *args, **kwargs):
        self.calls.append(("checkpoint", args, kwargs))
        return {"state": "durable", "nonce": kwargs["nonce"]}

    def request_reboot(self, **kwargs):
        self.calls.append(("reboot", (), kwargs))
        return {"status": "requested", **kwargs}

    def resume_attempt(self, **kwargs):
        self.calls.append(("resume", (), kwargs))
        return {"status": "resumed", **kwargs}

    def recover_realm(self, **kwargs):
        self.calls.append(("recover", (), kwargs))
        return {"state": "active", **kwargs}


def test_parser_exposes_operator_lifecycle_without_legacy_verbs():
    required = {
        "backup": ["--destination", "b"],
        "restore": ["backup", "--destination", "d"],
        "checkpoint": ["--attempt-id", "a", "--lease-id", "l", "--fence", "1", "--runtime-epoch", "1", "--nonce", "n", "--authorization", "n"],
        "prepare-reboot": ["--attempt-id", "a", "--lease-id", "l", "--fence", "1", "--runtime-epoch", "1"],
        "reboot": ["--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "1"],
        "resume": ["--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "1"],
        "recovery": [],
    }
    for command in ("up", "connect", "status", "restart", "backup", "restore", "checkpoint", "prepare-reboot", "reboot", "resume", "doctor", "recovery"):
        assert cli.parser().parse_args([command, *required.get(command, []), "--json"]).command == command
    upgrade = cli.parser().parse_args(["upgrade", "--profile", "astrid", "--data-root", "/tmp/astrid", "--json"])
    assert upgrade.command == "upgrade"
    assert upgrade.data_root == Path("/tmp/astrid")


def test_tasks_clear_cli_dispatches_exact_occurrences_and_uses_result_exit_code(monkeypatch, tmp_path, capsys):
    paths = RuntimePaths.sandbox(tmp_path)
    result = {"ok": False, "outcomes": [
        {"task_id": "named", "outcome": "settled", "repeated": False},
        {"task_id": "missing", "outcome": "unknown", "repeated": False},
    ]}
    observed = {}

    def clear_tasks(got_paths, task_ids, **kwargs):
        observed["paths"] = got_paths
        observed["task_ids"] = task_ids
        observed["kwargs"] = kwargs
        return result

    from astrid_runtime import task_clear
    monkeypatch.setattr(task_clear, "clear_tasks", clear_tasks)
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    assert cli.main(["tasks", "clear", "named", "missing", "--json"]) == 1
    assert observed["paths"] is paths
    assert observed["task_ids"] == ["named", "missing"]
    output = json.loads(capsys.readouterr().out)
    assert output == result


def test_tasks_clear_parser_help_mentions_exact_named_ids(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args(["tasks", "clear", "--help"])
    assert exc.value.code == 0
    assert "exact task ids" in capsys.readouterr().out


def test_tasks_clear_paths_failure_still_reports_every_input_occurrence(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_paths", lambda _args: (_ for _ in ()).throw(ValueError("bad support root")))
    assert cli.main(["tasks", "clear", "one", "one", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert [row["task_id"] for row in result["outcomes"]] == ["one", "one"]
    assert [row["outcome"] for row in result["outcomes"]] == ["failed", "failed"]
    assert result["outcomes"][1]["repeated"] is True


def test_checkpoint_requires_and_forwards_exact_epoch_nonce_and_state(monkeypatch, tmp_path, capsys):
    paths = RuntimePaths.sandbox(tmp_path)
    fake = _TypedClient()
    monkeypatch.setattr(cli, "_client", lambda _paths: fake)
    assert cli.main([
        "checkpoint", "--home", str(tmp_path), "--attempt-id", "a", "--lease-id", "l",
        "--fence", "3", "--runtime-epoch", "7", "--nonce", "n", "--authorization", "n",
        "--state", '{"step": 4}', "--json",
    ]) == 0
    assert fake.calls == [("checkpoint", ("a",), {"lease_id": "l", "fence": 3, "nonce": "n", "authorization": "n", "state": {"step": 4}, "runtime_epoch": 7})]
    assert json.loads(capsys.readouterr().out)["state"] == "durable"


def test_reboot_is_safe_disabled_and_resume_is_typed(monkeypatch, tmp_path, capsys):
    fake = _TypedClient()
    monkeypatch.setattr(cli, "_client", lambda _paths: fake)
    reboot_args = ["reboot", "--home", str(tmp_path), "--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "7", "--json"]
    assert cli.main(reboot_args) == 1
    assert "safe-disabled" in capsys.readouterr().out
    resume_args = ["resume", "--home", str(tmp_path), "--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "7", "--json"]
    assert cli.main(resume_args) == 0
    assert fake.calls[-1][0] == "resume"


def test_down_cli_json_preserves_complete_bootstrap_refusal_details(monkeypatch, tmp_path, capsys):
    paths = RuntimePaths.current(tmp_path / "home", data_root=tmp_path / "support")
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    realm_root.mkdir()
    paths.catalog_path.write_text(json.dumps({
        "version": 1,
        "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root)}],
        "source_profiles": {},
    }))
    paths.discovery_path.write_text(json.dumps({"pid": 123, "active_realm": "realm"}))
    (paths.source_profiles_dir / "astrid.json").write_text(json.dumps({
        "profile": "astrid", "runtime_checkout": "/runtime", "source_checkout": "/source",
    }))

    class Boundary:
        def prepare_restart(self, **_kwargs):
            return None

    details = {
        "safe": False,
        "blockers": [{"task_id": "task-17", "kind": "test", "state": "running",
                      "created_at": "2026-10-27T00:00:00Z", "age_seconds": 12,
                      "blocker_kind": "running_task"}],
        "task_count": 1,
        "headline": "Astrid is busy (1 tasks running). Try again when they finish.",
        "message": "Astrid is busy (1 tasks running). Try again when they finish.\ntask-17 [running_task; test; running; age 12s]",
    }
    monkeypatch.setattr(cli, "LocalRuntimeBoundary", Boundary)
    monkeypatch.setattr(cli, "down", lambda *_args: (_ for _ in ()).throw(
        BootstrapError(details["message"], details=details)
    ))
    assert cli.main(["down", "--data-root", str(paths.app_support), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == {"message": details["message"], "details": details}
