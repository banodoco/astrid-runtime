"""A sibling inspection must observe, not take over, a live launcher gap."""
from dataclasses import replace
import json
import os

import pytest

from astrid_runtime import workspace
from astrid_runtime.bootstrap import _bootstrap_mutex
from astrid_runtime.cli import main
from runtime_protocol import platform, startup_attempt
from runtime_protocol.startup_operation import read_operation
from runtime_protocol.store import RealmStore

from tests.test_startup_attempt import (
    REALM_ID,
    _INSPECT_RECEIPT,
    _observe,
    _process_waiting_after,
    _runtime_args,
    selection,
)


_LAUNCHER_HOLDING_INSPECTION = """
import pathlib, sys
from astrid_runtime.cli import _config, _paths, parser
from astrid_runtime.workspace import begin_startup_attempt
args = parser().parse_args(["startup-status", *sys.argv[2:]])
paths = _paths(args)
with begin_startup_attempt(paths, config=_config(args, paths)):
    pathlib.Path(sys.argv[1]).touch()
    sys.stdin.readline()
"""


def test_unrelated_startup_inspection_observes_launcher_inspecting_workspace(
    selection, tmp_path,
):
    paths, _, _ = selection
    launcher_ready = tmp_path / "launcher-inspecting"
    inspection_receipt = tmp_path / "sibling-inspection.json"

    with _process_waiting_after(
        _LAUNCHER_HOLDING_INSPECTION,
        _runtime_args(selection),
        launcher_ready,
    ) as launcher:
        attempt = _observe(selection)
        assert attempt["state"] == "inspecting_workspace"
        expected = {
            "ok": False,
            "state": "inspecting_workspace",
            "startup_attempt": {
                "attempt_id": attempt["attempt_id"],
                "state": "inspecting_workspace",
            },
        }
        with _process_waiting_after(
            _INSPECT_RECEIPT,
            _runtime_args(selection),
            inspection_receipt,
        ) as sibling:
            envelope = json.loads(inspection_receipt.read_text())
            result = json.loads(envelope["stdout"])
            operation = read_operation(paths.runtime_support)
            discovery_exists = paths.discovery_path.exists()
            launcher_alive = launcher.poll() is None

            assert (
                envelope["returncode"] == 1
                and result == expected
                and operation is None
                and sibling.pid != launcher.pid
                and launcher_alive
                and not discovery_exists
            ), (
                "unrelated inspection took over the launcher's offline verifier: "
                f"result={result!r}, operation="
                f"{None if operation is None else operation.as_observation()!r}, "
                f"operation_owner_pid={None if operation is None else operation.owner_pid!r}, "
                f"sibling_pid={sibling.pid}, launcher_pid={launcher.pid}, "
                f"launcher_alive={launcher_alive}, discovery_exists={discovery_exists}"
            )
        assert sibling.returncode == 0
        assert launcher.poll() is None
        assert not paths.discovery_path.exists()


@pytest.mark.parametrize("selection_change", ["unselected", "moved"])
def test_strict_startup_commands_refuse_changed_configured_selection(
    selection, tmp_path, capsys, selection_change,
):
    paths, root, config = selection
    explicit = ["--realm-root", str(root), "--expected-realm-id", REALM_ID, *_runtime_args(selection)]
    strict = ["--require-configured-selection", *explicit]
    with workspace.begin_startup_attempt(paths, config=config) as attempt:
        assert main(["startup-status", *strict]) == 0
        expected = {"state": "inspecting_workspace", "attempt_id": attempt.attempt_id}
        assert json.loads(capsys.readouterr().out) == expected

        catalog = json.loads(paths.catalog_path.read_text())
        if selection_change == "unselected":
            catalog["selected_realm_id"] = None
        else:
            catalog["realms"][0]["data_root"] = str(tmp_path / "moved-realm")
        paths.catalog_path.write_text(json.dumps(catalog))

        assert main(["startup-status", *strict]) == 1
        assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}
        assert main(["workspace", "inspect", "--startup-operation", *strict]) == 1
        refusal = json.loads(capsys.readouterr().out)
        assert set(refusal) == {"ok", "error"} and refusal["ok"] is False
        assert main(["workspace", "inspect", *strict]) == 1
        assert json.loads(capsys.readouterr().out) == refusal
        assert read_operation(paths.runtime_support) is None

        if selection_change == "unselected":
            assert main(["startup-status", *explicit]) == 0
            assert json.loads(capsys.readouterr().out) == expected
            assert main(["workspace", "inspect", "--startup-operation", *explicit]) == 0
            assert json.loads(capsys.readouterr().out)["state"] == "inspectable"
            operation = read_operation(paths.runtime_support)
            assert operation.owner_pid == os.getpid() and operation.state == "ended"


def test_strict_startup_commands_recheck_selection_during_requests(selection, capsys, monkeypatch):
    paths, root, config = selection
    strict = ["--require-configured-selection", "--realm-root", str(root),
              "--expected-realm-id", REALM_ID, *_runtime_args(selection)]
    original_catalog = paths.catalog_path.read_bytes()
    unselected = json.loads(original_catalog)
    unselected["selected_realm_id"] = None

    def unselect_after(read):
        changed = False

        def wrapped(*args, **kwargs):
            nonlocal changed
            result = read(*args, **kwargs)
            if not changed:
                with _bootstrap_mutex(paths, blocking=False):
                    paths.catalog_path.write_text(json.dumps(unselected))
                changed = True
            return result
        return wrapped

    with workspace.begin_startup_attempt(paths, config=config):
        with monkeypatch.context() as status:
            status.setattr(workspace, "_startup_observation", unselect_after(workspace._startup_observation))
            assert main(["startup-status", *strict]) == 1
            assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}
            assert json.loads(paths.catalog_path.read_text()) == unselected
        paths.catalog_path.write_bytes(original_catalog)

        with monkeypatch.context() as inspect:
            inspect.setattr(workspace, "_pending_inspection", unselect_after(workspace._pending_inspection))
            assert main(["workspace", "inspect", "--startup-operation", *strict]) == 1
            assert json.loads(capsys.readouterr().out)["ok"] is False
            assert json.loads(paths.catalog_path.read_text()) == unselected
            assert read_operation(paths.runtime_support) is None


def test_unavailable_inspector_identity_stays_observer(selection, monkeypatch, capsys):
    paths, _, config = selection
    with workspace.begin_startup_attempt(paths, config=config) as attempt:
        current_birth = startup_attempt._process_birth(os.getpid())

        def unavailable(_pid):
            raise PermissionError("inspector identity unavailable")

        with monkeypatch.context() as hidden:
            hidden.setattr(startup_attempt, "_process_birth", lambda _pid: current_birth)
            hidden.setattr(startup_attempt, "_process_identity", unavailable)
            assert main(["workspace", "inspect", "--startup-operation", *_runtime_args(selection)]) == 1
        assert json.loads(capsys.readouterr().out) == {
            "ok": False,
            "state": "inspecting_workspace",
            "startup_attempt": {"state": "inspecting_workspace", "attempt_id": attempt.attempt_id},
        }
        assert read_operation(paths.runtime_support) is None


@pytest.mark.skipif(platform.sys.platform != "linux", reason="Linux procfs namespace binding")
def test_startup_reservation_refuses_pid_identity_mismatched_with_proc_self(
    selection, monkeypatch,
):
    paths, _, config = selection
    scope = workspace._startup_selection(paths, None, None, config)[3]
    current_birth, current_uid = startup_attempt._process_birth(os.getpid())
    assert current_birth.startswith("proc-start-ticks:")
    assert current_uid == platform.current_user()
    original_readlink = startup_attempt.Path.readlink

    def misbound_readlink(path, *args, **kwargs):
        if path == startup_attempt.Path("/proc/self"):
            return startup_attempt.Path(f"/proc/{os.getpid() + 1}")
        return original_readlink(path, *args, **kwargs)

    with monkeypatch.context() as procfs:
        procfs.setattr(startup_attempt.Path, "readlink", misbound_readlink)
        rejected = False
        with _bootstrap_mutex(paths):
            try:
                startup_attempt.StartupAttempt.begin_locked(
                    paths.runtime_support.resolve(), scope,
                    inspecting=True, retry_attempt_id=None,
                )
            except startup_attempt.StartupAttemptError:
                rejected = True
        attempt = startup_attempt.read_attempt(paths.runtime_support.resolve())

    assert rejected and attempt is None, (
        "launcher reservation published despite /proc/self naming a different PID: "
        f"rejected={rejected}, attempt="
        f"{None if attempt is None else attempt.as_observation()!r}"
    )
    assert read_operation(paths.runtime_support) is None


def test_windows_creator_pid_requires_an_older_launcher_and_a_current_record(selection, monkeypatch):
    paths, _, config = selection
    support = paths.runtime_support.resolve()
    with workspace.begin_startup_attempt(paths, config=config):
        with _bootstrap_mutex(paths):
            actual = startup_attempt.read_attempt(support)
            parent = replace(actual._record, owner_pid=os.getpid() + 1, owner_birth="windows-creation:100")
            observed = replace(actual, _record=parent)
            caller = {"pid": os.getpid(), "uid": platform.current_user(), "parent_pid": parent.owner_pid}

            with monkeypatch.context() as windows:
                windows.setattr(startup_attempt, "read_attempt", lambda _support: observed)
                windows.setattr(startup_attempt, "_process_identity", lambda _pid: caller)

                caller["birth_id"] = "windows-creation:90"
                assert not observed.authorizes_inspection_locked(support)
                caller["birth_id"] = "windows-creation:100"
                assert not observed.authorizes_inspection_locked(support)
                caller["birth_id"] = "windows-creation:101"
                assert observed.authorizes_inspection_locked(support)
                windows.setattr(startup_attempt, "read_attempt", lambda _support: None)
                assert not observed.authorizes_inspection_locked(support)


def test_strict_startup_commands_accept_implicit_configured_selection(selection, capsys):
    paths, root, config = selection
    args = ["--require-configured-selection", *_runtime_args(selection)]
    with workspace.begin_startup_attempt(paths, config=config) as attempt:
        assert main(["startup-status", *args]) == 0
        assert json.loads(capsys.readouterr().out) == {
            "state": "inspecting_workspace", "attempt_id": attempt.attempt_id,
        }
        assert main(["workspace", "inspect", "--startup-operation", *args]) == 0
        result = json.loads(capsys.readouterr().out)
        assert (result["state"], result["realm_id"], result["realm_root"]) == ("configured", REALM_ID, str(root))
        assert result["inspection"]["state"] == "verified_offline"
        operation = read_operation(paths.runtime_support)
        assert operation.owner_pid == os.getpid() and operation.state == "ended"


@pytest.mark.parametrize("provided", ["root", "id", "no-catalog"])
def test_strict_startup_commands_reject_partial_selectors_or_missing_catalog(selection, capsys, provided):
    paths, root, config = selection
    args = ["--require-configured-selection", *_runtime_args(selection)]
    with workspace.begin_startup_attempt(paths, config=config):
        if provided == "root":
            args.extend(["--realm-root", str(root)])
        elif provided == "id":
            args.extend(["--expected-realm-id", REALM_ID])
        else:
            paths.catalog_path.unlink()
        assert main(["startup-status", *args]) == 1
        assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}
        assert main(["workspace", "inspect", "--startup-operation", *args]) == 1
        refusal = json.loads(capsys.readouterr().out)
        assert set(refusal) == {"ok", "error"} and refusal["ok"] is False
        assert read_operation(paths.runtime_support) is None


def test_strict_implicit_selection_rejects_a_catalog_swap_during_requests(selection, capsys, monkeypatch):
    paths, _, config = selection
    args = ["--require-configured-selection", *_runtime_args(selection)]
    original_catalog = paths.catalog_path.read_bytes()
    replacement = paths.realms_dir / "replacement-realm"
    RealmStore.initialize(replacement, realm_id=replacement.name).close()
    swapped = json.loads(original_catalog)
    swapped["selected_realm_id"] = replacement.name
    swapped["realms"][0].update(realm_id=replacement.name, data_root=str(replacement))

    def swap_after(read):
        changed = False

        def wrapped(*args, **kwargs):
            nonlocal changed
            result = read(*args, **kwargs)
            if not changed:
                with _bootstrap_mutex(paths, blocking=False):
                    paths.catalog_path.write_text(json.dumps(swapped))
                changed = True
            return result
        return wrapped

    with workspace.begin_startup_attempt(paths, config=config):
        with monkeypatch.context() as status:
            status.setattr(workspace, "_startup_observation", swap_after(workspace._startup_observation))
            assert main(["startup-status", *args]) == 1
            assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}
            assert json.loads(paths.catalog_path.read_text()) == swapped
    paths.catalog_path.write_bytes(original_catalog)

    with monkeypatch.context() as inspect:
        inspect.setattr(workspace, "_pending_inspection", swap_after(workspace._pending_inspection))
        assert main(["workspace", "inspect", "--startup-operation", *args]) == 1
        refusal = json.loads(capsys.readouterr().out)
        assert set(refusal) == {"ok", "error"} and refusal["ok"] is False
        assert json.loads(paths.catalog_path.read_text()) == swapped
        assert read_operation(paths.runtime_support) is None
