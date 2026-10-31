"""F1b/F1c Runtime acceptance, launcher and fresh-process status tests."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from astrid_runtime import update
from tests.door_helpers import DoorWorld, HOSTED, create_realm, start_door_world
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


@pytest.mark.integration
def test_production_daemon_door_advertises_and_executes_selected_updater(tmp_path, monkeypatch):
    home, root, data = (tmp_path / name for name in ("home", "program", "data"))
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "4")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    folder = root / "versions" / "old"
    agent, runtime = folder / "agent", folder / "runtime"
    agent.mkdir(parents=True)
    runtime.mkdir()
    python = folder / "bin" / "python"
    python.parent.mkdir()
    python.symlink_to(sys.executable)
    profile = _write(folder / "profile.json", {"profile": "astrid", "source_checkout": str(agent), "runtime_checkout": str(runtime)})
    identity = {"release": 4, "managed_by": None}
    _write(folder / "version.json", {"root": str(folder), "python": str(python), "profile": str(profile), "identity": identity})
    _write(folder / "manifest.json", {"release": 4})
    (root / "current").write_text("old\n")
    realm = data / "runtime" / "realms" / "test"
    create_realm(realm)
    credential = home / "astrid.json"
    daemon = RuntimeDaemon(realm, support_root=data / "runtime", door=DoorConfig(origin=HOSTED, port=0, credential_file=credential), agent_checkout=agent, runtime_checkout=runtime).start()
    world = DoorWorld(tmp_path, daemon, credential)
    try:
        record = {"owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
                  "realm_id": daemon.service.realm["id"], "realm_root": str(realm), "identity": identity}
        selected = _write(update._install_record_path(home), record)
        marker = _write(root / "install.json", record)
        world.provision()
        calls = []
        availability_queries = []

        def helper(selected_python, selected_agent, selected_runtime, payload):
            assert (selected_python, selected_agent, selected_runtime) == (python, agent, runtime)
            if payload.get("action") == "availability":
                availability_queries.append(payload)
                return {"available": True}
            calls.append(payload)
            if payload.get("action") == "accept":
                job = {"operation_id": payload["operation_id"], "state": "accepted"}
                _write(marker, {**record, "update_job": job})
                return job
            if payload.get("action") == "launch":
                return {"launch_status": "started"}
            result = {"release": 5}
            for name in ("manifest", "bootstrap"):
                path = Path(payload["directory"]) / name
                path.write_bytes(name.encode())
                update.platform.owner_only(path)
                result[name + "_sha256"] = hashlib.sha256(name.encode()).hexdigest()
            return result

        monkeypatch.setattr(daemon.update_admission, "_helper", helper)
        monkeypatch.setattr(daemon.update_admission, "launcher", lambda _job: pytest.fail("GET must not launch"))
        monkeypatch.setattr(update, "assert_interruption_safe", lambda _root: None)
        before = marker.read_bytes()
        for _ in range(2):
            response = world.call("/api/runtime/v1/update/status")
            assert response.status == 200
            assert response.json() == {"available": True, "state": "none"}
        assert calls == [] and marker.read_bytes() == before

        # GET only observes the durable records. It must not admit, launch,
        # reconcile, or mutate either an unacknowledged job or its journal.
        unacknowledged = {**record, "update_job": {
            "operation_id": "a" * 32, "state": "launching",
            "launch_status": "unknown", "message": "Update launch acknowledgement was lost.",
        }}
        _write(marker, unacknowledged)
        journal = _write(root / "update-transaction.json", {"step": "complete"})
        status_sources = {path: path.read_bytes() for path in (selected, marker, journal)}
        for _ in range(2):
            response = world.call("/api/runtime/v1/update/status")
            assert response.status == 200
            assert response.json()["state"] == "recovery-needed"
            assert response.json()["operation_id"] == "a" * 32
        assert calls == []
        assert {path: path.read_bytes() for path in status_sources} == status_sources
        journal.unlink()
        _write(marker, record)

        assert all(query == {"action": "availability"} for query in availability_queries)
        monkeypatch.setattr(daemon.update_admission, "launcher", None)
        record["preferences"] = {"autostart": False}
        _write(selected, record)
        assert world.call("/api/runtime/v1/update/status").json() == {
            "available": False, "reason": "autostart-off", "state": "none"}
        assert calls == [] and marker.read_bytes() == before
        del record["preferences"]
        _write(selected, record)
        _write(folder / "manifest.json", {"release": 3})
        assert world.call("/api/runtime/v1/update/status").json()["available"] is False
        assert calls == [] and marker.read_bytes() == before
        _write(folder / "manifest.json", {"release": 4})
        response = world.call("/api/runtime/v1/update", "POST", body=b"")
        assert response.status == 202
        operation_id = response.json()["operation_id"]
        assert [call.get("action") for call in calls] == [None, "accept", "launch"]
        assert calls[-1]["operation_id"] == operation_id
        assert world.call("/api/runtime/v1/update/status").json()["operation_id"] == operation_id
        shutil.rmtree(calls[0]["directory"])
    finally:
        world.stop()


def test_status_reads_authoritative_job_and_c2_journal_without_recovery(tmp_path):
    home = tmp_path / "home"
    root = tmp_path / "program with spaces"
    data = tmp_path / "data"
    selection = _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
        "operation_id": "11111111111111111111111111111111", "state": "accepted", "target_release": 9,
        "log_path": str(root / "logs/update.log"), "message": "Update accepted.",
    }})
    log = root / "logs/update.log"
    log.parent.mkdir(parents=True)
    log.write_text("log")
    update.platform.owner_only(log)
    assert update.read_update_status(home) == {
        "available": False, "state": "recovery-needed", "operation_id": "11111111111111111111111111111111",
        "result": "Recovery needed.", "target_release": 9,
        "log_path": str(root / "logs/update.log"),
    }
    fresh = subprocess.run(
        [sys.executable, "-c", "import json,sys; from astrid_runtime.update import read_update_status; print(json.dumps(read_update_status(sys.argv[1])))", str(home)],
        cwd=Path(__file__).parents[1], text=True, capture_output=True, check=True,
    )
    assert json.loads(fresh.stdout)["state"] == "recovery-needed"

    # A fresh status reader observes a pending C2 transaction but never calls
    # recovery or modifies either record.
    _write(root / "update-transaction.json", {"step": "stopping"})
    before = (root / "update-transaction.json").read_bytes()
    assert update.read_update_status(home)["state"] == "recovery-needed"
    assert (root / "update-transaction.json").read_bytes() == before
    assert selection.exists()


@pytest.mark.parametrize("reason", ["busy", "autostart-off"])
def test_status_projects_only_allowlisted_selection_reasons(tmp_path, monkeypatch, reason):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    admission = update.UpdateAdmission(SimpleNamespace())
    monkeypatch.setattr(admission, "_selection", lambda **_kwargs: (_ for _ in ()).throw(
        update.UpdateRefusal(reason, "selection refusal")))
    admission._helper = lambda *_args: pytest.fail("GET must not admit or launch an update")

    assert admission.status() == {"available": False, "reason": reason, "state": "none"}


def test_status_omits_noncontract_selection_reason(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    admission = update.UpdateAdmission(SimpleNamespace())
    monkeypatch.setattr(admission, "_selection", lambda **_kwargs: (_ for _ in ()).throw(
        update.UpdateRefusal("updater-unavailable", "selection refusal")))

    assert admission.status() == {"available": False, "state": "none"}


def test_status_projects_linux_service_manager_reason_without_admission(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(update.sys, "platform", "linux")
    admission = update.UpdateAdmission(SimpleNamespace())
    admission._selection = lambda **_kwargs: (None, {}, Path("/python"), Path("/agent"), Path("/runtime"), 1)
    calls = []

    def helper(_python, _agent, _runtime, payload):
        calls.append(payload)
        assert payload == {"action": "availability"}
        return {"available": False, "reason": "unsupported-service-manager"}

    admission._helper = helper
    assert admission.status() == {
        "available": False, "reason": "unsupported-service-manager", "state": "none"}
    assert calls == [{"action": "availability"}]


def test_status_preserves_allowlisted_service_manager_refusal(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(update.sys, "platform", "linux")
    admission = update.UpdateAdmission(SimpleNamespace())
    admission._selection = lambda **_kwargs: (None, {}, Path("/python"), Path("/agent"), Path("/runtime"), 1)

    def helper(_python, _agent, _runtime, payload):
        assert payload == {"action": "availability"}
        raise update.UpdateRefusal("unsupported-service-manager", "user systemd is unavailable")

    admission._helper = helper
    assert admission.status() == {
        "available": False, "reason": "unsupported-service-manager", "state": "none"}


def test_status_projects_busy_while_an_update_request_owns_admission(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    admission = update.UpdateAdmission(SimpleNamespace())
    admission._lock.acquire()
    try:
        assert admission.status() == {"available": False, "reason": "busy", "state": "none"}
    finally:
        admission._lock.release()


def test_helper_preserves_agent_busy_refusal_for_explicit_update(monkeypatch):
    admission = update.UpdateAdmission(SimpleNamespace())
    monkeypatch.setattr(update.subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 1, json.dumps({"reason": "busy", "message": "Still reconciling."}), ""))

    with pytest.raises(update.UpdateRefusal) as error:
        admission._helper(Path("/python"), Path("/agent"), Path("/runtime"), {"action": "accept"})

    assert error.value.details["reason"] == "busy"
    assert str(error.value) == "Still reconciling."


def test_status_projects_unacknowledged_launching_as_recovery_needed(tmp_path):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    marker = _write(root / "install.json", {
        "owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
            "operation_id": "a" * 32, "state": "launching", "launch_status": "unknown",
            "message": "Update launch acknowledgement was lost.",
        },
    })
    before = marker.read_bytes()

    status = update.read_update_status(home)

    assert status["state"] == "recovery-needed"
    assert status["operation_id"] == "a" * 32
    assert status["result"] == "Recovery needed."
    assert marker.read_bytes() == before


@pytest.mark.parametrize(("job_state", "expected", "outcome"), [
    ("updated", "terminal", "updated"),
    ("rolled_back", "terminal", "rolled_back"),
    ("failed", "terminal", "failed"),
])
def test_status_reports_terminal_job_result(tmp_path, job_state, expected, outcome):
    home, root = tmp_path / "home", tmp_path / "program"
    data = tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
        "operation_id": "22222222222222222222222222222222", "state": job_state, "result": "line one\nline two",
    }})
    status = update.read_update_status(home)
    assert status["state"] == expected
    assert status["outcome"] == outcome
    assert status["result"] == "line one line two"


def test_status_exposes_bounded_job_and_cleanup_metadata(tmp_path):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
        "operation_id": "2" * 32, "state": "failed", "result": "launch failed",
        "job_name": "transient-job-" + "x" * 500, "cleanup_status": " residue\nrecorded ",
        "cleanup_error": "cleanup\nfailed", "launch_status": "failed", "launch_error": "manager\nrefused",
        "cleanup_residue": ["task-one", "task-two", "x" * 500, 4],
    }, "update_job_residue": [{
        "operation_id": "3" * 32, "cleanup_status": "residue", "cleanup_error": "old cleanup issue",
        "residue": "leftover job", "descriptor": {"name": "astrid-update-old"},
    }]})
    status = update.read_update_status(home)
    assert status["job_name"] == "transient-job-" + "x" * 146
    assert status["cleanup_status"] == "residue recorded"
    assert status["cleanup_error"] == "cleanup failed"
    assert status["launch_status"] == "failed"
    assert status["launch_error"] == "manager refused"
    assert status["cleanup_residue"] == ["task-one", "task-two", "x" * 120]
    assert status["owned_residue"] == [{
        "operation_id": "3" * 32, "cleanup_status": "residue", "cleanup_error": "old cleanup issue",
        "residue": "leftover job", "job_name": "astrid-update-old",
    }]


def test_status_keeps_pending_c2_active_while_installer_lock_is_held(tmp_path):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
        "operation_id": "33333333333333333333333333333333", "state": "active", "message": "Updating.",
    }})
    _write(root / "update-transaction.json", {
        "operation_id": "c2-op", "step": "stopping", "update_job": {"operation_id": "33333333333333333333333333333333"},
    })
    lock_path = home / ".local/share/astrid-install.lock"
    lock_path.touch()
    with lock_path.open("r+b") as stream:
        update.platform.lock_file(stream.fileno())
        assert update.read_update_status(home)["state"] == "active"
        update.platform.unlock_file(stream.fileno())
    assert update.read_update_status(home)["state"] == "recovery-needed"

    _write(root / "update-transaction.json", {
        "operation_id": "c2-op", "step": "complete", "update_job": {"operation_id": "33333333333333333333333333333333"},
    })
    with lock_path.open("r+b") as stream:
        update.platform.lock_file(stream.fileno())
        assert update.read_update_status(home)["state"] == "active"
        update.platform.unlock_file(stream.fileno())
    assert update.read_update_status(home)["state"] == "recovery-needed"


def test_status_fails_conservatively_for_unmatched_or_corrupt_c2_journal(tmp_path):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
        "operation_id": "44444444444444444444444444444444", "state": "updated", "result": "Updated to release 9.",
    }})
    _write(root / "update-transaction.json", {
        "operation_id": "old-c2", "step": "stopping", "result": "unrelated old C2 result",
    })
    status = update.read_update_status(home)
    assert status["state"] == "recovery-needed"
    assert status["result"] == "Recovery needed."
    assert "unrelated old C2 result" not in json.dumps(status)

    (root / "update-transaction.json").write_text("{")
    assert update.read_update_status(home)["state"] == "recovery-needed"


def test_status_reports_pending_c2_even_without_f1_job(tmp_path):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    _write(home / ".local/share/astrid-install.json", {
        "owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data),
    })
    _write(root / "install.json", {"owner": "haus.astrid.runtime", "data_root": str(data)})
    _write(root / "update-transaction.json", {"step": "stopping"})
    assert update.read_update_status(home) == {
        "available": False, "state": "recovery-needed", "result": "Recovery needed.",
    }


def _admission_fixture(tmp_path, monkeypatch, launcher):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(update, "assert_interruption_safe", lambda _root: None)
    root = tmp_path / "program with spaces"
    data = tmp_path / "data with spaces"
    selected_value = {"owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data)}
    selected = _write(home / ".local/share/astrid-install.json", selected_value)
    _write(root / "install.json", {})
    (root / "current").parent.mkdir(parents=True, exist_ok=True)
    (root / "current").write_bytes(b"old\n")
    version = {"root": str(root / "versions/old"), "python": str(root / "versions/old/python"),
               "profile": str(root / "versions/old/profile.json"), "identity": {"release": 4, "managed_by": None}, "env": {}}
    version_path = _write(root / "versions/old/version.json", version)
    _write(Path(version["profile"]), {"profile": "astrid", "source_checkout": str(root / "agent"),
                                      "runtime_checkout": str(root / "runtime")})
    daemon = SimpleNamespace(
        instance_id="old-instance", startup_identity={"release": 4, "managed_by": None},
        root=tmp_path / "realm", update_launcher=launcher,
    )
    admission = update.UpdateAdmission(daemon)
    snapshots = {selected: json.dumps(selected_value).encode(), root / "current": b"old\n",
                 version_path: json.dumps(version).encode()}
    python, agent, runtime = root / "versions/old/python", root / "agent", root / "runtime"
    admission._selection = lambda **_kwargs: (selected, snapshots, python, agent, runtime, 4)

    @contextmanager
    def idle(_selection):
        yield

    admission._installer_idle = idle
    prepared = []
    accepted = {}

    def helper(_python, _agent, _runtime, payload, **_kwargs):
        if payload.get("action") == "accept":
            accepted.update(payload)
            record = {"owner": "haus.astrid.runtime", "data_root": str(data), "update_job": {
                "operation_id": payload["operation_id"], "state": "accepted",
                "log_path": payload["log_path"], "target_release": payload["metadata"]["release"],
                "message": "Update accepted.",
            }}
            _write(root / "install.json", record)
            return record["update_job"]
        directory = Path(payload["directory"])
        directory.mkdir(exist_ok=True)
        manifest = directory / "manifest"
        bootstrap = directory / "bootstrap"
        manifest.write_bytes(b'{"release":5}')
        bootstrap.write_bytes(b"bootstrap")
        update.platform.owner_only(manifest)
        update.platform.owner_only(bootstrap)
        prepared.append(directory)
        return {"manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "bootstrap_sha256": hashlib.sha256(bootstrap.read_bytes()).hexdigest(), "release": 5}

    admission._helper = helper
    return admission, accepted, prepared


def test_lost_launcher_ack_keeps_durable_job_and_inputs_without_retry(tmp_path, monkeypatch):
    calls = []

    def lose_ack(job):
        calls.append(job)
        raise OSError("launcher response lost")

    admission, accepted, prepared = _admission_fixture(tmp_path, monkeypatch, lose_ack)
    with pytest.raises(update.UpdateRefusal) as error:
        admission.request()
    assert error.value.details["reason"] == "launch-acknowledgement-unknown"
    assert len(calls) == 1
    assert accepted["action"] == "accept"
    assert accepted["old_instance_id"] == "old-instance"
    assert accepted["metadata"]["release"] == 5
    assert prepared[0].exists()  # The accepted worker owns these selected bytes.
    status = update.read_update_status(Path.home(), available=True)
    assert status["state"] == "recovery-needed"
    assert status["operation_id"] == accepted["operation_id"]
    assert len(calls) == 1


def test_record_write_failure_cleans_prepared_inputs_and_never_launches(tmp_path, monkeypatch):
    calls = []
    admission, _, prepared = _admission_fixture(tmp_path, monkeypatch, lambda job: calls.append(job))
    real_helper = admission._helper

    def fail_accept(python, agent, runtime, payload, **kwargs):
        if payload.get("action") == "accept":
            raise update.UpdateRefusal("update-record-failed", "record failure")
        return real_helper(python, agent, runtime, payload, **kwargs)

    admission._helper = fail_accept
    with pytest.raises(update.UpdateRefusal) as error:
        admission.request()
    assert error.value.details["reason"] == "update-record-failed"
    assert prepared and not prepared[0].exists()
    assert calls == []


def test_explicit_update_returns_agent_recovery_without_a_second_launch(tmp_path, monkeypatch):
    launches = []
    admission, _, prepared = _admission_fixture(tmp_path, monkeypatch, lambda job: launches.append(job))
    real_selection = admission._selection
    selection_calls = []

    def selection(**kwargs):
        selection_calls.append(kwargs)
        return real_selection(**kwargs)

    admission._selection = selection
    real_helper = admission._helper
    helper_actions = []

    def helper(python, agent, runtime, payload, **kwargs):
        helper_actions.append(payload.get("action"))
        if payload.get("action") == "accept":
            # This is the terminal result of the Agent's locked reconciliation
            # of an earlier operation, not acceptance of this new UUID.
            return {"operation_id": "b" * 32, "state": "rolled_back",
                    "message": "Recovered your previous version — run Update again"}
        return real_helper(python, agent, runtime, payload, **kwargs)

    admission._helper = helper
    result = admission.request()

    assert selection_calls == [{"allow_pending": True}]
    assert helper_actions == [None, "accept"]
    assert launches == []
    assert result == {
        "accepted": False, "state": "rolled_back", "operation_id": "b" * 32,
        "message": "Recovered your previous version — run Update again",
    }
    shutil.rmtree(prepared[0])


@pytest.mark.parametrize("choice", [False, "off"])
def test_explicit_autostart_off_refuses_before_preparation_or_launch(tmp_path, monkeypatch, choice):
    admission, _, prepared = _admission_fixture(tmp_path, monkeypatch, lambda job: pytest.fail("must not launch"))
    selection_path, snapshots, python, agent, runtime, installed = admission._selection()
    selected = json.loads(snapshots[selection_path])
    selected["preferences"] = {"autostart": choice}
    snapshots[selection_path] = json.dumps(selected).encode()
    admission._selection = lambda **_kwargs: (selection_path, snapshots, python, agent, runtime, installed)
    with pytest.raises(update.UpdateRefusal) as error:
        admission.request()
    assert error.value.details["reason"] == "autostart-off"
    assert prepared == []


def test_production_launcher_uses_selected_python_helper_once(tmp_path, monkeypatch):
    admission, accepted, prepared = _admission_fixture(tmp_path, monkeypatch, None)
    selection_path, snapshots, python, agent, runtime, installed = admission._selection()
    selected = json.loads(snapshots[selection_path])
    selected["preferences"] = {"autostart": "on"}
    snapshots[selection_path] = json.dumps(selected).encode()
    selection_path.write_bytes(snapshots[selection_path])
    admission._selection = lambda **_kwargs: (selection_path, snapshots, python, agent, runtime, installed)
    calls = []
    real_helper = admission._helper

    def helper(python, agent, runtime, payload, **kwargs):
        if payload.get("action") == "launch":
            calls.append((python, agent, runtime, payload))
            return {"state": "active", "launch_status": "started", "job_name": "job-1"}
        return real_helper(python, agent, runtime, payload, **kwargs)

    admission._helper = helper
    result = admission.request()
    assert result["accepted"] is True
    assert len(calls) == 1
    python, agent, runtime, payload = calls[0]
    assert str(python).endswith("/python")
    assert payload == {"action": "launch", "root": str(tmp_path / "program with spaces"),
                       "operation_id": accepted["operation_id"]}
    assert prepared[0].exists()


def test_known_helper_launch_failure_is_reported_without_retry(tmp_path, monkeypatch):
    admission, accepted, prepared = _admission_fixture(tmp_path, monkeypatch, None)
    calls = []
    real_helper = admission._helper

    def helper(python, agent, runtime, payload, **kwargs):
        if payload.get("action") == "launch":
            calls.append(payload)
            return {"launch_status": "failed", "launch_error": "systemd-run exited 1", "cleanup_residue": []}
        return real_helper(python, agent, runtime, payload, **kwargs)

    admission._helper = helper
    with pytest.raises(update.UpdateRefusal) as error:
        admission.request()
    assert error.value.details["reason"] == "launch-failed"
    assert "systemd-run exited 1" in str(error.value)
    assert len(calls) == 1
    assert accepted["operation_id"] == calls[0]["operation_id"]
    assert prepared[0].exists()


@pytest.mark.integration
@pytest.mark.parametrize("system", ["linux", "darwin", "win32"])
def test_authenticated_update_route_runs_selected_agent_platform_adapter(
    tmp_path, monkeypatch, system,
):
    """Real door POST -> Runtime helper action -> Agent adapter, with OS calls captured."""
    world = start_door_world(tmp_path)
    try:
        admission, accepted, prepared = _admission_fixture(tmp_path, monkeypatch, None)
        admission.daemon = world.daemon
        world.daemon.update_admission = admission
        helper_path = (Path(__file__).resolve().parents[2] / "astrid-agent"
                       / "astrid" / "installer" / "update_job_platform.py")
        agent_root = helper_path.parents[2]
        monkeypatch.syspath_prepend(str(agent_root))
        from astrid.installer import update_job as agent_update_job
        assert Path(agent_update_job.__file__).is_relative_to(agent_root)
        spec = importlib.util.spec_from_file_location("f1c_agent_update_job_platform", helper_path)
        adapter = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(adapter)
        captured = []

        def run(args):
            captured.append(args)
            stdout = "S-1-5-21-12345" if args[:1] == ["powershell.exe"] else ""
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        monkeypatch.setattr(adapter.os, "getuid", getattr(adapter.os, "getuid", lambda: 501), raising=False)
        monkeypatch.setattr(adapter, "_run", run)
        real_describe, real_launch = adapter.describe, adapter.launch
        monkeypatch.setattr(adapter, "describe", lambda job, command: real_describe(job, command, system=system))
        monkeypatch.setattr(adapter, "launch", lambda descriptor, command, log: real_launch(
            descriptor, command, log, system=system))
        monkeypatch.setattr(agent_update_job, "_platform_api", lambda: adapter)
        real_helper = admission._helper
        launch_errors = []

        def helper(python, agent, runtime, payload, **kwargs):
            if payload.get("action") == "accept":
                real_helper(python, agent, runtime, payload, **kwargs)
                root = Path(payload["root"])
                marker_path = root / "install.json"
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
                marker_job = marker["update_job"]
                marker_job.update({key: payload[key] for key in (
                    "operation_id", "job_name", "log_path", "data_root", "old_instance_id",
                    "old_identity", "old_version", "metadata",
                )})
                marker_job.update({"format": "astrid-update-job/v1", "program_root": str(root),
                                   "target_release": payload["metadata"]["release"],
                                   "state": "accepted", "autostart_snapshot": "on"})
                marker_path.write_text(json.dumps(marker), encoding="utf-8")
                return marker_job
            if payload.get("action") == "launch":
                try:
                    return agent_update_job.launch_job(Path(payload["root"]), payload["operation_id"])
                except Exception as failure:
                    launch_errors.append(failure)
                    return {"launch_status": "failed", "launch_error": str(failure)}
            return real_helper(python, agent, runtime, payload, **kwargs)

        admission._helper = helper
        response = world.call(
            "/api/runtime/v1/update", "POST", body=b"",
        )
        assert response.status == 202, (response.body, launch_errors)
        assert json.loads(response.body)["accepted"] is True
        assert accepted["action"] == "accept"
        assert prepared and prepared[0].exists()
        assert captured
        job_record = json.loads((Path(accepted["root"]) / "install.json").read_text(encoding="utf-8"))["update_job"]
        assert job_record["operation_id"] == json.loads(response.body)["operation_id"]
        assert job_record["job_name"] == "astrid-update-" + job_record["operation_id"]
        platform_command = job_record["platform"]["command"]
        if sys.platform == "win32":
            assert not any("run_job" in argument for argument in platform_command)
            worker_source = Path(platform_command[-1]).read_text(encoding="utf-8")
            assert "from astrid.installer.update_job import run_job" in worker_source
            command = [accepted["old_version"]["python"], "-B", "-X", "utf8", "-I"]
        else:
            assert any("run_job" in argument for argument in platform_command)
            command = [accepted["old_version"]["python"], "-B", "-X", "utf8", "-I", "-c"]
        if system == "linux":
            assert captured[0][:5] == ["systemd-run", "--user", "--no-block", "--expand-environment=no",
                                       f"--unit=astrid-update-{accepted['operation_id']}.service"]
            assert captured[0][captured[0].index("--") + 1:][:len(command)] == command
        elif system == "darwin":
            assert captured == [["launchctl", "bootstrap", f"gui/{adapter.os.getuid()}", captured[0][-1]]]
            plist_path = Path(captured[0][-1])
            assert plist_path.is_file()
            assert "KeepAlive" not in plist_path.read_text(encoding="utf-8")
        else:
            assert len(captured) == 3  # SID validation, current SID validation, then task registration/start
            task_script = __import__("base64").b64decode(captured[2][-1]).decode("utf-16le")
            assert "Register-ScheduledTask" in task_script
            assert "Start-ScheduledTask" in task_script
            assert "New-ScheduledTaskTrigger" not in task_script
    finally:
        world.stop()


def test_post_update_terminal_result_line_reads_back_through_status(tmp_path, monkeypatch):
    world = start_door_world(tmp_path)
    try:
        admission, _, _ = _admission_fixture(tmp_path, monkeypatch, None)
        admission.daemon = world.daemon
        world.daemon.update_admission = admission
        real_helper = admission._helper

        def helper(python, agent, runtime, payload, **kwargs):
            if payload.get("action") == "launch":
                return {"launch_status": "started"}
            return real_helper(python, agent, runtime, payload, **kwargs)

        admission._helper = helper
        response = world.call("/api/runtime/v1/update", "POST", body=b"")
        assert response.status == 202
        operation_id = response.json()["operation_id"]
        # The launched worker finishes: it records the terminal job and its result line.
        marker = tmp_path / "program with spaces" / "install.json"
        record = json.loads(marker.read_text())
        assert record["update_job"]["operation_id"] == operation_id
        record["update_job"].update(state="updated", result="line one\nline two")
        _write(marker, record)
        status = world.call("/api/runtime/v1/update/status").json()
        assert status["operation_id"] == operation_id
        assert status["state"] == "terminal" and status["outcome"] == "updated"
        assert status["result"] == "line one line two"
    finally:
        world.stop()
