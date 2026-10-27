"""F1b Runtime acceptance and fresh-process status reader tests."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from astrid_runtime import update


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


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
        "available": False, "state": "active", "operation_id": "11111111111111111111111111111111",
        "result": "Update accepted.", "target_release": 9,
        "log_path": str(root / "logs/update.log"),
    }
    fresh = subprocess.run(
        [sys.executable, "-c", "import json,sys; from astrid_runtime.update import read_update_status; print(json.dumps(read_update_status(sys.argv[1])))", str(home)],
        cwd=Path(__file__).parents[1], text=True, capture_output=True, check=True,
    )
    assert json.loads(fresh.stdout)["state"] == "active"

    # A fresh status reader observes a pending C2 transaction but never calls
    # recovery or modifies either record.
    _write(root / "update-transaction.json", {"step": "stopping"})
    before = (root / "update-transaction.json").read_bytes()
    assert update.read_update_status(home)["state"] == "recovery-needed"
    assert (root / "update-transaction.json").read_bytes() == before
    assert selection.exists()


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
    daemon = SimpleNamespace(
        instance_id="old-instance", startup_identity={"release": 4, "managed_by": None},
        root=tmp_path / "realm", update_launcher=launcher,
    )
    admission = update.UpdateAdmission(daemon)
    snapshots = {selected: json.dumps(selected_value).encode(), root / "current": b"old\n",
                 version_path: json.dumps(version).encode()}
    python, agent, runtime = root / "versions/old/python", root / "agent", root / "runtime"
    admission._selection = lambda: (selected, snapshots, python, agent, runtime, 4)

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
    assert status["state"] == "active"
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
