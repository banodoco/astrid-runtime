from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from astrid_runtime.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, doctor, installer_stop, restart
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol import platform
from runtime_protocol.backup import verify_backup
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def test_backup_tamper_with_recomputed_public_digest_still_requires_private_mac(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        backup = tmp_path / "backup"
        service.backup(backup)
        path = backup / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["realm"]["display_name"] = "forged"
        payload = {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac"}}
        manifest["manifest_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        path.write_text(json.dumps(manifest))
        with pytest.raises(ConflictError, match="authentication"):
            verify_backup(backup)
    finally:
        service.close()


def _upgrade_fixture(tmp_path):
    from astrid_runtime.bootstrap import SourceProfile

    paths = RuntimePaths.current(data_root=tmp_path / "support")
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    profile = SourceProfile("astrid", "/runtime", "/source")
    paths.catalog_path.write_text(json.dumps({
        "version": 1,
        "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root.resolve())}],
        "source_profiles": {"astrid": profile.as_dict()},
    }))
    (paths.source_profiles_dir / "astrid.json").write_text(json.dumps(profile.as_dict()))
    (paths.runtime_support / "credentials").mkdir(parents=True, exist_ok=True)
    (paths.runtime_support / "credentials" / "owner.token").write_text("owner-token")
    discovery = {
        "pid": 51515,
        "active_realm": "realm",
        "endpoint": "http://127.0.0.1:51515",
        "runtime_instance_id": "instance",
        "process_birth_id": "birth",
        "realm_root": str(realm_root.resolve()),
    }
    paths.discovery_path.write_text(json.dumps(discovery))
    paths.instance_lock_path.write_text(json.dumps({**discovery, "realm_id": "realm"}))
    return paths, realm_root, profile


def _insert_running_task(realm_root):
    import sqlite3

    with sqlite3.connect(realm_root / "realm.sqlite3") as connection:
        timestamp = "2026-10-27T00:00:00Z"
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("project", "realm", "project", "Project", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("run", "project", "rendering.render", None, "running", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_digest, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("task", "run", "rendering.render", None, "running", timestamp, timestamp),
        )


@pytest.fixture
def frozen_lifecycle_clock(monkeypatch):
    from datetime import datetime, timezone

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 27, 0, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr("runtime_protocol.lifecycle.datetime", Clock)


def test_upgrade_busy_refusal_reaches_real_cli_json_with_structured_report(tmp_path, monkeypatch, capsys, frozen_lifecycle_clock):
    from astrid_runtime import cli
    from runtime_protocol.lifecycle import inspect_interruption_state

    paths, realm_root, _profile = _upgrade_fixture(tmp_path)
    _insert_running_task(realm_root)
    report = inspect_interruption_state(realm_root)
    assert report["safe"] is False
    monkeypatch.setattr(cli, "RuntimePaths", type("Paths", (), {"current": staticmethod(lambda *_args, **_kwargs: paths)}))

    assert cli.main(["upgrade", "--data-root", str(paths.app_support), "--profile", "astrid", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["error"] == {"message": report["message"], "details": report}


def test_upgrade_final_fence_refusal_keeps_report_and_skips_recovery(tmp_path, monkeypatch, frozen_lifecycle_clock):
    from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile
    from astrid_runtime.operator_upgrade import OperatorUpgradeError, upgrade_workspace
    from runtime_protocol.lifecycle import inspect_interruption_state

    paths, realm_root, profile = _upgrade_fixture(tmp_path)

    class Boundary:
        stop_calls = 0

        def is_pid_alive(self, _pid):
            return True

        def validate_owner(self, **_kwargs):
            return True

        def endpoint_metadata(self, **_kwargs):
            return {"runtime_instance_id": "instance", "realm_id": "realm"}

        def prepare_restart(self, **_kwargs):
            # The initial read-only check has succeeded. Simulate newly admitted
            # work before the real BEGIN IMMEDIATE final check.
            _insert_running_task(realm_root)

        def stop_owner(self, **_kwargs):
            self.stop_calls += 1

    boundary = Boundary()
    recovery_calls = []
    monkeypatch.setattr("astrid_runtime.operator_upgrade._bootstrap_locked", lambda *_a, **_k: recovery_calls.append(True))
    with pytest.raises(OperatorUpgradeError) as caught:
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))

    expected = inspect_interruption_state(realm_root)
    assert caught.value.details == expected
    assert str(caught.value) == expected["message"]
    assert boundary.stop_calls == 0
    assert recovery_calls == []


def test_upgrade_idle_inspection_exception_preserves_lifecycle_details(tmp_path, monkeypatch):
    from astrid_runtime import operator_upgrade

    headline = "Astrid is busy (1 tasks running). Try again when they finish."
    report = {"safe": False, "headline": headline, "blockers": [{"task_id": "task"}]}

    def refuse(_root):
        raise ConflictError(headline, details=report)

    monkeypatch.setattr(operator_upgrade, "inspect_interruption_state", refuse)
    with pytest.raises(operator_upgrade.OperatorUpgradeError) as caught:
        operator_upgrade._assert_idle(tmp_path)
    assert caught.value.details == report
    assert str(caught.value) == headline


def test_upgrade_lifecycle_refusal_after_owner_stop_never_restarts_for_recovery(tmp_path, monkeypatch):
    from astrid_runtime import operator_upgrade

    paths, _realm_root, profile = _upgrade_fixture(tmp_path)
    headline = "Astrid is busy (1 tasks running). Try again when they finish."
    report = {"safe": False, "headline": headline, "message": headline,
              "blockers": [{"task_id": "new-work"}]}
    events = []

    class Boundary:
        def is_pid_alive(self, _pid):
            return True

        def validate_owner(self, **_kwargs):
            return True

        def endpoint_metadata(self, **_kwargs):
            return {"runtime_instance_id": "instance", "realm_id": "realm"}

        def prepare_restart(self, **_kwargs):
            pass

        def stop_owner(self, **_kwargs):
            events.append("stop")
            return {"status": "stopped"}

    def refuse(*_args, **_kwargs):
        events.append("migration-refused")
        raise ConflictError(headline, details=report)

    monkeypatch.setattr(operator_upgrade, "migrate_canonical_to_current", refuse)
    monkeypatch.setattr(operator_upgrade, "_bootstrap_locked", lambda *_a, **_k: events.append("start"))
    with pytest.raises(operator_upgrade.OperatorUpgradeError) as caught:
        operator_upgrade.upgrade_workspace(paths, Boundary(), BootstrapConfig(source_profile=profile))
    assert caught.value.details == report
    assert str(caught.value) == headline
    assert events == ["stop", "migration-refused"]


class _ForgedDiscoveryBoundary:
    def __init__(self, pid: int):
        self.pid = pid
        self.restart_calls = 0

    def is_pid_alive(self, pid):
        return int(pid) == self.pid

    def validate_owner(self, **_kwargs):
        return True

    def restart(self, **_kwargs):
        self.restart_calls += 1
        raise AssertionError("forged discovery reached the signal boundary")


def test_forged_current_pid_discovery_cannot_cross_lock_fence(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    paths.catalog_path.write_text(json.dumps({
        "version": 1, "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root.resolve())}],
        "source_profiles": {},
    }))
    pid = os.getpid()
    paths.discovery_path.write_text(json.dumps({
        "pid": pid,
        "process_birth_id": "forged-birth",
        "runtime_instance_id": "forged-instance",
        "endpoint": "http://127.0.0.1:1",
        "active_realm": "realm",
        "realm_root": str(realm_root.resolve()),
    }))
    paths.instance_lock_path.write_text(json.dumps({
        "pid": pid,
        "process_birth_id": "forged-birth",
        "runtime_instance_id": "different-owner",
        "realm_id": "realm",
        "realm_root": str(realm_root.resolve()),
    }))
    boundary = _ForgedDiscoveryBoundary(pid)
    with pytest.raises(BootstrapError, match="owner lock"):
        restart(paths, boundary, BootstrapConfig(source_profile=SourceProfile("astrid", "/runtime", "/source")))
    assert boundary.restart_calls == 0


def test_doctor_marks_dead_discovery_owner_unhealthy_and_nonzero_state(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    paths.catalog_path.write_text(json.dumps({"version": 1, "selected_realm_id": None, "realms": []}))
    paths.discovery_path.write_text(json.dumps({
        "pid": 2147483647,
        "process_birth_id": "dead",
        "runtime_instance_id": "dead-instance",
        "endpoint": "http://127.0.0.1:1",
        "active_realm": "dead-realm",
    }))
    report = doctor(paths)
    assert report["healthy"] is False
    assert "stale_discovery" in report["issues"]


def test_real_boundary_restart_rechecks_identity_before_signal(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    # No process handle/adopted owner means the boundary refuses before any
    # killpg call, even if a caller supplies a plausible current PID.
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _endpoint: {"status": "ok", "protocol": "workspace.v1", "runtime_instance_id": "x"})
    monkeypatch.setattr(boundary, "endpoint_metadata", lambda **_kwargs: {"status": "ok", "runtime_instance_id": "x", "realm_id": "r"})
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    realm_root = tmp_path / "realm"
    realm_root.mkdir()
    paths.discovery_path.write_text(json.dumps({"pid": pid, "process_birth_id": birth, "runtime_instance_id": "x", "endpoint": "http://127.0.0.1:1", "active_realm": "r", "realm_root": str(realm_root.resolve())}))
    paths.instance_lock_path.write_text(json.dumps({"pid": pid, "process_birth_id": birth, "runtime_instance_id": "x", "realm_id": "r", "realm_root": str(realm_root.resolve())}))
    boundary.prepare_restart(source_profile=SourceProfile("astrid", str(tmp_path), str(tmp_path)), realm_id="r", realm_root=realm_root, support_root=paths.runtime_support, pid=pid)
    with pytest.raises(BootstrapError, match="current operator process|process-group leader|owned process handle"):
        boundary.restart(endpoint="http://127.0.0.1:1", pid=pid, process_birth_id=birth, instance_id="x", realm_id="r", owner_lock=paths.instance_lock_path, discovery_path=paths.discovery_path)


def test_validate_owner_rejects_wrong_endpoint_instance_even_with_birth_match(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    root = tmp_path / "realm"
    root.mkdir()
    marker = tmp_path / "instance.lock"
    marker.write_text(json.dumps({
        "pid": pid,
        "process_birth_id": birth,
        "runtime_instance_id": "expected-instance",
        "realm_id": "realm",
        "realm_root": str(root.resolve()),
    }))
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _endpoint: {
        "status": "degraded",
        "protocol": "workspace.v1",
        "runtime_instance_id": "different-instance",
    })
    assert boundary.validate_owner(
        endpoint="http://127.0.0.1:1", pid=pid,
        instance_id="expected-instance", owner_lock=marker,
        process_birth_id=birth, expected_realm_id="realm",
        expected_realm_root=root,
    ) is False


def test_validate_owner_accepts_degraded_matching_instance_and_birth(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    root = tmp_path / "realm"
    root.mkdir()
    marker = tmp_path / "instance.lock"
    marker.write_text(json.dumps({
        "pid": pid, "process_birth_id": birth,
        "runtime_instance_id": "expected-instance", "realm_id": "realm",
        "realm_root": str(root.resolve()),
    }))
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _endpoint: {
        "status": "degraded", "protocol": "workspace.v1",
        "runtime_instance_id": "expected-instance",
    })
    assert boundary.validate_owner(
        endpoint="http://127.0.0.1:1", pid=pid,
        instance_id="expected-instance", owner_lock=marker,
        process_birth_id=birth, expected_realm_id="realm",
        expected_realm_root=root,
    ) is True


def test_installer_stop_accepts_only_retained_foreground_custody_handle(tmp_path, monkeypatch):
    class Child:
        pid = 51515
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def wait(self, timeout=None):
            self.exited = True
            return 0

    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    paths.catalog_path.write_text(json.dumps({
        "version": 1, "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root.resolve())}],
        "source_profiles": {},
    }))
    child = Child()
    boundary = LocalRuntimeBoundary()
    monkeypatch.setattr(boundary, "process_birth_identity", lambda pid: "birth" if pid == child.pid else None)
    monkeypatch.setattr("astrid_runtime.runtime_boundary.platform.process_group", lambda pid: pid)
    stopped = []

    def stop_tree(process, **_kwargs):
        assert process is child
        process.exited = True
        stopped.append(process.pid)

    monkeypatch.setattr("astrid_runtime.runtime_boundary.platform.stop_tree", stop_tree)
    record = {"pid": child.pid, "birth_id": "birth", "process": child,
              "realm_id": "realm", "realm_root": str(realm_root.resolve())}
    callback_seen = []
    result = installer_stop(
        paths, boundary,
        recorded_foreground=record,
        stop_manager=lambda: callback_seen.append(child.exited),
    )
    assert result["runtime"]["exit_evidence"] == "retained_child_stopped"
    assert stopped == [child.pid]
    assert callback_seen == [True]


def test_process_birth_lookup_error_is_not_reported_as_absent(monkeypatch):
    from astrid_runtime.custody_broker import CustodyError

    def denied(_pid):
        raise CustodyError("process observation denied")

    monkeypatch.setattr("astrid_runtime.runtime_boundary.default_process_identity", denied)
    with pytest.raises(BootstrapError, match="identity remains uncertain"):
        LocalRuntimeBoundary().process_birth_identity(123)


def test_installer_stop_refuses_pid_birth_without_retained_foreground_handle(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    paths.catalog_path.write_text(json.dumps({
        "version": 1, "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root.resolve())}],
        "source_profiles": {},
    }))
    boundary = LocalRuntimeBoundary()
    record = {"pid": 51515, "birth_id": "birth", "realm_id": "realm",
              "realm_root": str(realm_root.resolve())}
    called = []
    authority = []
    with pytest.raises(BootstrapError, match="retained child identity is incomplete"):
        installer_stop(paths, boundary, recorded_foreground=record,
                       stop_manager=lambda: called.append(True), record_stop_authority=authority.append)
    assert called == []
    assert authority == []


def test_installer_stop_terminates_real_retained_child_and_leaves_external_child_alone(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    RealmStore.initialize(realm_root, realm_id="realm").close()
    paths.catalog_path.write_text(json.dumps({
        "version": 1, "selected_realm_id": "realm",
        "realms": [{"realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root.resolve())}],
        "source_profiles": {},
    }))
    boundary = LocalRuntimeBoundary()
    retained = platform.spawn_tree(
        [sys.executable, "-c", "import time; time.sleep(60)"], detached=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    external = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        birth = boundary.process_birth_identity(retained.pid)
        assert birth
        record = {"pid": retained.pid, "birth_id": birth, "process": retained,
                  "realm_id": "realm", "realm_root": str(realm_root.resolve())}
        callbacks = []
        authority = []

        def record_authority(value):
            assert retained.poll() is None
            authority.append(value)

        result = installer_stop(
            paths, boundary, recorded_foreground=record,
            stop_manager=lambda: callbacks.append(True),
            record_stop_authority=record_authority,
        )
        assert result["runtime"]["exit_evidence"] == "retained_child_stopped"
        assert retained.poll() is not None
        assert callbacks == [True]
        assert authority[0]["pid"] == retained.pid
        # New C1 controller, with neither the Popen nor an in-memory receipt.
        fresh = LocalRuntimeBoundary()
        result = installer_stop(
            paths, fresh, recorded_foreground={key: value for key, value in record.items() if key != "process"},
            recovery_owner=authority[0],
            recovery_realm={"realm_id": "realm", "realm_root": str(realm_root.resolve())},
            stop_manager=lambda: callbacks.append(True),
        )
        assert result["runtime"] is None
        assert callbacks == [True, True]

        external_birth = boundary.process_birth_identity(external.pid)
        external_record = {"pid": external.pid, "birth_id": external_birth,
                           "process": external, "realm_id": "realm",
                           "realm_root": str(realm_root.resolve())}
        with pytest.raises(BootstrapError, match="session leader|Job Object custody"):
            boundary.stop_recorded_foreground(
                recorded_foreground=external_record, realm_id="realm", realm_root=realm_root,
                record_custody_authority=lambda: pytest.fail("authority before custody admission"),
            )
        assert external.poll() is None
    finally:
        if retained.poll() is None:
            platform.stop_tree(retained, grace=0.2)
        if external.poll() is None:
            external.terminate()
            external.wait(timeout=3)
