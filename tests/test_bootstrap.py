from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from astrid_runtime.bootstrap import (
    BootstrapConfig,
    BootstrapError,
    CompatibilityError,
    DuplicateOwnerError,
    LegacyRootCollisionError,
    SourceProfile,
    _rollback_failed_bootstrap,
    bootstrap,
    connect,
    down,
    doctor,
    restart,
)
from astrid_runtime.paths import RuntimePaths
from runtime_protocol.store import RealmStore


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
    capability_digest="caps-v1",
)


class FakeConnection:
    def __init__(self, boundary):
        self.boundary = boundary

    def handshake(self, **kwargs):
        self.boundary.handshakes.append(kwargs)

    def provision_actor(self, **kwargs):
        self.boundary.provisions.append(kwargs)
        return {"scope": kwargs["scope"], "actor_id": kwargs["actor_id"]}

    def select_realm(self, **kwargs):
        self.boundary.selections.append(kwargs)


class FakeBoundary:
    def __init__(self):
        self.creates = []
        self.starts = []
        self.calls = []
        self.connects = []
        self.provisions = []
        self.selections = []
        self.handshakes = []
        self.alive = set()
        self.valid_owner = True
        self.next_pid = 41001
        self.restart_calls = 0

    def start(self, **kwargs):
        self.calls.append("start")
        self.starts.append(kwargs)
        realm_root = kwargs["realm_root"]
        realm_root.mkdir(parents=True, exist_ok=True)
        (realm_root / "workspace.sqlite3").touch()
        pid = self.next_pid
        self.next_pid += 1
        self.alive.add(pid)
        return {
            "endpoint": "http://127.0.0.1:43100",
            "pid": pid,
            "runtime_instance_id": f"instance-{pid}",
            "coordinator_epoch": 1,
            "protocol_version": "workspace.v1",
            "schema_version": "workspace-schema-v1",
            "capability_digest": "caps-v1",
        }

    def create(self, **kwargs):
        self.calls.append("create")
        self.creates.append(kwargs)
        realm_root = kwargs["realm_root"]
        RealmStore.initialize(
            realm_root,
            realm_id=kwargs["realm_id"],
            display_name=kwargs["display_name"],
        ).close()
        return {"state": "created", "realm_id": kwargs["realm_id"], "root": str(realm_root)}

    def connect(self, **kwargs):
        self.connects.append(kwargs)
        return FakeConnection(self)

    def health(self, **kwargs):
        return kwargs["pid"] in self.alive

    def validate_owner(self, **kwargs):
        return self.valid_owner

    def endpoint_metadata(self, **_kwargs):
        if not self.starts:
            return {}
        pid = max(self.alive) if self.alive else self.next_pid - 1
        return {
            "runtime_instance_id": f"instance-{pid}",
            "realm_id": str(self.starts[-1]["realm_id"]),
            "status": "ok",
        }

    def is_pid_alive(self, pid):
        return pid in self.alive

    def restart(self, **kwargs):
        self.restart_calls += 1
        self.alive.discard(kwargs["pid"])
        return self.start(realm_id="ignored", realm_root=Path(tempfile.mkdtemp()) / "realm", owner_lock=Path("/tmp/lock"), source_profile=PROFILE)

    def stop_owner(self, **kwargs):
        self.restart_calls += 1
        self.alive.discard(kwargs["pid"])
        return {"status": "stopped"}


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = RuntimePaths.sandbox(self.temp.name)
        self.boundary = FakeBoundary()
        self.config = BootstrapConfig(source_profile=PROFILE)

    def tearDown(self):
        self.temp.cleanup()

    def _configure(self, *, realm_id="configured-realm"):
        self.paths.ensure_support_dirs()
        root = self.paths.realms_dir / realm_id
        self.boundary.create(
            realm_id=realm_id,
            realm_root=root,
            display_name="Astrid Workspace",
            source_profile=PROFILE,
        )
        self.paths.catalog_path.write_text(json.dumps({
            "version": 1,
            "selected_realm_id": realm_id,
            "realms": [{
                "realm_id": realm_id,
                "display_name": "Astrid Workspace",
                "data_root": str(root),
            }],
            "source_profiles": {},
        }))
        self.boundary.calls.clear()
        self.boundary.creates.clear()
        return root

    def test_first_launch_writes_catalog_discovery_without_synthesizing_activation(self):
        self._configure()
        result = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "started")
        self.assertEqual(result.runtime_instance_id, json.loads(self.paths.discovery_path.read_text())["runtime_instance_id"])
        self.assertEqual(result.credential_file, self.paths.credentials_dir / "astrid.json")
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(self.boundary.calls, ["start"])
        self.assertEqual(len(self.boundary.creates), 0)
        self.assertEqual(result.realm_id, json.loads(self.paths.discovery_path.read_text())["active_realm"])
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["selected_realm_id"], result.realm_id)
        self.assertEqual(len(catalog["realms"]), 1)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.assertNotIn("token", json.dumps(discovery))
        credential = json.loads((self.paths.credentials_dir / "astrid.json").read_text())
        self.assertEqual(credential["scope"], "astrid")
        self.assertEqual(len(credential["token"]), 64)
        mode = stat.S_IMODE((self.paths.credentials_dir / "astrid.json").stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertNotIn("activation_manifest", catalog["realms"][0])
        source_manifest = self.paths.source_profiles_dir / "astrid.json"
        self.assertEqual(json.loads(source_manifest.read_text()), PROFILE.as_dict())
        self.assertEqual(stat.S_IMODE(source_manifest.stat().st_mode), 0o600)

    def test_second_launch_reconnects_same_owner_and_actor(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        updated = SourceProfile(
            profile="astrid",
            runtime_checkout="/checkouts/runtime-pinned",
            source_checkout="/checkouts/astrid-pinned",
            capability_digest="caps-v1",
        )
        second = bootstrap(self.paths, self.boundary, BootstrapConfig(source_profile=updated))
        self.assertEqual(second.status, "reconnected")
        self.assertEqual(first.runtime_instance_id, second.runtime_instance_id)
        self.assertEqual(second.runtime_instance_id, json.loads(self.paths.discovery_path.read_text())["runtime_instance_id"])
        self.assertEqual(first.realm_id, second.realm_id)
        self.assertEqual(first.actor_id, second.actor_id)
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(len(self.boundary.connects), 2)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(json.loads((self.paths.source_profiles_dir / "astrid.json").read_text()), updated.as_dict())
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["source_profiles"]["astrid"], updated.as_dict())

    def test_stale_discovery_restarts_without_second_realm(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        second = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(second.realm_id, first.realm_id)
        self.assertEqual(len(self.boundary.starts), 2)
        self.assertEqual(json.loads(self.paths.catalog_path.read_text())["selected_realm_id"], first.realm_id)

    def test_restart_reuses_selected_realm(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        result = restart(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "restarted")
        self.assertEqual(result.realm_id, first.realm_id)
        # The old owner is already absent; restart must not signal a reused PID.
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_restart_and_down_share_unreconciled_attempt_refusal(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        timestamp = "2026-09-24T00:00:00Z"
        connection = sqlite3.connect(root / "realm.sqlite3")
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
            "VALUES ('p', 'configured-realm', 'p', 'P', '{}', ?, ?)",
            (timestamp, timestamp),
        )
        # Schema v28+ stores specs once in task_specs; runs and tasks reference them by digest.
        empty_spec = hashlib.sha256(b"{}").hexdigest()
        connection.execute(
            "INSERT INTO task_specs(digest, body_json, created_at) VALUES (?, '{}', ?)",
            (empty_spec, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_digest, status, created_at, updated_at) "
            "VALUES ('r', 'p', 'test', ?, 'running', ?, ?)",
            (empty_spec, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_digest, status, created_at, updated_at) "
            "VALUES ('t', 'r', 'test', ?, 'queued', ?, ?)",
            (empty_spec, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
            "VALUES ('a', 't', 'l', 1, 'e', '2000-01-01T00:00:00Z', 0, 1)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(BootstrapError, "active or unreconciled"):
            restart(self.paths, self.boundary, self.config)
        with self.assertRaisesRegex(BootstrapError, "active or unreconciled"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_down_refuses_wrong_endpoint_instance_without_signal(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.endpoint_metadata = lambda **_kwargs: {
            "runtime_instance_id": "different-instance",
            "realm_id": "configured-realm",
            "status": "degraded",
        }
        with self.assertRaisesRegex(BootstrapError, "endpoint identity"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)
        self.assertTrue(self.paths.discovery_path.exists())

    def test_down_accepts_degraded_but_identity_matching_endpoint(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        original = self.boundary.endpoint_metadata()
        self.boundary.endpoint_metadata = lambda **_kwargs: {**original, "status": "degraded"}
        result = down(self.paths, self.boundary)
        self.assertEqual(result["status"], "stopped")
        self.assertFalse(self.paths.discovery_path.exists())

    def test_down_refuses_wrong_discovery_root_without_signal(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        wrong = Path(self.temp.name) / "wrong-realm"
        wrong.mkdir()
        discovery = json.loads(self.paths.discovery_path.read_text())
        discovery["realm_root"] = str(wrong.resolve())
        self.paths.discovery_path.write_text(json.dumps(discovery))
        with self.assertRaisesRegex(BootstrapError, "discovery realm root"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_down_holds_bootstrap_mutex_through_stop_owner(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        observed = []

        def fenced_stop(**kwargs):
            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from runtime_protocol.platform import file_lock; p=sys.argv[1]; "
                    "\ntry: file_lock(p, blocking=False).__enter__()"
                    "\nexcept BlockingIOError: raise SystemExit(7)"
                    "\nraise SystemExit(0)",
                    str(self.paths.bootstrap_lock_path),
                ],
                check=False,
            )
            observed.append(probe.returncode)
            self.boundary.alive.discard(kwargs["pid"])

        self.boundary.stop_owner = fenced_stop
        result = down(self.paths, self.boundary)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(observed, [7])

    def test_down_never_cleans_up_new_owner_published_during_stop(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        replacement = {
            "pid": 49999,
            "endpoint": "http://127.0.0.1:49999",
            "runtime_instance_id": "replacement-instance",
            "process_birth_id": "replacement-birth",
            "active_realm": "configured-realm",
            "realm_root": str(root.resolve()),
        }

        def replace_owner(**kwargs):
            self.boundary.alive.discard(kwargs["pid"])
            self.paths.discovery_path.write_text(json.dumps(replacement))
            self.paths.instance_lock_path.write_text(json.dumps({
                **replacement, "realm_id": "configured-realm",
            }))

        self.boundary.stop_owner = replace_owner
        with self.assertRaisesRegex(BootstrapError, "changed during stop"):
            down(self.paths, self.boundary)
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)
        self.assertEqual(
            json.loads(self.paths.instance_lock_path.read_text())["runtime_instance_id"],
            "replacement-instance",
        )

    def test_legacy_collision_refuses_parallel_empty_realm_with_exact_action(self):
        legacy = self.paths.home / ".astrid"
        legacy.mkdir(parents=True)
        (legacy / "astrid.sqlite3").touch()
        with self.assertRaises(LegacyRootCollisionError) as caught:
            bootstrap(self.paths, self.boundary, self.config)
        self.assertIn("Legacy realm roots are unsupported", str(caught.exception))
        self.assertEqual(len(self.boundary.starts), 0)
        self.assertFalse(self.paths.catalog_path.exists())

    def test_incompatible_live_owner_fails_closed_without_mutation(self):
        self._configure(realm_id="realm")
        self.paths.runtime_support.mkdir(parents=True, exist_ok=True)
        self.paths.discovery_path.write_text(json.dumps({
            "protocol_version": "old", "schema_version": "old", "active_realm": "realm", "pid": 99,
        }))
        self.boundary.alive.add(99)
        before = self.paths.discovery_path.read_bytes()
        with self.assertRaises(CompatibilityError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.discovery_path.read_bytes(), before)
        self.assertEqual(len(self.boundary.starts), 0)

    def test_duplicate_owner_refuses_when_lock_validation_fails(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.valid_owner = False
        with self.assertRaises(DuplicateOwnerError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(len(self.boundary.starts), 1)

    def test_connect_is_side_effect_free_when_stopped(self):
        with self.assertRaisesRegex(Exception, "astrid-runtime up --profile astrid"):
            connect(self.paths, self.boundary, self.config)
        self.assertFalse(self.paths.runtime_support.exists())

    def test_selected_missing_realm_never_uses_fresh_create(self):
        self.paths.ensure_support_dirs()
        self.paths.catalog_path.write_text(json.dumps({
            "version": 1,
            "selected_realm_id": "existing-realm",
            "realms": [{
                "realm_id": "existing-realm",
                "display_name": "Existing",
                "data_root": str((self.paths.realms_dir / "existing-realm").resolve()),
            }],
            "source_profiles": {},
        }))

        class ExistingBoundary(FakeBoundary):
            def start(self, **kwargs):
                self.calls.append("start")
                raise BootstrapError("existing realm is missing")

            def create(self, **kwargs):
                raise AssertionError("selected existing realm was provisioned")

        boundary = ExistingBoundary()
        with self.assertRaisesRegex(BootstrapError, "Realm-root identity is unavailable"):
            bootstrap(self.paths, boundary, self.config)
        self.assertEqual(boundary.calls, [])
        self.assertFalse(self.paths.realms_dir.joinpath("existing-realm").exists())

    def test_configured_realm_handoff_failure_preserves_explicit_selection(self):
        class FailingHandoffBoundary(FakeBoundary):
            def start(self, **kwargs):
                super().start(**kwargs)
                raise RuntimeError("admission handoff failed")

        boundary = FailingHandoffBoundary()
        self.boundary = boundary
        root = self._configure()
        with self.assertRaisesRegex(RuntimeError, "admission handoff failed"):
            bootstrap(self.paths, boundary, self.config)
        self.assertEqual(boundary.calls, ["start"])
        self.assertTrue(root.is_dir())
        self.assertTrue(self.paths.catalog_path.exists())
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_failed_candidate_rollback_preserves_incumbent_support_metadata(self):
        self.paths.ensure_support_dirs()
        incumbent = {
            "pid": 99,
            "runtime_instance_id": "incumbent",
            "active_realm": "realm-1",
        }
        self.paths.discovery_path.write_text(json.dumps(incumbent))
        self.paths.instance_lock_path.write_text(json.dumps(incumbent))

        class CandidateBoundary:
            class Process:
                pid = 123

            _process = Process()

            def stop(self):
                return None

        _rollback_failed_bootstrap(
            self.paths,
            CandidateBoundary(),
            realm_root=self.paths.realms_dir / "realm-1",
            new_realm=False,
            credential_before=None,
        )

        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), incumbent)
        self.assertEqual(json.loads(self.paths.instance_lock_path.read_text()), incumbent)

    def test_doctor_is_side_effect_free(self):
        report = doctor(self.paths, self.boundary)
        self.assertFalse(report["healthy"])
        self.assertFalse(self.paths.runtime_support.exists())

    def test_bootstrap_uncertain_incumbent_probe_preserves_authority(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        authority = [self.paths.discovery_path, self.paths.instance_lock_path,
                     self.paths.catalog_path, self.paths.credentials_dir / "astrid.json",
                     self.paths.source_profiles_dir / "astrid.json"]
        before = {path: path.read_bytes() for path in authority}
        starts = len(self.boundary.starts)
        def unknown(_pid):
            raise BootstrapError("Runtime liveness observation remains uncertain.")
        self.boundary.is_pid_alive = unknown
        with self.assertRaisesRegex(BootstrapError, "uncertain"):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(before, {path: path.read_bytes() for path in authority})
        self.assertEqual(len(self.boundary.starts), starts)

    def test_source_manifest_is_validated_and_recorded(self):
        self.paths.source_profiles_dir.mkdir(parents=True)
        manifest = self.paths.source_profiles_dir / "astrid.json"
        manifest.write_text(json.dumps(PROFILE.as_dict()))
        profile = SourceProfile.load(manifest)
        self.assertEqual(profile.profile, "astrid")
        self.assertEqual(profile.digest, SourceProfile.from_mapping(PROFILE.as_dict()).digest)


if __name__ == "__main__":
    unittest.main()


def test_relinquish_runs_after_all_bootstrap_metadata_is_committed():
    case = BootstrapTests()
    case.setUp()
    try:
        case._configure()
        def release():
            assert case.paths.discovery_path.is_file()
            assert case.paths.instance_lock_path.is_file()
            assert case.paths.catalog_path.is_file()
            assert (case.paths.credentials_dir / "astrid.json").is_file()
            return {"generation": 2}
        case.boundary.release_owner_custody = release
        result = bootstrap(case.paths, case.boundary, case.config)
        assert result.status == "started"
        assert len(case.boundary.alive) == 1
    finally:
        case.tearDown()


def test_precommit_release_failure_uses_original_owned_rollback():
    import pytest
    case = BootstrapTests()
    case.setUp()
    try:
        case._configure()
        stops = []
        def stop():
            stops.append(True)
            case.boundary.alive.clear()
        def fail(): raise BootstrapError("release not committed")
        case.boundary.stop = stop
        case.boundary.release_owner_custody = fail
        with pytest.raises(BootstrapError, match="not committed"):
            bootstrap(case.paths, case.boundary, case.config)
        assert stops == [True]
        assert not case.paths.discovery_path.exists()
        assert not case.paths.instance_lock_path.exists()
    finally:
        case.tearDown()


def test_unknown_release_keeps_all_metadata_and_named_controller():
    import pytest
    from astrid_runtime.bootstrap import BootstrapCustodyUncertain
    case = BootstrapTests()
    case.setUp()
    try:
        case._configure()
        case.boundary.stop = lambda: pytest.fail("unknown commit must not roll back")
        def unknown():
            raise BootstrapCustodyUncertain("commit unknown", controller=case.boundary)
        case.boundary.release_owner_custody = unknown
        with pytest.raises(BootstrapCustodyUncertain) as failure:
            bootstrap(case.paths, case.boundary, case.config)
        assert failure.value.controller is case.boundary
        assert case.paths.discovery_path.is_file()
        assert case.paths.instance_lock_path.is_file()
        assert case.paths.catalog_path.is_file()
        assert (case.paths.credentials_dir / "astrid.json").is_file()
        assert (case.paths.source_profiles_dir / "astrid.json").is_file()
        assert (case.paths.realms_dir / "configured-realm").is_dir()
    finally:
        case.tearDown()


def test_uncertain_stop_preserves_entire_bootstrap_state():
    import pytest
    from astrid_runtime.bootstrap import BootstrapCustodyUncertain
    case = BootstrapTests()
    case.setUp()
    try:
        case._configure()
        bootstrap(case.paths, case.boundary, case.config)
        before = {p.relative_to(case.paths.catalog_path.parent): p.read_bytes()
                  for p in case.paths.catalog_path.parent.rglob("*") if p.is_file()}
        def unresolved(): raise BootstrapError("still alive")
        case.boundary.stop = unresolved
        with pytest.raises(BootstrapCustodyUncertain) as failure:
            _rollback_failed_bootstrap(case.paths, case.boundary, realm_root=case.paths.realms_dir / "configured-realm",
                                       new_realm=True, credential_before=None, catalog_before=None, source_before=None,
                                       candidate_pid=max(case.boundary.alive))
        assert failure.value.controller is case.boundary
        after = {p.relative_to(case.paths.catalog_path.parent): p.read_bytes()
                 for p in case.paths.catalog_path.parent.rglob("*") if p.is_file()}
        assert after == before
        assert (case.paths.realms_dir / "configured-realm").is_dir()
    finally:
        case.tearDown()


# Pack-only regression cases retained with the current-main custody suite.
def test_pack_rollback_stop_failure_preserves_all_metadata_and_root(tmp_path):
    from types import SimpleNamespace
    import pytest

    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm = paths.realms_dir / "uncertain-candidate"
    realm.mkdir(parents=True)
    (realm / "retained-bytes.bin").write_bytes(b"fixture-runtime-state")
    files = {paths.discovery_path: json.dumps({"pid": 12345}),
             paths.instance_lock_path: json.dumps({"pid": 12345}),
             paths.catalog_path: "fixture-catalog",
             paths.credentials_dir / "astrid.json": "fixture-credential",
             paths.source_profiles_dir / "astrid.json": "fixture-source-profile"}
    for path, value in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    controller = SimpleNamespace(_process=SimpleNamespace(pid=12345))
    def uncertain_stop():
        raise BootstrapError("fixture final wait uncertain")
    controller.stop = uncertain_stop
    with pytest.raises(BootstrapError, match="support state retained"):
        _rollback_failed_bootstrap(paths, controller, realm_root=realm, new_realm=True,
                                   credential_before=None, catalog_before=None, source_before=None,
                                   candidate_pid=12345)
    assert controller._process.pid == 12345
    assert {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before

def test_pack_public_down_uncertainty_preserves_discovery_lock(tmp_path):
    import pytest
    from types import SimpleNamespace

    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    realm = paths.realms_dir / "fixture-realm"
    realm.mkdir(parents=True)
    RealmStore.initialize(realm, realm_id="fixture-realm", display_name="Fixture").close()
    identity = {"pid": 12345, "process_birth_id": "fixture-birth", "runtime_instance_id": "fixture-instance",
                "realm_root": str(realm), "realm_id": "fixture-realm"}
    paths.catalog_path.write_text(json.dumps({"version": 1, "selected_realm_id": "fixture-realm",
        "realms": [{"realm_id": "fixture-realm", "display_name": "Fixture", "data_root": str(realm)}], "source_profiles": {}}))
    paths.discovery_path.write_text(json.dumps({**identity, "active_realm": "fixture-realm", "endpoint": "http://127.0.0.1:61217"}))
    paths.instance_lock_path.write_text(json.dumps(identity))
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    boundary = SimpleNamespace(process_birth_identity=lambda _pid: "fixture-birth", is_pid_alive=lambda _pid: True,
                               validate_owner=lambda **_kw: True,
                               endpoint_metadata=lambda **_kw: {"runtime_instance_id": "fixture-instance", "realm_id": "fixture-realm"})
    def uncertain_stop(**_kw):
        raise BootstrapError("fixture final wait uncertain")
    boundary.stop_owner = uncertain_stop
    with pytest.raises(BootstrapError, match="uncertain"):
        down(paths, boundary)
    # The existing interruption fence performs its own SQLite transaction.
    # It is not rollback cleanup; preserve every support authority file and
    # the selected realm, without asserting SQLite physical byte stability.
    after = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    realm_prefix = str(realm.relative_to(tmp_path)) + "/"
    assert all(after.get(path) == value for path, value in before.items() if not path.startswith(realm_prefix))
    assert realm.is_dir() and (realm / "realm.sqlite3").is_file()

def test_pack_bootstrap_probe_does_not_replace_boundary_uncertainty(monkeypatch):
    import pytest
    from types import SimpleNamespace
    from astrid_runtime.bootstrap import _pid_alive
    def unknown(_pid):
        raise BootstrapError("fixture uncertainty")
    def forbidden_fallback(*_args):
        raise AssertionError("boundary uncertainty must not trigger numeric fallback")
    monkeypatch.setattr(os, "kill", forbidden_fallback)
    with pytest.raises(BootstrapError, match="uncertainty"):
        _pid_alive(SimpleNamespace(is_pid_alive=unknown), 12345)

def test_pack_bootstrap_boundaryless_probe_only_esrch_is_absence(monkeypatch):
    import errno
    import pytest
    from astrid_runtime.bootstrap import _pid_alive
    from runtime_protocol import platform
    for error, result in [(PermissionError(errno.EPERM, "denied"), True),
                          (ProcessLookupError(errno.ESRCH, "absent"), False)]:
        def fail(*_args, error=error):
            raise error
        monkeypatch.setattr(platform, "process_identity", fail)
        assert _pid_alive(None, 12345) is result
    def unknown(*_args):
        raise OSError(errno.EIO, "unknown")
    monkeypatch.setattr(platform, "process_identity", unknown)
    with pytest.raises(BootstrapError, match="uncertain"):
        _pid_alive(None, 12345)


def test_bootstrap_uncertain_incumbent_probe_preserves_authority():
    import pytest
    case = BootstrapTests()
    case.setUp()
    try:
        case._configure()
        bootstrap(case.paths, case.boundary, case.config)
        authority = [case.paths.discovery_path, case.paths.instance_lock_path,
                     case.paths.catalog_path, case.paths.credentials_dir / "astrid.json",
                     case.paths.source_profiles_dir / "astrid.json"]
        before = {path: path.read_bytes() for path in authority}
        starts = len(case.boundary.starts)
        def unknown(_pid):
            raise BootstrapError("Runtime liveness observation remains uncertain.")
        case.boundary.is_pid_alive = unknown
        with pytest.raises(BootstrapError, match="uncertain"):
            bootstrap(case.paths, case.boundary, case.config)
        assert before == {path: path.read_bytes() for path in authority}
        assert len(case.boundary.starts) == starts
    finally:
        case.tearDown()


class StaleOwnerTests(unittest.TestCase):
    setUp = BootstrapTests.setUp
    tearDown = BootstrapTests.tearDown
    _configure = BootstrapTests._configure
    """Exercise reclamation using an occupied PID, without signalling it."""

    def _occupied_pid(self, *, observation="different"):
        from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        for path in (self.paths.discovery_path, self.paths.instance_lock_path):
            record = json.loads(path.read_text())
            record["pid"] = os.getpid()
            path.write_text(json.dumps(record))
        expected = json.loads(self.paths.discovery_path.read_text())["process_birth_id"]
        # The reused PID is a real live process. Birth observations for newly
        # launched fake owners still use their synthetic test marker.
        self.boundary.is_pid_alive = lambda pid: pid == os.getpid() or pid in self.boundary.alive
        self.boundary.process_birth_identity = lambda pid: (
            (None if observation == "unknown" else expected if observation == "same"
             else LocalRuntimeBoundary.process_birth_identity(pid)) if pid == os.getpid() else None)
        self.boundary.valid_owner = False
        return first

    def test_up_reclaims_reused_pid_without_signalling(self):
        first = self._occupied_pid()
        second = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(first.realm_id, second.realm_id)
        self.assertEqual(len(self.boundary.starts), 2)
        self.assertEqual(self.boundary.restart_calls, 0)
        self.assertNotEqual(json.loads(self.paths.instance_lock_path.read_text())["pid"], os.getpid())

    def test_down_reclaims_reused_pid_without_signalling(self):
        self._occupied_pid()
        result = down(self.paths, self.boundary)
        self.assertEqual(result["status"], "stopped")
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_up_reclaims_stale_lock_without_discovery(self):
        self._occupied_pid()
        self.paths.discovery_path.unlink()
        bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(len(self.boundary.starts), 2)

    def test_unknown_or_matching_owner_is_preserved(self):
        for observation in ("unknown", "same"):
            with self.subTest(observation=observation):
                if self.paths.catalog_path.exists():
                    self.tearDown()
                    self.setUp()
                self._occupied_pid(observation=observation)
                before = {p: p.read_bytes() for p in (self.paths.discovery_path, self.paths.instance_lock_path)}
                with self.assertRaises(DuplicateOwnerError):
                    bootstrap(self.paths, self.boundary, self.config)
                with self.assertRaises(BootstrapError):
                    down(self.paths, self.boundary)
                self.assertEqual({p: p.read_bytes() for p in before}, before)
                self.assertEqual(self.boundary.restart_calls, 0)

    def test_live_lock_protects_owner_despite_stale_discovery(self):
        self._occupied_pid()
        marker = json.loads(self.paths.instance_lock_path.read_text())
        marker["process_birth_id"] = self.boundary.process_birth_identity(os.getpid())
        self.paths.instance_lock_path.write_text(json.dumps(marker))
        with self.assertRaises(BootstrapError):
            down(self.paths, self.boundary)
        self.assertTrue(self.paths.discovery_path.exists())
        self.assertTrue(self.paths.instance_lock_path.exists())

    def test_up_preserves_genuine_live_owner_lock(self):
        self._occupied_pid()
        self.paths.discovery_path.unlink()
        marker = json.loads(self.paths.instance_lock_path.read_text())
        marker["process_birth_id"] = self.boundary.process_birth_identity(os.getpid())
        self.paths.instance_lock_path.write_text(json.dumps(marker))
        before = self.paths.instance_lock_path.read_bytes()
        with self.assertRaises(DuplicateOwnerError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), before)
        self.assertEqual(len(self.boundary.starts), 1)

    def test_reclamation_preserves_replacement_records(self):
        self._occupied_pid()
        observe = self.boundary.process_birth_identity
        replacement = json.loads(self.paths.instance_lock_path.read_text())
        replacement["runtime_instance_id"] = "replacement-instance"

        def replace_during_observation(pid):
            self.paths.instance_lock_path.write_text(json.dumps(replacement))
            return observe(pid)

        self.boundary.process_birth_identity = replace_during_observation
        with self.assertRaisesRegex(BootstrapError, "changed during stale-owner cleanup"):
            down(self.paths, self.boundary)
        self.assertTrue(self.paths.discovery_path.exists())
        self.assertEqual(json.loads(self.paths.instance_lock_path.read_text()), replacement)
