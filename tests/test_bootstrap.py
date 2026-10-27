from __future__ import annotations

import json
import gc
import os
from pathlib import Path
import stat
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from importlib import import_module
from contextlib import closing, contextmanager
from unittest.mock import patch

bootstrap_module = import_module("astrid_runtime.bootstrap")
from astrid_runtime.bootstrap import (
    BootstrapConfig,
    BootstrapError,
    CompatibilityError,
    DuplicateOwnerError,
    LegacyRootCollisionError,
    RestoreSelection,
    SourceProfile,
    _rollback_failed_bootstrap,
    bootstrap,
    connect,
    down,
    doctor,
    preflight_stop,
    restart,
)
from astrid_runtime.paths import RuntimePaths
from runtime_protocol.lifecycle import inspect_interruption_state
from runtime_protocol.store import RealmStore


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
    capability_digest="caps-v1",
)
NATIVE_IDENTITY = {"release": 0, "managed_by": None}


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
        self.live_identity = dict(NATIVE_IDENTITY)
        self.live_instance_id = None

    def start(self, **kwargs):
        self.calls.append("start")
        self.starts.append(kwargs)
        realm_root = kwargs["realm_root"]
        realm_root.mkdir(parents=True, exist_ok=True)
        (realm_root / "workspace.sqlite3").touch()
        pid = self.next_pid
        self.next_pid += 1
        self.alive.add(pid)
        self.live_instance_id = f"instance-{pid}"
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

    def owner_startup_identity(self, *, endpoint, instance_id):
        return {
            "runtime_instance_id": self.live_instance_id or instance_id,
            "identity": (
                dict(self.live_identity)
                if isinstance(self.live_identity, dict)
                else self.live_identity
            ),
        }

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
        self.identity_env = patch.dict(os.environ, {
            "ASTRID_INSTALL_RELEASE": "0",
            "ASTRID_INSTALL_MANAGED_BY": "",
        })
        self.identity_env.start()
        self.addCleanup(self.identity_env.stop)
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

    def _add_running_task(self, realm_root, task_id="task-busy"):
        with closing(sqlite3.connect(realm_root / "realm.sqlite3")) as connection, connection:
            connection.execute(
                "INSERT INTO tasks (id, run_id, capability, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, "run-busy", "test-capability", "running", "2026-10-27T00:00:00Z", "2026-10-27T00:00:00Z"),
            )

    def _assert_identity_refusal_preserves_state(
        self, *, case_name, path, source_profile, expected_identity, observed_identity,
        bad_instance_id=None,
    ):
        case_root = Path(self.temp.name) / case_name
        self.paths = RuntimePaths.sandbox(case_root)
        self.boundary = FakeBoundary()
        self.boundary.live_identity = dict(expected_identity)
        self.config = BootstrapConfig(source_profile=source_profile)
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        files = (
            self.paths.catalog_path,
            self.paths.source_profiles_dir / "astrid.json",
            self.paths.discovery_path,
            self.paths.instance_lock_path,
            self.paths.credentials_dir / "astrid.json",
        )
        before = {file: file.read_bytes() for file in files}
        side_effect_counts = (
            len(self.boundary.starts), len(self.boundary.connects),
            len(self.boundary.provisions), len(self.boundary.handshakes),
            self.boundary.restart_calls,
        )
        self.boundary.live_identity = observed_identity
        if bad_instance_id is not None:
            self.boundary.live_instance_id = bad_instance_id
        with self.assertRaises(BootstrapError) as caught:
            if path == "connect":
                connect(self.paths, self.boundary, self.config)
            else:
                bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(
            str(caught.exception),
            "An older Astrid is still running. Restart it after its running tasks finish.",
        )
        self.assertEqual(before, {file: file.read_bytes() for file in files})
        self.assertEqual(
            side_effect_counts,
            (len(self.boundary.starts), len(self.boundary.connects),
             len(self.boundary.provisions), len(self.boundary.handshakes),
             self.boundary.restart_calls),
        )

    @staticmethod
    def _git_checkout(root: Path) -> None:
        root.mkdir(parents=True)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        (root / "tracked.txt").write_text("baseline", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)

    def test_identity_mismatch_and_invalid_live_identity_refuse_up_and_connect_without_writes(self):
        expected = dict(NATIVE_IDENTITY)
        cases = (
            ("release", {"release": 1, "managed_by": None}),
            ("managed_by", {"release": 0, "managed_by": "pinokio"}),
            ("missing", None),
            ("malformed", {"release": -1, "managed_by": None}),
            ("extra-field", {"release": 0, "managed_by": None, "dirty": False}),
        )
        for path in ("up", "connect"):
            for name, observed in cases:
                with self.subTest(path=path, field=name):
                    self._assert_identity_refusal_preserves_state(
                        case_name=f"{path}-{name}", path=path, source_profile=PROFILE,
                        expected_identity=expected, observed_identity=observed,
                    )
            with self.subTest(path=path, field="owner-binding"):
                self._assert_identity_refusal_preserves_state(
                    case_name=f"{path}-owner-binding", path=path, source_profile=PROFILE,
                    expected_identity=expected, observed_identity=expected,
                    bad_instance_id="different-owner",
                )

    def test_source_identity_fields_are_compared_for_up_and_connect(self):
        with patch.dict(os.environ):
            os.environ.pop("ASTRID_INSTALL_RELEASE", None)
            os.environ.pop("ASTRID_INSTALL_MANAGED_BY", None)
            runtime = Path(self.temp.name) / "source-runtime"
            agent = Path(self.temp.name) / "source-agent"
            self._git_checkout(runtime)
            self._git_checkout(agent)
            (agent / "untracked.txt").write_text("dirty", encoding="utf-8")
            source_profile = SourceProfile(
                profile="astrid", runtime_checkout=str(runtime), source_checkout=str(agent),
                capability_digest="caps-v1",
            )
            from astrid_runtime.identity import requested_startup_identity

            expected = requested_startup_identity(source_profile)
            changed_runtime_head = {**expected, "runtime_head": "f" * 40}
            changed_agent_head = {**expected, "agent_head": "e" * 40}
            changed_dirty = {**expected, "dirty": False}
            changed_hash = {**expected, "dirty_hash": "a" * 64}
            cases = (
                ("runtime_head", changed_runtime_head),
                ("agent_head", changed_agent_head),
                ("dirty", changed_dirty),
                ("dirty_hash", changed_hash),
            )
            for path in ("up", "connect"):
                for name, observed in cases:
                    with self.subTest(path=path, field=name):
                        self._assert_identity_refusal_preserves_state(
                            case_name=f"source-{path}-{name}", path=path,
                            source_profile=source_profile, expected_identity=expected,
                            observed_identity=observed,
                        )

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

    def _restore_selection_fixture(self, *, realm_id="restore-realm", missing_catalog=True):
        realm_root = self._configure(realm_id=realm_id)
        retained_catalog = self.paths.catalog_path.read_bytes()
        self.paths.discovery_path.unlink(missing_ok=True)
        self.paths.instance_lock_path.unlink(missing_ok=True)
        install_root = Path(self.temp.name) / "install"
        backup_root = install_root / "backups" / "backup-1"
        backup_catalog = backup_root / "support" / "runtime" / "catalog.json"
        backup_catalog.parent.mkdir(parents=True, exist_ok=True)
        journal_path = install_root / "update-transaction.json"
        selection_path = Path(self.temp.name) / "astrid-install.json"
        for stale in (journal_path, selection_path, backup_catalog):
            if os.path.lexists(str(stale)):
                stale.unlink()
        backup_catalog.write_bytes(retained_catalog)
        journal_path.write_text(json.dumps({
            "format": "astrid-install-update/v1", "step": "recovering",
            "operation_id": "a" * 32, "transaction_kind": "migration",
            "data_root": str(self.paths.app_support),
            "realm": {"realm_id": realm_id, "realm_root": str(realm_root)},
            "backup": {"kind": "runtime", "root": str(backup_root)},
        }))
        selection_path.write_text(json.dumps({
            "owner": "haus.astrid.runtime", "program_root": str(install_root),
            "data_root": str(self.paths.app_support), "realm_id": realm_id,
            "realm_root": str(realm_root),
        }))
        if missing_catalog:
            self.paths.catalog_path.unlink()
        return {
            "selection": RestoreSelection(journal_path=journal_path, selection_path=selection_path),
            "journal_path": journal_path, "selection_path": selection_path,
            "backup_catalog": backup_catalog, "backup_root": backup_root,
            "realm_root": realm_root, "retained_catalog": retained_catalog,
        }

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
        # The recorded publication is provably dead, so restart cleans it and
        # starts the selected realm without sending a redundant stop request.
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_restart_stops_once_under_fence_before_relaunch(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        order = []
        original_stop = self.boundary.stop_owner
        original_start = self.boundary.start

        def stop_owner(**kwargs):
            order.append("stop")
            # The shared stop callback must retain both launcher serialization
            # and the SQLite interruption fence until it has returned.
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
            self.assertEqual(probe.returncode, 7)
            connection = sqlite3.connect(root / "realm.sqlite3", timeout=0.02)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.close()
            return original_stop(**kwargs)

        def start(**kwargs):
            order.append("start")
            return original_start(**kwargs)

        self.boundary.stop_owner = stop_owner
        self.boundary.start = start
        result = restart(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "restarted")
        self.assertEqual(order, ["stop", "start"])
        self.assertEqual(self.boundary.restart_calls, 1)

    def test_down_manager_callback_runs_once_after_stop_under_shared_fence(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        order = []
        original_stop = self.boundary.stop_owner

        def stop_owner(**kwargs):
            order.append("runtime")
            return original_stop(**kwargs)

        def stop_manager():
            order.append("manager")
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
            self.assertEqual(probe.returncode, 7)
            connection = sqlite3.connect(root / "realm.sqlite3", timeout=0.02)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.close()

        self.boundary.stop_owner = stop_owner
        result = down(self.paths, self.boundary, stop_manager=stop_manager)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(order, ["runtime", "manager"])

    def test_down_restart_and_installer_stop_use_shared_primitive(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        with patch(
            "astrid_runtime.bootstrap._fenced_stop_and_manager",
            wraps=bootstrap_module._fenced_stop_and_manager,
        ) as shared_stop:
            down(self.paths, self.boundary)
            self.assertEqual(shared_stop.call_count, 1)

            bootstrap(self.paths, self.boundary, self.config)
            restart(self.paths, self.boundary, self.config)
            self.assertEqual(shared_stop.call_count, 2)

            bootstrap(self.paths, self.boundary, self.config)
            down(self.paths, self.boundary, stop_manager=lambda: None)
            self.assertEqual(shared_stop.call_count, 3)
        self.assertEqual(self.boundary.restart_calls, 3)

    def test_restore_selection_repairs_missing_catalog_after_fenced_manager(self):
        fixture = self._restore_selection_fixture(realm_id="restore-realm")
        retained_catalog = fixture["retained_catalog"]
        selection = fixture["selection"]
        self.assertTrue(preflight_stop(self.paths, restore_selection=selection)["safe"])
        self.assertFalse(self.paths.catalog_path.exists())
        order = []

        def manager_callback(catalog_expected):
            order.append(("manager", self.paths.catalog_path.exists()))
            lock_probe = subprocess.run(
                [sys.executable, "-c",
                 "import sys; from runtime_protocol.platform import file_lock; "
                 "p=sys.argv[1]; "
                 "\ntry: file_lock(p, blocking=False).__enter__()"
                 "\nexcept BlockingIOError: raise SystemExit(7)"
                 "\nraise SystemExit(0)", str(self.paths.bootstrap_lock_path)],
                check=False,
            )
            self.assertEqual(lock_probe.returncode, 7)
            connection = sqlite3.connect(fixture["realm_root"] / "realm.sqlite3", timeout=0.02)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.close()

        result = down(
            self.paths, self.boundary, restore_selection=selection,
            stop_manager=lambda: manager_callback(False),
        )

        self.assertEqual(order, [("manager", False)])
        self.assertTrue(result["catalog_restored"])
        self.assertEqual(json.loads(self.paths.catalog_path.read_text()), json.loads(retained_catalog))

        # A valid live catalog may carry metadata written during the pending
        # update. C1 confirms its selected realm and leaves that metadata intact.
        live_catalog = json.loads(self.paths.catalog_path.read_text())
        live_catalog["realms"][0]["display_name"] = "Current selection metadata"
        self.paths.catalog_path.write_text(json.dumps(live_catalog))
        second = down(self.paths, self.boundary, restore_selection=selection,
                      stop_manager=lambda: manager_callback(True))
        self.assertFalse(second["catalog_restored"])
        self.assertEqual(json.loads(self.paths.catalog_path.read_text())["realms"][0]["display_name"],
                         "Current selection metadata")
        self.assertEqual(order, [("manager", False), ("manager", True)])

    def test_normal_down_still_refuses_missing_catalog(self):
        self._configure()
        self.paths.discovery_path.unlink(missing_ok=True)
        self.paths.instance_lock_path.unlink(missing_ok=True)
        self.paths.catalog_path.unlink()
        with self.assertRaises(BootstrapError):
            down(self.paths, self.boundary)

    def test_restore_selection_malformed_and_conflicting_metadata_refuses_without_writes(self):
        for index, mutation in enumerate((
            "journal", "selection", "wrong_data_root", "wrong_realm_root",
            "retained_catalog", "live_catalog", "bad_live_catalog", "live_catalog_link",
            "bad_backup_catalog", "missing_realm",
            "foreign_realm", "selection_link", "journal_link", "backup_catalog_link",
            "realm_root_link",
        )):
            with self.subTest(mutation=mutation):
                fixture = self._restore_selection_fixture(
                    realm_id=f"restore-realm-{index}",
                    missing_catalog=mutation not in {"live_catalog", "bad_live_catalog", "live_catalog_link"},
                )
                selection = fixture["selection"]
                if mutation == "journal":
                    fixture["journal_path"].write_text("{")
                elif mutation == "selection":
                    fixture["selection_path"].write_text("not-json")
                elif mutation == "wrong_data_root":
                    value = json.loads(fixture["selection_path"].read_text())
                    value["data_root"] = str(Path(self.temp.name) / "other-data")
                    fixture["selection_path"].write_text(json.dumps(value))
                elif mutation == "wrong_realm_root":
                    value = json.loads(fixture["selection_path"].read_text())
                    value["realm_root"] = str(fixture["realm_root"].parent)
                    fixture["selection_path"].write_text(json.dumps(value))
                elif mutation == "retained_catalog":
                    value = json.loads(fixture["backup_catalog"].read_text())
                    value["selected_realm_id"] = "foreign-realm"
                    fixture["backup_catalog"].write_text(json.dumps(value))
                elif mutation == "live_catalog":
                    value = json.loads(self.paths.catalog_path.read_text())
                    value["selected_realm_id"] = "foreign-realm"
                    self.paths.catalog_path.write_text(json.dumps(value))
                elif mutation == "bad_backup_catalog":
                    fixture["backup_catalog"].write_text("not-json")
                elif mutation == "bad_live_catalog":
                    self.paths.catalog_path.write_text("not-json")
                elif mutation == "live_catalog_link":
                    self.paths.catalog_path.unlink()
                    self.paths.catalog_path.symlink_to(fixture["backup_catalog"])
                elif mutation == "missing_realm":
                    import shutil
                    shutil.rmtree(fixture["realm_root"])
                elif mutation == "foreign_realm":
                    value = json.loads(fixture["selection_path"].read_text())
                    value["realm_id"] = "foreign-realm"
                    fixture["selection_path"].write_text(json.dumps(value))
                    value = json.loads(fixture["journal_path"].read_text())
                    value["realm"]["realm_id"] = "foreign-realm"
                    fixture["journal_path"].write_text(json.dumps(value))
                    value = json.loads(fixture["backup_catalog"].read_text())
                    value["selected_realm_id"] = "foreign-realm"
                    value["realms"][0]["realm_id"] = "foreign-realm"
                    fixture["backup_catalog"].write_text(json.dumps(value))
                elif mutation == "selection_link":
                    fixture["selection_path"].unlink()
                    fixture["selection_path"].symlink_to(fixture["journal_path"])
                elif mutation == "journal_link":
                    fixture["journal_path"].unlink()
                    fixture["journal_path"].symlink_to(fixture["backup_catalog"])
                elif mutation == "backup_catalog_link":
                    fixture["backup_catalog"].unlink()
                    fixture["backup_catalog"].symlink_to(fixture["journal_path"])
                elif mutation == "realm_root_link":
                    link = Path(self.temp.name) / "realm-root-link"
                    link.symlink_to(fixture["realm_root"], target_is_directory=True)
                    value = json.loads(fixture["selection_path"].read_text())
                    value["realm_root"] = str(link)
                    fixture["selection_path"].write_text(json.dumps(value))

                watched = (fixture["journal_path"], fixture["selection_path"],
                           fixture["backup_catalog"], self.paths.catalog_path)
                before = {path: path.read_bytes() for path in watched
                          if path.exists() and not path.is_symlink()}
                manager_calls = []
                if mutation == "missing_realm":
                    result = down(self.paths, self.boundary, restore_selection=selection,
                                  stop_manager=lambda: manager_calls.append(True))
                    self.assertEqual(manager_calls, [True])
                    self.assertTrue(result["catalog_restored"])
                    self.assertTrue(self.paths.catalog_path.is_file())
                    self.assertEqual(before[fixture["journal_path"]],
                                     fixture["journal_path"].read_bytes())
                    self.assertEqual(before[fixture["selection_path"]],
                                     fixture["selection_path"].read_bytes())
                    continue
                with self.assertRaises(BootstrapError):
                    down(self.paths, self.boundary, restore_selection=selection,
                         stop_manager=lambda: manager_calls.append(True))
                self.assertEqual(manager_calls, [])
                self.assertEqual(before, {path: path.read_bytes() for path in watched
                                          if path.exists() and not path.is_symlink()})
                if self.paths.catalog_path.is_symlink():
                    self.paths.catalog_path.unlink()

    def test_restore_selection_refuses_any_publication_and_fence_race(self):
        for index, publication in enumerate(("discovery", "instance_lock")):
            with self.subTest(publication=publication):
                fixture = self._restore_selection_fixture(realm_id=f"restore-pub-{index}")
                path = getattr(self.paths, "discovery_path" if publication == "discovery"
                               else "instance_lock_path")
                path.write_text(json.dumps({"pid": 99999999, "runtime_instance_id": "unknown"}))
                before = (fixture["journal_path"].read_bytes(), fixture["backup_catalog"].read_bytes())
                manager_calls = []
                with self.assertRaisesRegex(BootstrapError, "publications are present"):
                    down(self.paths, self.boundary, restore_selection=fixture["selection"],
                         stop_manager=lambda: manager_calls.append(True))
                self.assertEqual(manager_calls, [])
                self.assertFalse(self.paths.catalog_path.exists())
                self.assertEqual(before, (fixture["journal_path"].read_bytes(),
                                          fixture["backup_catalog"].read_bytes()))

        fixture = self._restore_selection_fixture(realm_id="restore-fence-race")
        manager_calls = []

        @contextmanager
        def refusing_fence(_realm_root):
            raise BootstrapError("busy at final fence")
            yield  # pragma: no cover

        with patch("astrid_runtime.bootstrap.interruption_fence", refusing_fence):
            with self.assertRaisesRegex(BootstrapError, "busy at final fence"):
                down(self.paths, self.boundary, restore_selection=fixture["selection"],
                     stop_manager=lambda: manager_calls.append(True))
        self.assertEqual(manager_calls, [])
        self.assertFalse(self.paths.catalog_path.exists())

        fixture = self._restore_selection_fixture(realm_id="restore-publication-race")
        real_fence = bootstrap_module.interruption_fence

        @contextmanager
        def publishing_fence(realm_root):
            with real_fence(realm_root) as report:
                self.paths.discovery_path.write_text(json.dumps({"pid": 123456789}))
                yield report

        manager_calls = []
        with patch("astrid_runtime.bootstrap.interruption_fence", publishing_fence):
            with self.assertRaisesRegex(BootstrapError, "discovery changed before stop"):
                down(self.paths, self.boundary, restore_selection=fixture["selection"],
                     stop_manager=lambda: manager_calls.append(True))
        self.assertEqual(manager_calls, [])
        self.assertFalse(self.paths.catalog_path.exists())
        self.paths.discovery_path.unlink()

        fixture = self._restore_selection_fixture(realm_id="restore-pre-manager-race")
        original_shared_stop = bootstrap_module._fenced_stop_and_manager

        def publishing_before_manager(*args, **kwargs):
            validate = kwargs["validate_stop"]

            def changed_validate():
                self.paths.instance_lock_path.write_text(json.dumps({"pid": 123456789}))
                validate()

            kwargs["validate_stop"] = changed_validate
            return original_shared_stop(*args, **kwargs)

        manager_calls = []
        with patch("astrid_runtime.bootstrap._fenced_stop_and_manager", publishing_before_manager):
            with self.assertRaisesRegex(BootstrapError, "publications are present"):
                down(self.paths, self.boundary, restore_selection=fixture["selection"],
                     stop_manager=lambda: manager_calls.append(True))
        self.assertEqual(manager_calls, [])
        self.assertFalse(self.paths.catalog_path.exists())
        self.paths.instance_lock_path.unlink()

    def test_restore_selection_busy_preflight_refuses_before_manager(self):
        fixture = self._restore_selection_fixture(realm_id="restore-busy")
        before = (fixture["journal_path"].read_bytes(), fixture["backup_catalog"].read_bytes())
        manager_calls = []
        with patch("astrid_runtime.bootstrap.inspect_interruption_state",
                   return_value={"safe": False, "running_tasks": [{"task_id": "busy"}]}):
            with self.assertRaisesRegex(BootstrapError, "work is active"):
                down(self.paths, self.boundary, restore_selection=fixture["selection"],
                     stop_manager=lambda: manager_calls.append(True))
        self.assertEqual(manager_calls, [])
        self.assertFalse(self.paths.catalog_path.exists())
        self.assertEqual(before, (fixture["journal_path"].read_bytes(),
                                  fixture["backup_catalog"].read_bytes()))

    def test_restore_catalog_publication_failure_replays_from_retained_snapshot(self):
        fixture = self._restore_selection_fixture(realm_id="restore-write-replay")
        manager_calls = []
        journal_before = fixture["journal_path"].read_bytes()
        backup_before = fixture["backup_catalog"].read_bytes()
        write_attempts = 0
        real_write = bootstrap_module.atomic_write_json

        def fail_first_two_writes(*args, **kwargs):
            nonlocal write_attempts
            write_attempts += 1
            if write_attempts <= 2:
                raise OSError(f"simulated interruption {write_attempts}")
            return real_write(*args, **kwargs)

        with patch("astrid_runtime.bootstrap.atomic_write_json", side_effect=fail_first_two_writes):
            for attempt in (1, 2):
                with self.assertRaisesRegex(OSError, f"simulated interruption {attempt}"):
                    down(self.paths, self.boundary, restore_selection=fixture["selection"],
                         stop_manager=lambda: manager_calls.append(f"attempt-{attempt}"))
                self.assertFalse(self.paths.catalog_path.exists())
                self.assertEqual(fixture["journal_path"].read_bytes(), journal_before)
                self.assertEqual(fixture["backup_catalog"].read_bytes(), backup_before)

            result = down(self.paths, self.boundary, restore_selection=fixture["selection"],
                          stop_manager=lambda: manager_calls.append("attempt-3"))

        self.assertEqual(write_attempts, 3)
        self.assertTrue(result["catalog_restored"])
        self.assertEqual(manager_calls, ["attempt-1", "attempt-2", "attempt-3"])
        self.assertEqual(fixture["journal_path"].read_bytes(), journal_before)
        self.assertEqual(fixture["backup_catalog"].read_bytes(), backup_before)
        self.assertEqual(json.loads(self.paths.catalog_path.read_text()), json.loads(backup_before))

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
        discovery_before = self.paths.discovery_path.read_bytes()
        active_pid = json.loads(discovery_before)["pid"]
        with self.assertRaisesRegex(BootstrapError, "Astrid is busy") as caught:
            restart(self.paths, self.boundary, self.config)
        self.assertEqual(caught.exception.details["unreconciled_attempts"][0]["attempt_id"], "a")
        self.assertEqual(caught.exception.details["unreconciled_attempts"][0]["task_id"], "t")
        with self.assertRaisesRegex(BootstrapError, "Astrid is busy") as caught:
            down(self.paths, self.boundary)
        self.assertEqual(caught.exception.details["unreconciled_attempts"][0]["attempt_id"], "a")
        self.assertEqual(caught.exception.details["unreconciled_attempts"][0]["task_id"], "t")
        self.assertEqual(self.boundary.restart_calls, 0)
        self.assertIn(active_pid, self.boundary.alive)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        connection = sqlite3.connect(root / "realm.sqlite3")
        self.assertEqual(connection.execute("SELECT status FROM runs WHERE id='r'").fetchone(), ("running",))
        self.assertEqual(connection.execute("SELECT status FROM tasks WHERE id='t'").fetchone(), ("queued",))
        connection.close()

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

    def test_down_and_restart_refuse_missing_or_invalid_owner_lock(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        valid_marker = json.loads(self.paths.instance_lock_path.read_text())
        realm_root = Path(discovery["realm_root"])
        malformed = {
            "empty": {},
            "bad_pid": {**valid_marker, "pid": "not-a-pid"},
            "missing_birth": {key: value for key, value in valid_marker.items()
                               if key != "process_birth_id"},
            "wrong_instance": {**valid_marker, "runtime_instance_id": "other-instance"},
            "wrong_realm_root": {**valid_marker, "realm_root": str(realm_root.parent)},
            # active_realm is a discovery field; the instance lock must bind
            # its owner using its own required realm_id field.
            "active_realm_without_realm_id": {
                **{key: value for key, value in valid_marker.items() if key != "realm_id"},
                "active_realm": "configured-realm",
            },
        }
        manager_calls = []
        starts = len(self.boundary.starts)
        for case, marker in (("missing", None), *malformed.items()):
            with self.subTest(case=case):
                if marker is None:
                    self.paths.instance_lock_path.unlink()
                else:
                    self.paths.instance_lock_path.write_text(json.dumps(marker))
                watched = (
                    self.paths.catalog_path,
                    self.paths.discovery_path,
                    self.paths.instance_lock_path,
                    self.paths.credentials_dir / "astrid.json",
                    realm_root / "realm.sqlite3",
                )
                before = {path: path.read_bytes() for path in watched if path.exists()}
                for command in (
                    lambda: down(
                        self.paths, self.boundary,
                        stop_manager=lambda: manager_calls.append("down manager"),
                    ),
                    lambda: restart(self.paths, self.boundary, self.config),
                ):
                    with self.assertRaisesRegex(BootstrapError, "owner lock"):
                        command()
                self.assertEqual(manager_calls, [])
                self.assertEqual(self.boundary.restart_calls, 0)
                self.assertEqual(len(self.boundary.starts), starts)
                self.assertEqual(before, {path: path.read_bytes() for path in watched if path.exists()})
                # Restore the starting publication so each subcase begins
                # with the same valid owner identity.
                self.paths.discovery_path.write_text(json.dumps(discovery))
                self.paths.instance_lock_path.write_text(json.dumps(valid_marker))

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

    def test_installer_stop_runs_runtime_then_manager_under_same_fence(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        order = []
        original_stop = self.boundary.stop_owner

        def stop_owner(**kwargs):
            order.append("runtime")
            return original_stop(**kwargs)

        def stop_manager():
            order.append("manager")
            connection = sqlite3.connect(root / "realm.sqlite3", timeout=0.02)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.close()

        self.boundary.stop_owner = stop_owner
        result = down(self.paths, self.boundary, stop_manager=stop_manager)
        self.assertEqual(order, ["runtime", "manager"])
        self.assertEqual(result["status"], "stopped")
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_replacement_during_runtime_stop_skips_manager_and_cleanup(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        replacement = {
            "pid": 49998,
            "endpoint": "http://127.0.0.1:49998",
            "runtime_instance_id": "replacement-instance",
            "process_birth_id": "replacement-birth",
            "active_realm": "configured-realm",
            "realm_root": str(root.resolve()),
        }
        manager_calls = []
        original_stop = self.boundary.stop_owner

        def replace_owner(**kwargs):
            result = original_stop(**kwargs)
            self.paths.discovery_path.write_text(json.dumps(replacement))
            self.paths.instance_lock_path.write_text(json.dumps({
                **replacement, "realm_id": "configured-realm",
            }))
            return result

        self.boundary.stop_owner = replace_owner
        with self.assertRaisesRegex(BootstrapError, "changed before manager stop") as caught:
            down(
                self.paths,
                self.boundary,
                stop_manager=lambda: manager_calls.append("manager"),
            )
        self.assertEqual(manager_calls, [])
        self.assertIsNone(caught.exception.details)
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)
        self.assertEqual(
            json.loads(self.paths.instance_lock_path.read_text()),
            {**replacement, "realm_id": "configured-realm"},
        )

    def test_recovery_retained_stale_lock_only_rechecks_pid_at_final_fence(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        pid = int(discovery["pid"])
        self.boundary.alive.discard(pid)
        state = {"fenced": False, "observations": 0, "events": []}

        def is_pid_alive(observed_pid):
            self.assertEqual(observed_pid, pid)
            state["events"].append(("liveness", state["fenced"]))
            return False

        def birth_identity(observed_pid):
            self.assertEqual(observed_pid, pid)
            state["observations"] += 1
            state["events"].append(("birth", state["fenced"]))
            return "replacement-birth" if state["fenced"] else None

        self.boundary.is_pid_alive = is_pid_alive
        self.boundary.process_birth_identity = birth_identity
        real_fence = bootstrap_module.interruption_fence

        @contextmanager
        def reused_during_fence(realm_root):
            with real_fence(realm_root) as report:
                state["fenced"] = True
                yield report

        manager_calls = []
        with patch("astrid_runtime.bootstrap.interruption_fence", reused_during_fence):
            with self.assertRaisesRegex(BootstrapError, "identity changed at the final fence"):
                down(self.paths, self.boundary,
                     stop_manager=lambda: manager_calls.append("manager"))

        self.assertEqual(state["observations"], 2)
        self.assertEqual(state["events"], [
            ("liveness", False), ("birth", False),
            ("liveness", True), ("birth", True),
        ])
        self.assertEqual(manager_calls, [])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), discovery)
        self.assertTrue(self.paths.instance_lock_path.exists())

    def test_recovery_retained_stale_owner_lookup_uncertainty_refuses(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        marker_before = self.paths.instance_lock_path.read_bytes()
        pid = json.loads(discovery_before)["pid"]
        self.boundary.alive.discard(int(pid))

        def uncertain(observed_pid):
            self.assertEqual(observed_pid, pid)
            raise OSError("process identity observation denied")

        self.boundary.process_birth_identity = uncertain
        manager_calls = []
        with self.assertRaisesRegex(BootstrapError, "absence could not be established"):
            down(self.paths, self.boundary,
                 stop_manager=lambda: manager_calls.append("manager"))
        self.assertEqual(manager_calls, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), marker_before)

    def test_recovery_reconciles_foreground_against_admitted_live_owner(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        order = []
        result = down(
            self.paths, self.boundary,
            stop_foreground=lambda: self.fail("live published owner must use stop_owner"),
            stop_manager=lambda: order.append("manager"),
        )
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(order, ["manager"])
        self.assertEqual(self.boundary.restart_calls, 1)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_recovery_rechecks_retired_foreground_absence_before_stopping_candidate(self):
        root = self._configure()
        order = []

        def stop_foreground():
            order.append("foreground")
            self.assertFalse(self.paths.discovery_path.exists())
            self.assertFalse(self.paths.instance_lock_path.exists())
            with sqlite3.connect(root / "realm.sqlite3", timeout=0.02) as connection:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")

        def stop_manager():
            order.append("manager")
            self.assertFalse(self.paths.discovery_path.exists())

        result = down(self.paths, self.boundary, stop_foreground=stop_foreground,
                      stop_manager=stop_manager)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(order, ["foreground", "manager"])
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_stop_recovery_handles_catalog_restore_gap_with_live_realm(self):
        fixture = self._restore_selection_fixture(realm_id="restore-live-gap")
        before = fixture["backup_catalog"].read_bytes()
        calls = []
        result = down(self.paths, self.boundary,
                      restore_selection=fixture["selection"],
                      stop_manager=lambda: calls.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["manager"])
        self.assertTrue(result["catalog_restored"])
        self.assertEqual(json.loads(self.paths.catalog_path.read_text()), json.loads(before))
        self.assertEqual(fixture["backup_catalog"].read_bytes(), before)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_stop_recovery_refuses_replacement_publication(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        replacement = {
            "pid": 49998, "endpoint": "http://127.0.0.1:49998",
            "runtime_instance_id": "replacement-instance",
            "process_birth_id": "replacement-birth",
            "active_realm": "configured-realm", "realm_root": str(root.resolve()),
        }
        original_stop = self.boundary.stop_owner

        def replace_owner(**kwargs):
            result = original_stop(**kwargs)
            self.paths.discovery_path.write_text(json.dumps(replacement))
            self.paths.instance_lock_path.write_text(json.dumps({**replacement, "realm_id": "configured-realm"}))
            return result

        self.boundary.stop_owner = replace_owner
        manager_calls = []
        with self.assertRaisesRegex(BootstrapError, "changed before manager stop"):
            down(self.paths, self.boundary,
                 stop_manager=lambda: manager_calls.append("manager"))
        self.assertEqual(manager_calls, [])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)
        self.assertEqual(json.loads(self.paths.instance_lock_path.read_text()),
                         {**replacement, "realm_id": "configured-realm"})

    def test_installer_stop_accepts_json_round_tripped_exact_authority(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(json.dumps(json.loads(self.paths.discovery_path.read_text())))
        marker = json.loads(json.dumps(json.loads(self.paths.instance_lock_path.read_text())))
        self.paths.discovery_path.write_text(json.dumps(discovery))
        self.paths.instance_lock_path.write_text(json.dumps(marker))
        calls = []
        result = down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["manager"])
        self.assertEqual(self.boundary.restart_calls, 1)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_stop_accepts_only_operation_and_identity_bound_replacement(self):
        self._configure()
        with patch.dict(os.environ, {"ASTRID_INSTALLER_OPERATION_ID": "c" * 32}):
            bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        marker = json.loads(self.paths.instance_lock_path.read_text())
        self.assertNotIn("installer_operation_id", discovery)
        self.assertNotIn("installer_operation_id", marker)
        calls = []
        result = down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["manager"])
        self.assertEqual(self.boundary.restart_calls, 1)

    def test_installer_stop_rejects_operation_binding_without_authorized_identity(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery_before = json.loads(self.paths.discovery_path.read_text())
        marker_before = json.loads(self.paths.instance_lock_path.read_text())
        discovery_before["installer_operation_id"] = "d" * 32
        marker_before["installer_operation_id"] = "d" * 32
        self.paths.discovery_path.write_text(json.dumps(discovery_before))
        self.paths.instance_lock_path.write_text(json.dumps(marker_before))
        pid = int(discovery_before["pid"])
        self.boundary.alive.discard(pid)
        self.boundary.process_birth_identity = lambda observed: "replacement-birth" if observed == pid else None
        calls = []
        with self.assertRaisesRegex(BootstrapError, "process identity changed"):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), discovery_before)
        self.assertEqual(json.loads(self.paths.instance_lock_path.read_text()), marker_before)

    def test_installer_stop_recovery_allows_absent_realm_only_with_absent_owner(self):
        import shutil

        fixture = self._restore_selection_fixture(realm_id="restore-absent-realm")
        shutil.rmtree(fixture["realm_root"])
        calls = []
        result = down(self.paths, self.boundary, restore_selection=fixture["selection"],
                      stop_manager=lambda: calls.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["manager"])
        self.assertTrue(result["idle"]["realm_absent"])
        self.assertTrue(result["catalog_restored"])

    def test_installer_stop_recovery_retires_matching_foreground_after_process_exit(self):
        self._configure()
        order = []

        def stop_foreground():
            order.append("foreground")

        def stop_manager():
            order.append("manager")

        result = down(self.paths, self.boundary, stop_foreground=stop_foreground,
                      stop_manager=stop_manager)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(order, ["foreground", "manager"])
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_manager_failure_reports_known_runtime_stop(self):
        self._configure()
        def manager_failure():
            raise BootstrapError("manager stop failed", details={"safe": False, "blocker": "service"})
        with self.assertRaises(BootstrapError) as caught:
            down(self.paths, self.boundary, stop_manager=manager_failure)
        self.assertEqual(caught.exception.details, {"cause_details": {"safe": False, "blocker": "service"}})
        self.assertIn("manager stop failed", str(caught.exception))

    def test_stop_owner_error_details_are_downstream_context(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        manager_calls = []

        def uncertain_stop(**_kwargs):
            raise BootstrapError("stop handoff failed", details={"safe": False, "blocker": "owner"})

        self.boundary.stop_owner = uncertain_stop
        with self.assertRaises(BootstrapError) as caught:
            down(self.paths, self.boundary, stop_manager=lambda: manager_calls.append(True))
        self.assertEqual(caught.exception.details, {
            "cause_details": {"safe": False, "blocker": "owner"},
        })
        self.assertEqual(manager_calls, [])

    def test_same_controller_stop_retry_revalidates_completed_owner_absence(self):
        root = self._configure()
        calls = []

        def manager_failure():
            calls.append("first")
            raise RuntimeError("manager unavailable")

        with self.assertRaisesRegex(BootstrapError, "manager unavailable") as caught:
            down(self.paths, self.boundary, stop_manager=manager_failure)
        self.assertIsNone(caught.exception.details)

        def retry_manager():
            with sqlite3.connect(root / "realm.sqlite3", timeout=0.02) as connection:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            calls.append("retry")

        result = down(self.paths, self.boundary, stop_manager=retry_manager)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["first", "retry"])
        self.assertEqual(self.boundary.restart_calls, 0)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_same_controller_receipt_never_authorizes_reused_or_unknown_pid(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        marker_before = self.paths.instance_lock_path.read_bytes()
        pid = json.loads(discovery_before)["pid"]
        self.boundary.alive.discard(int(pid))
        self.boundary.process_birth_identity = lambda observed: "reused-birth" if observed == pid else None
        calls = []
        with self.assertRaisesRegex(BootstrapError, "process identity changed"):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append(True))
        self.assertEqual(calls, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), marker_before)

    def test_completed_owner_receipt_retires_legacy_foreground_on_retry(self):
        self._configure()
        order = []
        result = down(self.paths, self.boundary,
                      stop_foreground=lambda: order.append("foreground"),
                      stop_manager=lambda: order.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(order, ["foreground", "manager"])

    def test_completed_owner_receipt_does_not_mistake_candidate_for_old_foreground(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        calls = []
        result = down(self.paths, self.boundary,
                      stop_foreground=lambda: self.fail("live selected owner is already the stop target"),
                      stop_manager=lambda: calls.append("manager"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["manager"])
        self.assertEqual(self.boundary.restart_calls, 1)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_manager_failure_after_owner_removes_ads_keeps_retry_receipt(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        calls = []

        def owner_exits(**kwargs):
            self.boundary.restart_calls += 1
            self.boundary.alive.discard(kwargs["pid"])
            self.paths.discovery_path.unlink()
            self.paths.instance_lock_path.unlink()
            return {"status": "stopped"}

        self.boundary.stop_owner = owner_exits
        with self.assertRaisesRegex(BootstrapError, "manager unavailable") as caught:
            down(self.paths, self.boundary,
                 stop_manager=lambda: (_ for _ in ()).throw(RuntimeError("manager unavailable")))
        self.assertIsNone(caught.exception.details)
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

        result = down(self.paths, self.boundary, stop_manager=lambda: calls.append("retry"))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(calls, ["retry"])
        self.assertEqual(self.boundary.restart_calls, 1)

    def test_unsafe_discovery_path_revokes_completed_stop_receipt(self):
        self._configure()
        calls = []
        target = Path(self.temp.name) / "foreign-discovery.json"
        target.write_text(json.dumps({"pid": 12345}))
        self.paths.discovery_path.symlink_to(target)
        with self.assertRaises(BootstrapError):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])
        self.assertTrue(self.paths.discovery_path.is_symlink())

    def test_post_mutex_receipt_validation_failures_revoke_authority(self):
        root = self._configure()
        calls = []
        replacement = {"pid": 49998, "runtime_instance_id": "replacement"}

        def publish_replacement():
            calls.append("manager")
            self.paths.discovery_path.write_text(json.dumps(replacement))

        with self.assertRaisesRegex(BootstrapError, "discovery changed during stop"):
            down(self.paths, self.boundary, stop_manager=publish_replacement)
        self.assertEqual(calls, ["manager"])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)

    def test_invalid_foreground_identity_cannot_use_completed_receipt(self):
        self._configure()
        calls = []

        def invalid_foreground():
            raise BootstrapError("Runtime foreground stop refused: recorded birth identity changed.")

        with self.assertRaisesRegex(BootstrapError, "birth identity changed"):
            down(self.paths, self.boundary, stop_foreground=invalid_foreground,
                 stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])

    def test_observed_replacement_invalidates_old_receipt_for_later_absence(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        old = json.loads(self.paths.discovery_path.read_text())
        self.boundary.alive.discard(int(old["pid"]))
        self.boundary.process_birth_identity = lambda _pid: None
        replacement = {"pid": 49998, "runtime_instance_id": "new-owner"}
        calls = []

        def publish_replacement():
            self.paths.discovery_path.write_text(json.dumps(replacement))

        with self.assertRaisesRegex(BootstrapError, "discovery changed during stop"):
            down(self.paths, self.boundary, stop_manager=publish_replacement)
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)

    def test_replacement_seen_before_busy_refusal_invalidates_receipt(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self._add_running_task(root)
        discovery_before = self.paths.discovery_path.read_bytes()
        marker_before = self.paths.instance_lock_path.read_bytes()
        calls = []
        with self.assertRaises(BootstrapError):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), marker_before)
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_receipt_retry_rechecks_process_absence_under_final_fence(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        pid = int(discovery["pid"])
        self.boundary.alive.discard(pid)
        fenced = False
        observations = 0
        real_fence = bootstrap_module.interruption_fence

        def identity(observed_pid):
            nonlocal observations
            self.assertEqual(observed_pid, pid)
            observations += 1
            return "reused-birth" if fenced else None

        self.boundary.process_birth_identity = identity

        @contextmanager
        def fence(realm_root):
            nonlocal fenced
            with real_fence(realm_root) as report:
                fenced = True
                yield report

        manager_calls = []
        with patch("astrid_runtime.bootstrap.interruption_fence", fence):
            with self.assertRaisesRegex(BootstrapError, "identity changed at the final fence"):
                down(self.paths, self.boundary,
                     stop_manager=lambda: manager_calls.append("manager"))
        self.assertEqual(observations, 2)
        self.assertEqual(manager_calls, [])

    def test_receipt_retry_rechecks_publications_after_final_absence_lookup(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        pid = int(discovery["pid"])
        self.boundary.alive.discard(pid)
        observations = 0

        def observe_and_publish(observed_pid):
            nonlocal observations
            observations += 1
            if observations == 2:
                self.paths.discovery_path.write_text(json.dumps({"pid": 90001, "runtime_instance_id": "new"}))
            return None

        self.boundary.process_birth_identity = observe_and_publish
        calls = []
        with self.assertRaisesRegex(BootstrapError, "owner changed before manager stop"):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(observations, 2)
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(self.paths.discovery_path.read_text())["pid"], 90001)

    def test_receipt_identity_lookup_failure_revokes_receipt(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        marker_before = self.paths.instance_lock_path.read_bytes()
        pid = json.loads(discovery_before)["pid"]
        self.boundary.alive.discard(int(pid))

        def uncertain(observed_pid):
            self.assertEqual(observed_pid, pid)
            raise OSError("process identity observation denied")

        self.boundary.process_birth_identity = uncertain
        manager_calls = []
        with self.assertRaisesRegex(BootstrapError, "absence could not be established"):
            down(self.paths, self.boundary,
                 stop_manager=lambda: manager_calls.append("manager"))
        self.assertEqual(manager_calls, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), marker_before)

    def test_lock_only_unknown_identity_revokes_receipt_before_later_disappearance(self):
        self._configure()
        self.paths.instance_lock_path.write_text(json.dumps({"pid": 12345}))
        calls = []
        with self.assertRaisesRegex(BootstrapError, "owner lock has no matching discovery"):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])
        self.assertTrue(self.paths.instance_lock_path.exists())

    def test_reused_identity_in_matching_publication_revokes_receipt(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        marker_before = self.paths.instance_lock_path.read_bytes()
        pid = json.loads(discovery_before)["pid"]
        self.boundary.alive.discard(int(pid))
        self.boundary.process_birth_identity = lambda observed: "reused-birth" if observed == pid else None
        calls = []
        with self.assertRaisesRegex(BootstrapError, "process identity changed"):
            down(self.paths, self.boundary, stop_manager=lambda: calls.append("manager"))
        self.assertEqual(calls, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(self.paths.instance_lock_path.read_bytes(), marker_before)

    def test_installer_preflight_busy_preserves_owner_and_skips_manager(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self._add_running_task(root)
        before = {
            path: path.read_bytes()
            for path in (self.paths.discovery_path, self.paths.instance_lock_path)
        }
        self.paths.bootstrap_lock_path.unlink(missing_ok=True)
        called = []
        with self.assertRaises(BootstrapError) as caught:
            down(self.paths, self.boundary, stop_manager=lambda: called.append(True))
        self.assertIn("Astrid is busy (1 tasks running)", str(caught.exception))
        self.assertEqual(caught.exception.details["task_count"], 1)
        self.assertEqual(caught.exception.details["blockers"][0]["task_id"], "task-busy")
        self.assertEqual(called, [])
        self.assertEqual(self.boundary.restart_calls, 0)
        # Busy preflight occurs before Runtime acquires/creates its mutex.
        self.assertFalse(self.paths.bootstrap_lock_path.exists())
        self.assertEqual(before, {
            path: path.read_bytes()
            for path in (self.paths.discovery_path, self.paths.instance_lock_path)
        })

    def test_down_busy_preflight_does_not_create_bootstrap_lock_or_mutate_state(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        database = root / "realm.sqlite3"
        # FakeBoundary has no real owner's SQLite connection. Hold one open
        # explicitly so WAL/SHM lifetime does not depend on garbage collection
        # of the task writer (a Connection context manager only commits).
        with closing(sqlite3.connect(database)) as owner_connection:
            owner_connection.execute("SELECT COUNT(*) FROM tasks").fetchone()
            self._add_running_task(root)
            self.paths.bootstrap_lock_path.unlink(missing_ok=True)
            watched = (
                self.paths.discovery_path, self.paths.instance_lock_path,
                self.paths.credentials_dir / "astrid.json",
            )
            before = {path: path.read_bytes() for path in watched if path.exists()}
            stop_calls = self.boundary.restart_calls
            self.assertTrue(Path(str(database) + "-wal").exists())
            self.assertTrue(Path(str(database) + "-shm").exists())
            committed_before = tuple(owner_connection.iterdump())
            for force_collection in (False, True):
                with self.subTest(force_collection=force_collection):
                    def observe(root):
                        if force_collection:
                            gc.collect()
                        return inspect_interruption_state(root)

                    with patch("astrid_runtime.bootstrap.inspect_interruption_state", side_effect=observe):
                        with self.assertRaisesRegex(BootstrapError, "Astrid is busy") as caught:
                            down(self.paths, self.boundary)
                    self.assertEqual(caught.exception.details["task_count"], 1)
                    self.assertEqual(stop_calls, self.boundary.restart_calls)
                    self.assertFalse(self.paths.bootstrap_lock_path.exists())
                    # WAL/SHM bookkeeping is allowed; realm data and owner
                    # publications must remain unchanged on refusal.
                    self.assertEqual(committed_before, tuple(owner_connection.iterdump()))
                    after = {path: path.read_bytes() for path in watched if path.exists()}
                    self.assertEqual(before.keys(), after.keys())
                    for path, contents in before.items():
                        self.assertEqual(contents, after[path], str(path))

    def test_installer_final_fence_catches_work_after_read_only_preflight(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        called = []
        original_preflight = preflight_stop
        inserted = False

        def raced_preflight(paths):
            nonlocal inserted
            report = original_preflight(paths)
            if not inserted:
                inserted = True
                self._add_running_task(root, "task-raced")
            return report

        with patch("astrid_runtime.bootstrap.preflight_stop", side_effect=raced_preflight):
            with self.assertRaises(BootstrapError) as caught:
                down(self.paths, self.boundary, stop_manager=lambda: called.append(True))
        self.assertIn("Astrid is busy (1 tasks running)", str(caught.exception))
        self.assertEqual(caught.exception.details["blockers"][0]["task_id"], "task-raced")
        self.assertEqual(called, [])
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_installer_stop_missing_owner_evidence_never_authorizes_manager(self):
        root = self._configure()
        called = []

        def stop_manager():
            probe = subprocess.run(
                [sys.executable, "-c",
                 "import sys; from runtime_protocol.platform import file_lock; p=sys.argv[1]; "
                 "\ntry: file_lock(p, blocking=False).__enter__()"
                 "\nexcept BlockingIOError: raise SystemExit(7)"
                 "\nraise SystemExit(0)", str(self.paths.bootstrap_lock_path)],
                check=False,
            )
            self.assertEqual(probe.returncode, 7)
            connection = sqlite3.connect(root / "realm.sqlite3", timeout=0.02)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.close()
            called.append(True)

        result = down(self.paths, self.boundary, stop_manager=stop_manager)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(called, [True])
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_stop_refuses_corrupt_discovery_before_callback(self):
        self._configure()
        self.paths.discovery_path.write_text("{broken", encoding="utf-8")
        called = []
        with self.assertRaises(BootstrapError):
            down(self.paths, self.boundary, stop_manager=lambda: called.append(True))
        self.assertEqual(called, [])

    def test_installer_stop_cleans_only_proven_dead_publication(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.boundary.alive.discard(int(discovery["pid"]))
        self.boundary.process_birth_identity = lambda _pid: None
        called = []
        result = down(self.paths, self.boundary, stop_manager=lambda: called.append(True))
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(called, [True])
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_installer_stop_unknown_process_observation_never_proves_absence(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.boundary.alive.discard(int(discovery["pid"]))

        def uncertain(_pid):
            raise OSError("process observation denied")

        self.boundary.process_birth_identity = uncertain
        before = self.paths.discovery_path.read_bytes()
        called = []
        with self.assertRaisesRegex(BootstrapError, "absence could not be established"):
            down(self.paths, self.boundary, stop_manager=lambda: called.append(True))
        self.assertEqual(called, [])
        self.assertEqual(self.paths.discovery_path.read_bytes(), before)

    def test_installer_stop_preserves_changed_discovery_after_absent_owner(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.boundary.alive.discard(int(discovery["pid"]))
        self.boundary.process_birth_identity = lambda _pid: None
        replacement = {"pid": 998877, "runtime_instance_id": "new", "active_realm": "configured-realm"}

        def stop_manager():
            self.paths.discovery_path.write_text(json.dumps(replacement), encoding="utf-8")

        with self.assertRaisesRegex(BootstrapError, "discovery changed"):
            down(self.paths, self.boundary, stop_manager=stop_manager)
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)

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
        with self.assertRaisesRegex(BootstrapError, "changed before manager stop"):
            down(self.paths, self.boundary)
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)
        self.assertEqual(
            json.loads(self.paths.instance_lock_path.read_text())["runtime_instance_id"],
            "replacement-instance",
        )

    def test_legacy_collision_refuses_parallel_empty_realm_with_exact_action(self):
        legacy = self.paths.home / ".astrid"
        legacy.mkdir(parents=True)
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


def test_restart_cli_preserves_named_lifecycle_blockers(monkeypatch, tmp_path, capsys):
    import astrid_runtime.cli as cli

    home = tmp_path / "home"
    data_root = tmp_path / "support"
    paths = RuntimePaths.current(home, data_root=data_root)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm"
    realm_root.mkdir()
    paths.catalog_path.write_text(json.dumps({
        "version": 1,
        "selected_realm_id": "realm",
        "realms": [{
            "realm_id": "realm", "display_name": "Realm", "data_root": str(realm_root),
        }],
        "source_profiles": {},
    }))
    paths.discovery_path.write_text(json.dumps({"pid": 123, "active_realm": "realm"}))
    manifest = tmp_path / "source-profile.json"
    manifest.write_text(json.dumps({
        "profile": "astrid", "runtime_checkout": "/runtime", "source_checkout": "/source",
    }))
    monkeypatch.setenv("ASTRID_RUNTIME_SOURCE_MANIFEST", str(manifest))

    class Boundary:
        def prepare_restart(self, **_kwargs):
            return None

    blockers = {
        "safe": False,
        "active_tasks": [{"task_id": "task-17", "status": "running"}],
        "unreconciled_attempts": [{"attempt_id": "attempt-4", "task_id": "task-17"}],
        "claimed_or_stale_bindings": [{"binding_id": "binding-9", "task_id": "task-17", "status": "claimed"}],
        "unreleased_reservations": [{"task_id": "task-17", "resource_key": "gpu:0", "lease_token": "lease-3"}],
    }
    monkeypatch.setattr(cli, "LocalRuntimeBoundary", Boundary)
    monkeypatch.setattr(
        cli, "restart",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            BootstrapError("runtime lifecycle refused while work is active or unreconciled", details=blockers)
        ),
    )

    assert cli.main(["restart", "--data-root", str(data_root), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["details"]["active_tasks"][0]["task_id"] == "task-17"
    assert payload["error"]["details"]["unreconciled_attempts"][0]["attempt_id"] == "attempt-4"
    assert payload["error"]["details"]["claimed_or_stale_bindings"][0]["binding_id"] == "binding-9"
    assert payload["error"]["details"]["unreleased_reservations"][0]["resource_key"] == "gpu:0"
