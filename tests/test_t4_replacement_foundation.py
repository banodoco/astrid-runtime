from __future__ import annotations

import json
import multiprocessing
import threading

import pytest

from tests.lanes import requires_posix_fork

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol import server
from runtime_protocol.server import RuntimeHandler, RuntimeHTTPServer
from runtime_protocol.store import RealmStore
from runtime_protocol.catalog import RealmCatalog
from runtime_protocol.errors import ConflictError


def _fresh(root):
    RealmStore.initialize(root).close()


def test_verified_candidate_replaces_owner_with_fresh_epoch_credentials_and_quarantine(tmp_path, monkeypatch):
    active_root = tmp_path / "active"
    support_root = tmp_path / "support"
    _fresh(active_root)
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "10")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    daemon = RuntimeDaemon(active_root, support_root=support_root).start()
    old_service = daemon.service
    old_epoch = old_service.health()["runtime_epoch"]
    old_token = daemon.token
    old_instance_id = daemon.instance_id
    assert daemon.startup_identity == {"release": 10, "managed_by": None}
    assert daemon.startup_identity_instance_id == old_instance_id
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    try:
        old_service.backup(backup)
        old_service.restore(backup, candidate)
        monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "11")
        result = daemon.activate_candidate(candidate, retain_superseded=True)
        assert result["state"] == "complete"
        assert result["retained"] is True
        assert result["runtime_epoch"] > old_epoch
        assert result["runtime_instance_id"] != old_instance_id
        assert daemon.startup_identity == {"release": 11, "managed_by": None}
        assert daemon.startup_identity_instance_id == result["runtime_instance_id"]
        assert daemon.token != old_token
        assert daemon.service is not old_service
        assert old_service.store.conn is None
        assert active_root.is_dir()
        assert not candidate.exists()
        assert (tmp_path / result["superseded_root"].split("/")[-1]).is_dir()
        assert json.loads((support_root / "replacement-state.json").read_text())["state"] == "complete"
        catalog = daemon.catalog.read()
        row = next(item for item in catalog["realms"] if item["realm_id"] == daemon.service.realm["id"])
        assert row["data_root"] == str(active_root)
        assert row["runtime_epoch"] == result["runtime_epoch"]
        assert row["runtime_instance_id"] == result["runtime_instance_id"]
        assert row["readiness"] == "ready"
    finally:
        daemon.stop()


def test_verified_candidate_activation_discards_superseded_root_by_default(tmp_path):
    active_root = tmp_path / "active"
    support_root = tmp_path / "support"
    _fresh(active_root)
    daemon = RuntimeDaemon(active_root, support_root=support_root).start()
    old_service = daemon.service
    old_epoch = old_service.health()["runtime_epoch"]
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    try:
        old_service.backup(backup)
        old_service.restore(backup, candidate)
        result = daemon.activate_candidate(candidate)
        assert result["state"] == "complete"
        assert result["retained"] is False
        assert result["superseded_root"] is None
        assert result["runtime_epoch"] > old_epoch
        assert daemon.service is not old_service
        assert active_root.is_dir()
        assert not candidate.exists()
        assert not any(path.name.startswith(".active.superseded-") for path in tmp_path.iterdir())
        state = json.loads((support_root / "replacement-state.json").read_text())
        assert state["state"] == "complete"
        assert state["retain_superseded"] is False
        assert state["superseded_root"] is None
    finally:
        daemon.stop()


def test_failed_replacement_rolls_back_and_leaves_recoverable_state(tmp_path, monkeypatch):
    active_root = tmp_path / "active"
    support_root = tmp_path / "support"
    _fresh(active_root)
    daemon = RuntimeDaemon(active_root, support_root=support_root).start()
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    original_start = daemon._start
    failed = False

    def fail_once(*, rotate_credentials=False):
        nonlocal failed
        if rotate_credentials and not failed:
            failed = True
            raise RuntimeError("injected replacement startup interruption")
        return original_start(rotate_credentials=rotate_credentials)

    monkeypatch.setattr(daemon, "_start", fail_once)
    try:
        daemon.service.backup(backup)
        daemon.service.restore(backup, candidate)
        try:
            daemon.activate_candidate(candidate)
        except RuntimeError as exc:
            assert "interruption" in str(exc)
        else:  # pragma: no cover - the injected interruption is required
            raise AssertionError("replacement did not exercise the injected interruption")
        state = json.loads((support_root / "replacement-state.json").read_text())
        assert state["state"] == "rolled_back"
        assert active_root.is_dir()
        assert candidate.is_dir()
        assert daemon.service is not None
        assert daemon.service.health()["status"] == "ok"
        assert daemon.startup_identity_instance_id == daemon.instance_id
        assert any(path.name.startswith(".active.superseded-") for path in tmp_path.iterdir()) is False
    finally:
        daemon.stop()


def test_in_root_default_support_is_rejected_before_replacement_moves(tmp_path):
    active_root = tmp_path / "active"
    _fresh(active_root)
    daemon = RuntimeDaemon(active_root).start()
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    try:
        daemon.service.backup(backup)
        daemon.service.restore(backup, candidate)
        with pytest.raises(ConflictError, match="support_root outside the active realm root"):
            daemon.activate_candidate(candidate)
        assert active_root.is_dir()
        assert candidate.is_dir()
        assert daemon.service.health()["status"] == "ok"
    finally:
        daemon.stop()

    offline = RuntimeDaemon(active_root)
    try:
        with pytest.raises(ConflictError, match="support_root outside the active realm root"):
            offline.replace_from_backup(backup)
        assert active_root.is_dir()
    finally:
        offline.stop()


def test_cleanup_does_not_shutdown_http_server_without_serving_thread():
    daemon = RuntimeDaemon("/tmp/runtime-cleanup-regression")
    daemon.httpd = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
    try:
        daemon._shutdown_http()
        assert daemon.httpd is None
        assert daemon.thread is None
    finally:
        daemon._shutdown_http()


def test_listener_binds_ephemeral_loopback_without_hostname_lookup(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    done = threading.Event()
    result = {}

    def blocking_getfqdn(host):
        entered.set()
        release.wait()
        return host

    monkeypatch.setattr(server.socket, "getfqdn", blocking_getfqdn)

    def create_listener():
        try:
            result["listener"] = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
        except BaseException as exc:  # pragma: no cover - surfaced by the parent assertion
            result["error"] = exc
        finally:
            done.set()

    worker = threading.Thread(target=create_listener, daemon=True)
    worker.start()
    try:
        assert done.wait(1), "listener creation reached a hostname lookup"
        assert not entered.is_set()
        assert "error" not in result
        listener = result["listener"]
        assert listener.server_address[0] == "127.0.0.1"
        assert listener.server_port > 0
        assert listener.server_port == listener.server_address[1] == listener.socket.getsockname()[1]
    finally:
        release.set()
        worker.join(1)
        listener = result.get("listener")
        if listener is not None:
            listener.server_close()
        assert not worker.is_alive()


def _register_catalog_worker(path, realm_id, ready, release, result):
    try:
        catalog = RealmCatalog(path)
        ready.put(realm_id)
        release.get()
        catalog.register(realm_id=realm_id, display_name=realm_id, data_root=str(path.parent / realm_id))
        result.put((realm_id, "ok"))
    except Exception as exc:  # pragma: no cover - surfaced by the parent assertion
        result.put((realm_id, type(exc).__name__, str(exc)))


@requires_posix_fork
def test_catalog_full_read_modify_write_preserves_parallel_registrations(tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    catalog_path = support / "catalog.json"
    catalog_path.write_text(json.dumps({"version": 1, "realms": [], "selected_realm_id": None}))
    context = multiprocessing.get_context("fork")
    ready = context.Queue()
    release = context.Queue()
    result = context.Queue()
    workers = [context.Process(target=_register_catalog_worker, args=(catalog_path, f"realm-{index}", ready, release, result)) for index in (1, 2)]
    for worker in workers:
        worker.start()
    assert {ready.get(timeout=5), ready.get(timeout=5)} == {"realm-1", "realm-2"}
    release.put(True)
    release.put(True)
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    outcomes = [result.get(timeout=5) for _ in workers]
    assert all(item[1] == "ok" for item in outcomes), outcomes
    catalog = RealmCatalog(catalog_path).read()
    assert {row["realm_id"] for row in catalog["realms"]} == {"realm-1", "realm-2"}


def test_catalog_rejects_stale_owner_and_revokes_readiness(tmp_path):
    root = tmp_path / "active"
    support = tmp_path / "support"
    _fresh(root)
    daemon = RuntimeDaemon(root, support_root=support).start()
    try:
        proof = daemon.service.catalog_admission(daemon.instance_id)
        realm_id = daemon.service.realm["id"]
        daemon.service.store.begin_runtime_session("replacement-epoch")
        with pytest.raises(ConflictError, match="admitted runtime owner"):
            daemon.catalog.register(realm_id=realm_id, display_name="stale", data_root=str(root), owner=proof)
        daemon.service._verified = False
        daemon._revoke_readiness({"ok": False})
        row = next(item for item in daemon.catalog.read()["realms"] if item["realm_id"] == realm_id)
        assert row["readiness"] == "not_ready"
        assert row["readiness_reason"] == "runtime_admission_failed"
        assert not (support / "discovery.json").exists()
    finally:
        daemon.stop()
