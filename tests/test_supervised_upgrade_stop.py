"""C1 contract tests, not native systemd or installed-upgrade qualification."""
import json
import gc
import sqlite3
from pathlib import Path

import pytest

from astrid_runtime.bootstrap import BootstrapError, admit_deferred_upgrade, bootstrap, down, inspect_upgrade_stop
import test_bootstrap as bootstrap_fixture


@pytest.fixture
def owner():
    harness = bootstrap_fixture.BootstrapTests()
    harness.setUp()
    try:
        root = harness._configure()
        bootstrap(harness.paths, harness.boundary, harness.config)
        # Stable disk bytes for the no-write oracle: WAL readers legitimately
        # update shared-memory read marks and the last close may checkpoint.
        # Keep the same real schema but settle its setup before measuring.
        gc.collect()
        with sqlite3.connect(root / "realm.sqlite3") as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("PRAGMA journal_mode=DELETE")
        for path in (harness.paths.discovery_path, harness.paths.instance_lock_path):
            value = json.loads(path.read_text())
            value["process_birth_id"] = "upgrade-birth"
            path.write_text(json.dumps(value))
        harness.boundary.process_birth_identity = (
            lambda pid: "upgrade-birth" if pid in harness.boundary.alive else None)
        yield harness.paths, harness.boundary, root
    finally:
        harness.tearDown()
        harness.doCleanups()


def snapshot(paths):
    return {str(p): p.read_bytes() for p in paths.app_support.rglob("*") if p.is_file()}


class Supervisor:
    def __init__(self, expected, boundary):
        self.expected, self.boundary = expected, boundary
        self.calls = []

    def validate(self, inspection):
        assert inspection == self.expected

    def stop(self, owner):
        assert owner == self.expected.owner
        self.calls.append("supervisor-stop")
        with sqlite3.connect(Path(owner["realm_root"]) / "realm.sqlite3", timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        self.boundary.alive.remove(owner["pid"])


def test_inspection_has_no_writes_and_authenticates_endpoint(owner):
    paths, boundary, root = owner
    before = snapshot(paths)
    result = inspect_upgrade_stop(paths, boundary).owner
    assert result["realm_root"] == str(root)
    assert result["process_birth_id"] == "upgrade-birth"
    assert snapshot(paths) == before
    boundary.valid_owner = False
    with pytest.raises(BootstrapError, match="failed validation"):
        inspect_upgrade_stop(paths, boundary)
    assert snapshot(paths) == before


def test_deferred_request_is_fenced_without_owner_stop_or_cleanup(owner):
    paths, boundary, root = owner
    expected = inspect_upgrade_stop(paths, boundary)
    before = snapshot(paths)
    calls = []
    def admit():
        assert snapshot(paths) == before
        with sqlite3.connect(root / "realm.sqlite3", timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        calls.append("durable-request")
        return "accepted"
    assert admit_deferred_upgrade(paths, boundary, expected,
                                   validate=lambda observed: calls.append(observed), on_admitted=admit) == "accepted"
    assert calls == [expected, "durable-request"] and snapshot(paths) == before
    assert expected.owner["pid"] in boundary.alive and boundary.restart_calls == 0


@pytest.mark.parametrize("change", ["live-resume", "reused", "unknown", "catalog", "lock", "busy", "installer"])
def test_failed_deferred_admission_has_no_callback_or_runtime_writes(owner, change):
    paths, boundary, root = owner
    expected = inspect_upgrade_stop(paths, boundary)
    if change in {"reused", "unknown"}:
        boundary.process_birth_identity = lambda _pid: "reused" if change == "reused" else None
    elif change == "catalog":
        catalog = json.loads(paths.catalog_path.read_text())
        catalog["fixture_change"] = True
        paths.catalog_path.write_text(json.dumps(catalog))
    elif change == "lock":
        paths.bootstrap_lock_path.rename(paths.bootstrap_lock_path.with_suffix(".previous"))
        paths.bootstrap_lock_path.touch(mode=0o600)
    elif change == "busy":
        with sqlite3.connect(root / "realm.sqlite3") as db:
            db.execute("INSERT INTO tasks(id,run_id,capability,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                       ("deferred-busy", "run", "render", "running", "now", "now"))
    def validate(_observed):
        if change == "installer":
            raise ValueError("changed installer selection")
    before = snapshot(paths)
    with pytest.raises((BootstrapError, ValueError)):
        admit_deferred_upgrade(paths, boundary, expected, validate=validate,
                                on_admitted=lambda: pytest.fail("write before fence"), require_quiescent=change == "live-resume")
    assert snapshot(paths) == before and boundary.restart_calls == 0


def test_deferred_quiescence_must_be_fresh_and_does_not_clean_stale_publications(owner):
    paths, boundary, _root = owner
    live = inspect_upgrade_stop(paths, boundary)
    boundary.alive.clear()
    before = snapshot(paths)
    with pytest.raises(BootstrapError):
        admit_deferred_upgrade(paths, boundary, live, validate=lambda _: None,
                                on_admitted=lambda: pytest.fail("stale observation admitted"), require_quiescent=True)
    cold = inspect_upgrade_stop(paths, boundary)
    assert cold.owner is None
    assert admit_deferred_upgrade(paths, boundary, cold, validate=lambda _: None,
                                   on_admitted=lambda: "ready", require_quiescent=True) == "ready"
    assert snapshot(paths) == before and boundary.restart_calls == 0


@pytest.mark.parametrize("birth", ["reused-birth", None])
def test_reused_or_unknown_owner_is_not_quiescence_and_has_no_writes(owner, birth):
    paths, boundary, _root = owner
    before = snapshot(paths)
    boundary.process_birth_identity = lambda _pid: birth
    with pytest.raises(BootstrapError, match="birth changed or is unverified"):
        inspect_upgrade_stop(paths, boundary)
    assert snapshot(paths) == before
    assert boundary.restart_calls == 0


def test_exact_supervisor_stop_precedes_commit_and_never_calls_detached_stop(owner):
    paths, boundary, _root = owner
    expected = inspect_upgrade_stop(paths, boundary)
    supervisor = Supervisor(expected, boundary)
    order = []

    def intent():
        assert json.loads(paths.instance_lock_path.read_text()).get("state") is None
        order.append("transaction-intent")

    original = supervisor.stop
    def stop(value):
        assert order == ["transaction-intent"]
        assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
        original(value)
        order.append("old-owner-exit")
    supervisor.stop = stop
    result = down(paths, boundary, supervised_stop=supervisor, on_stop_admitted=intent,
                  stop_manager=lambda: order.append("post-stop"))
    assert result["status"] == "stopped"
    assert order == ["transaction-intent", "old-owner-exit", "post-stop"]
    assert boundary.restart_calls == 0
    assert not paths.discovery_path.exists()
    assert not paths.instance_lock_path.exists()


@pytest.mark.parametrize("change_at", [1, 2, 3])
def test_changed_supervisor_refuses_before_intent_or_owner_write(owner, change_at):
    paths, boundary, _root = owner
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    before = snapshot(paths)
    calls = []
    def validate(_owner):
        calls.append("validate")
        if len(calls) == change_at:
            raise RuntimeError("changed exact invocation")
    supervisor.validate = validate
    with pytest.raises((RuntimeError, BootstrapError), match="changed exact invocation"):
        down(paths, boundary, supervised_stop=supervisor,
             on_stop_admitted=lambda: pytest.fail("transaction write before admission"))
    assert snapshot(paths) == before
    assert supervisor.calls == []
    assert boundary.restart_calls == 0


@pytest.mark.parametrize("replacement", [False, True])
def test_supervisor_reply_is_not_owner_absence(owner, replacement):
    paths, boundary, _root = owner
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    before = paths.discovery_path.read_bytes()
    def stop(_owner):
        if replacement:
            boundary.process_birth_identity = lambda _pid: "reused-birth"
        return {"status": "stopped"}  # Metadata is deliberately insufficient.
    supervisor.stop = stop
    with pytest.raises(BootstrapError, match="still present"):
        down(paths, boundary, supervised_stop=supervisor)
    assert paths.discovery_path.read_bytes() == before
    assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
    assert boundary.restart_calls == 0


def test_stop_timeout_preserves_intent_and_cold_retry_requires_observed_absence(owner):
    paths, boundary, _root = owner
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    def timeout(_owner):
        raise TimeoutError("supervisor timeout")
    supervisor.stop = timeout
    with pytest.raises(BootstrapError, match="supervisor timeout"):
        down(paths, boundary, supervised_stop=supervisor)
    assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
    boundary.alive.clear()  # A later normal lifecycle exit, not an updater signal.
    inspection = inspect_upgrade_stop(paths, boundary)
    assert inspection.owner is None
    cold = Supervisor(inspection, boundary)
    down(paths, boundary, supervised_stop=cold)
    assert cold.calls == []
    assert boundary.restart_calls == 0
    assert not paths.discovery_path.exists()


def test_new_owner_after_quiescent_inspection_is_not_covered(owner):
    paths, boundary, _root = owner
    boundary.alive.clear()
    inspection = inspect_upgrade_stop(paths, boundary)
    assert inspection.owner is None
    supervisor = Supervisor(inspection, boundary)
    before = snapshot(paths)
    pid = json.loads(paths.discovery_path.read_text())["pid"]
    boundary.alive.add(pid)
    with pytest.raises(AssertionError):
        down(paths, boundary, supervised_stop=supervisor)
    assert snapshot(paths) == before


def test_transaction_callback_requires_explicit_supervisor_admission(owner):
    paths, boundary, _root = owner
    with pytest.raises(TypeError, match="requires supervised"):
        down(paths, boundary, on_stop_admitted=lambda: None)


def test_quiescent_catalog_change_is_not_covered_by_old_inspection(owner):
    paths, boundary, _root = owner
    boundary.alive.clear()
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    # Even selection metadata changes must be caught for owner=None. Realm
    # selection must never be inferred from the absence of an owner mapping.
    catalog = json.loads(paths.catalog_path.read_text())
    catalog["realms"][0]["display_name"] = "Changed after admission"
    paths.catalog_path.write_text(json.dumps(catalog))
    before = snapshot(paths)
    with pytest.raises(AssertionError):
        down(paths, boundary, supervised_stop=supervisor,
             on_stop_admitted=lambda: pytest.fail("journal write"))
    assert snapshot(paths) == before and supervisor.calls == []


def test_replaced_bootstrap_lock_at_final_fence_has_no_intent_or_stop(owner, monkeypatch):
    paths, boundary, _root = owner
    import importlib
    module = importlib.import_module("astrid_runtime.bootstrap")
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    original = module._fenced_stop_and_manager
    before = snapshot(paths)

    def replace_lock(*args, **kwargs):
        replacement = paths.bootstrap_lock_path.with_name("replacement.lock")
        replacement.touch(mode=0o600)
        replacement.replace(paths.bootstrap_lock_path)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "_fenced_stop_and_manager", replace_lock)
    with pytest.raises(BootstrapError, match="bootstrap lock changed"):
        down(paths, boundary, supervised_stop=supervisor,
             on_stop_admitted=lambda: pytest.fail("journal write"))
    assert snapshot(paths) == before and supervisor.calls == []


@pytest.mark.parametrize("cause", ["manager lost", "job canceled", "child still draining", "policy changed"])
def test_post_admission_supervisor_failure_preserves_intent_and_is_not_initial_refusal(owner, cause):
    paths, boundary, root = owner
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    before_discovery = paths.discovery_path.read_bytes()
    before_realm = (root / "realm.sqlite3").read_bytes()
    intent = []
    def uncertain(_owner):
        assert intent == ["stopping"]
        assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
        # Even a provider that carries an initial-admission classification
        # cannot retrospectively erase this already admitted stop intent.
        raise BootstrapError(cause, details={"safe": False})
    supervisor.stop = uncertain
    with pytest.raises(BootstrapError, match=cause) as caught:
        down(paths, boundary, supervised_stop=supervisor, on_stop_admitted=lambda: intent.append("stopping"),
             stop_manager=lambda: pytest.fail("manager cleanup after uncertain stop"))
    assert caught.value.details.get("safe") is not False
    assert caught.value.details["cause_details"] == {"safe": False}
    assert paths.discovery_path.read_bytes() == before_discovery
    assert (root / "realm.sqlite3").read_bytes() == before_realm
    assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
    assert boundary.restart_calls == 0


def test_verify_only_manager_failure_after_owner_absence_prevents_cleanup(owner):
    paths, boundary, root = owner
    supervisor = Supervisor(inspect_upgrade_stop(paths, boundary), boundary)
    before_discovery = paths.discovery_path.read_bytes()
    def verify():
        assert supervisor.expected.owner["pid"] not in boundary.alive
        with sqlite3.connect(root / "realm.sqlite3", timeout=0) as db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                db.execute("BEGIN IMMEDIATE")
        raise RuntimeError("original manager continuity lost after independent owner absence")
    with pytest.raises(BootstrapError, match="continuity lost"):
        down(paths, boundary, supervised_stop=supervisor, stop_manager=verify)
    assert paths.discovery_path.read_bytes() == before_discovery
    assert json.loads(paths.instance_lock_path.read_text())["state"] == "stopping"
    assert supervisor.calls == ["supervisor-stop"] and boundary.restart_calls == 0
