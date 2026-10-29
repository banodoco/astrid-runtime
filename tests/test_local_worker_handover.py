from __future__ import annotations

import os
import copy
from dataclasses import replace
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore
from tests.test_local_worker_placement import FakeInspector, FakePreparer, _observation, _profile
from tests.test_remote_credential_generation import _task
from tests.test_remote_worker_activation import OWNER


class StoreProxy:
    store = None

    def __getattr__(self, name):
        return getattr(self.store, name)


class StopPreparer(FakePreparer):
    fail_stop = False

    def prepare(self, profile, *, operation_id, channel_id):
        self.aborted = False
        return super().prepare(profile, operation_id=operation_id, channel_id=channel_id)

    def stop_owned(self, receipt, *, handle=None):
        assert receipt["worker"]["pid"] == self.observation.worker.pid
        if handle is not None:
            assert handle is self.handle
        self.events.append("stop_owned")
        if self.fail_stop:
            raise ConflictError("receipt-owned process stop failed")
        self.handle = None
        self.aborted = True
        return True


def _daemon(tmp_path, preparer=None, proxy=None, *, host_only=False):
    root = tmp_path / "realm"
    if not root.exists():
        initialized = RealmStore.initialize(root)
        workspace_uuid = initialized.realm["id"]
        initialized.close()
    else:
        opened = RealmStore(root)
        workspace_uuid = opened.realm["id"]
        opened.close()
    profile = _profile(tmp_path, workspace_uuid)
    proxy = proxy or StoreProxy()
    if host_only:
        from tests.test_local_worker_placement import _host_only_fixture
        profile, observation = _host_only_fixture(tmp_path, os.getpid())
        profile = replace(profile, profile_id="astrid", workspace_uuid=workspace_uuid)
        observation = replace(observation, workspace_uuid=workspace_uuid)
        preparer = preparer or HostOnlyStopPreparer(proxy, observation)
        inspector = HostOnlyInspector(proxy, observation)
    else:
        observation = _observation(profile, os.getpid())
        preparer = preparer or StopPreparer(proxy, observation)
        inspector = FakeInspector(proxy, observation)
    daemon = RuntimeDaemon(
        root, support_root=profile.support_root,
        local_worker_profiles={"astrid": profile},
        local_worker_preparer=preparer,
        local_worker_inspector=inspector,
    ).start()
    proxy.store = daemon.credentials
    return daemon, preparer, proxy, workspace_uuid


def _launch(daemon, workspace_uuid):
    return Api(daemon.endpoint, daemon.token).request(
        "POST", "/v1/control/local-worker/start",
        {"profile_id": "astrid", "expected_workspace_uuid": workspace_uuid},
    )


def _relinquish(daemon, launch):
    return Api(daemon.endpoint, daemon.token).request(
        "POST", "/v1/control/local-worker/relinquish",
        {"executor_incarnation": launch["executor_incarnation"],
         "evidence_digest": launch["evidence_digest"]},
    )


def test_owner_exact_handover_fences_and_retires_local_generation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        observed = Api(daemon.endpoint, daemon.token).request(
            "GET", "/v1/control/local-worker/generation"
        )
        assert observed["executor_incarnation"] == launch["executor_incarnation"]
        assert observed["evidence_digest"] == launch["evidence_digest"]
        assert observed["state"] == "active"
        worker_token = daemon.credentials.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        with pytest.raises(RuntimeError) as denied_read:
            Api(daemon.endpoint, worker_token).request(
                "GET", "/v1/control/local-worker/generation"
            )
        assert denied_read.value.status == 401
        with pytest.raises(RuntimeError) as denied:
            Api(daemon.endpoint, daemon.token).request(
                "POST", "/v1/control/local-worker/relinquish",
                {"executor_incarnation": "foreign", "evidence_digest": launch["evidence_digest"]},
            )
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0

        result = _relinquish(daemon, launch)
        assert result == {"state": "relinquished", "executor_incarnation": launch["executor_incarnation"]}
        assert preparer.events.count("stop_owned") == 1
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is None
        assert daemon.local_worker_launcher is None
        assert _relinquish(daemon, launch) == result
    finally:
        daemon.stop()


def test_handover_refuses_active_actor_claim_and_reservation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        service = daemon.service
        capability = service.register_capability({
            "capability_id": "handover.fixture",
            "definition_digest": "sha256:" + hashlib.sha256(b"handover.fixture").hexdigest(),
        })
        service.register_executor({
            "executor_id": WORKER_ACTOR, "capabilities": ["handover.fixture"],
            "max_concurrency": 1, "resource_keys": ["gpu"],
        }, idempotency_key="handover-executor")
        task = service.create_task({
            "capability_id": "handover.fixture",
            "capability_digest": capability["definition_digest"],
            "input_object_ids": [], "spec": {}, "idempotency_key": "handover-task",
        })["task"]
        claim = service.claim_next({
            "executor_id": WORKER_ACTOR, "capability_ids": ["handover.fixture"],
            "runtime_epoch": service.store._current_runtime_epoch(),
        }, idempotency_key="handover-claim")
        assert claim["task_id"] == task["id"]
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
    finally:
        daemon.stop()


def test_failed_stop_stays_fenced_and_exact_replay_survives_restart(tmp_path):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path)
    launch = _launch(daemon, workspace_uuid)
    preparer.fail_stop = True
    try:
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        assert Api(daemon.endpoint, daemon.token).request(
            "GET", "/v1/control/local-worker/generation"
        )["state"] == "stop_unknown"
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        assert daemon.credentials._disabled_actors == {WORKER_ACTOR}
    finally:
        daemon.stop()

    preparer.fail_stop = False
    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy)
    try:
        assert replacement.local_worker_launcher is None
        assert replacement._local_worker_deferred
        restored = Api(replacement.endpoint, replacement.token).request(
            "GET", "/v1/control/local-worker/generation"
        )
        assert restored["executor_incarnation"] == launch["executor_incarnation"]
        assert restored["state"] == "stop_unknown"
        with pytest.raises(RuntimeError) as denied:
            Api(replacement.endpoint, replacement.token).request(
                "POST", "/v1/control/local-worker/relinquish",
                {"executor_incarnation": "foreign", "evidence_digest": launch["evidence_digest"]},
            )
        assert denied.value.status == 409
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert replacement.credentials.actor_metadata(WORKER_ACTOR) is None
    finally:
        replacement.stop()


def test_relinquished_actor_allows_remote_provision_then_fresh_local_launcher(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        old_launcher = daemon.local_worker_launcher
        _relinquish(daemon, launch)
        task_id, qualification, placement = _task(daemon, "after-local-handover")
        daemon.remote_credential_control(
            task_id, {"action": "provision", "qualification": qualification, "placement": placement},
            identity=OWNER,
        )
        daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
        daemon.remote_credential_control(
            task_id, {"action": "enable", "activation_id": qualification["activation_id"]},
            identity=OWNER,
        )
        with pytest.raises(RuntimeError) as denied:
            _launch(daemon, workspace_uuid)
        assert denied.value.status == 409
        daemon.remote_credential_control(
            task_id, {"action": "begin-drain", "qualification": qualification},
            identity=OWNER,
        )
        daemon.service.cancel_run(
            daemon.service.store.get_task(task_id)["run"]["id"],
            idempotency_key="handover-finish-remote-run",
        )
        assert daemon.remote_credential_control(
            task_id, {"action": "finish-drain", "qualification": qualification},
            identity=OWNER,
        )["state"] == "drained"
        daemon.local_worker_inspector.calls = 0
        fresh = _launch(daemon, workspace_uuid)
        assert fresh["executor_incarnation"] != launch["executor_incarnation"]
        assert daemon.local_worker_launcher is not old_launcher
        assert preparer.events.count("prepare") == 2
    finally:
        daemon.stop()


def test_claim_cannot_race_fenced_generation_and_store_remains_available(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_stop = preparer.stop_owned

    def waiting_stop(receipt, *, handle=None):
        entered.set()
        assert release.wait(5)
        return original_stop(receipt, handle=handle)

    preparer.stop_owned = waiting_stop
    try:
        launch = _launch(daemon, workspace_uuid)
        worker_token = daemon.credentials.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_relinquish, daemon, launch)
            assert entered.wait(3)
            assert Api(daemon.endpoint, None).health()["status"] == "ok"
            with pytest.raises(RuntimeError) as denied:
                Api(daemon.endpoint, worker_token).request(
                    "POST", "/v1/tasks/claim",
                    {"executor_id": WORKER_ACTOR, "capability_ids": [],
                     "runtime_epoch": daemon.service.store._current_runtime_epoch()},
                    headers={"Idempotency-Key": "claim-during-local-stop"},
                )
            assert denied.value.status == 401
            release.set()
            assert future.result(timeout=5)["state"] == "relinquished"
    finally:
        release.set()
        daemon.stop()


def test_credential_cleanup_failure_replays_exact_stopped_generation_after_restart(tmp_path):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path)
    launch = _launch(daemon, workspace_uuid)

    def failed_revoke(_actor):
        raise OSError("injected credential cleanup failure")

    daemon.credentials.revoke = failed_revoke
    try:
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 500
        assert daemon._local_relinquish_state()["state"] == "stopped"
        assert preparer.events.count("stop_owned") == 1
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
    finally:
        daemon.stop()

    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy)
    try:
        assert replacement._local_worker_deferred
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert replacement.credentials.actor_metadata(WORKER_ACTOR) is None
    finally:
        replacement.stop()


class HostOnlyInspector(FakeInspector):
    def observe(self, handle):
        if self.calls >= 5:
            self.calls += 1
            return self.observation
        return super().observe(handle)


class HostOnlyStopPreparer(StopPreparer):
    def report(self, handle):
        from runtime_protocol.local_worker import RELAY_PREPARATION_VERSION, _digest, _selected_profile_payload
        profile = self.profile
        return {"version": RELAY_PREPARATION_VERSION, "execution_mode": "host_only_cpu",
            "operation_id": self.operation_id, "channel_id": self.channel_id,
            "processes": {"host": {"pid": self.observation.host.pid, "birth_id": self.observation.host.birth_id}},
            "session_config_digest": profile.session_config_digest, "owner_epoch": self.observation.owner_epoch,
            "custody_scope": self.observation.custody_scope, "custody_capabilities": self.observation.custody_capabilities,
            "profile_binding_digest": _digest(_selected_profile_payload(profile))}

    def prepare(self, profile, *, operation_id, channel_id):
        self.profile = profile
        return super().prepare(profile, operation_id=operation_id, channel_id=channel_id)

    def bind_activation_acceptor(self, handle, grant, acceptor):
        self.acceptor = acceptor

    def activate(self, handle, grant):
        super().activate(handle, grant)
        request = {"version": "astrid.local-worker-activation-request/v1",
            "operation_id": grant["operation_id"], "channel_id": grant["channel_id"],
            "grant": {key: grant[key] for key in ("activation_id", "credential_file", "executor_incarnation", "evidence_digest")},
            "host": {"pid": self.observation.host.pid, "birth_id": self.observation.host.birth_id}}
        assert self.acceptor(request) == {**request, "version": "runtime.local-worker-activation-recorded/v1"}

    def stop_owned(self, receipt, *, handle=None):
        assert receipt["execution_mode"] == "host_only_cpu" and "worker" not in receipt
        assert receipt["host"]["pid"] == self.observation.host.pid
        assert handle is not None and handle is self.handle, "lost or closed original host handle cannot be adopted"
        self.events.append("stop_owned")
        if self.fail_stop:
            raise ConflictError("original host/child cleanup is unconfirmed")
        self.handle = None
        self.aborted = True
        return True


def test_host_only_public_generation_and_owned_relinquish(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        observed = Api(daemon.endpoint, daemon.token).request("GET", "/v1/control/local-worker/generation")
        assert observed == {key: launch[key] for key in ("executor_incarnation", "evidence_digest", "profile_id", "workspace_uuid", "state")}
        metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
        assert metadata["local_launch_receipt"]["version"] == "runtime.local-worker-receipt/v4"
        assert set(metadata["local_launch_receipt"]) & {"worker", "engine", "engine_listener"} == set()
        result = _relinquish(daemon, launch)
        assert result == {"state": "relinquished", "executor_incarnation": launch["executor_incarnation"]}
        assert preparer.events.count("stop_owned") == 1
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is None
        assert daemon._local_relinquish_state()["state"] == "complete"
        assert _relinquish(daemon, launch) == result
    finally:
        daemon.stop()


@pytest.mark.parametrize("field,value", [
    ("version", "runtime.local-worker-receipt/v3"), ("execution_mode", "worker_engine"),
    ("release_digest", "sha256:" + "9" * 64), ("profile_digest", "sha256:" + "8" * 64),
    ("evidence_digest", "sha256:" + "7" * 64), ("owner_epoch", "foreign"),
    ("worker", {"pid": 4, "birth_id": "fabricated"}), ("host", {"pid": True, "birth_id": "fabricated"}),
])
def test_host_only_daemon_rejects_drifted_receipt(tmp_path, field, value):
    daemon, _, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
        receipt = copy.deepcopy(metadata["local_launch_receipt"])
        receipt[field] = value
        with pytest.raises(ConflictError):
            daemon._assert_local_relinquish_receipt(receipt, metadata)
    finally:
        daemon.stop()


def test_host_only_failed_original_cleanup_preserves_credential_obligation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        before = daemon.credentials.actor_metadata(WORKER_ACTOR)
        preparer.fail_stop = True
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) == before
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        preparer.fail_stop = False
        assert _relinquish(daemon, launch)["state"] == "relinquished"
    finally:
        preparer.fail_stop = False
        daemon.stop()


def test_host_only_lost_original_handle_cannot_relinquish(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        original = preparer.handle
        preparer.handle = object()
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 500
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        preparer.handle = original
        assert _relinquish(daemon, launch)["state"] == "relinquished"
    finally:
        daemon.stop()


@pytest.mark.parametrize("binding_field", ["executor_incarnation", "evidence_digest"])
def test_host_only_daemon_rejects_credential_binding_mismatch(tmp_path, binding_field):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
        changed = copy.deepcopy(metadata)
        if binding_field == "executor_incarnation":
            changed["execution_binding"][binding_field] = "foreign"
        else:
            changed["execution_binding"]["verification"][binding_field] = "sha256:" + "6" * 64
        with pytest.raises(ConflictError):
            daemon._assert_local_relinquish_receipt(metadata["local_launch_receipt"], changed)
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) == metadata
        assert preparer.events.count("stop_owned") == 0
    finally:
        daemon.stop()


def _owned_cancel_claim(daemon, *, key="owned-cancel", cancel=True, resource_key="cpu"):
    """Actual store/claim/cancel transitions; only the OS stop is a fixture."""
    service = daemon.service
    metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
    placement = metadata["execution_binding"]
    worker = {"actor": WORKER_ACTOR, "scopes": list(WORKER_SCOPES),
              "execution_binding": placement}
    capability_id = "handover." + resource_key
    capability = service.register_capability({
        "capability_id": capability_id, "definition_digest": "sha256:" + hashlib.sha256(capability_id.encode()).hexdigest(),
        "required_resource_keys": [resource_key],
    })
    service.register_executor({"executor_id": WORKER_ACTOR, "capabilities": [capability_id],
        "max_concurrency": 4, "resource_keys": [resource_key], "runtime_epoch": service.store._current_runtime_epoch()}, idempotency_key=key + "-executor", identity=worker)
    task = service.create_task({"capability_id": capability_id, "capability_digest": capability["definition_digest"],
        "input_object_ids": [], "spec": {}, "idempotency_key": key,
        "execution_request": {"schema_version": 1, "target": {"kind": "default"}, "inputs": []}})["task"]
    attempt = service.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": [capability_id],
        "runtime_epoch": service.store._current_runtime_epoch(), "target": {"kind": "default"}},
        idempotency_key=key + "-claim", identity=worker)
    assert attempt["task_id"] == task["id"]
    if cancel:
        service.cancel_task_canonical(task["id"], idempotency_key=key + "-cancel")
        assert service.task(task["id"])["task"]["status"] == "cancel_requested"
    return task["id"], attempt


def _assert_owned_cancel_finalized(daemon, task_id, attempt):
    store = daemon.service.store
    value = store.get_task(task_id)
    assert value["task"]["status"] == "cancelled"
    assert value["run"]["status"] == "cancelled"
    assert store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
    assert not store.conn.execute("SELECT 1 FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()
    assert store.execution_binding(task_id)["status"] == "released"


def test_owned_cancel_stop_after_capture_may_cross_lease_deadline(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon)
        original_stop = preparer.stop_owned
        def stop(receipt, *, handle=None):
            assert daemon._local_relinquish_state()["state"] == "fenced"
            assert WORKER_ACTOR in daemon.credentials._disabled_actors
            assert daemon.service.store.get_task(task_id)["task"]["status"] == "cancel_requested"
            # Deterministic passage of the captured lease while the original
            # owner's positive stop runs. This is not live venue recovery.
            with daemon.service.store._mutex:
                daemon.service.store.conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (task_id,))
                daemon.service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (attempt["attempt_id"],))
            return original_stop(receipt, handle=handle)
        preparer.stop_owned = stop
        assert _relinquish(daemon, launch)["state"] == "relinquished"
        _assert_owned_cancel_finalized(daemon, task_id, attempt)
        assert preparer.events.count("stop_owned") == 1
        assert daemon._local_relinquish_state()["stop_proof"]["kind"] == "retained_host_children_ack_and_wait"
    finally:
        daemon.stop()


@pytest.mark.parametrize("invalid", ["expired", "running", "foreign", "extra_attempt"])
def test_owned_cancel_entry_rejects_uncaptured_work_before_stop(tmp_path, invalid):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon, cancel=invalid != "running")
        store = daemon.service.store
        if invalid == "expired":
            store.conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (task_id,))
        elif invalid == "foreign":
            import json
            row = store.conn.execute("SELECT resolved_target_json FROM execution_bindings WHERE task_id=?", (task_id,)).fetchone()
            placement = json.loads(row[0])
            placement["executor_incarnation"] = "foreign"
            store.conn.execute("UPDATE execution_bindings SET resolved_target_json=? WHERE task_id=?", (json.dumps(placement), task_id))
        elif invalid == "extra_attempt":
            columns = [row[1] for row in store.conn.execute("PRAGMA table_info(attempts)")]
            row = dict(store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone())
            row["id"] = "foreign-unsettled-attempt"
            store.conn.execute("INSERT INTO attempts (" + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ")", [row[key] for key in columns])
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        assert store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 0
    finally:
        daemon.stop()


@pytest.mark.parametrize("failure", ["sqlite_before_commit", "retirement_after_commit"])
def test_owned_cancel_stopped_replay_after_restart_never_repeats_stop(tmp_path, failure):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    launch = _launch(daemon, workspace_uuid)
    task_id, attempt = _owned_cancel_claim(daemon)
    if failure == "sqlite_before_commit":
        original = daemon.service.store._append_event
        def append(run_id, task_id, kind, payload, **kwargs):
            if kind == "task.cancelled" and "owned_local_stop_proof" in payload:
                raise OSError("injected SQLite transaction failure")
            return original(run_id, task_id, kind, payload, **kwargs)
        daemon.service.store._append_event = append
    else:
        def revoke(actor):
            raise OSError("injected credential retirement failure")
        daemon.credentials.revoke = revoke
    try:
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 500
        assert daemon._local_relinquish_state()["state"] == "stopped"
        assert preparer.events.count("stop_owned") == 1
        assert preparer.handle is None
        assert daemon.service.store.get_task(task_id)["task"]["status"] == ("cancel_requested" if failure == "sqlite_before_commit" else "cancelled")
    finally:
        daemon.stop()
    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy, host_only=True)
    try:
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert preparer.events.count("stop_owned") == 1
        _assert_owned_cancel_finalized(replacement, task_id, attempt)
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert preparer.events.count("stop_owned") == 1
    finally:
        replacement.stop()


def test_owned_cancel_lost_durable_stop_proof_cannot_reconstruct_closed_handle(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon)
        original = daemon._write_local_relinquish
        def write(value):
            if value["state"] == "stopped":
                raise OSError("injected stopped-proof write failure")
            return original(value)
        daemon._write_local_relinquish = write
        with pytest.raises(RuntimeError):
            _relinquish(daemon, launch)
        assert daemon._local_relinquish_state()["state"] == "fenced"
        assert preparer.handle is None
        daemon._write_local_relinquish = original
        with pytest.raises(RuntimeError):
            _relinquish(daemon, launch)
        assert preparer.events.count("stop_owned") == 1
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        assert daemon.service.store.get_task(task_id)["task"]["status"] == "cancel_requested"
    finally:
        daemon.stop()


@pytest.mark.parametrize("failure", ["negative_child_ack", "host_wait_failure", "identity_drift"])
def test_owned_cancel_uncertain_or_changed_stop_never_finalizes(tmp_path, failure):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon)
        original_stop = preparer.stop_owned
        def stop(receipt, *, handle=None):
            if failure == "negative_child_ack":
                return False
            if failure == "host_wait_failure":
                raise ConflictError("fixture retained wait unconfirmed")
            value = original_stop(receipt, handle=handle)
            with daemon.service.store._mutex:
                daemon.service.store.conn.execute("UPDATE attempts SET fence=fence+1 WHERE id=?", (attempt["attempt_id"],))
            return value
        preparer.stop_owned = stop
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert daemon._local_relinquish_state()["state"] == ("stopped" if failure == "identity_drift" else "stop_unknown")
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        store = daemon.service.store
        assert store.get_task(task_id)["task"]["status"] == "cancel_requested"
        assert store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 0
        assert store.execution_binding(task_id)["status"] == "stale"
        assert store.conn.execute("SELECT 1 FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()
    finally:
        daemon.stop()


def test_owned_cancel_captured_replay_rejects_drift_before_second_stop(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, attempt = _owned_cancel_claim(daemon)
        preparer.fail_stop = True
        with pytest.raises(RuntimeError):
            _relinquish(daemon, launch)
        assert preparer.events.count("stop_owned") == 1
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        daemon.service.store.conn.execute("UPDATE attempts SET fence=fence+1 WHERE id=?", (attempt["attempt_id"],))
        preparer.fail_stop = False
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 1
        assert daemon.service.store.get_task(task_id)["task"]["status"] == "cancel_requested"
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
    finally:
        preparer.fail_stop = False
        daemon.stop()


def _named_relinquish(daemon, launch, task_ids):
    return Api(daemon.endpoint, daemon.token).request(
        "POST", "/v1/control/local-worker/relinquish",
        {"executor_incarnation": launch["executor_incarnation"],
         "evidence_digest": launch["evidence_digest"], "expected_task_ids": task_ids})


def _settlement(daemon, task_id, token=None):
    return Api(daemon.endpoint, token or daemon.token).request(
        "GET", f"/v1/control/tasks/{task_id}/settlement")


def test_named_full_generation_settles_and_down_fence_is_safe(tmp_path):
    from runtime_protocol.lifecycle import interruption_fence
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        first, first_attempt = _owned_cancel_claim(daemon)
        second, second_attempt = _owned_cancel_claim(daemon, key="second", resource_key="cpu2")
        assert not _settlement(daemon, first)["settled"]
        assert _named_relinquish(daemon, launch, [first, second])["state"] == "relinquished"
        _assert_owned_cancel_finalized(daemon, first, first_attempt)
        _assert_owned_cancel_finalized(daemon, second, second_attempt)
        observation = _settlement(daemon, first)
        assert {key: observation[key] for key in ("task_id", "state", "settled", "blockers")} == {"task_id": first, "state": "cancelled", "settled": True, "blockers": []}
        assert observation["task"]["task_id"] == first
        assert observation["task"]["state"] == "cancelled"
        assert preparer.events.count("stop_owned") == 1
        # Order is irrelevant; expanding even a completed checkpoint is denied.
        assert _named_relinquish(daemon, launch, [second, first])["state"] == "relinquished"
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, launch, [first, second, "unrelated"])
        assert denied.value.status == 409
        with interruption_fence(daemon.root) as report:
            assert report["safe"]
        for task_id in (first, second):
            assert daemon.service.store.conn.execute(
                "SELECT count(*) FROM events WHERE task_id=? AND kind='task.cancelled'", (task_id,)).fetchone()[0] == 1
    finally:
        daemon.stop()


@pytest.mark.parametrize("cancel_unlisted", [False, True])
def test_named_subset_refuses_unlisted_work_before_fencing_or_stop(tmp_path, cancel_unlisted):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        named, _ = _owned_cancel_claim(daemon)
        other, attempt = _owned_cancel_claim(daemon, key="other", resource_key="cpu2", cancel=cancel_unlisted)
        before = daemon.service.store.get_task(other)
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, launch, [named])
        assert denied.value.status == 409
        assert denied.value.detail["details"]["required_task_ids"] == [other]
        assert daemon.service.store.get_task(other) == before
        assert daemon.service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 0
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
        assert WORKER_ACTOR not in daemon.credentials._disabled_actors
    finally:
        daemon.stop()


def test_named_owner_rechecks_claim_raced_after_generation_observation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        named, _ = _owned_cancel_claim(daemon)
        observed = Api(daemon.endpoint, daemon.token).request("GET", "/v1/control/local-worker/generation")
        claimed = threading.Event()
        def claim():
            with daemon.service.store._mutex:
                task_id, _ = _owned_cancel_claim(daemon, key="raced", resource_key="cpu2", cancel=False)
            claimed.set()
            return task_id
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(claim)
            assert claimed.wait(5)
            other = future.result(5)
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, observed, [named])
        assert denied.value.status == 409
        assert daemon.service.store.get_task(other)["task"]["status"] == "running"
        assert preparer.events.count("stop_owned") == 0
    finally:
        daemon.stop()


@pytest.mark.parametrize("ids", [None, [], ["same", "same"], [1], "task-id"])
def test_named_relinquish_rejects_malformed_authority(tmp_path, ids):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, launch, ids)
        assert denied.value.status == 400
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
    finally:
        daemon.stop()


@pytest.mark.parametrize("actor,scopes", [("worker-control", list(WORKER_SCOPES)), ("browser-control", ["tasks:read", "tasks:write"]), ("other-admin", ["admin"])])
def test_named_controls_require_owner_actor_and_admin_scope(tmp_path, actor, scopes):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, _ = _owned_cancel_claim(daemon)
        token, _ = daemon.credentials.provision(actor, scopes)
        api = Api(daemon.endpoint, token)
        for method, path, body in (
            ("GET", f"/v1/control/tasks/{task_id}/settlement", None),
            ("GET", "/v1/control/local-worker/generation", None),
            ("POST", "/v1/control/local-worker/relinquish", {"executor_incarnation": launch["executor_incarnation"], "evidence_digest": launch["evidence_digest"], "expected_task_ids": [task_id]}),
        ):
            with pytest.raises(RuntimeError) as denied:
                api.request(method, path, body)
            assert denied.value.status in {401, 403}
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
    finally:
        daemon.stop()


def test_named_stopped_replay_binds_task_authority_and_deduplicates_terminal_events(tmp_path):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    launch = _launch(daemon, workspace_uuid)
    task_id, attempt = _owned_cancel_claim(daemon)
    original_revoke = daemon.credentials.revoke
    def fail_revoke(actor):
        raise OSError("fixture failure after settlement before response")
    daemon.credentials.revoke = fail_revoke
    try:
        with pytest.raises(RuntimeError):
            _named_relinquish(daemon, launch, [task_id])
        assert _settlement(daemon, task_id)["settled"]
        assert daemon._local_relinquish_state()["state"] == "stopped"
        assert preparer.events.count("stop_owned") == 1
    finally:
        daemon.credentials.revoke = original_revoke
        daemon.stop()
    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy, host_only=True)
    try:
        for changed in ([task_id, "another-task"], ["another-task"]):
            with pytest.raises(RuntimeError) as denied:
                _named_relinquish(replacement, launch, changed)
            assert denied.value.status == 409
        assert _named_relinquish(replacement, launch, [task_id])["state"] == "relinquished"
        _assert_owned_cancel_finalized(replacement, task_id, attempt)
        assert preparer.events.count("stop_owned") == 1
        assert replacement.service.store.conn.execute(
            "SELECT count(*) FROM events WHERE task_id=? AND kind='task.cancelled'", (task_id,)).fetchone()[0] == 1
    finally:
        replacement.stop()


def test_terminal_state_with_outstanding_attempt_is_not_settlement_proof(tmp_path):
    daemon, _, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        task_id, _ = _owned_cancel_claim(daemon)
        daemon.service.store.conn.execute("UPDATE tasks SET status='failed' WHERE id=?", (task_id,))
        report = _settlement(daemon, task_id)
        assert report["state"] == "failed" and not report["settled"]
        assert {row["blocker_kind"] for row in report["blockers"]} == {"unsettled_attempt", "unreleased_reservation", "claimed_or_stale_binding"}
        with pytest.raises(RuntimeError) as missing:
            _settlement(daemon, "unknown-exact-id")
        assert missing.value.status == 404
    finally:
        daemon.stop()


def test_named_unrelated_id_cannot_authorize_idle_worker_termination(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, launch, ["task-on-another-executor"])
        assert denied.value.status == 409
        assert "no named outstanding task" in str(denied.value)
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
        assert WORKER_ACTOR not in daemon.credentials._disabled_actors
    finally:
        daemon.stop()


@pytest.mark.parametrize("field,value", [("executor_incarnation", "wrong"), ("evidence_digest", "sha256:" + "f" * 64)])
def test_named_wrong_generation_or_evidence_never_stops(tmp_path, field, value):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        launch = _launch(daemon, workspace_uuid)
        task_id, _ = _owned_cancel_claim(daemon)
        with pytest.raises(RuntimeError) as denied:
            _named_relinquish(daemon, {**launch, field: value}, [task_id])
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0
        assert daemon._local_relinquish_state() is None
        assert not _settlement(daemon, task_id)["settled"]
    finally:
        daemon.stop()


def test_owner_settlement_observation_does_not_reap_expired_work(tmp_path):
    daemon, _, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        named, attempt = _owned_cancel_claim(daemon, cancel=False)
        store = daemon.service.store
        with store._mutex:
            store.conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (named,))
            before = "\n".join(store.conn.iterdump())
        report = _settlement(daemon, named)
        assert report["task"]["state"] == "running"
        assert report["task"]["attempt_id"] == attempt["attempt_id"]
        assert report["task"]["lease_expires_at"] == "2000-01-01T00:00:00+00:00"
        assert not report["settled"]
        with store._mutex:
            assert "\n".join(store.conn.iterdump()) == before
    finally:
        daemon.stop()
