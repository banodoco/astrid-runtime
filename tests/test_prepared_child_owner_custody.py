"""Synthetic realms, real HTTP authentication and resident credential custody."""
from __future__ import annotations

import copy
import hashlib

import pytest

from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api
from tests.test_remote_activation_http import _qualification


PARENT = "h3_av.project_parent"
CHILD = "vibecomfy.run"
TARGET = {"kind": "runpod", "pod_id": "synthetic-pod", "provider_account_ref": "synthetic-account"}
REQUEST = {"schema_version": 1, "target": TARGET, "remote_activation_required": True,
           "lifecycle": {"mode": "leave_running"}}


def digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def lease(value):
    return {key: value[key] for key in ("lease_id", "fence", "runtime_epoch")}


@pytest.fixture
def custody(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        worker = Api(daemon.endpoint, daemon.worker_token)
        worker.register_executor(WORKER_ACTOR, [PARENT, CHILD], max_concurrency=8)
        project = owner.create_project("prepared", "Prepared fixture")["project_id"]
        policy = {"capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}],
                  "targets": [{"kind": "default"}, TARGET], "input_object_ids": [],
                  "stages": [{"name": "run", "capability_id": CHILD,
                              "capability_digest": digest(CHILD), "target": TARGET,
                              "inputs": [], "execution_request": REQUEST}]}
        parent = owner.request("POST", "/v1/tasks", {"project": project, "capability_id": PARENT,
            "capability_digest": digest(PARENT), "input_object_ids": [], "spec": {},
            "child_delegation": policy}, headers={"Idempotency-Key": "parent"})["data"]
        epoch = worker.health()["runtime_epoch"]
        claim = worker.request("POST", "/v1/tasks/claim", {"executor_id": WORKER_ACTOR,
            "capability_ids": [PARENT], "runtime_epoch": epoch}, headers={"Idempotency-Key": "claim-parent"})
        authority = worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/child-authority", lease(claim))["authority"]
        # Earlier unrelated work shares the remote capability and placement;
        # the prepared child's exact actor must neither claim nor block it.
        owner.request("POST", "/v1/tasks", {"project": project, "capability_id": CHILD,
            "capability_digest": digest(CHILD), "input_object_ids": [], "spec": {},
            "execution_request": REQUEST}, headers={"Idempotency-Key": "unrelated"})
        child_body = {"authority": authority, "task": {"capability_id": CHILD,
            "capability_digest": digest(CHILD), "stage": "run", "input_refs": [],
            "spec": {"inputs": {}}, "execution_request": REQUEST}}
        admitted = worker.request("POST", "/v1/delegated-tasks", child_body,
            headers={"Idempotency-Key": "child"})["data"]
        child_id = admitted["task_id"]
        qualification = _qualification(daemon.service, child_id)
        qualification["credential_actor"] = "astrid-prepared-" + hashlib.sha256(child_id.encode()).hexdigest()[:32]
        placement = {"actual": TARGET, "executor_incarnation": qualification["executor_incarnation"],
            "verification": {"method": "credential_claim", "verified": True,
                             "evidence_digest": qualification["evidence_digest"]}}
        yield daemon, owner, worker, claim, child_id, qualification, placement, child_body
    finally:
        daemon.stop()


def control(owner, child, action, **fields):
    return owner.request("POST", f"/v1/tasks/{child}/remote-credential", {"action": action, **fields})


def activate(custody):
    daemon, owner, _, _, child, qualification, placement, _ = custody
    result = control(owner, child, "provision", qualification=qualification, placement=placement)
    actor = qualification["credential_actor"]
    assert result["credential_actor"] == actor
    assert control(owner, child, "provision", qualification=qualification, placement=placement) == result
    # Test-only generated token is consumed by HTTP; never emitted in evidence.
    remote = Api(daemon.endpoint, daemon.credentials.path_for(actor).read_text())
    with pytest.raises(RuntimeError) as error:
        remote.register_executor(actor, [CHILD])
    assert error.value.status == 401
    owner.request("POST", f"/v1/tasks/{child}/remote-activation", qualification)
    control(owner, child, "enable", activation_id=qualification["activation_id"])
    remote.register_executor(actor, [CHILD])
    return remote


def test_owner_keeps_parent_and_replays_one_prepared_child(custody):
    daemon, owner, worker, parent, child, qualification, placement, body = custody
    before = daemon.credentials.actor_metadata(WORKER_ACTOR)
    remote = activate(custody)
    # Admission and owner activation replies may be lost; exact replay keeps
    # one child, attempt, actor, and credential generation.
    replay = worker.request("POST", "/v1/delegated-tasks", body, headers={"Idempotency-Key": "child"})["data"]
    assert replay["task_id"] == child
    actor_before = daemon.credentials.actor_metadata(qualification["credential_actor"])
    assert owner.request("POST", f"/v1/tasks/{child}/remote-activation", qualification) == qualification
    assert control(owner, child, "verify", activation_id=qualification["activation_id"]) == {"fresh": True}
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) == actor_before
    assert daemon.credentials.actor_metadata(WORKER_ACTOR) == before
    assert owner.task(parent["task_id"])["state"] == "running"
    assert daemon.service.store.conn.execute("SELECT count(*) FROM attempts WHERE task_id=?", (parent["task_id"],)).fetchone()[0] == 1
    assert len(daemon.service.store.delegated_children(parent["task_id"], parent["attempt_id"])) == 1
    assert set(actor_before["scopes"]) == set(WORKER_SCOPES)
    assert not {"admin", "tasks:write", "credentials:provision"} & set(actor_before["scopes"])
    child_claim = remote.request("POST", "/v1/tasks/claim", {"executor_id": qualification["credential_actor"],
        "capability_ids": [CHILD], "target": TARGET, "runtime_epoch": qualification["runtime_epoch"]},
        headers={"Idempotency-Key": "child-claim"})
    assert child_claim["task_id"] == child
    unrelated = daemon.service.store.conn.execute("SELECT id, status FROM tasks WHERE capability=? AND id!=?", (CHILD, child)).fetchall()
    assert len(unrelated) == 1 and unrelated[0]["status"] == "queued"
    assert child_claim["execution_request"] == {**REQUEST, "inputs": []}
    with pytest.raises(RuntimeError) as error:
        control(owner, child, "revoke", activation_id=qualification["activation_id"])
    assert error.value.status == 409
    remote.request("POST", f"/v1/attempts/{child_claim['attempt_id']}/settle",
        {**lease(child_claim), "outputs": []}, headers={"Idempotency-Key": "settle-child"})
    assert control(owner, child, "begin-drain", qualification=qualification)["state"] == "pending"
    assert control(owner, child, "finish-drain", qualification=qualification)["state"] == "drained"
    assert control(owner, child, "finish-drain", qualification=qualification)["state"] == "drained"
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) is None
    assert daemon.credentials.actor_metadata(WORKER_ACTOR) == before
    assert owner.task(parent["task_id"])["state"] == "running"


@pytest.mark.parametrize("caller", ["worker", "other_admin", "anonymous"])
def test_prepared_control_remains_authenticated_owner_only(custody, caller):
    daemon, owner, worker, _, child, qualification, placement, _ = custody
    if caller == "other_admin":
        token, _ = daemon.credentials.provision("synthetic-other-admin", ["admin"])
        actor = Api(daemon.endpoint, token)
    else:
        actor = worker if caller == "worker" else Api(daemon.endpoint, None)
    with pytest.raises(RuntimeError) as error:
        control(actor, child, "provision", qualification=qualification, placement=placement)
    assert error.value.status == 401
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) is None


@pytest.mark.parametrize("mutation", ["actor", "foreign_task", "parent_fence", "parent_attempt", "parent_lease", "epoch", "project", "stage", "request"])
def test_prepared_binding_rejects_forgery(custody, mutation):
    daemon, owner, worker, parent, child, qualification, placement, body = custody
    if mutation == "actor":
        qualification["credential_actor"] = WORKER_ACTOR
    elif mutation == "foreign_task":
        qualification["task_id"] = parent["task_id"]
    elif mutation == "epoch":
        qualification["runtime_epoch"] += 1
    elif mutation == "request":
        changed = copy.deepcopy(body)
        changed["task"]["execution_request"]["lifecycle"]["mode"] = "terminate"
        with pytest.raises(RuntimeError) as error:
            worker.request("POST", "/v1/delegated-tasks", changed, headers={"Idempotency-Key": "forged-child"})
        assert error.value.status in {401, 409, 422}
        return
    else:
        # Simulate durable binding corruption rather than forging privileged
        # worker fields (which ordinary admission already refuses).
        row = daemon.service.store.conn.execute("SELECT spec_digest FROM tasks WHERE id=?", (child,)).fetchone()
        spec = daemon.service.store._spec(row)
        if mutation == "parent_fence":
            spec["delegated_parent"]["parent_fence"] += 1
        elif mutation == "parent_attempt":
            spec["delegated_parent"]["parent_attempt_id"] = "foreign-attempt"
        elif mutation == "parent_lease":
            spec["delegated_parent"]["parent_lease_id"] = "foreign-lease"
        elif mutation == "project":
            spec["delegated_parent"]["project_id"] = "foreign-project"
        else:
            spec["delegated_stage"] = "compose"
        daemon.service.store.conn.execute("UPDATE tasks SET spec_digest=? WHERE id=?", (daemon.service.store._store_spec(spec), child))
    with pytest.raises(RuntimeError) as error:
        control(owner, child, "provision", qualification=qualification, placement=placement)
    assert error.value.status in {401, 409}


def test_parent_interruption_fences_new_work_and_allows_exact_retirement(custody):
    daemon, owner, _, parent, child, qualification, _, _ = custody
    activate(custody)
    owner.request("POST", f"/v1/tasks/{parent['task_id']}/cancel", {}, headers={"Idempotency-Key": "interrupt-parent"})
    with pytest.raises(RuntimeError) as error:
        control(owner, child, "enable", activation_id=qualification["activation_id"])
    assert error.value.status == 409
    assert control(owner, child, "begin-drain", qualification=qualification)["state"] == "pending"
    assert control(owner, child, "finish-drain", qualification=qualification)["state"] == "drained"
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) is None


@pytest.mark.parametrize("phase", ["provision", "enable", "claim"])
def test_closed_parent_delegation_cannot_start_prepared_work(custody, phase):
    daemon, owner, _, parent, child, qualification, placement, _ = custody
    if phase in {"enable", "claim"}:
        remote = activate(custody)
    row = daemon.service.store.conn.execute("SELECT spec_digest FROM tasks WHERE id=?", (parent["task_id"],)).fetchone()
    spec = daemon.service.store._spec(row)
    spec["delegation_closed_attempt_id"] = parent["attempt_id"]
    daemon.service.store.conn.execute("UPDATE tasks SET spec_digest=? WHERE id=?", (daemon.service.store._store_spec(spec), parent["task_id"]))
    if phase == "claim":
        result = remote.request("POST", "/v1/tasks/claim", {"executor_id": qualification["credential_actor"],
            "capability_ids": [CHILD], "target": TARGET, "runtime_epoch": qualification["runtime_epoch"]},
            headers={"Idempotency-Key": "closed-claim"})
        assert isinstance(result, tuple) and result[0] == b""
        assert owner.task(child)["state"] == "cancelled"
        assert daemon.service.store.conn.execute("SELECT count(*) FROM attempts WHERE task_id=?", (child,)).fetchone()[0] == 0
        return
    with pytest.raises(RuntimeError) as error:
        if phase == "provision":
            control(owner, child, phase, qualification=qualification, placement=placement)
        else:
            control(owner, child, phase, activation_id=qualification["activation_id"])
    assert error.value.status in {401, 409}


@pytest.mark.parametrize("unknown_actor", [None, "legacy-actor", "astrid-prepared-forged"])
def test_only_exact_prepared_actor_exempts_shared_custody_guard(custody, unknown_actor):
    daemon, _, _, _, child, qualification, _, _ = custody
    activate(custody)
    assert daemon._has_unrevoked_remote_activation() is False
    unknown = {**qualification, "activation_id": "unknown-activation"}
    if unknown_actor is None:
        unknown.pop("credential_actor")
    else:
        unknown["credential_actor"] = unknown_actor
    with daemon.service.store._transaction():
        daemon.service.store._append_event(qualification["run_id"], child, "task.remote_activation_qualified", unknown)
    assert daemon._has_unrevoked_remote_activation() is True


def test_new_owner_fences_old_prepared_generation_before_authenticated_http(custody):
    daemon, _, _, _, child, qualification, _, _ = custody
    remote = activate(custody)
    old_generation = daemon.credentials.actor_metadata(qualification["credential_actor"])
    old_token = remote.credential
    daemon.stop()
    daemon.start()
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) == old_generation
    stale = Api(daemon.endpoint, old_token)
    with pytest.raises(RuntimeError) as error:
        stale.register_executor(qualification["credential_actor"], [CHILD])
    assert error.value.status == 401
    owner = Api(daemon.endpoint, daemon.token)
    assert control(owner, child, "revoke", activation_id=qualification["activation_id"]) == {"revoked": True}
    assert daemon.credentials.actor_metadata(qualification["credential_actor"]) is None
