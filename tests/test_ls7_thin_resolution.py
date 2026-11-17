"""LS-7 descriptor custody, pre-admission refusal, and frozen replay."""
from __future__ import annotations

import copy
import hashlib

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, ValidationError
from runtime_protocol.resolution import DESCRIPTOR_KEY, FORMAT, ResolutionRefusal, ResolutionUnavailable, descriptor_digest
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


DIGEST = "sha256:" + hashlib.sha256(b"ls7.scalar.v1").hexdigest()


def descriptor(**changes):
    return {"format": FORMAT, "entry_id": "scalar", "capability_id": "ls7.scalar", "capability_digest": DIGEST,
            "source_digest": "source-v1", "source_epoch": "epoch-v1", "settings_digest": "settings-v1", "placement_generation": "placement-v1", "project_id": None,
            "inputs": [{"name": "prompt", "type": "string", "required": True, "aliases": ["text"]},
                       {"name": "width", "type": "integer", "default": 512, "min": 1, "max": 2048},
                       {"name": "seed", "type": "integer"}],
            "seed_parameter": "seed", "admission": {"spec": {"pack": "scalar"}},
            "bindings": {name: ["spec", "inputs", name] for name in ("prompt", "width", "seed")}, **changes}


def registration(service, value=None):
    return {"executor_id": "scalar-host", "runtime_epoch": service._runtime_state["runtime_epoch"],
            "source_digest": "source-v1", "source_epoch": "epoch-v1",
            "capabilities": [{"capability_id": "ls7.scalar", "definition_digest": DIGEST}],
            "resolution_descriptors": [value or descriptor()]}


@pytest.fixture
def service(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    value = RuntimeService(tmp_path / "realm")
    value.register_executor(registration(value), idempotency_key="register")
    yield value
    value.close()


def request(key="create", **changes):
    return {"thin_request": {"format": FORMAT, "entry_id": "scalar", "values": {"prompt": "hello"}, **changes}, "idempotency_key": key}


def claim(service, key="claim"):
    return service.claim_next({"executor_id": "scalar-host", "capability_ids": ["ls7.scalar"], "runtime_epoch": service._runtime_state["runtime_epoch"]}, idempotency_key=key)


def test_scalar_defaults_frozen_seed_and_three_lifecycle_commits(service):
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    created = service.create_task(request())
    values = created["task"]["spec"]["spec"]["inputs"]
    assert values["prompt"] == "hello" and values["width"] == 512
    assert type(values["seed"]) is int and 0 <= values["seed"] < 2**32
    assert service.create_task(request())["task"]["id"] == created["task"]["id"]
    attempted = claim(service)
    service.settle_attempt(attempted["attempt_id"], {"lease_id": attempted["lease_id"], "fence": attempted["fence"], "runtime_epoch": attempted["runtime_epoch"], "outputs": []}, idempotency_key="settle")
    assert sum(s == "COMMIT" for s in statements) == 3
    assert service.store.get_task(created["task"]["id"])["task"]["status"] == "completed"


def test_replay_precedes_resolution_after_descriptor_change(service, monkeypatch):
    original = request()
    first = service.create_task(original)
    service.register_executor(registration(service, descriptor(settings_digest="settings-v2", inputs=[
        {"name": "prompt", "type": "string", "required": True}, {"name": "width", "type": "integer", "default": 1024}, {"name": "seed", "type": "integer"}
    ])), idempotency_key="register-v2")
    monkeypatch.setattr(service, "_resolution_descriptor", lambda *_: pytest.fail("a replay must not resolve again"))
    replay = service.create_task(original)
    assert replay["task"]["id"] == first["task"]["id"]
    assert replay["task"]["spec"]["spec"]["inputs"] == first["task"]["spec"]["spec"]["inputs"]
    with pytest.raises(ConflictError, match="different input"):
        service.create_task(request(values={"prompt": "changed"}))


def test_replay_keeps_authenticated_caller_identity(service):
    service.create_task(request(), identity={"actor": "alice"})
    with pytest.raises(ConflictError, match="different input"):
        service.create_task(request(), identity={"actor": "bob"})


@pytest.mark.parametrize("values,message", [({}, "missing required entry inputs: prompt"),
    ({"prompt": "hello", "width": True}, "entry input 'width' requires an integer"),
    ({"prompt": "hello", "width": 0}, "entry input 'width' violates min=1"),
    ({"prompt": "hello", "text": "other"}, "duplicate/conflicting entry inputs for 'prompt'"),
    ({"prompt": "hello", "path": "/etc/passwd"}, "unsupported entry inputs: path")])
def test_typed_input_refusals_have_no_admission_side_effects(service, values, message):
    with pytest.raises(ResolutionRefusal) as error:
        service.create_task(request(values=values))
    assert error.value.code == "input_rejected" and error.value.message == message
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='task.create'").fetchone()[0] == 0


def test_aliases_and_explicit_values_override_defaults(service):
    result = service.create_task(request(values={"text": "override", "width": 640, "seed": 7}))
    assert result["task"]["spec"]["spec"]["inputs"] == {"prompt": "override", "width": 640, "seed": 7}


def test_static_prerequisite_refusal_keeps_full_envelope(service):
    refusal = {"code": "missing_model", "message": "model is not installed", "details": {"next_action": "install the selected model"}}
    service.register_executor(registration(service, descriptor(refusal=refusal)), idempotency_key="refusal")
    with pytest.raises(ResolutionRefusal) as error:
        service.create_task(request())
    assert error.value.as_dict() == refusal
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0


@pytest.mark.parametrize("changes", [{"entry_id": "missing"}, {"descriptor_digest": "sha256:" + "0"*64}, {"format": "unknown/v9"}, {"input_paths": ["/etc/passwd"]}])
def test_missing_stale_forged_or_executable_request_falls_back_before_create(service, changes):
    with pytest.raises(ResolutionUnavailable):
        service.create_task(request(**changes))
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0


def test_descriptor_registration_checks_actor_source_and_capability(service):
    body = registration(service)
    with pytest.raises(AuthorizationError):
        service.register_executor(body, idempotency_key="wrong-actor", identity={"actor": "caller", "scopes": ["tasks:write"]})
    wrong = copy.deepcopy(body)
    wrong["resolution_descriptors"][0]["source_digest"] = "wrong"
    with pytest.raises(ValidationError, match="source_digest"):
        service.register_executor(wrong, idempotency_key="wrong-source")
    forged = copy.deepcopy(body)
    forged["capabilities"][0][DESCRIPTOR_KEY] = body["resolution_descriptors"]
    with pytest.raises(ValidationError, match="extra keys"):
        service.register_executor(forged, idempotency_key="raw-extra-key")
    executable = copy.deepcopy(body)
    executable["resolution_descriptors"][0]["callback"] = "some.module:resolve"
    with pytest.raises(ValidationError, match="unsupported"):
        service.register_executor(executable, idempotency_key="executable")


def test_source_change_between_resolution_and_commit_rolls_back(service, monkeypatch):
    from runtime_protocol import thin_requests
    original = thin_requests.resolve
    def changed(*args):
        result = original(*args)
        service.store.conn.execute("UPDATE executors SET source_digest='changed' WHERE id='scalar-host'")
        return result
    monkeypatch.setattr(thin_requests, "resolve", changed)
    with pytest.raises(ResolutionUnavailable, match="before admission"):
        service.create_task(request())
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0


def test_changed_descriptor_cannot_claim_frozen_task(service):
    task = service.create_task(request())
    service.register_executor(registration(service, descriptor(settings_digest="settings-v2")), idempotency_key="update")
    result = claim(service)
    assert result["waiting_reason"] == "resolution_descriptor_stale"
    assert result["task"]["task_id"] == task["task"]["id"]
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_scoped_settings_are_rechecked_at_admission_and_claim_but_not_replay(service):
    from runtime_protocol.util import canonical_json
    settings = {"defaults": {"image.t2i": {"pack": "scalar", "entry": "scalar"}}}
    actor = {"actor": "alice"}
    service.update_app_state("generation", settings, 0, "settings-v1", identity=actor)
    snapshot = descriptor(settings_ref={"actor": "alice", "key": "generation", "version": 1},
                          settings_digest="sha256:" + hashlib.sha256(canonical_json(settings).encode()).hexdigest())
    service.register_executor(registration(service, snapshot), idempotency_key="scoped-descriptor")
    with pytest.raises(ResolutionUnavailable):
        service.create_task(request("wrong-user"), identity={"actor": "bob"})
    first = service.create_task(request(), identity=actor)
    service.update_app_state("generation", {"defaults": {}}, 1, "settings-v2", identity=actor)
    assert service.create_task(request(), identity=actor) == first
    with pytest.raises(ResolutionUnavailable):
        service.create_task(request("fresh-after-change"), identity=actor)
    assert claim(service)["waiting_reason"] == "resolution_descriptor_stale"
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1


def test_invalid_defaults_are_refused_at_registration(service):
    bad = descriptor(inputs=[{"name": "prompt", "type": "string", "default": 42},
                             {"name": "width", "type": "integer"}, {"name": "seed", "type": "integer"}])
    with pytest.raises(ValidationError, match="invalid resolution default"):
        service.register_executor(registration(service, bad), idempotency_key="bad-default")


def test_lost_create_response_replays_frozen_data_after_runtime_restart(service, monkeypatch):
    first = service.create_task(request())
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        monkeypatch.setattr(restarted, "_resolution_descriptor", lambda *_: pytest.fail("replay re-resolved"))
        replay = restarted.create_task(request())
        assert replay == first
        assert restarted.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        restarted.close()
