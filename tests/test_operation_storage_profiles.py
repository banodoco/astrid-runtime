"""Synthetic Runtime boundaries; no client gates or producer arithmetic claims."""
import copy
import io
import json
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from generators import generate
from runtime_protocol.auth import CredentialStore
from runtime_protocol.contract_metadata import OPERATIONS, OPERATION_VERSIONS, SCHEMA_DIGEST
from runtime_protocol.errors import ConflictError, RuntimeErrorBase, ValidationError
from runtime_protocol.operation_versions import normalize_operation_versions, supports_operation
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.paired_session import PairedSessionAuthority
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

DIGEST = "sha256:" + "a" * 64
ESTIMATOR = {"id": "fixture.plan", "version": 1, "implementation_digest": "sha256:" + "b" * 64}
REQUEST = {"mode": "request_estimated", "estimator": ESTIMATOR}


@pytest.fixture
def service(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    value = RuntimeService(tmp_path / "realm")
    try:
        yield value
    finally:
        value.close()


def register(service, contract=None, *, executor="fixture-worker", digest=DIGEST, capability="fixture.action"):
    descriptor = {"capability_id": capability, "definition_digest": digest,
                  "estimated_scratch_bytes": 0, "estimated_output_bytes": 0}
    if contract is not None:
        descriptor["storage_estimate_contract"] = contract
    return service.register_executor({"executor_id": executor, "capabilities": [descriptor]},
                                     idempotency_key="register-" + executor)


def body(pair=None):
    value = {"capability_id": "fixture.action", "capability_digest": DIGEST,
             "idempotency_key": "same-request", "spec": {"message": "hello"}}
    if pair is not None:
        value["storage_estimate"] = pair
    return value


def snapshot(service):
    return {table: [tuple(row) for row in service.store.conn.execute("SELECT * FROM " + table)]
            for table in ("tasks", "runs", "events", "command_idempotency")}


def test_exact_membership_and_legacy_singleton():
    assert normalize_operation_versions({"additive": [2, 1, 2], "legacy": 2}) == {"additive": [1, 2], "legacy": [2]}
    assert supports_operation({"op": [1, 2]}, "op", 1)
    assert not supports_operation({"op": [2]}, "op", 1)
    assert not supports_operation({"op": 2}, "op", 1)
    assert not supports_operation({"op": [1]}, "missing", 1)


@pytest.mark.parametrize("versions", [[], [0], [-1], [True], [1.0], [float("inf")], [float("nan")], "1", None, {}, [1, "2"]])
def test_operation_descriptor_refuses_invalid_versions(versions):
    with pytest.raises(ValueError):
        normalize_operation_versions({"op": versions})


def contract_fixture(tmp_path, monkeypatch, versions):
    contract = tmp_path / "contract"
    contract.mkdir()
    (contract / "manifest.json").write_text('{"openapi":"wire.yaml"}')
    (contract / "wire.yaml").write_text("info:\n  x-operation-version: 1\npaths:\n  /fixture:\n    get:\n      operationId: fixture\n      x-operation-versions: " + json.dumps(versions) + "\n    post:\n      operationId: other\n")
    monkeypatch.setattr(generate, "ROOT", tmp_path)
    return contract / "manifest.json"


@pytest.mark.parametrize("versions,expected", [(1, [1]), ([2], [2]), ([2, 1, 2], [1, 2])])
def test_generation_is_deterministic_and_source_declared(tmp_path, monkeypatch, versions, expected):
    manifest = contract_fixture(tmp_path, monkeypatch, versions)
    first = generate.operation_versions(manifest)
    assert first == {"fixture": expected, "other": [1]}
    assert json.dumps(first) == json.dumps(generate.operation_versions(manifest))


@pytest.mark.parametrize("versions", [[], [0], [True], [1.5], "1", None])
def test_generation_refuses_invalid_contract_versions(tmp_path, monkeypatch, versions):
    manifest = contract_fixture(tmp_path, monkeypatch, versions)
    with pytest.raises(ValueError):
        generate.operation_versions(manifest)


def test_generated_inventory_preserves_every_r4_operation():
    assert set(OPERATION_VERSIONS) == set(OPERATIONS) == set(generate.operation_index())
    assert OPERATION_VERSIONS == generate.operation_versions()
    assert OPERATION_VERSIONS["listCapabilities"] == [1, 2]
    assert OPERATION_VERSIONS["createDocument"] == [1, 2]
    assert OPERATION_VERSIONS["updateDocument"] == [1, 2]
    assert all(value == [1] for key, value in OPERATION_VERSIONS.items() if key not in {"listCapabilities", "createDocument", "updateDocument"})


def test_static_zero_request_and_unavailable_are_distinct(service):
    register(service, {"mode": "static", "scratch_bytes": 0, "output_bytes": 0}, capability="static", executor="static")
    acknowledgment = register(service, REQUEST, capability="request", executor="request")
    assert acknowledgment["capabilities"][0]["status"] == "unsupported"
    register(service, {"mode": "unavailable", "reason": "fixture_no_bound"}, capability="unknown", executor="unknown")
    page = service.list_capabilities(catalog_version=2)
    assert page["catalog_version"] == 2
    rows = {row["capability_id"]: row for row in page["items"]}
    assert rows["static"]["storage_estimate"] == {"mode": "static", "scratch_bytes": 0, "output_bytes": 0}
    assert rows["static"]["status"] == "ready"
    assert rows["request"]["storage_estimate"] == REQUEST
    assert rows["request"]["status"] == "unavailable"
    assert rows["request"]["unavailable_reason"] == "preparation_binding_unavailable"
    assert rows["unknown"]["storage_estimate"] == {"mode": "unavailable", "reason": "fixture_no_bound"}
    assert all("estimated_scratch_bytes" not in row and "estimated_output_bytes" not in row for row in rows.values())
    assert all(None not in row["storage_estimate"].values() for row in rows.values())
    legacy = {row["capability_id"]: row for row in service.list_capabilities()["items"]}
    assert "catalog_version" not in service.list_capabilities()
    assert legacy["static"]["status"] == "ready"
    assert legacy["static"]["estimated_scratch_bytes"] == 0
    assert legacy["request"]["status"] == "unsupported"
    assert legacy["request"]["unavailable_reason"] == "request_estimated_requires_catalog_v2"


@pytest.mark.parametrize("version", [0, 3, True, "2", 2.0, None])
def test_unsupported_catalog_versions_refuse(service, version):
    with pytest.raises(ValidationError):
        service.list_capabilities(catalog_version=version)


@pytest.mark.parametrize("contract", [None, {}, {"mode": "unknown"}, {"mode": "static", "scratch_bytes": 1, "output_bytes": 0},
    {"mode": "request_estimated", "estimator": None},
    {"mode": "request_estimated", "estimator": {**ESTIMATOR, "version": True}},
    {"mode": "request_estimated", "estimator": {**ESTIMATOR, "implementation_digest": "bad"}},
    {"mode": "request_estimated", "estimator": {**ESTIMATOR, "argv": ["private"]}},
    {"mode": "unavailable", "reason": ""}])
def test_malformed_contract_registration_is_atomic(service, contract):
    before = snapshot(service)
    descriptor = {"capability_id": "fixture.action", "definition_digest": DIGEST, "storage_estimate_contract": contract}
    with pytest.raises(ValidationError):
        service.register_executor({"executor_id": "bad", "capabilities": [descriptor]}, idempotency_key="bad")
    assert snapshot(service) == before
    assert service.list_capabilities()["items"] == []
    assert service.store.conn.execute("SELECT COUNT(*) FROM executors").fetchone()[0] == 0


def test_request_pair_required_and_same_explicit_pair_reaches_claim(service):
    register(service, REQUEST)
    before = snapshot(service)
    with pytest.raises(ValidationError, match="requires task storage_estimate"):
        service.create_task(body())
    assert snapshot(service) == before
    with pytest.raises(ValidationError, match="requires task storage_estimate"):
        service.store.storage_preflight("fixture.action")
    assert service.store.storage_preflight("fixture.action", storage_estimate={"scratch_bytes": 0, "output_bytes": 0})["ok"]
    admitted = service.create_task(body({"scratch_bytes": 0, "output_bytes": 0}), _host_owned=True)
    assert admitted["task"].get("waiting_reason") is None
    assert service.create_task(body({"scratch_bytes": 0, "output_bytes": 0}), _host_owned=True) == admitted
    before = snapshot(service)
    with pytest.raises(ConflictError):
        service.create_task(body({"scratch_bytes": 1, "output_bytes": 0}), _host_owned=True)
    assert snapshot(service) == before
    claimed = service.claim_next({"executor_id": "fixture-worker", "capability_ids": ["fixture.action"], "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim")
    assert claimed["task_id"] == admitted["task"]["id"]
    assert claimed["storage_estimate"] == {"scratch_bytes": 0, "output_bytes": 0}


def test_legacy_static_projection_keeps_current_capability_estimates(service):
    register(service)
    service.register_capability({"capability_id": "fixture.action", "definition_digest": DIGEST,
                                 "estimated_scratch_bytes": 100, "estimated_output_bytes": 200})
    row = service.list_capabilities(catalog_version=2)["items"][0]
    assert row["storage_estimate"] == {"mode": "static", "scratch_bytes": 100, "output_bytes": 200}
    assert row["status"] == "ready"
    assert service.store.storage_preflight("fixture.action")["required_bytes"] == 300


@pytest.mark.parametrize("pair", [{"scratch_bytes": float("nan"), "output_bytes": 0},
    {"scratch_bytes": float("inf"), "output_bytes": 0}, {"scratch_bytes": "1", "output_bytes": 0},
    {"scratch_bytes": None, "output_bytes": 0}, {"scratch_bytes": 0, "output_bytes": False},
    {"scratch_bytes": 2**53-1, "output_bytes": 1}])
def test_request_pair_malformed_before_any_mutation(service, pair):
    register(service, REQUEST)
    before = snapshot(service)
    with pytest.raises(ValidationError):
        service.create_task(body(pair))
    assert snapshot(service) == before


def test_pair_and_spec_identity_survive_catalog_advance(service):
    register(service)
    original = body({"scratch_bytes": 10, "output_bytes": 20})
    first = service.create_task(original)
    # Advance the catalog without changing the immutable old request.
    register(service, REQUEST, executor="new-worker", digest="sha256:" + "c" * 64)
    assert service.create_task(copy.deepcopy(original)) == first
    before = snapshot(service)
    for field in ("storage_estimate", "spec"):
        changed = copy.deepcopy(original)
        changed[field] = {"scratch_bytes": 11, "output_bytes": 20} if field == "storage_estimate" else {"message": "changed"}
        with pytest.raises(ConflictError):
            service.create_task(changed)
        assert snapshot(service) == before


def test_conflicting_exact_descriptors_fail_closed_and_other_digest_is_ignored(service):
    register(service, REQUEST)
    register(service, executor="other-source", digest="sha256:" + "c" * 64)
    # Current capability selects c; old a request descriptor cannot retarget c.
    assert service.list_capabilities(catalog_version=2)["items"][0]["storage_estimate"]["mode"] == "static"
    register(service, executor="conflict")
    row = service.list_capabilities(catalog_version=2)["items"][0]
    assert row["storage_estimate"] == {"mode": "unavailable", "reason": "conflicting_storage_estimate_contracts"}
    with pytest.raises(ValidationError):
        service.create_task(body())
    assert not service.store.matching_live_executor("fixture.action", DIGEST)


def test_standalone_registration_cannot_silently_drop_contract(service):
    with pytest.raises(ValidationError, match="executor descriptor"):
        service.register_capability({"capability_id": "fixture.action", "definition_digest": DIGEST, "storage_estimate_contract": REQUEST})
    assert service.list_capabilities()["items"] == []


def test_http_identity_catalog_and_scope_boundaries(service, tmp_path):
    register(service, REQUEST)
    credentials = CredentialStore(tmp_path / "credentials")
    token = "a" * 64
    credentials.provision_static("fixture-reader", token, ["tasks:read", "handshake"])
    server = SimpleNamespace(runtime=service, credentials=credentials, accepting_authenticated_requests=True,
                             paired_sessions=PairedSessionAuthority(), daemon_runtime=SimpleNamespace(instance_id="fixture-runtime"))

    def route(path, method="GET", authenticated=True):
        handler = object.__new__(RuntimeHandler)
        handler.server, handler.path, handler.command = server, path, method
        handler.headers = Message()
        if authenticated:
            handler.headers["Authorization"] = "Bearer " + token
        handler.headers["Content-Length"] = "2"
        handler.rfile = io.BytesIO(b"{}")
        handler._send = lambda status, value=None, **kw: (status, value)
        try:
            return handler._route()
        except RuntimeErrorBase as exc:
            return exc.status, exc.as_dict()

    health = route("/v1/health")[1]
    for method in ("GET", "POST"):
        status, handshake = route("/v1/handshake", method)
        assert status == 200
        for key in ("protocol", "schema_digest", "runtime_epoch", "runtime_session_id", "runtime_instance_id", "operation_versions", "capability_catalog_versions"):
            assert handshake[key] == health[key]
    assert health["schema_digest"] == SCHEMA_DIGEST
    assert health["operation_versions"] == OPERATION_VERSIONS
    assert route("/v1/capabilities?catalog_version=2")[1]["catalog_version"] == 2
    assert route("/v1/capabilities?catalog_version=3")[0] == 422
    assert route("/v1/capabilities?catalog_version=")[0] == 422
    assert route("/v1/capabilities?catalog_version=2&catalog_version=1")[0] == 422
    assert route("/v1/capabilities?catalog_version=2", authenticated=False)[0] == 401
    assert route("/v1/capabilities", "POST")[0] == 401
    # Returned compatibility arrays cannot mutate the process's advertisement.
    health["operation_versions"]["admitTask"].append(99)
    assert 99 not in service.health()["operation_versions"]["admitTask"]


def test_v2_shapes_and_identity_validate_against_local_contract(service):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    schemas = [json.loads(path.read_text()) for path in (Path(__file__).parents[1] / "contract/schemas").glob("*.json")]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas if "$id" in schema)
    by_name = {schema["$id"].rsplit("/", 1)[-1]: schema for schema in schemas if "$id" in schema}
    validator = Draft202012Validator(by_name["capability-v2.json"], registry=registry)
    register(service, capability="static", executor="static")
    register(service, REQUEST, capability="request", executor="request")
    register(service, {"mode": "unavailable", "reason": "no_bound"}, capability="unknown", executor="unknown")
    for row in service.list_capabilities(catalog_version=2)["items"]:
        validator.validate(row)
        malformed = copy.deepcopy(row)
        malformed["storage_estimate"]["output_bytes"] = None
        assert not validator.is_valid(malformed)
    handshake = service.handshake({"authenticated_actor": "fixture", "authenticated_scopes": []})
    Draft202012Validator(by_name["handshake-response.json"], registry=registry).validate(handshake)
    health = {**service.health(), "runtime_instance_id": "fixture-runtime"}
    Draft202012Validator(by_name["health.json"], registry=registry).validate(health)
