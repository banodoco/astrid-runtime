"""Synthetic preparation-only transport boundaries; no producer integration claim."""
from runtime_protocol.contract_metadata import OPERATION_VERSIONS
from runtime_protocol.service import RuntimeService

def test_preparation_operation_is_implemented_and_declared():
    assert OPERATION_VERSIONS.get("prepareCapabilityStorage") == [1]
    assert callable(getattr(RuntimeService, "prepare_capability_storage", None))

def test_production_binding_projects_rich_launch_receipt_and_fences_revocation(runtime, tmp_path, monkeypatch):
    """Real bind_selected_host/configure/service validation; native launch is doubled."""
    from types import SimpleNamespace
    from astrid.core.execution import generic_host as hosts
    from runtime_protocol import local_preparation_relay as transport
    from runtime_protocol.daemon import WORKER_ACTOR
    d, _ = runtime
    source = hosts._canonical_digest({CAP: SOURCE.removeprefix("sha256:")})
    dependency = hosts._canonical_digest({CAP: DEPENDENCY.removeprefix("sha256:")})
    d.service.store.conn.execute("UPDATE executors SET source_digest=?,dependency_digest=? WHERE id='host'", (source, dependency))
    record = SimpleNamespace(id=CAP, has_request_storage_estimator=True,
        source_digest=SOURCE.removeprefix("sha256:"), dependency_digest=DEPENDENCY.removeprefix("sha256:"),
        capability_digest=SHA, request_storage_estimate_contract=CONTRACT)
    class Inventory:
        def __init__(self, **kwargs):
            assert kwargs["pack_roots"] == [str(tmp_path)]
        def discover(self): return [record]
        def shutdown(self): pass
    monkeypatch.setattr(hosts, "GenericPackHost", Inventory)
    class Actor:
        def verify(self): return copy.deepcopy(ACTOR)
    monkeypatch.setattr(transport.AuthenticatedCleanupActor, "current", lambda: Actor())
    handle = SimpleNamespace(closed=False, activated=True, retained=Actor())
    report = {"owner_epoch": d.service.runtime_instance_id,
              "processes": {"host": {k: ACTOR[k] for k in ("pid", "birth_id")}}}
    d.local_worker_preparer = SimpleNamespace(current_handle=lambda: handle,
        report=lambda value: report, timeout_seconds=1)
    receipt = {"host": {**report["processes"]["host"], "uid": ACTOR["uid"],
                       "executable": "/trusted/python", "artifact_digest": SHA},
               "executor_incarnation": "fixture-host"}
    d.credentials.provision(WORKER_ACTOR, ["worker:execute"], metadata={"local_launch_receipt": receipt}, rotate=True)
    verified = []
    monkeypatch.setattr(d, "_assert_local_relinquish_receipt", lambda value, metadata: verified.append(copy.deepcopy(value)))
    monkeypatch.setattr(transport.LocalPreparationRelay, "_paths", lambda self: None)
    profile = SimpleNamespace(execution_mode="host_only_cpu", support_root=tmp_path,
        host_launch={"pack_root": str(tmp_path), "executor_id": "host", "boot_manifest_hash": "e"*64})
    transport.bind_selected_host(d, profile, handle)
    relay = d.service._preparation_relay
    assert relay.binding["source_digest"] == source
    assert relay.binding["preparation_source_digest"] == SOURCE
    assert relay.binding["preparation_dependency_digest"] == DEPENDENCY
    assert relay.binding["host_instance_id"] == receipt["executor_incarnation"]
    assert verified and relay._selected_host_check is not None
    relay._selected_host_check()
    handle.closed = True
    with pytest.raises(RuntimeErrorBase):
        relay._selected_host_check()
    handle.closed = False
    d.credentials.revoke(WORKER_ACTOR)
    with pytest.raises(RuntimeErrorBase):
        relay._selected_host_check()


import copy
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import threading
import time

import pytest
from banodoco_local.custody_broker import AuthenticatedCleanupActor, CustodyError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.local_preparation_relay import (LocalPreparationRelay, PROTOCOL, COMMAND, FRAME_LIMIT,
    canonical, digest, validate_preparation)
from runtime_protocol.store import RealmStore

CAP = "rendering.render"
SHA = "sha256:" + "a" * 64
SOURCE = "sha256:" + "c" * 64
DEPENDENCY = "sha256:" + "d" * 64
ESTIMATOR = {"id": "fixture.plan", "version": 1, "implementation_digest": "sha256:" + "b" * 64}
CONTRACT = {"mode": "request_estimated", "estimator": ESTIMATOR}
SPEC = {"family": CAP, "params": {"extra": "é", "nested": [1, None, False]}, "output_policy": {"keep": True}}
BODY = {"capability_digest": SHA, "schema_version": 1, "spec": SPEC, "input_object_ids": []}
ACTOR = {"pid": os.getpid(), "uid": os.getuid(), "birth_id": "fixture-birth", "audit_token_sha256": SHA, "audit_token_pidversion": 1}


def prepared(request):
    result = {**copy.deepcopy(request), "spec_digest": digest(request["spec"]), "source_digest": SOURCE,
              "estimator": ESTIMATOR, "storage_estimate": {"scratch_bytes": 123, "output_bytes": 456}}
    result["preparation_digest"] = digest(result)
    return result


@pytest.fixture
def runtime(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    d = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    s = d.service
    project = s.create_project({"slug": "one", "name": "One"}, idempotency_key="project")["id"]
    s.register_executor({"executor_id": "host", "capabilities": [{"capability_id": CAP, "definition_digest": SHA,
        "storage_estimate_contract": CONTRACT}], "source_digest": SOURCE, "dependency_digest": DEPENDENCY,
        "source_epoch": "opaque:E1"}, idempotency_key="register")
    try:
        yield d, project
    finally:
        d.stop()


def binding_for(d, root):
    return dict(support_root=str(root), socket_path=str(root / "s"), readiness_record_path=str(root / "r.json"),
        runtime_process=copy.deepcopy(ACTOR), host_process=copy.deepcopy(ACTOR), realm_id=d.service.realm["id"], runtime_instance_id=d.instance_id,
        runtime_session_id=d.service.runtime_session_id, runtime_epoch=d.service.health()["runtime_epoch"],
        executor_id="host", source_epoch="opaque:E1", capability_id=CAP, capability_digest=SHA,
        storage_estimate_contract=CONTRACT, source_digest=SOURCE, dependency_digest=DEPENDENCY, preparation_source_digest=SOURCE, preparation_dependency_digest=DEPENDENCY,
        host_instance_id="fixture-host", boot_manifest_hash="e"*64, deadline_ms=1000)


def identity(d, token=None):
    token = token or d.token
    value = d.credentials.require(token, "tasks:write")
    return {**value, "_credential_binding": d.credentials._sha256(token.encode())}


def db_snapshot(s):
    # All persisted rows, including idempotency/reservation/history/output state.
    return list(s.store.conn.iterdump())


def http(d, project, body=BODY, token=None, context=None, suffix=None):
    channel = HTTPConnection("127.0.0.1", d.httpd.server_port, timeout=3)
    headers = {"Authorization": "Bearer " + (token or d.token), "Content-Type": "application/json"}
    if context is not None:
        headers["X-Reigh-Paired-Session"] = json.dumps(context)
    route = suffix or f"/v1/projects/{project}/capabilities/{CAP}/prepare"
    channel.request("POST", route, json.dumps(body), headers)
    response = channel.getresponse()
    result = response.status, json.loads(response.read())
    channel.close()
    return result


class FakeRelay:
    def __init__(self, binding, action=None):
        self.binding = binding
        self.action = action
        self.calls = 0
    def exchange(self, request):
        self.calls += 1
        if self.action:
            self.action(request)
        return prepared(request)


def install_fake(d, tmp_path, action=None):
    relay = FakeRelay(binding_for(d, tmp_path), action)
    d.service._preparation_relay = relay
    return relay


def test_http_route_alias_full_spec_pure_and_no_store_mutex(runtime, tmp_path):
    d, project = runtime
    def action(request):
        assert request["spec"] == SPEC and request["input_facts"] == []
        # A different handler must be able to acquire the store mutex in flight.
        acquired = []
        def take_lock():
            with d.service.store._mutex:
                acquired.append(True)
        thread = threading.Thread(target=take_lock); thread.start(); thread.join(0.5)
        assert acquired
    relay = install_fake(d, tmp_path, action)
    before = db_snapshot(d.service)
    status, value = http(d, "one")
    assert status == 200, value
    assert value == prepared({"capability_id": CAP, "capability_digest": SHA, "schema_version": 1, "spec": SPEC, "input_facts": []})
    assert relay.calls == 1 and db_snapshot(d.service) == before


@pytest.mark.parametrize("change", [{"schema_version": True}, {"schema_version": "1"}, {"schema_version": 2},
    {"input_facts": []}, {"executor_id": "host"}, {"source_epoch": "opaque:E1"}, {"socket_path": "/tmp/a"},
    {"host_process": ACTOR}, {"storage_estimate_contract": CONTRACT}, {"project": "one"}, {"spec": []},
    {"input_object_ids": None}, {"capability_digest": "bad"}])
def test_body_rejects_attestation_and_wrong_version_before_ipc(runtime, tmp_path, change):
    d, p = runtime; relay = install_fake(d, tmp_path)
    assert http(d, p, {**BODY, **change})[0] == 422
    assert relay.calls == 0


def test_nonempty_inputs_and_missing_endpoint_are_typed(runtime, tmp_path):
    d, p = runtime
    assert http(d, p)[1]["details"]["reason"] == "preparation_endpoint_unconfigured"
    relay = install_fake(d, tmp_path)
    status, value = http(d, p, {**BODY, "input_object_ids": ["sha256:any"]})
    assert status == 409 and value["details"]["reason"] == "input_facts_unavailable"
    assert relay.calls == 0


@pytest.mark.parametrize("scopes", [["tasks:read"], ["admin"], ["projects:read"], ["worker:execute"]])
def test_scope_denial(runtime, tmp_path, scopes):
    d, p = runtime; relay = install_fake(d, tmp_path)
    token, _ = d.credentials.provision("limited", scopes)
    assert http(d, p, token=token)[0] in (401, 403)
    assert relay.calls == 0


@pytest.mark.parametrize("change", ["source_epoch", "source_digest", "dependency_digest", "descriptor", "dead", "session", "epoch", "relay", "revoke"])
def test_rechecks_after_ipc(runtime, tmp_path, change):
    d, p = runtime; s = d.service
    def action(request):
        if change in {"source_epoch", "source_digest", "dependency_digest"}:
            s.store.conn.execute("UPDATE executors SET " + change + "=? WHERE id='host'", ("changed",))
        elif change == "descriptor":
            s.store.conn.execute("UPDATE executors SET capabilities_json='[]' WHERE id='host'")
        elif change == "dead":
            s.store.conn.execute("UPDATE executors SET last_seen_at='2000-01-01T00:00:00+00:00' WHERE id='host'")
        elif change == "session":
            s.runtime_session_id = "changed"
        elif change == "epoch":
            s._preparation_relay.binding["runtime_epoch"] += 1
        elif change == "relay":
            s._preparation_relay = None
        else:
            d.credentials.revoke("owner")
    install_fake(d, tmp_path, action)
    assert http(d, p)[0] in (401, 403, 409)


def test_wrong_capability_and_stale_binding_refuse_before_ipc(runtime, tmp_path):
    d, p = runtime; relay = install_fake(d, tmp_path)
    assert http(d, p, {**BODY, "capability_digest": "sha256:" + "f" * 64})[0] == 409
    relay.binding["source_epoch"] = "stale"
    assert http(d, p)[0] == 409
    assert relay.calls == 0


def test_paired_guard_and_capability_project_grants(runtime, tmp_path):
    d, p = runtime; s = d.service; relay = install_fake(d, tmp_path)
    s.select_project("connector", p)
    token, _ = d.credentials.provision_connector("connector", ["handshake", "projects:read", "projects:write", "tasks:write"],
        connector_id="c", realm_id=s.realm["id"], expires_at=time.time()+120)
    ctx = dict(pair_id="pair", connector_id="c", generation=1, realm_id=s.realm["id"], expires_at=int((time.time()+90)*1000))
    status, value = http(d, p, token=token, context=ctx)
    assert status == 200, value
    assert http(d, p, token=token)[0] == 403
    other = s.create_project({"slug": "two", "name": "Two"}, idempotency_key="p2")["id"]
    assert http(d, other, token=token, context=ctx)[0] == 403
    assert http(d, p, token=token, context=ctx, suffix=f"/v1/projects/{p}/timelines")[0] == 403
    assert http(d, p, token=token, context=ctx, suffix=f"/v1/projects/{p}/capabilities/foreign/prepare")[0] == 403
    assert relay.calls == 1


@pytest.mark.parametrize("field", ["preparation_digest", "spec_digest", "source_digest", "capability_id", "capability_digest", "spec", "estimator", "storage_estimate", "schema_version", "input_facts"])
def test_reply_tamper_refuses(runtime, tmp_path, field):
    d, p = runtime; b = binding_for(d, tmp_path)
    request = {"capability_id": CAP, "capability_digest": SHA, "schema_version": 1, "spec": SPEC, "input_facts": []}
    value = prepared(request)
    value[field] = True if field == "schema_version" else "tampered"
    with pytest.raises(RuntimeErrorBase):
        validate_preparation(value, request, b)


@pytest.fixture
def socket_relay(runtime, monkeypatch):
    d, _ = runtime
    # Short owner-only endpoint beneath task scratch; not a live host/store.
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="c100-", dir="/private/tmp"))
    root.chmod(0o700)
    relay = LocalPreparationRelay(binding_for(d, root))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(relay.binding["socket_path"]); os.chmod(relay.binding["socket_path"], 0o600); listener.listen(1)
    record = Path(relay.binding["readiness_record_path"]); record.write_bytes(canonical(relay.readiness_record())); record.chmod(0o600)
    class Actor:
        def verify(self): return copy.deepcopy(ACTOR)
    monkeypatch.setattr(AuthenticatedCleanupActor, "current", lambda: Actor())
    monkeypatch.setattr(AuthenticatedCleanupActor, "private_peer", lambda channel: Actor())
    monkeypatch.setattr("runtime_protocol.local_preparation_relay.default_process_identity", lambda pid: ACTOR)
    monkeypatch.setattr("runtime_protocol.local_preparation_relay.current_process_audit_token", lambda pid: {
        "pid": ACTOR["pid"], "uid": ACTOR["uid"], "pidversion": ACTOR["audit_token_pidversion"], "sha256": ACTOR["audit_token_sha256"]})
    yield relay, listener, root
    listener.close()
    for p in root.iterdir():
        p.unlink()
    root.rmdir()


def exchange_with_server(relay, listener, alter=None):
    seen = []
    def serve():
        with listener.accept()[0] as c:
            raw = bytearray()
            while b"\n" not in raw:
                part = c.recv(4096)
                if not part: return
                raw.extend(part)
            envelope = json.loads(raw); seen.append(envelope)
            reply = {k: v for k, v in envelope.items() if k != "request"}
            reply["preparation"] = prepared(envelope["request"])
            wire = canonical(reply)+b"\n"
            if alter: wire = alter(reply, wire)
            try: c.sendall(wire)
            except (BrokenPipeError, OSError): pass
    thread = threading.Thread(target=serve); thread.start()
    request = {"capability_id": CAP, "capability_digest": SHA, "schema_version": 1, "spec": SPEC, "input_facts": []}
    try:
        value = relay.exchange(request)
        return value, seen
    finally:
        thread.join(2)
        assert not thread.is_alive()


def test_real_socket_framing_and_correlation_with_mocked_native_peer(socket_relay):
    relay, listener, _ = socket_relay
    value, seen = exchange_with_server(relay, listener)
    assert value["storage_estimate"] == {"scratch_bytes": 123, "output_bytes": 456}
    assert seen[0]["protocol"] == PROTOCOL and seen[0]["command"] == COMMAND
    assert seen[0]["request_id"] and seen[0]["request"]["spec"] == SPEC


@pytest.mark.parametrize("alter", [lambda r,w:b'{}\n', lambda r,w:b'{bad\n', lambda r,w:b'{"x":1,"x":2}\n',
    lambda r,w:b'{"x":NaN}\n', lambda r,w:w+b'{}\n', lambda r,w:b'x'*(FRAME_LIMIT+1),
    lambda r,w:canonical({**r,"request_id":"wrong"})+b'\n',
    lambda r,w:canonical({**r,"source_epoch":"wrong"})+b'\n',
    lambda r,w:canonical({**r,"runtime":{}})+b'\n', lambda r,w:w[:-1]])
def test_malformed_oversized_uncorrelated_reply(socket_relay, alter):
    relay, listener, _ = socket_relay
    with pytest.raises(RuntimeErrorBase): exchange_with_server(relay, listener, alter)


def test_finite_timeout_does_not_kill_host(socket_relay):
    relay, listener, _ = socket_relay; relay._binding["deadline_ms"] = 50
    Path(relay.binding["readiness_record_path"]).write_bytes(canonical(relay.readiness_record()))
    begin = time.monotonic()
    with pytest.raises(RuntimeErrorBase) as e:
        exchange_with_server(relay, listener, lambda r,w:(time.sleep(.15) or w))
    assert e.value.details["reason"] == "preparation_deadline" and time.monotonic()-begin < 1
    assert listener.fileno() >= 0


@pytest.mark.parametrize("case", ["record_permissions", "root_permissions", "record_symlink", "socket_symlink", "record_stale", "missing", "dead_socket"])
def test_readiness_containment_and_lifecycle(socket_relay, case):
    relay, listener, root = socket_relay; b = relay.binding
    record = Path(b["readiness_record_path"]); endpoint = Path(b["socket_path"])
    if case == "record_permissions": record.chmod(0o644)
    elif case == "root_permissions": root.chmod(0o755)
    elif case == "record_symlink":
        other=root/"other"; record.rename(other); record.symlink_to(other)
    elif case == "socket_symlink":
        other=root/"other"; endpoint.rename(other); endpoint.symlink_to(other)
    elif case == "record_stale": record.write_bytes(canonical({**relay.readiness_record(),"source_epoch":"old"}))
    elif case == "missing": record.unlink()
    else: listener.close()
    request = {"capability_id": CAP, "capability_digest": SHA, "schema_version": 1, "spec": SPEC, "input_facts": []}
    with pytest.raises(RuntimeErrorBase): relay.exchange(request)


def test_wrong_peer_and_unsupported_native_identity(socket_relay, monkeypatch):
    relay, listener, _ = socket_relay
    class Wrong:
        def verify(self): return {**ACTOR, "audit_token_pidversion": 2}
    monkeypatch.setattr(AuthenticatedCleanupActor, "private_peer", lambda channel: Wrong())
    with pytest.raises(RuntimeErrorBase) as e:
        relay.exchange({})
    assert e.value.details["reason"] == "host_peer_mismatch"
    def unsupported(): raise CustodyError("unsupported")
    monkeypatch.setattr(AuthenticatedCleanupActor, "current", unsupported)
    with pytest.raises(RuntimeErrorBase) as e: relay.exchange({})
    assert e.value.details["reason"] == "peer_identity_unsupported"


def test_real_kernel_socket_via_daemon_binding_and_public_route(socket_relay, runtime, monkeypatch):
    relay, listener, root = socket_relay; d, project = runtime
    # Real Darwin verifier and same-process fixture listener; this is not J's Host.
    monkeypatch.undo()
    actor = AuthenticatedCleanupActor.current().verify()
    binding = relay.binding
    binding.update(runtime_process=actor, host_process=actor)
    relay = LocalPreparationRelay(binding)
    Path(binding["readiness_record_path"]).write_bytes(canonical(relay.readiness_record()))
    d.configure_preparation_relay(binding)
    seen = []
    def serve():
        with listener.accept()[0] as c:
            peer = AuthenticatedCleanupActor.private_peer(c).verify()
            assert peer == actor
            raw = bytearray()
            while b"\n" not in raw:
                raw.extend(c.recv(4096))
            envelope = json.loads(raw); seen.append(envelope)
            response = {k:v for k,v in envelope.items() if k != "request"}
            response["preparation"] = prepared(envelope["request"])
            c.sendall(canonical(response)+b"\n")
    thread = threading.Thread(target=serve); thread.start()
    before = db_snapshot(d.service)
    try:
        status, value = http(d, project)
        assert status == 200, value
        assert value["spec"] == SPEC and value["source_digest"] == SOURCE
        assert db_snapshot(d.service) == before
        assert seen[0]["context"]["runtime"]["runtime_instance_id"] == d.instance_id
    finally:
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize("field", ["pid", "birth_id", "audit_token_pidversion", "audit_token_sha256"])
def test_native_peer_requires_exact_configured_incarnation(socket_relay, monkeypatch, field):
    relay, listener, _ = socket_relay
    monkeypatch.undo()
    actor = AuthenticatedCleanupActor.current().verify()
    binding = relay.binding
    binding.update(runtime_process=actor, host_process={**actor, field: (actor[field]+1 if type(actor[field]) is int else "foreign")})
    # Hash field needs a valid but foreign hash at config validation.
    if field == "audit_token_sha256": binding["host_process"][field] = "sha256:"+"0"*64
    relay = LocalPreparationRelay(binding)
    Path(binding["readiness_record_path"]).write_bytes(canonical(relay.readiness_record()))
    with pytest.raises(RuntimeErrorBase) as e: relay.exchange({})
    assert e.value.details["reason"] == "host_peer_mismatch"


@pytest.mark.parametrize("change", ["missing_token", "boolean_pid", "outside_root", "relative", "symlink_root", "zero_deadline", "infinite_deadline", "extra", "wrong_descriptor"])
def test_trusted_startup_binding_is_closed(runtime, tmp_path, change):
    d, _ = runtime; b = binding_for(d, tmp_path)
    if change == "missing_token": del b["host_process"]["audit_token_sha256"]
    elif change == "boolean_pid": b["host_process"]["pid"] = True
    elif change == "outside_root": b["socket_path"] = "/private/tmp/other"
    elif change == "relative": b["readiness_record_path"] = "relative"
    elif change == "symlink_root": b["support_root"] = str(tmp_path/".."/"other")
    elif change == "zero_deadline": b["deadline_ms"] = 0
    elif change == "infinite_deadline": b["deadline_ms"] = float("inf")
    elif change == "extra": b["callable"] = "forbidden"
    else: b["storage_estimate_contract"] = {"mode":"static","scratch_bytes":0,"output_bytes":0}
    with pytest.raises(RuntimeErrorBase): LocalPreparationRelay(b)


def test_paired_authority_revoked_in_flight(runtime, tmp_path):
    d,p = runtime; s=d.service
    s.select_project("connector",p)
    token,_=d.credentials.provision_connector("connector",["tasks:write","handshake"],connector_id="c",realm_id=s.realm["id"],expires_at=time.time()+120)
    ctx=dict(pair_id="pair",connector_id="c",generation=1,realm_id=s.realm["id"],expires_at=int((time.time()+90)*1000))
    def action(request):
        grant=d.httpd.paired_sessions._sessions["pair"]
        d.httpd.paired_sessions.revoke(grant)
    install_fake(d,tmp_path,action)
    assert http(d,p,token=token,context=ctx)[0] == 403


def test_contract_schemas_clients_and_original_profiles_preserved():
    import subprocess
    from jsonschema import Draft202012Validator
    from generators import generate
    root=Path(__file__).resolve().parents[1]
    request_schema=json.loads((root/"contract/schemas/storage-preparation-request.json").read_text())
    reply_schema=json.loads((root/"contract/schemas/storage-preparation.json").read_text())
    request={"capability_id":CAP,"capability_digest":SHA,"schema_version":1,"spec":SPEC,"input_facts":[]}
    Draft202012Validator(request_schema).validate(BODY)
    # The schema admits strings so the service can issue the named no-input refusal.
    Draft202012Validator(request_schema).validate({**BODY,"input_object_ids":[SHA]})
    assert list(Draft202012Validator(request_schema).iter_errors({**BODY,"input_facts":[]}))
    Draft202012Validator(reply_schema).validate(prepared(request))
    assert list(Draft202012Validator(reply_schema).iter_errors({"preparation":prepared(request)}))
    old=json.loads(subprocess.check_output(["git","show","6f96b62e40eb5fde69500727053d626cf9d101b2:runtime_protocol/contract_metadata.py"]).decode().split("OPERATION_VERSIONS = ")[1].split("\n")[0].replace("'",'"'))
    assert len(old) == 139
    assert all(set(versions).issubset(OPERATION_VERSIONS[key]) for key, versions in old.items())
    assert len(OPERATION_VERSIONS) >= 140
    generate.validate_python_client(generate.render_python_client())
    generate.validate_typescript_client(source=generate.render_typescript_client())


def test_generated_python_client_sends_exact_body_and_flat_reply():
    from banodoco_workspace_client.generated import WorkspaceClient
    client=object.__new__(WorkspaceClient)
    calls=[]
    response={"capability_id":CAP,"capability_digest":SHA,"schema_version":1,"spec":SPEC,"input_facts":[]}
    value=prepared(response)
    def transport(method,path,**kwargs):
        calls.append((method,path,kwargs))
        return 200,{},json.dumps(value).encode()
    client._request=transport
    assert client.prepare_capability_storage("project/alias",CAP,BODY) == value
    assert calls[0][:2] == ("POST","/v1/projects/project%2Falias/capabilities/rendering.render/prepare")
    assert json.loads(calls[0][2]["body"]) == BODY


def test_preparation_can_quote_legacy_pending_status_without_enabling_execution(runtime, tmp_path):
    d,p=runtime; s=d.service
    reason="request storage estimator unsupported by legacy catalog; prepare/execute join required"
    descriptor={"capability_id":CAP,"definition_digest":SHA,"storage_estimate_contract":CONTRACT,
                "status":"unavailable","unavailable_reason":reason}
    s.store.conn.execute("UPDATE capabilities SET status='unavailable',unavailable_reason=? WHERE id=?",(reason,CAP))
    s.store.conn.execute("UPDATE executors SET capabilities_json=? WHERE id='host'",(json.dumps([descriptor]),))
    install_fake(d,tmp_path)
    before=db_snapshot(s)
    assert http(d,p)[0] == 200
    assert s.store.storage_preflight(CAP,storage_estimate={"scratch_bytes":123,"output_bytes":456})["ok"] is False
    assert db_snapshot(s) == before
    s.store.conn.execute("UPDATE capabilities SET unavailable_reason='producer_failed' WHERE id=?",(CAP,))
    assert http(d,p)[0] == 409


def test_descriptor_change_in_flight_is_discarded(runtime, tmp_path):
    d,p=runtime; s=d.service
    def action(request):
        row=s.store.conn.execute("SELECT capabilities_json FROM executors WHERE id='host'").fetchone()
        descriptor=json.loads(row[0]); descriptor[0]["unavailable_reason"]="changed"
        s.store.conn.execute("UPDATE executors SET capabilities_json=? WHERE id='host'",(json.dumps(descriptor),))
    install_fake(d,tmp_path,action)
    assert http(d,p)[0] == 409

@pytest.mark.parametrize("versions", [[True], [0], [-1], [], "1,2", [1, 2.0]])
def test_generated_health_rejects_invalid_catalog_negotiation(runtime, versions):
    from banodoco_workspace_client.generated import Health
    d, _ = runtime
    value = {**d.service.health(), "runtime_instance_id": d.instance_id,
             "capability_catalog_versions": versions}
    with pytest.raises(ValueError):
        Health.from_json(value)


def test_generated_health_keeps_authenticated_catalog_versions(runtime):
    from banodoco_workspace_client.generated import Health
    d, _ = runtime
    value = {**d.service.health(), "runtime_instance_id": d.instance_id}
    parsed = Health.from_json(value)
    assert parsed.capability_catalog_versions == [1, 2]
    value["capability_catalog_versions"].clear()
    assert parsed.capability_catalog_versions == [1, 2]
    del value["capability_catalog_versions"]
    assert Health.from_json(value).capability_catalog_versions is None


def test_request_estimated_catalog_admission_and_claim_use_explicit_pair(runtime):
    d, project = runtime
    service = d.service
    v1 = service.list_capabilities(catalog_version=1)["items"][0]
    v2 = service.list_capabilities(catalog_version=2)["items"][0]
    assert v1["status"] == "unsupported"
    assert v2["status"] == "ready" and v2["storage_estimate"] == CONTRACT
    authority = service.task_authority_for_identity(identity(d), project_id=project, operation=CAP)
    body = {"project": project, "capability_id": CAP, "capability_digest": SHA,
            "schema_version": "1", "spec": SPEC, "input_object_ids": [],
            "idempotency_key": "dynamic-task"}
    with pytest.raises(RuntimeErrorBase):
        service.create_task(body, enforce_readiness=True, authority_binding=authority)
    pair = {"scratch_bytes": 123, "output_bytes": 456}
    admitted = service.create_task({**body, "storage_estimate": pair},
        enforce_readiness=True, authority_binding=authority)
    assert admitted["task"]["status"] == "queued"
    assert service.store.storage_preflight(CAP, storage_estimate=pair)["estimate_source"] == "task"
    claimed = service.claim_next({"executor_id": "host", "capability_ids": [CAP],
        "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="dynamic-claim")
    assert claimed["task_id"] == admitted["task"]["id"]
    assert claimed["storage_estimate"] == pair

