"""Owner state is independent of executor/profile source claims."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pickle
import shutil
import zlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from runtime_protocol import external_pack_sources as sources
from runtime_protocol import verified_host_launch as gate
from runtime_protocol.errors import AuthorizationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from tests.test_remote_worker_activation import OWNER
from tests.test_verified_host_launch import fixture_authority


COMMIT = "a" * 40
TREE = "b" * 40
REPOSITORY = "https://example.test/owner/tool.git"


def install_pack(collection, pack_id="tool", *, source=None, files=None, tamper_digest=False, pin_commit=COMMIT):
    """An installed collection in the Agent's record shape: <root>/.group.json,
    <root>/<pack>/{PIN,.build/definitions.json,...}; no git and no explicit grant."""
    files = files or {"__init__.py": b"", "action.py": b"ANSWER = 7\n", "pack.json": b'{"action":"tool"}'}
    root = collection / pack_id
    (root / ".build").mkdir(parents=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    source = source if source is not None else {"kind": "git", "repository": REPOSITORY, "revision": COMMIT, "tree": TREE}
    definition = {"path": "pack.json", "capability_kind": "action", "capability_id": "tool",
        "definition_digest": "sha256:" + gate.raw_digest({"action": "tool"})}
    git = source["kind"] == "git"
    record = {"version": 1, "repository": source.get("repository") if git else None, "revision": source.get("revision") if git else None,
        "tree": source.get("tree") if git else None, "subpath": "packs/tool", "source": source, "definitions": [definition]}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    (root / ".build" / "definitions.json").write_bytes(raw)
    source_digest = "c" * 64
    (root / "PIN").write_bytes(json.dumps({"commit": pin_commit, "digest": source_digest, "origin": "git"}).encode() + b"\n")
    state = {"version": 1, "revision": 1, "transaction_id": "d" * 32, "removals": [], "refresh": None,
        "admissions": {pack_id: {"packId": pack_id, "sourceDigest": source_digest, "committedRevision": 1,
            "transactionId": "d" * 32, "definitionsDigest": ("0" * 64 if tamper_digest else hashlib.sha256(raw).hexdigest())}}}
    (collection / ".group.json").write_text(json.dumps(state))
    return root


@pytest.fixture
def owner_source(tmp_path):
    f = fixture_authority(tmp_path)
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    service = RuntimeService(realm, support_root=tmp_path / "support")
    collection = tmp_path / "home" / "Astrid" / "packs"; collection.mkdir(parents=True)
    root = install_pack(collection)
    files = {name: (root / name).read_bytes() for name in ("__init__.py", "action.py", "pack.json")}
    grant = sources._derive_installed_grant(str(collection), "tool")
    profile = f.args["preparation"]["profile"]
    profile.update(workspace_uuid=service.realm["id"], host_launch={"additional_pack_roots": [{"path": str(root), "files": grant["files"]}]})
    f.args["config"]["installed_pack_root"] = str(collection)
    f.record["selected_profile_digest"] = gate.raw_digest(profile)
    f.record["import_binding"]["mode"] = gate.TRUSTED_LOCAL_MODE
    yield SimpleNamespace(f=f, service=service, grant=grant, root=root, files=files, collection=collection,
        capture=lambda: sources.OwnerSourceCapture(preparation=f.args["preparation"], config=f.args["config"]))
    service.store.close()


def test_installed_pack_is_selectable_and_runnable_with_no_explicit_grant(owner_source, monkeypatch):
    """(a) The grant is derived from the selected installed root; nothing wrote grants.json first."""
    from runtime_protocol.store import selected_installed_pack_root
    case = owner_source; f = case.f
    monkeypatch.setenv("HOME", str(case.collection.parents[1]))
    assert selected_installed_pack_root() == case.collection
    assert not sources._state_path(case.service.support_root).exists()
    capture = case.capture()
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    argv, payload = verifier.claim(proof, **f.args, binding_fd=31)
    assert argv[1:5] == ["-X", "utf8", "-I", "-S"]
    body = json.loads(payload)["external_pack_sources"]
    source = body["sources"][0]
    assert (source["repository"], source["revision"], source["tree"]) == (REPOSITORY, COMMIT, TREE)
    assert {name: base64.b64decode(value) for name, value in source["contents"].items() if name in case.files} == case.files
    # The Agent-facing select() accepts the derived definition and nothing else.
    handle = gate._RuntimeExternalSources(capture.payload)
    chosen = json.loads(handle.select(scope=body["scope"], selected_profile_digest=body["selected_profile_digest"],
        root=str(case.root), definition=copy.deepcopy(case.grant["definitions"][0])))
    assert chosen["source"]["root"] == str(case.root)
    with pytest.raises(gate.HostLaunchError, match="already attempted"):
        verifier.claim(proof, **f.args, binding_fd=31)
    with pytest.raises(gate.HostLaunchError, match="already claimed"):
        capture.claim(preparation=f.args["preparation"], config=f.args["config"])


def test_pack_outside_the_selected_installed_root_is_refused(owner_source, tmp_path):
    """(b) An arbitrary path, even a fully valid install record, has no grant."""
    case = owner_source
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    foreign = install_pack(elsewhere)
    grant = sources._derive_installed_grant(str(elsewhere), "tool")
    case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"] = [{"path": str(foreign), "files": grant["files"]}]
    with pytest.raises(gate.HostLaunchError, match="no owner grant: it is outside the selected installed pack collection"):
        case.capture()
    assert not sources._state_path(case.service.support_root).exists()


def test_no_selected_installed_root_means_no_grant(owner_source):
    del owner_source.f.args["config"]["installed_pack_root"]
    with pytest.raises(gate.HostLaunchError, match="no installed pack collection is selected"):
        owner_source.capture()


def test_explicit_grant_writer_no_longer_exists():
    # One grant path only: the dead owner-only writer and its explicit-grant tests were removed.
    assert not hasattr(sources, "_write_owner_grants")


@pytest.mark.parametrize("edge,reason", [
    ("definitions", "definitions record differs from its admission digest"),
    ("admission", "definitions record differs from its admission digest"),
    ("admission-source", "admission does not verify"),
    ("revision", "definitions revision differs from the install source commit"),
    ("no-binding", "binds no definitions record"),
    ("unadmitted", "admission does not verify"),
    ("folder", "local folder"),
    ("bytes", "no owner grant"),
    ("inventory", "no owner grant"),
])
def test_edited_or_unverifiable_install_records_are_refused_with_a_named_reason(owner_source, edge, reason):
    case = owner_source; build = case.root / ".build"; group = case.collection / ".group.json"
    state = json.loads(group.read_text())
    if edge == "definitions":
        record = json.loads((build / "definitions.json").read_text())
        record["definitions"][0]["capability_id"] = "forged"
        (build / "definitions.json").write_text(json.dumps(record))
    elif edge == "admission":
        state["admissions"]["tool"]["definitionsDigest"] = "1" * 64; group.write_text(json.dumps(state))
    elif edge == "admission-source":
        state["admissions"]["tool"]["sourceDigest"] = "short"; group.write_text(json.dumps(state))
    elif edge == "revision":
        pin = json.loads((case.root / "PIN").read_text()); pin["commit"] = "f" * 40
        (case.root / "PIN").write_text(json.dumps(pin) + "\n")
    elif edge == "no-binding":
        del state["admissions"]["tool"]["definitionsDigest"]; group.write_text(json.dumps(state))
    elif edge == "unadmitted":
        state["admissions"] = {}; group.write_text(json.dumps(state))
    elif edge == "folder":
        shutil.rmtree(case.collection); case.collection.mkdir()
        case.root = install_pack(case.collection, source={"kind": "folder", "path": "/somewhere"})
    elif edge == "bytes": (case.root / "action.py").write_bytes(b"FORGED = 1\n")
    else: (case.root / "extra.py").write_bytes(b"EXTRA = 1\n")
    with pytest.raises(gate.HostLaunchError, match=reason): case.capture()


@pytest.mark.parametrize("name", ["astrid.py", "astrid_runtime_client.py", "runtime_protocol.py", "astrid/__init__.py"])
def test_installed_pack_cannot_authorize_reserved_package_collision(owner_source, name):
    path = owner_source.root / name; path.parent.mkdir(exist_ok=True); path.write_bytes(b"")
    with pytest.raises(gate.HostLaunchError, match="collision"):
        sources._derive_installed_grant(str(owner_source.collection), "tool")


@pytest.mark.parametrize("edge", ["descendant", "root", "state"])
def test_aliases_never_become_source_authority(owner_source, edge, tmp_path):
    case = owner_source
    if edge == "descendant": (case.root / "alias.py").symlink_to(case.root / "action.py")
    elif edge == "root":
        alias = case.collection / "alias"; alias.symlink_to(case.root, target_is_directory=True)
        case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"][0]["path"] = str(alias)
    else:
        case.capture()
        path = sources._state_path(case.service.support_root)
        other = tmp_path / "other-state"; other.write_bytes(path.read_bytes()); other.chmod(0o600)
        path.unlink(); path.symlink_to(other)
    with pytest.raises(gate.HostLaunchError): case.capture()


@pytest.mark.parametrize("edge", ["bytes", "owner-grant", "foreign-scope", "same-bytes-replacement"])
def test_capture_to_claim_toctou_and_foreign_scope_refused(owner_source, edge):
    case = owner_source; capture = case.capture(); f = case.f
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    if edge == "bytes": (case.root / "action.py").write_bytes(b"changed after verify")
    elif edge == "owner-grant":
        from runtime_protocol.local_execution_handoff import write_protected
        write_protected(sources._state_path(case.service.support_root), {"workspace_uuid": case.service.realm["id"], "grants": []})
    elif edge == "same-bytes-replacement":
        replacement = case.root / "replacement"
        replacement.write_bytes(case.files["action.py"])
        replacement.replace(case.root / "action.py")
    else: f.args["preparation"]["owner_epoch"] = "foreign"
    with pytest.raises(gate.HostLaunchError): verifier.claim(proof, **f.args, binding_fd=31)


def test_retained_child_observation_rejects_source_mutation(owner_source):
    case = owner_source; capture = case.capture(); f = case.f
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args); verifier.claim(proof, **f.args, binding_fd=31)
    child = SimpleNamespace(pid=42); identity = {"pid": 42, "birth_id": "original"}
    verifier.bind_child(proof, child=child, identity=identity)
    (case.root / "action.py").write_bytes(b"changed after child binding")
    with pytest.raises(gate.HostLaunchError): verifier.verify_child(proof, child=child, identity=identity)


@pytest.mark.parametrize("edge", ["definition", "root", "scope", "profile"])
def test_agent_selection_requires_exact_owner_definition_and_launch_scope(owner_source, edge):
    capture = owner_source.capture(); body = json.loads(capture.payload)
    handle = gate._RuntimeExternalSources(capture.payload)
    args = {"scope": body["scope"], "selected_profile_digest": body["selected_profile_digest"],
        "root": owner_source.grant["root"], "definition": copy.deepcopy(owner_source.grant["definitions"][0])}
    assert json.loads(handle.select(**args))["source"]["contents"] == body["sources"][0]["contents"]
    if edge == "definition": args["definition"]["definition_digest"] = "sha256:" + "f" * 64
    elif edge == "root": args["root"] = "/foreign"
    elif edge == "scope": args["scope"] = {**body["scope"], "owner_epoch": "foreign"}
    else: args["selected_profile_digest"] = "f" * 64
    with pytest.raises(gate.HostLaunchError): handle.select(**args)
    with pytest.raises(TypeError): pickle.dumps(handle)


def test_cli_never_runs_before_private_agent_consumer():
    called = []
    module = SimpleNamespace(__file__="selected-host.py", _cli=lambda: called.append("discovery"))
    with pytest.raises(gate.HostLaunchError, match="no private Runtime source consumer"):
        gate._run_external_host(module, b"{}", ["run"])
    assert called == []
    module._consume_runtime_external_sources = lambda **kwargs: called.append(kwargs["sources"].inventory())
    with pytest.raises(SystemExit): gate._run_external_host(module, b"{}", ["run"])
    assert called == [b"{}", "discovery"]


def test_equal_profile_inventory_cannot_substitute_for_private_capture(owner_source):
    f = owner_source.f
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    with pytest.raises(gate.HostLaunchError, match="lacks private owner capture"): verifier.verify(**f.args)


def test_caller_admission_map_digest_and_environment_never_create_grant(owner_source, monkeypatch, tmp_path):
    case = owner_source
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir(); foreign = install_pack(elsewhere)
    case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"] = [
        {"path": str(foreign), "files": sources._derive_installed_grant(str(elsewhere), "tool")["files"]}]
    monkeypatch.setenv("ASTRID_SOURCE_STATE", str(case.root / "pack.json"))
    monkeypatch.setenv("ASTRID_PACKS_PATH", str(elsewhere))
    monkeypatch.setenv("PYTHONPATH", str(case.root))
    case.f.args["config"]["external_source_grants"] = [case.grant]
    with pytest.raises(gate.HostLaunchError, match="no owner grant"): case.capture()


def test_production_preparer_admits_external_sources_before_any_child_transport(owner_source, monkeypatch):
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.local_worker import _digest
    from tests.test_local_worker import host_only_profile_case

    case = owner_source
    selected = host_only_profile_case()
    assert selected.host_launch is not None
    launch = {**selected.host_launch, "additional_pack_roots": [{"path": str(case.root), "files": case.grant["files"]}]}
    profile = replace(selected, workspace_uuid=case.service.realm["id"], support_root=case.service.support_root,
        host_launch=launch, session_config_digest=_digest(launch))
    config = {**launch, "support_root": str(case.service.support_root), "runtime_instance_id": "epoch"}
    monkeypatch.setattr(composition.socket, "socketpair", lambda: pytest.fail("transport before source admission"))
    preparer = cast(Any, composition.CrossProcessWorkerPreparer)(profile=profile, config=config, environment={})
    with pytest.raises(gate.HostLaunchError, match="no owner grant"):
        preparer._prepare_host_only(profile, operation_id="op", channel_id="channel")


def test_capture_is_nonserializable_and_keeps_bytes_after_files_change(owner_source):
    capture = owner_source.capture(); original = capture.payload
    with pytest.raises(TypeError): pickle.dumps(capture)
    (owner_source.root / "action.py").write_bytes(b"mutated")
    assert capture.payload == original
    assert base64.b64decode(json.loads(original)["sources"][0]["contents"]["action.py"]) == b"ANSWER = 7\n"


def test_empty_reserved_namespace_is_also_a_collision(owner_source):
    (owner_source.root / "runtime_protocol").mkdir()
    with pytest.raises(gate.HostLaunchError, match="collision"): owner_source.capture()


