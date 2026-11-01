"""Owner state is independent of executor/profile source claims."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pickle
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


def repository(root, files):
    """Real loose Git objects without invoking a Git mutation or hooks."""
    git = root / ".git"
    (git / "objects").mkdir(parents=True)
    (git / "refs/heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "config").write_text('[core]\nrepositoryformatversion = 0\nbare = false\n[remote "origin"]\nurl = https://example.test/owner/tool.git\n')

    def obj(kind, data):
        raw = kind.encode() + b" " + str(len(data)).encode() + b"\0" + data
        identity = hashlib.sha1(raw).hexdigest()
        path = git / "objects" / identity[:2] / identity[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        return identity

    tree = obj("tree", b"".join(b"100644 " + name.encode() + b"\0" + bytes.fromhex(obj("blob", data)) for name, data in sorted(files.items())))
    top = obj("tree", b"40000 tool\0" + bytes.fromhex(tree))
    commit = obj("commit", f"tree {top}\nauthor Owner <owner@example.test> 1 +0000\ncommitter Owner <owner@example.test> 1 +0000\n\nfixture\n".encode())
    (git / "refs/heads/main").write_text(commit + "\n")
    pack = root / "tool"; pack.mkdir()
    for name, data in files.items():
        (pack / name).write_bytes(data)
    return commit, tree, pack


@pytest.fixture
def owner_source(tmp_path):
    f = fixture_authority(tmp_path)
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    service = RuntimeService(realm, support_root=tmp_path / "support")
    files = {"__init__.py": b"", "action.py": b"ANSWER = 7\n", "pack.json": b'{"action":"tool"}'}
    revision, tree, root = repository(tmp_path / "repository", files)
    definition = {"path": "pack.json", "capability_kind": "action", "capability_id": "tool",
        "definition_digest": "sha256:" + gate.raw_digest({"action": "tool"})}
    grant = {"repository": "https://example.test/owner/tool.git", "checkout": str(root.parent),
        "revision": revision, "subpath": "tool", "tree": tree, "root": str(root),
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}, "definitions": [definition]}
    profile = f.args["preparation"]["profile"]
    profile.update(workspace_uuid=service.realm["id"], host_launch={"additional_pack_roots": [{"path": str(root), "files": grant["files"]}]})
    f.record["selected_profile_digest"] = gate.raw_digest(profile)
    f.record["import_binding"]["mode"] = gate.TRUSTED_LOCAL_MODE
    sources._write_owner_grants(service, [grant], identity=OWNER)
    yield SimpleNamespace(f=f, service=service, grant=grant, root=root, files=files,
        capture=lambda: sources.OwnerSourceCapture(preparation=f.args["preparation"], config=f.args["config"]))
    service.store.close()


def test_owner_grant_captures_real_exact_git_tree_before_one_use_launch(owner_source):
    case = owner_source; capture = case.capture(); f = case.f
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    argv, payload = verifier.claim(proof, **f.args, binding_fd=31)
    assert argv[1:5] == ["-X", "utf8", "-I", "-S"]
    body = json.loads(payload)["external_pack_sources"]
    source = body["sources"][0]
    assert source["revision"] == case.grant["revision"] and source["tree"] == case.grant["tree"]
    assert {name: base64.b64decode(value) for name, value in source["contents"].items()} == case.files
    with pytest.raises(gate.HostLaunchError, match="already attempted"):
        verifier.claim(proof, **f.args, binding_fd=31)
    with pytest.raises(gate.HostLaunchError, match="already claimed"):
        capture.claim(preparation=f.args["preparation"], config=f.args["config"])


@pytest.mark.parametrize("identity", [None, {}, {"actor": "executor:host", "scopes": ["executors:write"]}, {"actor": "executor:host", "scopes": ["admin"]}])
def test_executor_and_caller_claims_never_write_owner_grants(owner_source, identity):
    case = owner_source
    path = sources._state_path(case.service.support_root); before = path.read_bytes()
    with pytest.raises(AuthorizationError):
        sources._write_owner_grants(case.service, [], identity=identity)
    assert path.read_bytes() == before


@pytest.mark.parametrize("edge", ["repository", "revision", "subpath", "tree", "bytes", "inventory", "ungranted"])
def test_wrong_repository_identity_and_source_are_refused(owner_source, edge):
    case = owner_source; grant = copy.deepcopy(case.grant)
    if edge == "repository": grant[edge] = "https://example.test/foreign.git"
    elif edge in {"revision", "tree"}: grant[edge] = "f" * 40
    elif edge == "subpath": grant.update(subpath="foreign", root=str(case.root.parent / "foreign"))
    elif edge == "bytes": (case.root / "action.py").write_bytes(b"FORGED = 1\n")
    elif edge == "inventory": (case.root / "extra.py").write_bytes(b"EXTRA = 1\n")
    grants = [] if edge == "ungranted" else [grant]
    sources._write_owner_grants(case.service, grants, identity=OWNER)
    if edge == "subpath":
        case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"][0]["path"] = grant["root"]
    with pytest.raises(gate.HostLaunchError): case.capture()


@pytest.mark.parametrize("name", ["astrid.py", "astrid_runtime_client.py", "runtime_protocol.py", "astrid/__init__.py"])
def test_owner_grant_cannot_authorize_reserved_package_collision(owner_source, name):
    grant = copy.deepcopy(owner_source.grant); grant["files"][name] = "a" * 64
    with pytest.raises(gate.HostLaunchError, match="collision"):
        sources._write_owner_grants(owner_source.service, [grant], identity=OWNER)


@pytest.mark.parametrize("edge", ["root", "parent", "descendant", "state"])
def test_aliases_never_become_source_authority(owner_source, edge, tmp_path):
    case = owner_source
    if edge in {"root", "parent"}:
        alias = tmp_path / "alias"; alias.symlink_to(case.root if edge == "root" else case.root.parent, target_is_directory=True)
        grant = copy.deepcopy(case.grant)
        if edge == "root": grant.update(checkout=str(tmp_path), subpath="alias", root=str(alias))
        else: grant.update(checkout=str(alias), root=str(alias / "tool"))
        sources._write_owner_grants(case.service, [grant], identity=OWNER)
        case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"][0]["path"] = grant["root"]
    elif edge == "descendant": (case.root / "alias.py").symlink_to(case.root / "action.py")
    else:
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
    elif edge == "owner-grant": sources._write_owner_grants(case.service, [], identity=OWNER)
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


def test_owner_file_permissions_are_required(owner_source):
    path = sources._state_path(owner_source.service.support_root)
    path.chmod(0o644)
    with pytest.raises(gate.HostLaunchError, match="owner-only"): owner_source.capture()


def test_caller_admission_map_digest_and_environment_never_create_grant(owner_source, monkeypatch):
    case = owner_source
    sources._write_owner_grants(case.service, [], identity=OWNER)
    monkeypatch.setenv("ASTRID_SOURCE_STATE", str(case.root / "pack.json"))
    monkeypatch.setenv("PYTHONPATH", str(case.root))
    monkeypatch.setenv("GIT_DIR", str(case.root.parent / ".git"))
    case.f.args["config"]["external_source_grants"] = [case.grant]
    with pytest.raises(gate.HostLaunchError, match="no owner grant"): case.capture()


def test_production_preparer_admits_external_sources_before_any_child_transport(owner_source, monkeypatch):
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.local_worker import _digest
    from tests.test_local_worker import host_only_profile_case

    case = owner_source
    sources._write_owner_grants(case.service, [], identity=OWNER)
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


def test_even_owner_inventory_equality_cannot_replace_exact_git_tree(owner_source):
    case = owner_source; grant = copy.deepcopy(case.grant)
    changed = b"FORGED = 1\n"; (case.root / "action.py").write_bytes(changed)
    grant["files"]["action.py"] = hashlib.sha256(changed).hexdigest()
    sources._write_owner_grants(case.service, [grant], identity=OWNER)
    case.f.args["preparation"]["profile"]["host_launch"]["additional_pack_roots"][0]["files"] = grant["files"]
    with pytest.raises(gate.HostLaunchError, match="bytes differ from repository tree"): case.capture()


def test_empty_reserved_namespace_is_also_a_collision(owner_source):
    (owner_source.root / "runtime_protocol").mkdir()
    with pytest.raises(gate.HostLaunchError, match="collision"): owner_source.capture()


def test_repository_object_contents_must_hash_to_exact_owner_revision(owner_source):
    case = owner_source; revision = case.grant["revision"]
    path = case.root.parent / ".git/objects" / revision[:2] / revision[2:]
    path.write_bytes(zlib.compress(zlib.decompress(path.read_bytes()).replace(b"fixture", b"forgery")))
    with pytest.raises(gate.HostLaunchError, match="object identity differs"): case.capture()
