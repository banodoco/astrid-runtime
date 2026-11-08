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




# --- Plan 06 Runtime-5: grant bound, state custody, inventory bound, bytecode ---

def install_many(collection, count):
    """``count`` extra installed packs plus the fixture's "tool", one group record."""
    admissions = json.loads((collection / ".group.json").read_text())["admissions"]
    roots = []
    for index in range(count):
        pack_id = f"pack{index:02d}"
        roots.append(install_pack(collection, pack_id))
        admissions.update(json.loads((collection / ".group.json").read_text())["admissions"])
    state = json.loads((collection / ".group.json").read_text()); state["admissions"] = admissions
    (collection / ".group.json").write_text(json.dumps(state))
    return roots


def launch(case, root):
    """One full launch of ``root`` in the case's workspace: capture, verify, claim."""
    f = case.f; profile = f.args["preparation"]["profile"]
    grant = sources._derive_installed_grant(str(case.collection), root.name)
    profile["host_launch"]["additional_pack_roots"] = [{"path": str(root), "files": grant["files"]}]
    f.record["selected_profile_digest"] = gate.raw_digest(profile)
    capture = case.capture()
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    verifier.claim(proof, **f.args, binding_fd=31)
    return capture


def stored_roots(case):
    state = sources._read_state(sources._state_path(case.service.support_root))
    return [g["root"] for g in state["grants"]]


def test_seventeen_or_more_installed_packs_all_launch_in_one_workspace(owner_source):
    """(a) The bound is the real installed-pack count, not a constant 16."""
    case = owner_source
    roots = install_many(case.collection, 17)
    for root in [case.root, *roots]:
        launch(case, root)
    assert len(stored_roots(case)) == 18 == sources._installed_pack_count(case.collection)
    assert sorted(stored_roots(case)) == sorted(str(r) for r in [case.root, *roots])


def test_stored_grant_whose_install_no_longer_verifies_is_dropped_not_refused(owner_source):
    """Stored history never refuses a launch; it is re-derived or dropped."""
    case = owner_source
    first, second = install_many(case.collection, 2)
    launch(case, first); launch(case, second)
    pin = json.loads((first / "PIN").read_text()); pin["commit"] = "f" * 40
    (first / "PIN").write_text(json.dumps(pin) + "\n")  # no longer verifies
    shutil.rmtree(second)  # no longer installed
    launch(case, case.root)
    assert stored_roots(case) == [str(case.root)]


@pytest.mark.parametrize("corruption", ["bytes", "shape"])
def test_corrupt_previous_state_is_refused_by_name_and_never_overwritten(owner_source, corruption):
    """(b) Unreadable state is a named refusal, not a silent reset of old grants."""
    case = owner_source
    case.capture()
    path = sources._state_path(case.service.support_root)
    if corruption == "bytes":
        path.write_bytes(b"\x00not json"); path.chmod(0o600)
    else:
        from runtime_protocol.local_execution_handoff import write_protected
        write_protected(path, {"workspace_uuid": case.service.realm["id"], "grants": "lost"})
    before = path.read_bytes()
    with pytest.raises(gate.HostLaunchError, match=r"owner state .*grants\.json.*refusing to overwrite"):
        case.capture()
    assert path.read_bytes() == before


@pytest.mark.parametrize("locked", [True, False])
def test_concurrent_writers_never_lose_a_grant(owner_source, monkeypatch, locked):
    """(c) Two launches interleave read-merge-write; the lock serializes them.

    Writer A reads the state, then waits for writer B to finish writing. With
    the lock B cannot even read until A has published, so both grants survive.
    The unlocked control shows this interleaving would otherwise lose A's grant.
    """
    import contextlib
    import threading
    from runtime_protocol import local_execution_handoff as handoff
    case = owner_source
    first, second = install_many(case.collection, 2)
    grants = {name: sources._derive_installed_grant(str(case.collection), name) for name in (first.name, second.name)}
    workspace = case.service.realm["id"]
    events = []; b_written = threading.Event(); a_read = threading.Event()
    real_read, real_write = sources._read_state, handoff.write_protected

    def read(path, **kwargs):
        name = threading.current_thread().name
        value = real_read(path, **kwargs)
        events.append((name, "read"))
        if name == "A":
            a_read.set(); b_written.wait(0.5)
        return value

    def write(path, value):
        real_write(path, value)
        name = threading.current_thread().name
        events.append((name, "write"))
        if name == "B": b_written.set()

    monkeypatch.setattr(sources, "_read_state", read)
    monkeypatch.setattr(handoff, "write_protected", write)
    if not locked:
        monkeypatch.setattr(sources.platform, "file_lock", lambda *_a, **_k: contextlib.nullcontext())
    errors = []

    def writer(name):
        try:
            if name == "B": a_read.wait(2)
            sources._persist_derived_grants(case.service.support_root, workspace, [grants[{"A": first.name, "B": second.name}[name]]], str(case.collection))
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=writer, args=(n,), name=n) for n in ("A", "B")]
    for t in threads: t.start()
    for t in threads: t.join(10)
    assert not errors
    roots = [g["root"] for g in real_read(sources._state_path(case.service.support_root))["grants"]]
    if locked:
        assert events == [("A", "read"), ("A", "write"), ("B", "read"), ("B", "write")]
        assert roots == sorted([str(first), str(second)])
    else:
        assert events[:3] == [("A", "read"), ("B", "read"), ("B", "write")]
        assert roots == [str(first)]  # B's grant lost: what the lock prevents


def test_many_concurrent_launch_writers_keep_every_grant(owner_source):
    import threading
    case = owner_source
    roots = install_many(case.collection, 12)
    grants = [sources._derive_installed_grant(str(case.collection), r.name) for r in roots]
    workspace = case.service.realm["id"]; barrier = threading.Barrier(len(grants))

    def writer(grant):
        barrier.wait()
        sources._persist_derived_grants(case.service.support_root, workspace, [grant], str(case.collection))
    threads = [threading.Thread(target=writer, args=(g,)) for g in grants]
    for t in threads: t.start()
    for t in threads: t.join(30)
    assert stored_roots(case) == sorted(str(r) for r in roots)


def test_oversized_installed_file_is_refused_by_name_before_reading(owner_source, monkeypatch):
    """(d) st_size is checked before any byte of the file is read."""
    from pathlib import Path
    case = owner_source
    big = case.root / "weights.bin"
    with big.open("wb") as handle:
        handle.truncate(sources.SOURCE_LIMIT + 1)
    real = Path.read_bytes
    def guarded(self):
        assert self != big, "oversized file was read"
        return real(self)
    monkeypatch.setattr(Path, "read_bytes", guarded)
    with pytest.raises(gate.HostLaunchError, match=r"installed pack file weights\.bin exceeds"):
        sources._derive_installed_grant(str(case.collection), "tool")
    with pytest.raises(gate.HostLaunchError, match=r"weights\.bin exceeds"):
        case.capture()


def _tree_snapshot(root):
    return {str(p.relative_to(root)): (p.lstat().st_mode, None if p.is_dir() else p.read_bytes())
        for p in sorted(root.rglob("*"))}


def test_installed_tree_is_byte_identical_after_derive_launch_and_import(owner_source):
    """(e) No __pycache__ or byte changes appear in the installed collection,
    even when a child imports pack code with the Runtime pack-host env."""
    import subprocess
    import sys
    case = owner_source
    before = _tree_snapshot(case.collection)
    sources._derive_installed_grant(str(case.collection), "tool")
    launch(case, case.root)
    config = case.f.args["config"]
    environment = {"PATH": "/usr/bin:/bin",
        **gate.bytecode_environment(case.service.support_root, config, case.f.args["preparation"]["profile"])}
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    prefix = environment["PYTHONPYCACHEPREFIX"]
    assert not Path_is_within(prefix, str(case.collection))
    subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(case.root)!r}); import action; assert action.ANSWER == 7"],
        env=environment, check=True, cwd=str(case.service.support_root))
    assert _tree_snapshot(case.collection) == before
    assert not list(case.collection.rglob("__pycache__")) and not list(case.collection.rglob("*.pyc"))


def Path_is_within(child, parent):
    from pathlib import Path
    return Path(child).is_relative_to(parent)


@pytest.mark.parametrize("edge", ["writes", "inside", "partial"])
def test_verifier_refuses_any_bytecode_env_but_the_runtime_policy(owner_source, edge):
    case = owner_source; f = case.f
    config = f.args["config"]; profile = f.args["preparation"]["profile"]
    policy = gate.bytecode_environment(case.service.support_root, config, profile)
    capture = case.capture()
    ok = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    ok.verify(**{**f.args, "environment": {**f.args["environment"], **policy}})
    if edge == "writes": bad = {**policy, "PYTHONDONTWRITEBYTECODE": "0"}
    elif edge == "inside": bad = {**policy, "PYTHONPYCACHEPREFIX": str(case.collection / "cache")}
    else: bad = {"PYTHONDONTWRITEBYTECODE": "1"}
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=case.capture())
    with pytest.raises(gate.HostLaunchError, match="bytecode"):
        verifier.verify(**{**f.args, "environment": {**f.args["environment"], **bad}})
    with pytest.raises(gate.HostLaunchError, match="inside an installed pack collection"):
        gate.bytecode_environment(case.collection, config, profile)


# --- Plan 06 Runtime-6: launch-time discovery of every verified installed pack ---

def _no_selection(case):
    profile = case.f.args["preparation"]["profile"]
    profile["host_launch"]["additional_pack_roots"] = []
    case.f.record["selected_profile_digest"] = gate.raw_digest(profile)


def _break_revision(root):
    pin = json.loads((root / "PIN").read_text()); pin["commit"] = "f" * 40
    (root / "PIN").write_text(json.dumps(pin) + "\n")


def test_custody_host_with_no_selection_discovers_every_verified_installed_pack(owner_source):
    """(a) No selection at all: every pack whose record verifies is granted,
    captured and selectable; the one that does not verify is a named refusal."""
    case = owner_source
    first, second, broken = install_many(case.collection, 3)
    _break_revision(broken)
    _no_selection(case)
    assert not sources._state_path(case.service.support_root).exists()
    capture = case.capture()
    verified = sorted(str(r) for r in (case.root, first, second))
    assert sorted(capture.launch_roots) == verified
    assert stored_roots(case) == verified
    assert capture.refusals == [{"pack_id": broken.name, "root": str(broken),
        "reason": f"installed pack {broken.name} is excluded from host discovery: "
                  "installed pack definitions revision differs from the install source commit"}]
    # The refusal is recorded for diagnostics, outside the grants the Agent re-reads.
    record = sources._read_state(sources._discovery_path(case.service.support_root))
    assert record["refusals"] == capture.refusals and record["installed_pack_root"] == str(case.collection)
    assert set(sources._read_state(sources._state_path(case.service.support_root))) == {"workspace_uuid", "grants"}
    # The full launch carries every verified source; selection is still owner-bound.
    f = case.f
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    _, payload = verifier.claim(proof, **f.args, binding_fd=31)
    body = json.loads(payload)["external_pack_sources"]
    assert sorted(s["root"] for s in body["sources"]) == verified
    handle = gate._RuntimeExternalSources(capture.payload)
    definition = sources._derive_installed_grant(str(case.collection), first.name)["definitions"][0]
    args = {"scope": body["scope"], "selected_profile_digest": body["selected_profile_digest"], "definition": definition}
    assert json.loads(handle.select(root=str(first), **args))["source"]["root"] == str(first)
    with pytest.raises(gate.HostLaunchError, match="external selected definition has no owner grant"):
        handle.select(root=str(broken), **args)


def test_pack_edited_after_install_is_excluded_from_discovery_by_name(owner_source):
    """(b) Editing an installed record (or its bytes) after install excludes only that pack."""
    case = owner_source
    edited, kept = install_many(case.collection, 2)
    record = json.loads((edited / ".build" / "definitions.json").read_text())
    record["definitions"][0]["capability_id"] = "forged"
    (edited / ".build" / "definitions.json").write_text(json.dumps(record))
    _no_selection(case)
    capture = case.capture()
    assert sorted(capture.launch_roots) == sorted([str(case.root), str(kept)])
    assert [(r["pack_id"], r["reason"]) for r in capture.refusals] == [(edited.name,
        f"installed pack {edited.name} is excluded from host discovery: "
        "installed pack definitions record differs from its admission digest")]
    # Selecting the edited pack is still refused by name, not silently dropped.
    profile = case.f.args["preparation"]["profile"]
    profile["host_launch"]["additional_pack_roots"] = [{"path": str(edited), "files": {"pack.json": "0" * 64}}]
    with pytest.raises(gate.HostLaunchError, match="definitions record differs from its admission digest"):
        case.capture()


def test_selected_pack_is_captured_first_and_others_are_discovered(owner_source):
    case = owner_source
    others = install_many(case.collection, 2)
    capture = case.capture()
    assert capture.launch_roots == [str(case.root), *sorted(str(r) for r in others)]
    assert capture.refusals == []


def test_production_preparer_launches_every_discovered_root_with_no_selection(owner_source, monkeypatch):
    """The host argv carries --pack-root for each verified installed pack, unselected."""
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.local_worker import _digest
    from tests.test_local_worker import host_only_profile_case

    case = owner_source
    first, broken = install_many(case.collection, 2)
    _break_revision(broken)
    selected = host_only_profile_case()
    assert selected.host_launch is not None
    launch_config = dict(selected.host_launch)
    profile = replace(selected, workspace_uuid=case.service.realm["id"], support_root=case.service.support_root,
        host_launch=launch_config, session_config_digest=_digest(launch_config))
    config = {**launch_config, "support_root": str(case.service.support_root), "runtime_instance_id": "epoch",
        "installed_pack_root": str(case.collection), "runtime_endpoint": "http://127.0.0.1:1",
        "credential_file": "/support/credential", "ready_file": "/support/ready.json"}
    seen = {}

    class Stop(Exception):
        pass

    class Verifier:
        def __init__(self, *, installed_release, external_sources=None):
            seen["sources"] = external_sources

        def verify(self, *, host_argv, **_kwargs):
            seen["argv"] = host_argv
            raise Stop

    monkeypatch.setattr(composition, "_installed_host_release", lambda *_a: None)
    monkeypatch.setattr(gate, "TrustedLocalHostLaunchVerifier", Verifier)
    preparer = cast(Any, composition.CrossProcessWorkerPreparer)(profile=profile, config=config, environment={})
    with pytest.raises(Stop):
        preparer._prepare_host_only(profile, operation_id="op", channel_id="channel")
    argv = seen["argv"]
    roots = [argv[i + 1] for i, value in enumerate(argv) if value == "--pack-root"]
    assert roots == [launch_config["pack_root"], *sorted([str(case.root), str(first)])]
    assert str(broken) not in argv
    assert [r["pack_id"] for r in seen["sources"].refusals] == [broken.name]


def test_concurrent_discovering_launches_keep_every_grant(owner_source):
    """(c) Concurrent custody builds, each discovering, serialize on the grants lock."""
    import threading
    case = owner_source
    roots = install_many(case.collection, 6)
    _no_selection(case)
    barrier = threading.Barrier(6); captures = []; errors = []

    def launch_once():
        try:
            barrier.wait(); captures.append(case.capture())
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=launch_once) for _ in range(6)]
    for t in threads: t.start()
    for t in threads: t.join(60)
    expected = sorted(str(r) for r in [case.root, *roots])
    assert not errors and len(captures) == 6
    assert stored_roots(case) == expected
    assert all(sorted(c.launch_roots) == expected for c in captures)


def test_agent_host_shape_check_of_the_capture_needs_no_collection_count(owner_source):
    """The Agent host re-validates the launcher capture as ``_validate_grants(grants)``
    (generic_host._RuntimeSourceCustody). A real custody spawn failed with
    "invalid private Runtime source capture" while ``limit`` was required."""
    grant = owner_source.grant
    sources._validate_grants([grant])
    sources._validate_grants([grant], limit=1)
    with pytest.raises(gate.HostLaunchError, match="grants are invalid"):
        sources._validate_grants([grant], limit=0)


# --- Plan 06 Runtime-8: B1 refused packs, N1 single count, N2 per-pack exclusion ---

def _install_refused(collection):
    """Add a folder install (no source provenance) and a pack whose admission
    binds the wrong definitionsDigest, keeping every admission in one record."""
    admissions = json.loads((collection / ".group.json").read_text())["admissions"]
    folder = install_pack(collection, "folderpack", source={"kind": "folder", "path": "/somewhere"})
    admissions.update(json.loads((collection / ".group.json").read_text())["admissions"])
    digest = install_pack(collection, "baddigest", tamper_digest=True)
    admissions.update(json.loads((collection / ".group.json").read_text())["admissions"])
    state = json.loads((collection / ".group.json").read_text()); state["admissions"] = admissions
    (collection / ".group.json").write_text(json.dumps(state))
    return folder, digest


_REFUSED_REASONS = {
    "baddigest": "installed pack baddigest is excluded from host discovery: "
                 "installed pack definitions record differs from its admission digest",
    "folderpack": "installed pack folderpack is excluded from host discovery: "
                  "installed pack came from a local folder and has no source repository provenance",
}


def _prepare_unselected(case, monkeypatch):
    """Drive the production custody build (CrossProcessWorkerPreparer._prepare_host_only)
    with no selection up to the verifier; return what the verifier was handed."""
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.local_worker import _digest
    from tests.test_local_worker import host_only_profile_case

    selected = host_only_profile_case()
    assert selected.host_launch is not None and not selected.host_launch.get("additional_pack_roots")
    launch_config = dict(selected.host_launch)
    profile = replace(selected, workspace_uuid=case.service.realm["id"], support_root=case.service.support_root,
        host_launch=launch_config, session_config_digest=_digest(launch_config))
    config = {**launch_config, "support_root": str(case.service.support_root), "runtime_instance_id": "epoch",
        "installed_pack_root": str(case.collection), "runtime_endpoint": "http://127.0.0.1:1",
        "credential_file": "/support/credential", "ready_file": "/support/ready.json"}
    seen = {}

    class Stop(Exception):
        pass

    class Verifier:
        def __init__(self, *, installed_release, external_sources=None):
            seen["sources"] = external_sources

        def verify(self, *, preparation, host_argv, **_kwargs):
            seen.update(argv=host_argv, preparation=preparation)
            raise Stop

    monkeypatch.setattr(composition, "_installed_host_release", lambda *_a: None)
    monkeypatch.setattr(gate, "TrustedLocalHostLaunchVerifier", Verifier)
    preparer = cast(Any, composition.CrossProcessWorkerPreparer)(profile=profile, config=config, environment={})
    with pytest.raises(Stop):
        preparer._prepare_host_only(profile, operation_id="op", channel_id="channel")
    seen["pack_roots"] = [seen["argv"][i + 1] for i, v in enumerate(seen["argv"]) if v == "--pack-root"]
    seen["builtin_root"] = launch_config["pack_root"]
    return seen


def test_refused_installed_packs_keep_custody_stay_out_of_argv_and_are_named(owner_source, monkeypatch):
    """B1 ruling (a)+(b): with no selection the Runtime keeps OwnerSourceCapture whenever the
    installed collection is present; refused packs get no --pack-root and are named in
    discovery.json with their reasons."""
    case = owner_source
    folder, digest = _install_refused(case.collection)
    seen = _prepare_unselected(case, monkeypatch)
    capture = seen["sources"]
    assert capture is not None  # (a) custody kept
    assert seen["pack_roots"] == [seen["builtin_root"], str(case.root)]  # granted pack only
    for refused in (folder, digest):  # (b) never a launch root, never anywhere in argv
        assert str(refused) not in seen["argv"]
    named = {r["pack_id"]: r["reason"] for r in capture.refusals}
    assert named == _REFUSED_REASONS
    record = sources._read_state(sources._discovery_path(case.service.support_root))
    assert record["installed_pack_root"] == str(case.collection)
    assert {r["pack_id"]: (r["root"], r["reason"]) for r in record["refusals"]} == {
        "baddigest": (str(digest), _REFUSED_REASONS["baddigest"]),
        "folderpack": (str(folder), _REFUSED_REASONS["folderpack"])}
    assert [s["root"] for s in json.loads(capture.payload)["sources"]] == [str(case.root)]


def test_collection_with_only_refused_packs_still_keeps_custody(owner_source, monkeypatch):
    """B1 ruling (a): no launch root at all, and custody is still kept (not the bare host)."""
    case = owner_source
    shutil.rmtree(case.root)
    state = json.loads((case.collection / ".group.json").read_text()); state["admissions"] = {}
    (case.collection / ".group.json").write_text(json.dumps(state))
    folder, digest = _install_refused(case.collection)
    seen = _prepare_unselected(case, monkeypatch)
    capture = seen["sources"]
    assert capture is not None and capture.launch_roots == []
    assert seen["pack_roots"] == [seen["builtin_root"]]
    assert str(folder) not in seen["argv"] and str(digest) not in seen["argv"]
    assert {r["pack_id"]: r["reason"] for r in capture.refusals} == _REFUSED_REASONS


@pytest.mark.integration
def test_agent_host_built_from_the_custody_argv_does_not_load_refused_packs(owner_source, monkeypatch, astrid_importable):
    """B1 ruling (c): the Agent host constructed the way `generic_host run --register`
    does (personal_collection=True), under the Runtime's custody handle, keeps exactly the
    argv roots; the personal collection (where the refused packs live) is not added."""
    from astrid.core.execution import generic_host

    case = owner_source
    folder, digest = _install_refused(case.collection)
    monkeypatch.setenv("HOME", str(case.collection.parents[1]))
    monkeypatch.delenv("ASTRID_PACKS_PATH", raising=False)
    seen = _prepare_unselected(case, monkeypatch)
    handle = gate._RuntimeExternalSources(seen["sources"].payload)
    custody = generic_host._RuntimeSourceCustody(handle)
    custody.bind(seen["preparation"])
    monkeypatch.setattr(generic_host, "_runtime_external_sources", custody)
    host = generic_host.GenericPackHost(pack_roots=seen["pack_roots"], personal_collection=True)
    roots = {str(root) for root in host.pack_roots}
    assert str(case.root) in roots
    assert str(case.collection) not in roots
    assert not any(str(r) == str(p) or str(r).startswith(str(p) + "/") for r in roots for p in (folder, digest))
    assert not {str(record.source_root) for record in host.capabilities.values()} & {str(folder), str(digest)}


def test_pack_removed_between_persist_and_check_is_a_named_exclusion_not_a_grant_refusal(owner_source, monkeypatch):
    """N1: the collection is counted once, before the persist. A ``packs remove`` after the
    persist used to recount and refuse the launch with "external source grants are invalid"."""
    case = owner_source
    removed, kept = install_many(case.collection, 2)
    _no_selection(case)
    real_persist = sources._persist_derived_grants

    def persist_then_remove(*args, **kwargs):
        real_persist(*args, **kwargs)
        shutil.rmtree(removed)  # `astrid packs remove` lands here
    monkeypatch.setattr(sources, "_persist_derived_grants", persist_then_remove)
    capture = case.capture()
    assert sorted(capture.launch_roots) == sorted([str(case.root), str(kept)])
    assert [r["pack_id"] for r in capture.refusals] == [removed.name]
    assert capture.refusals[0]["reason"].startswith(f"installed pack {removed.name} is excluded from host discovery: ")


def test_grant_count_overflow_is_refused_by_name(owner_source):
    """N1: a pack set that grew past the launch's one count names the cause."""
    case = owner_source
    grant = sources._derive_installed_grant(str(case.collection), "tool")
    other = dict(grant, root=str(case.collection / "other"), subpath="other")
    with pytest.raises(gate.HostLaunchError, match="installed pack collection changed during launch: 2 grants exceed the 1 installed packs"):
        sources._persist_derived_grants(case.service.support_root, case.service.realm["id"], [grant, other],
            str(case.collection), limit=1)


@pytest.mark.parametrize("change", ["bytes", "removed", "record"])
def test_unselected_pack_changed_after_capture_is_excluded_by_name_and_others_launch(owner_source, change):
    """N2: one changed unselected pack no longer blocks the launch; it is excluded on its own."""
    case = owner_source; f = case.f
    changed, kept = install_many(case.collection, 2)
    capture = case.capture()  # "tool" stays selected
    assert capture.launch_roots == [str(case.root), str(changed), str(kept)]
    if change == "bytes":
        (changed / "action.py").write_bytes(b"ANSWER = 8\n")
    elif change == "removed":
        shutil.rmtree(changed)
    else:
        record = json.loads((changed / ".build" / "definitions.json").read_text())
        record["definitions"][0]["capability_id"] = "forged"
        (changed / ".build" / "definitions.json").write_text(json.dumps(record))
    roots = capture.pin(preparation=f.args["preparation"], config=f.args["config"])
    assert roots == [str(case.root), str(kept)]
    assert [r["pack_id"] for r in capture.refusals] == [changed.name]
    assert capture.refusals[0]["reason"].startswith(f"installed pack {changed.name} is excluded from host discovery: it changed after capture")
    record = sources._read_state(sources._discovery_path(case.service.support_root))
    assert [r["pack_id"] for r in record["refusals"]] == [changed.name]
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record, external_sources=capture)
    proof = verifier.verify(**f.args)
    _, payload = verifier.claim(proof, **f.args, binding_fd=31)
    assert [s["root"] for s in json.loads(payload)["external_pack_sources"]["sources"]] == [str(case.root), str(kept)]


@pytest.mark.parametrize("edge", ["selected", "pinned", "collection"])
def test_selected_pinned_or_collection_changes_still_refuse_the_whole_launch(owner_source, edge, tmp_path):
    """N2: the whole-launch refusal stays for a selected pack, for any pack the pinned launch
    carries, and for the collection itself."""
    case = owner_source; f = case.f
    other, = install_many(case.collection, 1)
    capture = case.capture()
    if edge == "pinned":
        capture.pin(preparation=f.args["preparation"], config=f.args["config"])
    if edge == "selected":
        (case.root / "action.py").write_bytes(b"ANSWER = 8\n")
    elif edge == "pinned":
        (other / "action.py").write_bytes(b"ANSWER = 8\n")
    else:
        moved = tmp_path / "moved"; case.collection.rename(moved); shutil.copytree(moved, case.collection)
    message = ("installed pack collection changed after capture" if edge == "collection"
        else "installed pack differs from its derived custody grant")
    with pytest.raises(gate.HostLaunchError, match=message):
        capture.verify(preparation=f.args["preparation"], config=f.args["config"])
