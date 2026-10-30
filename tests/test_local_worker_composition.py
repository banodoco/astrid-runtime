from __future__ import annotations

import hashlib
import json
import os
import importlib.metadata
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from tests.lanes import requires_posix_uid_metadata

from runtime_protocol.errors import ConflictError
from runtime_protocol import platform as runtime_platform
from runtime_protocol.local_worker import LocalWorkerProfile, ProcessIdentity
from runtime_protocol.local_worker_composition import (
    CrossProcessWorkerPreparer,
    OSProcessInspector,
    _PreparedWorker,
    _listening_socket_owner,
    _pack_inventory,
    load_local_worker_composition,
)


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _content_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _simulate_windows_path_semantics(monkeypatch):
    path_type = type(Path())
    relative_to = path_type.relative_to

    def windows_relative_to(path, other, *args, **kwargs):
        relative = relative_to(path, other, *args, **kwargs)
        return PureWindowsPath(*relative.parts)

    monkeypatch.setattr(path_type, "relative_to", windows_relative_to)
    monkeypatch.setattr(path_type, "parts", property(lambda path: PureWindowsPath(path.as_posix()).parts))
    monkeypatch.setattr(
        path_type,
        "__lt__",
        lambda path, other: tuple(part.casefold() for part in path.parts)
        < tuple(part.casefold() for part in other.parts),
    )


def test_installed_host_root_comparison_resolves_both_sides(tmp_path, monkeypatch):
    from runtime_protocol import local_worker_composition as composition
    from runtime_protocol.verified_host_launch import raw_digest

    selected = tmp_path / "site-packages"
    selected.mkdir()
    alias = tmp_path / "site-alias"
    alias.symlink_to(selected, target_is_directory=True)
    record = "file.py,,\n"
    distribution = SimpleNamespace(
        locate_file=lambda _relative: selected,
        read_text=lambda _name: record,
    )
    monkeypatch.setattr(importlib.metadata, "distribution", lambda _package: distribution)
    records = {name: hashlib.sha256(record.encode()).hexdigest() for name in ("astrid", "astrid-runtime")}
    profile = SimpleNamespace(release_digest="sha256:" + raw_digest(records))

    assert composition._verify_installed_host_records(profile, {"source_checkout": str(alias)}) == records


def test_pack_inventory_uses_portable_nested_keys(tmp_path, monkeypatch):
    root = tmp_path / "packs"
    for relative, content in {"Z/effect.py": b"z", "a/x.py": b"x", "a.txt": b"a"}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    inventory = _pack_inventory(root)
    assert list(inventory) == ["Z/effect.py", "a/x.py", "a.txt"]
    assert all("\\" not in key for key in inventory)
    _simulate_windows_path_semantics(monkeypatch)
    inventory = _pack_inventory(root)
    assert list(inventory) == ["Z/effect.py", "a/x.py", "a.txt"]
    assert all("\\" not in key for key in inventory)


def _profile_document(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    source = tmp_path / "astrid"
    packs = source / "astrid" / "packs"
    packs.mkdir(parents=True)
    support = tmp_path / "support"
    support.mkdir()
    boot = support / "boot.json"
    boot.write_text("{}", encoding="utf-8")
    session_root = tmp_path / "vibecomfy" / "out" / "sessions" / "fixture"
    document = {
        "profile_id": "astrid",
        "machine_id": platform.node(),
        "engine_endpoint": "http://127.0.0.1:8188",
        "worker_environment": sys.prefix,
        "worker_executable": str(Path(sys.executable).resolve()),
        "host_executable": str(Path(sys.executable).resolve()),
        "engine_executable": str(Path(sys.executable).resolve()),
        "engine_listener_executable": str(Path(sys.executable).resolve()),
        "worker_artifact_digest": _digest("1"),
        "host_artifact_digest": _digest("2"),
        "engine_artifact_digest": _digest("3"),
        "engine_listener_artifact_digest": _digest("4"),
        "session_config_digest": _digest("5"),
        "profile_revision": "fixture-r1",
        "profile_digest": _digest("6"),
        "release_digest": _digest("7"),
        "source_checkout": str(source),
        "pack_root": str(packs),
        "boot_manifest_path": str(boot),
        "boot_manifest_hash": _digest("8"),
        "environment": {
            "ASTRID_VIBECOMFY_SESSION_DIR": str(session_root),
            "ASTRID_VIBECOMFY_PORT": "8188",
        },
    }
    return document, source, support, packs


def test_factory_derives_runtime_identity_and_roots(tmp_path: Path) -> None:
    document, source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm-from-runtime",
        realm_root=tmp_path / "runtime-realm",
        support_root=support,
        runtime_instance_id="instance-1",
    )
    profile = composition.profiles["astrid"]
    assert profile.workspace_uuid == "realm-from-runtime"
    assert profile.realm_root == (tmp_path / "runtime-realm").resolve()
    assert profile.support_root == support.resolve()
    assert profile.realm_root != source.resolve()
    composition.bind_runtime(endpoint="http://127.0.0.1:1234", runtime_instance_id="instance-2", credential_file=support / "worker.token")
    assert composition.preparer.config["runtime_endpoint"] == "http://127.0.0.1:1234"
    assert composition.preparer.config["runtime_instance_id"] == "instance-2"


def test_factory_rejects_unknown_authority_fields(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["realm_root"] = "/attacker/realm"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="unsupported fields"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_rejects_endpoint_that_disagrees_with_worker_launch_port(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["engine_endpoint"] = "http://127.0.0.1:8189"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="engine_endpoint"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_independent_inspector_rejects_worker_birth_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=support,
        runtime_instance_id="instance",
    )
    profile = composition.profiles["astrid"]
    inspector = OSProcessInspector(profile)
    pid = os.getpid()
    report = {
        "processes": {
            "worker": {"pid": pid, "birth_id": "worker-claim"},
            "host": {"pid": pid, "birth_id": "host-claim"},
            "engine": {"pid": pid, "birth_id": "engine-claim"},
            "engine_listener": {"pid": pid, "birth_id": "listener-claim"},
        },
        "engine_binding": {"socket_owner_pid": pid},
        "session_config_digest": profile.session_config_digest,
    }
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.runtime_platform.process_identity",
        lambda observed_pid: {"pid": observed_pid, "birth_id": "independently-observed-birth"},
    )
    handle = SimpleNamespace(report_value=report)
    with pytest.raises(ConflictError, match="birth identity"):
        inspector.observe(handle)


@pytest.mark.parametrize(
    ("socket_name", "accepted"),
    [
        ("127.0.0.1:8188", True),
        ("127.0.0.1:8189", False),
        ("127.0.0.2:8188", False),
        ("*:8188", False),
    ],
)
def test_listener_proof_requires_exact_configured_endpoint(monkeypatch, socket_name, accepted):
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=f"p4321\nn{socket_name}\n"),
    )
    if accepted:
        assert _listening_socket_owner(4321, "http://127.0.0.1:8188") == (
            4321,
            "http://127.0.0.1:8188",
        )
    else:
        with pytest.raises(ConflictError, match="configured engine endpoint"):
            _listening_socket_owner(4321, "http://127.0.0.1:8188")


def _inspector_fixture(tmp_path: Path, *, machine_id="owner-machine", session_digest=None):
    config = b'{"port":8188,"warm_policy":"auto"}'
    config_path = tmp_path / "session" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_bytes(config)
    session_digest = session_digest or _content_digest(config)
    profile = LocalWorkerProfile(
        profile_id="astrid",
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        machine_id=machine_id,
        worker_executable=Path("/worker"),
        host_executable=Path("/host"),
        engine_executable=Path("/engine"),
        engine_listener_executable=Path("/listener"),
        engine_endpoint="http://127.0.0.1:8188",
        worker_artifact_digest=_digest("1"),
        host_artifact_digest=_digest("2"),
        engine_artifact_digest=_digest("3"),
        engine_listener_artifact_digest=_digest("4"),
        session_config_digest=session_digest,
        profile_revision="r1",
        profile_digest=_digest("6"),
        release_digest=_digest("7"),
    )
    report = {
        "processes": {
            "worker": {"pid": 100, "birth_id": "b100"},
            "host": {"pid": 101, "birth_id": "b101"},
            "engine": {"pid": 102, "birth_id": "b102"},
            "engine_listener": {"pid": 103, "birth_id": "b103"},
        },
        "engine_binding": {"socket_owner_pid": 103},
        "session_config_digest": session_digest,
    }
    return profile, SimpleNamespace(
        report_value=report,
        owner_session_config_path=config_path,
    )


def test_private_worker_v2_profile_shape_excludes_runtime_only_endpoint(tmp_path):
    profile, _handle = _inspector_fixture(tmp_path)
    payload = CrossProcessWorkerPreparer._profile_payload(profile)
    assert "engine_endpoint" not in payload
    assert set(payload) == {
        "profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
        "worker_executable", "host_executable", "engine_executable",
        "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
        "engine_artifact_digest", "engine_listener_artifact_digest",
        "session_config_digest", "profile_revision", "profile_digest", "release_digest",
    }


def _patch_inspector_os(monkeypatch, inspector):
    def identity(pid, birth, executable, digest, **kwargs):
        parents = {100: os.getpid(), 101: 100, 102: 100, 103: 102}
        groups = {100: 100, 101: 101, 102: 102, 103: 102}
        return ProcessIdentity(pid, birth, runtime_platform.current_user(), parents[pid], groups[pid], groups[pid], executable, digest)

    monkeypatch.setattr(inspector, "_identity", identity)
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._listening_socket_owner",
        lambda pid, endpoint: (pid, endpoint),
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._owner_machine_id",
        lambda: "owner-machine",
    )


def test_inspector_derives_machine_and_session_from_owner_facts(tmp_path, monkeypatch):
    profile, handle = _inspector_fixture(tmp_path)
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)

    observed = inspector.observe(handle)

    assert observed.machine_id == "owner-machine"
    assert observed.session_config_digest == _content_digest(handle.owner_session_config_path.read_bytes())
    assert observed.engine_endpoint == profile.engine_endpoint


def test_forged_profile_machine_cannot_create_observed_fact(tmp_path, monkeypatch):
    profile, handle = _inspector_fixture(tmp_path, machine_id="forged-machine")
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)
    with pytest.raises(ConflictError, match="machine identity"):
        inspector.observe(handle)


@pytest.mark.parametrize("forgery", ["profile", "report", "observed_file"])
def test_forged_session_digest_cannot_create_observed_fact(tmp_path, monkeypatch, forgery):
    profile, handle = _inspector_fixture(tmp_path)
    if forgery == "profile":
        from dataclasses import replace
        profile = replace(profile, session_config_digest=_digest("9"))
    else:
        if forgery == "report":
            handle.report_value = dict(handle.report_value)
            handle.report_value["session_config_digest"] = _digest("9")
        else:
            handle.owner_session_config_path.write_bytes(b'{"port":8189}')
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)
    with pytest.raises(ConflictError, match="session configuration"):
        inspector.observe(handle)


def test_cross_process_abort_is_bounded_and_reaps_after_kill(tmp_path, monkeypatch):
    profile, _handle = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("worker", timeout)
            return self.returncode

    parent, peer = socket.socketpair()
    worker = Worker()
    handle = _PreparedWorker(worker, "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
        timeout_seconds=900,
        cleanup_timeout_seconds=0.05,
    )
    preparer._active = handle
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    signals = []

    def kill_tree(_process, sent_signal):
        signals.append(sent_signal)
        if sent_signal == signal.SIGKILL:
            worker.returncode = -signal.SIGKILL

    monkeypatch.setattr("runtime_protocol.local_worker_composition.runtime_platform.signal_tree", kill_tree)
    try:
        with pytest.raises((TimeoutError, OSError)):
            preparer.abort(handle)
    finally:
        peer.close()

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert worker.poll() == -signal.SIGKILL
    assert handle.closed is True
    assert preparer._active is None


def test_prepared_worker_launch_uses_utf8_interpreter_flag(tmp_path, monkeypatch):
    profile, _handle = _inspector_fixture(tmp_path)
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={"support_root": str(tmp_path)},
        environment={},
    )
    captured = []

    def stop_after_capture(argv, **_kwargs):
        captured.append(list(argv))
        raise RuntimeError("stop after launch capture")

    monkeypatch.setattr(runtime_platform, "spawn_tree", stop_after_capture)
    with pytest.raises(RuntimeError, match="stop after launch capture"):
        preparer.prepare(profile, operation_id="operation", channel_id="channel")

    assert captured[0][:4] == [str(profile.worker_executable), "-X", "utf8", "-m"]


def test_prepared_relay_and_custody_launches_keep_utf8_flags(tmp_path, monkeypatch):
    from dataclasses import replace
    import runtime_protocol.local_worker_composition as composition
    import runtime_protocol.local_execution_supervisor as supervisor
    import astrid_runtime.custody_broker as custody

    profile, _handle = _inspector_fixture(tmp_path)
    profile = replace(profile, engine_launch={"session_root": str(tmp_path / "session")})
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={"runtime_instance_id": "epoch"},
        environment={},
    )
    captured = {}
    monkeypatch.setattr(composition, "_selected_profile_payload", lambda _profile: {})
    monkeypatch.setattr(composition, "_actual_executable", lambda _pid: profile.worker_executable)
    monkeypatch.setattr(composition, "_file_digest", lambda _path: profile.worker_artifact_digest)
    monkeypatch.setattr(supervisor, "host_prepare_request", lambda **_kwargs: {})
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: {"pid": 1, "birth_id": "owner"})

    class Broker:
        def __init__(self, **_kwargs):
            pass

        def child_environment(self, argv, **_kwargs):
            captured["target"] = list(argv)
            return {}

        def abort_before_spawn(self):
            pass

    monkeypatch.setattr(custody, "RoleBoundCustodyBroker", Broker)

    def stop_after_capture(argv, **_kwargs):
        captured["wrapper"] = list(argv)
        raise RuntimeError("stop after wrapper capture")

    monkeypatch.setattr(runtime_platform, "spawn_tree", stop_after_capture)
    with pytest.raises(RuntimeError, match="stop after wrapper capture"):
        preparer.prepare(profile, operation_id="operation", channel_id="channel")

    assert captured["target"][:6] == [
        sys.executable, "-X", "utf8", "-I", "-m", "runtime_protocol.local_execution_supervisor",
    ]
    assert captured["wrapper"][:4] == [sys.executable, "-X", "utf8", "-I"]


def test_cancel_current_is_observable_while_spawn_handoff_is_locked(tmp_path):
    profile, _handle = _inspector_fixture(tmp_path)
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
        cleanup_timeout_seconds=0.05,
    )
    preparer._handoff_lock.acquire()
    try:
        preparer.cancel_current()
        assert preparer._prepare_cancel.is_set()
        assert preparer._handoff_lock.locked()
    finally:
        preparer._handoff_lock.release()


def test_control_probe_rejects_buffered_data_from_closed_peer(tmp_path, monkeypatch):
    profile, _unused = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    parent, peer = socket.socketpair()
    handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    peer.sendall(b"unexpected")
    peer.close()
    try:
        assert preparer.control_alive(handle) is False
    finally:
        parent.close()


def test_explicit_relay_profile_translates_exact_engine_launch_without_worker_environment(tmp_path):
    from test_local_execution_supervisor import _prepare_case
    document, _source, support, _packs = _profile_document(tmp_path)
    selected, _ = _prepare_case()
    document.pop("worker_environment")
    document["engine_launch"] = selected["profile"]["engine_launch"]
    document["session_config_digest"] = selected["profile"]["session_config_digest"]
    path = tmp_path / "relay-profile.json"
    path.write_text(json.dumps(document))
    composition = load_local_worker_composition(path, workspace_uuid="realm", realm_root=tmp_path / "realm", support_root=support, runtime_instance_id="runtime-epoch")
    assert composition.profiles["astrid"].engine_launch == document["engine_launch"]
    assert "ASTRID_WORKER_ENVIRONMENT" not in composition.preparer.environment
    assert composition.preparer.config["runtime_instance_id"] == "runtime-epoch"


def test_relay_receipt_v4_binds_epoch_scope_roles_and_selected_profile(tmp_path):
    from dataclasses import replace
    from test_local_execution_supervisor import _prepare_case
    from runtime_protocol.local_execution_supervisor import preparation_report, digest
    from runtime_protocol.local_worker import LocalWorkerLauncher, LocalWorkerObservation, _selected_profile_payload, _receipt_identity_digest_valid
    selected, host_report = _prepare_case()
    profile = LocalWorkerProfile(**{k: Path(v) if k in {"realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"} else v for k, v in selected["profile"].items()})
    refs = dict(host_report["custody_capabilities"])
    for role, pid, birth in (("relay", 20, "relay-birth"), ("host", 21, "host-birth")):
        refs[role] = {**refs["engine"], "role": role, "target": {**refs["engine"]["target"], "pid": pid, "birth_id": birth}}
    for ref in refs.values():
        ref["target"] = {**ref["target"], "uid": runtime_platform.current_user()}
    host_report = {**host_report, "custody_capabilities": {role: refs[role] for role in ("engine", "engine_listener")}}
    report = preparation_report(selected, host_report, relay_process={"pid": 20, "birth_id": "relay-birth"}, relay_reference=refs["relay"], host_reference=refs["host"])
    processes = {}
    for role, pid, parent, birth in (("worker", 20, 19, "relay-birth"), ("host", 21, 20, "host-birth"), ("engine", 22, 21, "engine-birth"), ("engine_listener", 23, 22, "listener-birth")):
        exe_name = "worker" if role == "worker" else role
        processes[role] = ProcessIdentity(pid, birth, runtime_platform.current_user(), parent, 22 if role == "engine_listener" else pid, 22 if role == "engine_listener" else pid, getattr(profile, exe_name + "_executable"), getattr(profile, exe_name + "_artifact_digest"))
    observed = LocalWorkerObservation(profile.machine_id, runtime_platform.current_user(), profile.workspace_uuid, profile.realm_root, profile.support_root, **processes, engine_listener_socket_owner_pid=23, engine_endpoint=profile.engine_endpoint, session_config_digest=profile.session_config_digest, owner_epoch="runtime-epoch", custody_scope=selected["custody_scope"], custody_capabilities=refs)
    launcher = object.__new__(LocalWorkerLauncher)
    launcher.runtime_pid = 19
    launcher.workspace_uuid = profile.workspace_uuid
    launcher.realm_root = profile.realm_root
    launcher.support_root = profile.support_root
    identity = launcher._validate_observation(profile, observed, report=report, operation_id="operation", channel_id="channel")
    receipt = {"version": "runtime.local-worker-receipt/v4", **identity, "executor_incarnation": "incarnation"}
    assert identity["profile_binding_digest"] == digest(_selected_profile_payload(profile))
    args = dict(workspace_uuid=profile.workspace_uuid, realm_root=profile.realm_root, support_root=profile.support_root)
    assert _receipt_identity_digest_valid(profile, receipt, **args)
    changed = {**receipt, "owner_epoch": "replacement-runtime"}
    assert not _receipt_identity_digest_valid(profile, changed, **args)
    changed_report = {**report, "owner_epoch": "replacement-runtime"}
    with pytest.raises(ConflictError, match="independently verified custody"):
        launcher._validate_observation(profile, observed, report=changed_report, operation_id="operation", channel_id="channel")


def test_relay_stop_without_retained_control_never_uses_numeric_signal(tmp_path, monkeypatch):
    from dataclasses import replace
    document, _, support, _ = _profile_document(tmp_path)
    profile = LocalWorkerProfile(**{k: Path(v) if k in {"realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"} else v for k, v in __import__("test_local_execution_supervisor")._prepare_case()[0]["profile"].items()})
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    monkeypatch.setattr(runtime_platform, "signal_process", lambda *_: pytest.fail("numeric fallback"))
    monkeypatch.setattr(runtime_platform, "signal_tree", lambda *_: pytest.fail("numeric fallback"))
    with pytest.raises(ConflictError, match="retained control"):
        preparer.stop_owned({})


def test_relay_restart_cannot_treat_missing_control_as_absent_generation():
    from test_local_execution_supervisor import _prepare_case
    selected = _prepare_case()[0]["profile"]
    profile = LocalWorkerProfile(**{k: Path(v) if k in {"realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"} else v for k, v in selected.items()})
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    with pytest.raises(ConflictError, match="capability recovery remains unresolved"):
        preparer.reconnect({"version": "runtime.local-worker-receipt/v4"})


def test_relay_retained_reconnect_requires_exact_receipt_and_incarnation(tmp_path, monkeypatch):
    import copy
    from test_local_execution_supervisor import _handoff_case, _prepare_case
    from runtime_protocol.auth import CredentialStore
    from runtime_protocol.local_worker import _credential_commit_generation
    from runtime_protocol.local_execution_handoff import write_protected
    request, _ = _handoff_case(tmp_path)
    caps = request["binding"]["current_roles"]
    selected = _prepare_case()[0]["profile"]
    selected.update(support_root=str(tmp_path))
    profile = LocalWorkerProfile(**{k: Path(v) if k in {"realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"} else v for k, v in selected.items()})
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    scope = tmp_path / "custody"
    receipt = {"version": "runtime.local-worker-receipt/v4", "owner_epoch": "A", "custody_scope": str(scope), "profile_binding_digest": "sha256:" + "1" * 64, "executor_incarnation": "incarnation", "evidence_digest": "sha256:" + "2" * 64, "custody_capabilities": caps,
               **{alias: {k: caps[role]["target"][k] for k in ("pid", "birth_id")} for alias, role in (("worker", "relay"), ("host", "host"), ("engine", "engine"), ("engine_listener", "engine_listener"))}}
    credentials = CredentialStore(tmp_path / "credentials")
    credentials.provision("actor", [], metadata={"local_launch_receipt": receipt})
    generation = _credential_commit_generation(credentials, "actor")
    write_protected(scope / "activation-record.json", {"evidence_digest": receipt["evidence_digest"], "executor_incarnation": "incarnation", "custody_capabilities": caps, "original_owner_epoch": "A", "credential_generation": generation})
    live = copy.deepcopy(caps)
    current = request["binding"]["source_owner"]
    monkeypatch.setattr("astrid_runtime.custody_broker.AuthenticatedCleanupActor.current", lambda: SimpleNamespace(verify=lambda: current))
    class Authority:
        def __init__(self, scope, role):
            self.role = role
        def verify_reference(self, ref, **kwargs):
            if ref != live[self.role]:
                raise ConflictError("kernel incarnation changed")
            return ref
    monkeypatch.setattr("astrid_runtime.custody_broker.RoleCustodyAuthority", Authority)
    handle = SimpleNamespace(relay=True, activated=True, closed=False, owner_epoch="A", custody_scope=str(scope), retained=SimpleNamespace(verify=lambda: caps["relay"]["target"]))
    preparer._active = handle
    preparer._generation_verifier = (handle, lambda: _credential_commit_generation(credentials, "actor"))
    report = {"owner_epoch": "A", "profile_binding_digest": receipt["profile_binding_digest"], "custody_scope": str(scope), "custody_capabilities": caps, "processes": {role: receipt[role] for role in ("worker", "host", "engine", "engine_listener")}}
    monkeypatch.setattr(preparer, "report", lambda h: copy.deepcopy(report))
    before = (scope / "activation-record.json").read_bytes()
    assert preparer.reconnect(receipt) is handle
    assert (scope / "activation-record.json").read_bytes() == before
    changed = {**receipt, "evidence_digest": "sha256:" + "9" * 64}
    with pytest.raises(ConflictError, match="activation evidence"):
        preparer.reconnect(changed)
    live["engine"]["target"]["birth_id"] = "replacement"
    with pytest.raises(ConflictError, match="incarnation changed"):
        preparer.reconnect(receipt)


def test_relay_adoption_failure_retains_nonchild_cleanup_obligation(tmp_path, monkeypatch):
    from test_local_execution_supervisor import _prepare_case
    selected = _prepare_case()[0]["profile"]
    profile = LocalWorkerProfile(**{k: Path(v) if k in {"realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"} else v for k, v in selected.items()})
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    a, b = socket.socketpair()
    obligation = SimpleNamespace(control=a, inherited_from="A", cleanup_unresolved=True)
    monkeypatch.setattr(runtime_platform, "signal_process", lambda *_: pytest.fail("numeric fallback"))
    try:
        with pytest.raises(ConflictError, match="fresh authenticated B"):
            preparer.adopt_control_descriptor(obligation, {}, {})
        assert obligation.control.fileno() >= 0 and obligation.cleanup_unresolved
        assert preparer._active is None
        a.sendall(b"retained"); assert b.recv(8) == b"retained"
    finally:
        a.close(); b.close()


def test_g1b_both_profile_projections_preserve_optional_protocol():
    from dataclasses import replace
    from runtime_protocol.local_worker import _selected_profile_payload
    from test_local_worker import profile_case, declaration
    profile=profile_case()
    assert 'host_protocol' not in CrossProcessWorkerPreparer._profile_payload(profile)
    selected=replace(profile,host_protocol=declaration())
    projected=CrossProcessWorkerPreparer._profile_payload(selected)
    canonical=_selected_profile_payload(selected)
    assert projected['host_protocol']==canonical['host_protocol']==declaration()
    from runtime_protocol.local_execution_supervisor import digest
    assert digest(projected)!=digest(CrossProcessWorkerPreparer._profile_payload(profile))


@pytest.mark.parametrize('protocol',[None, {}, {'version':'unknown'}, {'version':'runtime.local-execution-current-roles/v1','module':'astrid.core.execution.generic_host','source_closure_digest':'sha256:'+'a'*64}])
def test_g1b_profile_loader_rejects_malformed_optional_field(tmp_path,protocol):
    document,source,support,packs=_profile_document(tmp_path);document['host_protocol']=protocol
    path=tmp_path/'worker-profile.json';path.write_text(json.dumps(document))
    with pytest.raises(Exception,match='host_protocol'):
        load_local_worker_composition(path,workspace_uuid='w',realm_root=tmp_path/'realm',support_root=support,runtime_instance_id='epoch')


def test_g1b_profile_loader_rejects_legacy_protocol_path(tmp_path):
    from test_local_worker import declaration
    document,source,support,packs=_profile_document(tmp_path);document['host_protocol']=declaration()
    path=tmp_path/'worker-profile.json';path.write_text(json.dumps(document))
    with pytest.raises(Exception,match='requires.*engine_launch'):
        load_local_worker_composition(path,workspace_uuid='w',realm_root=tmp_path/'realm',support_root=support,runtime_instance_id='epoch')


def test_g1b_selected_loader_carries_protocol_without_claiming_verification(tmp_path):
    from test_local_execution_supervisor import _prepare_case
    from test_local_worker import declaration
    document,source,support,packs=_profile_document(tmp_path);selected=_prepare_case()[0]['profile']
    document.update(engine_launch=selected['engine_launch'],session_config_digest=selected['session_config_digest'],host_protocol=declaration())
    path=tmp_path/'worker-profile.json';path.write_text(json.dumps(document))
    composition=load_local_worker_composition(path,workspace_uuid='w',realm_root=tmp_path/'realm',support_root=support,runtime_instance_id='epoch')
    assert composition.profiles['astrid'].host_protocol==declaration()
    assert CrossProcessWorkerPreparer._profile_payload(composition.profiles['astrid'])['host_protocol']==declaration()


def test_host_only_loader_preserves_lexical_interpreter_and_rejects_engine(tmp_path):
    from runtime_protocol.local_worker import _digest
    from runtime_protocol.local_execution_supervisor import CURRENT_ROLES_VERSION
    document, source, support, packs = _profile_document(tmp_path)
    for key in ['worker_environment','worker_executable','worker_artifact_digest','engine_executable','engine_listener_executable','engine_artifact_digest','engine_listener_artifact_digest','engine_endpoint']:
        document.pop(key)
    document.update(execution_mode='host_only_cpu', host_executable=os.path.abspath(sys.executable),
        host_os_executable=str(Path(sys.executable).resolve()), host_os_artifact_digest=_digest('1'),
        host_protocol={'version':CURRENT_ROLES_VERSION,'module':'astrid.core.execution.generic_host','source_closure_digest':'a'*64},environment={},max_concurrency=4)
    launch = {k:document[k] for k in ('source_checkout','pack_root','boot_manifest_path','boot_manifest_hash','environment')}
    launch['capability_matrix']=None
    launch['max_concurrency']=4
    document['session_config_digest']=_digest(launch)
    path=tmp_path/'host-only.json';path.write_text(json.dumps(document))
    result=load_local_worker_composition(path, workspace_uuid='realm', realm_root=tmp_path/'realm',support_root=support,runtime_instance_id='epoch')
    profile=result.profiles['astrid']
    assert str(profile.host_executable)==os.path.abspath(sys.executable)
    assert profile.worker_executable is None and profile.engine_launch is None
    document['engine_launch']={};path.write_text(json.dumps(document))
    with pytest.raises(Exception,match='cannot declare'):
        load_local_worker_composition(path, workspace_uuid='realm',realm_root=tmp_path/'realm',support_root=support,runtime_instance_id='epoch')


def test_host_only_nonchild_stop_and_reconnect_never_signal(tmp_path, monkeypatch):
    from test_local_worker import host_only_profile_case
    profile=host_only_profile_case()
    preparer=CrossProcessWorkerPreparer(profile=profile,config={},environment={})
    monkeypatch.setattr(runtime_platform,'signal_process',lambda *args:pytest.fail('numeric PID cleanup'))
    monkeypatch.setattr(runtime_platform,'signal_tree',lambda *args:pytest.fail('numeric group cleanup'))
    with pytest.raises(ConflictError,match='original retained'):
        preparer.stop_owned({'host':{'pid':123,'birth_id':'old'}})
    with pytest.raises(ConflictError,match='unsupported'):
        preparer.reconnect({'host':{'pid':123,'birth_id':'old'}})


def test_host_only_abort_missing_ack_retains_handle_and_does_not_signal(tmp_path, monkeypatch):
    import threading
    from test_local_worker import host_only_profile_case
    profile=host_only_profile_case(); preparer=CrossProcessWorkerPreparer(profile=profile,config={},environment={})
    retained=SimpleNamespace(verify=lambda:{'pid':42,'birth_id':'b'})
    handle=_PreparedWorker(SimpleNamespace(pid=42), 'b', SimpleNamespace(settimeout=lambda value:None), {}, tmp_path/'config.json',
        retained=retained,host_only=True,owner_epoch='epoch',custody_scope=str(tmp_path),
        preparation={'version':'runtime.local-execution-preparation/v1','operation_id':'op','channel_id':'ch','owner_epoch':'epoch'},
        broker=SimpleNamespace(signal=lambda *args,**kwargs:pytest.fail('signal before cleanup ack')))
    preparer._active=handle
    monkeypatch.setattr(preparer,'_host_only_report',lambda h:{'profile_binding_digest':_digest('1'),'custody_capabilities':{'host':{'pid':42}}})
    monkeypatch.setattr('runtime_protocol.local_worker_composition._frame_send',lambda *args:None)
    monkeypatch.setattr('runtime_protocol.local_worker_composition._frame_receive',lambda *args:{'status':'unresolved'})
    with pytest.raises(ConflictError,match='acknowledgement'):
        preparer.abort(handle)
    assert preparer._active is handle and not handle.closed and preparer.cleanup_uncertain


@pytest.fixture
def retained_host_cleanup(tmp_path, monkeypatch):
    """Real original-child wait; synthetic host identity and ACK transport."""
    from runtime_protocol.local_execution_supervisor import RetainedProcess
    from test_local_worker import host_only_profile_case

    profile = host_only_profile_case()
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    child = subprocess.Popen([sys.executable, "-I", "-c",
        "import sys; sys.stdin.buffer.read(1); raise SystemExit(23)"], stdin=subprocess.PIPE)
    retained = RetainedProcess(child)
    monkeypatch.setattr(retained, "verify", lambda: {"pid": child.pid, "birth_id": "original"})
    control, peer = socket.socketpair()
    activation, activation_peer = socket.socketpair()
    events, requests = [], []

    def signal(signum, *, expected_pid):
        assert expected_pid == child.pid and signum == runtime_platform.TERM
        assert events[-1] == "ack"
        events.append("signal")
        child.stdin.close()

    handle = _PreparedWorker(child, "original", control, {}, tmp_path / "config.json",
        retained=retained, host_only=True, activation=activation, owner_epoch="epoch",
        custody_scope=str(tmp_path),
        preparation={"version": "runtime.local-execution-preparation/v1", "operation_id": "op",
            "channel_id": "channel", "owner_epoch": "epoch"},
        broker=SimpleNamespace(signal=signal))
    preparer._active = handle
    monkeypatch.setattr(preparer, "_host_only_report", lambda _: {
        "profile_binding_digest": _digest("1"), "custody_capabilities": {"host": {"pid": child.pid}}})

    def send(channel, request):
        events.append("request")
        requests.append(request)

    def receive(channel):
        events.append("ack")
        return {**{key: value for key, value in requests[-1].items() if key != "command"},
            "status": "cleaned", "cleanup": {"host_children": "absent"}}

    monkeypatch.setattr("runtime_protocol.local_worker_composition._frame_send", send)
    monkeypatch.setattr("runtime_protocol.local_worker_composition._frame_receive", receive)
    original_wait = retained.wait

    def wait(timeout):
        events.append("reap")
        return original_wait(timeout)

    monkeypatch.setattr(retained, "wait", wait)
    try:
        yield SimpleNamespace(preparer=preparer, handle=handle, child=child, retained=retained,
            events=events, receive=receive, original_wait=original_wait)
    finally:
        child.stdin.close()
        for channel in (control, peer, activation, activation_peer):
            channel.close()
        if retained.exit_code is None:
            child.wait(timeout=5.0)


def _terminal_cleanup_launcher(preparer):
    from runtime_protocol.local_worker import LocalWorkerLauncher
    launcher = LocalWorkerLauncher.__new__(LocalWorkerLauncher)
    launcher.preparer = preparer
    launcher._watch_thread = None
    return launcher


def test_host_only_ack_then_real_original_child_reap_closes_and_clears(retained_host_cleanup):
    case = retained_host_cleanup
    _terminal_cleanup_launcher(case.preparer).finish_shutdown([case.handle])
    assert case.events == ["request", "ack", "signal", "reap"]
    assert case.retained.exit_code == case.child.returncode == 23
    assert case.handle.closed and case.preparer.current_handle() is None
    assert not case.handle.cleanup_abandoned
    assert case.handle.control.fileno() == case.handle.activation.fileno() == -1


@pytest.mark.parametrize("ack", ["missing", "wrong-epoch", "children-unresolved"])
def test_terminal_shutdown_child_exit_without_valid_ack_releases_channels_but_keeps_custody(
    retained_host_cleanup, monkeypatch, ack,
):
    case = retained_host_cleanup

    def receive(channel):
        # A positively reaped original child is still insufficient without the
        # authenticated, exactly bound ACK covering all owned descendants.
        case.child.stdin.close()
        assert case.original_wait(5.0) == 23
        if ack == "missing":
            raise OSError("host cleanup ACK missing")
        response = case.receive(channel)
        if ack == "wrong-epoch":
            response["owner_epoch"] = "other"
        else:
            response["cleanup"]["host_children"] = "unresolved"
        return response

    monkeypatch.setattr("runtime_protocol.local_worker_composition._frame_receive", receive)
    with pytest.raises(ConflictError, match="cleanup is uncertain"):
        _terminal_cleanup_launcher(case.preparer).finish_shutdown([case.handle])
    assert "signal" not in case.events
    assert case.retained.exit_code == case.child.returncode == 23
    assert case.preparer.current_handle() is case.handle and not case.handle.closed
    assert case.handle.cleanup_abandoned and case.preparer.cleanup_uncertain
    assert case.handle.control.fileno() == case.handle.activation.fileno() == -1


def test_terminal_shutdown_timeout_prevents_late_cleanup_from_clearing_custody(
    retained_host_cleanup, monkeypatch,
):
    import threading
    case = retained_host_cleanup
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    abort = case.preparer.abort

    def wait(timeout):
        entered.set()
        assert release.wait(5.0)
        return case.original_wait(timeout)

    def delayed_abort(handle):
        try:
            abort(handle)
        finally:
            completed.set()

    monkeypatch.setattr(case.retained, "wait", wait)
    monkeypatch.setattr(case.preparer, "abort", delayed_abort)
    try:
        with pytest.raises(ConflictError, match="bounded deadline"):
            _terminal_cleanup_launcher(case.preparer).finish_shutdown([case.handle])
        assert entered.is_set()
        assert case.handle.control.fileno() == case.handle.activation.fileno() == -1
    finally:
        release.set()
        assert completed.wait(5.0)
    assert case.retained.exit_code == 23
    assert case.preparer.current_handle() is case.handle and not case.handle.closed
    assert case.handle.cleanup_abandoned and case.preparer.cleanup_uncertain


def test_host_only_preparer_projects_admitted_slots_and_canonical_binding_without_engine(tmp_path,monkeypatch):
    """Offline transport contract only; fake handles grant no native custody proof."""
    import threading
    from dataclasses import replace
    from test_local_worker import host_only_profile_case
    from runtime_protocol import local_worker_composition as module
    from runtime_protocol import verified_host_launch, local_execution_supervisor
    import astrid_runtime.custody_broker as custody
    original=SimpleNamespace(pid=4242)
    identity={'pid':4242,'birth_id':'original','uid':runtime_platform.current_user()}
    selected=host_only_profile_case()
    profile=replace(selected,support_root=tmp_path)
    config={**profile.host_launch,'runtime_endpoint':'http://127.0.0.1:1','runtime_instance_id':'epoch',
        'credential_file':str(tmp_path/'credential'),'ready_file':str(tmp_path/'ready')}
    captures={};read_done=threading.Event()
    for key in ('PYTHONPATH','PYTHONHOME','PYTHONDONTWRITEBYTECODE','ASTRID_RUNTIME_DATA_ROOT','ASTRID_RUNTIME_OWNER_TOKEN','ASTRID_OUTPUT_ROOT','ASTRID_EXECUTION_TARGET_JSON'):
        monkeypatch.setenv(key,'unadmitted-ambient')
    class Verifier:
        def __init__(self,**kwargs):pass
        def verify(self,**kwargs):captures['argv']=kwargs['host_argv'];captures['environment']=kwargs['environment'];return object()
        def claim(self,proof,**kwargs):
            captures['binding_fd']=kwargs['binding_fd']
            return kwargs['host_argv'],b'{"canonical":true}'
        def bind_child(self,proof,**kwargs):assert kwargs['child'] is original
        def verify_child(self,proof,**kwargs):assert kwargs['child'] is original
    class Retained:
        def __init__(self,process):assert process is original
        def bind_actor(self):pass
        def verify(self):return identity
    class Broker:
        def __init__(self,**kwargs):
            assert kwargs['role']=='host'
            descriptor=custody._open_authority_scope_lock(kwargs['authority_scope_root'])
            os.close(descriptor)
            self.role_authority=SimpleNamespace(reference=lambda:{'role':'host'})
        def child_environment(self,argv,**kwargs):return {}
        def wait_until_sealed(self):pass
    def popen(argv,**kwargs):
        descriptor=os.dup(captures['binding_fd'])
        def read_binding():
            data=b''
            while True:
                chunk=os.read(descriptor,4096)
                if not chunk:break
                data+=chunk
            os.close(descriptor);captures['binding']=data;read_done.set()
        threading.Thread(target=read_binding,daemon=True).start()
        return original
    monkeypatch.setattr(verified_host_launch,'TrustedLocalHostLaunchVerifier',Verifier)
    monkeypatch.setattr(local_execution_supervisor,'RetainedProcess',Retained)
    monkeypatch.setattr(custody,'RoleBoundCustodyBroker',Broker)
    monkeypatch.setattr(custody,'default_process_identity',lambda pid:{'pid':os.getpid(),'uid':runtime_platform.current_user(),'parent_pid':1,'birth_id':'owner'})
    monkeypatch.setattr(module,'_installed_host_release',lambda *args:{})
    monkeypatch.setattr(module.subprocess,'Popen',popen)
    monkeypatch.setattr(module,'_frame_send',lambda channel,value:captures.update(request=value))
    monkeypatch.setattr(module,'_frame_receive',lambda channel:{'version':captures['request']['version'],'status':'prepared',
        'operation_id':'op','channel_id':'channel','owner_epoch':'epoch','execution_mode':'host_only_cpu',
        'processes':{'host':{'pid':4242,'birth_id':'original'}},'session_config_digest':profile.session_config_digest})
    preparer=CrossProcessWorkerPreparer(profile=profile,config=config,environment={})
    handle=preparer.prepare(profile,operation_id='op',channel_id='channel')
    try:
        assert preparer._active is handle and handle.worker is original and handle.host_only
        assert read_done.wait(1) and captures['binding']==b'{"canonical":true}'
        argv=captures['argv'];assert argv[argv.index('--max-concurrency')+1]=='4'
        target=json.loads(argv[argv.index('--execution-target-json')+1]);assert target=={'kind':'default'}
        assert set(handle.report_value['processes'])=={'host'}
        env=captures['environment']
        assert env['ASTRID_OUTPUT_ROOT']==str(profile.support_root/'host-output')
        assert env['ASTRID_RUNTIME_DATA_ROOT']==str(profile.realm_root)
        assert not set(env)&{'PYTHONPATH','PYTHONHOME','PYTHONDONTWRITEBYTECODE','ASTRID_RUNTIME_OWNER_TOKEN','ASTRID_EXECUTION_TARGET_JSON'}
    finally:
        handle.control.close();handle.activation.close()


def test_host_only_observation_rejects_missing_original_handle():
    from test_local_worker import host_only_profile_case
    with pytest.raises(ConflictError, match="original retained handle"):
        OSProcessInspector(host_only_profile_case()).observe(None)


def test_host_only_custody_scope_is_private_before_real_authority_open(tmp_path):
    from runtime_protocol.local_worker_composition import _create_host_custody_scope
    from astrid_runtime.custody_broker import _open_authority_scope_lock
    scope=tmp_path/'new-parent'/'operation'
    _create_host_custody_scope(scope)
    assert scope.stat().st_mode & 0o777 == 0o700
    descriptor=_open_authority_scope_lock(scope)
    os.close(descriptor)


@pytest.mark.parametrize('mode',[0o700,0o755])
def test_host_only_custody_scope_collision_retains_existing_bytes(tmp_path,mode):
    from runtime_protocol.local_worker_composition import _create_host_custody_scope
    scope=tmp_path/'operation';scope.mkdir(mode=mode);scope.chmod(mode)
    evidence=scope/'retained';evidence.write_bytes(b'original obligation')
    before=scope.stat()
    with pytest.raises(ConflictError,match='already exists'):
        _create_host_custody_scope(scope)
    after=scope.stat()
    assert (after.st_ino,after.st_mode)==(before.st_ino,before.st_mode)
    assert evidence.read_bytes()==b'original obligation'


def test_host_only_custody_scope_alias_never_mutates_target(tmp_path):
    from runtime_protocol.local_worker_composition import _create_host_custody_scope
    target=tmp_path/'target';target.mkdir()
    alias=tmp_path/'alias';alias.symlink_to(target,target_is_directory=True)
    with pytest.raises(ConflictError,match='not canonical'):
        _create_host_custody_scope(alias/'operation')
    assert not list(target.iterdir())


@requires_posix_uid_metadata
def test_host_only_custody_scope_wrong_owner_never_grants_authority(tmp_path,monkeypatch):
    from runtime_protocol.local_worker_composition import _create_host_custody_scope
    scope=tmp_path/'operation'
    original_uid=runtime_platform.current_user()
    monkeypatch.setattr(runtime_platform,'current_user',lambda:original_uid+1)
    with pytest.raises(ConflictError,match='not owner-only'):
        _create_host_custody_scope(scope)
    assert scope.stat().st_uid==original_uid
    assert not list(scope.iterdir())
