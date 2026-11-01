"""Installed local Worker composition owned by Runtime.

This module is deliberately small: Runtime owns the profile, private control
channel, and OS observation; the Python 3.10 Worker remains a separate
installed process.  No Worker implementation is imported into Runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
import ipaddress
from pathlib import Path
import platform
import select
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import platform as runtime_platform
from .errors import ConflictError, ValidationError
from .local_worker import (
    LocalWorkerObservation,
    LocalWorkerPreparer,
    LocalWorkerProfile,
    ProcessIdentity,
    _engine_endpoint,
    _selected_profile_payload,
    _host_only,
    _secure_profile,
)


CONTROL_VERSION = "workspace.local-worker-control/v1"
CONTROL_FRAME_LIMIT = 64 * 1024
PROFILE_FIELDS = (
    "profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
    "worker_executable", "host_executable", "engine_executable",
    "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
    "engine_artifact_digest", "engine_listener_artifact_digest", "session_config_digest",
    "profile_revision", "profile_digest", "release_digest",
)


def _create_host_custody_scope(scope: Path) -> None:
    # The broker creates its ledger child first. Its implicit mkdir parents
    # must not supply the operation's owner-only authority directory.
    if not scope.is_absolute() or scope.resolve() != scope:
        raise ConflictError("host-only custody scope is not canonical")
    try:
        scope.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError as exc:
        raise ConflictError("host-only custody scope already exists") from exc
    if os.name == "nt":
        runtime_platform.owner_only(scope, directory=True)
    observed = scope.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or not runtime_platform.is_owner_only(scope if os.name == "nt" else observed, directory=True)
            or scope.resolve() != scope):
        raise ConflictError("host-only custody scope is not owner-only")


def _frame_send(channel: socket.socket, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(dict(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > CONTROL_FRAME_LIMIT:
        raise ConflictError("local Worker control frame is too large")
    channel.sendall(encoded + b"\n")


def _frame_receive(channel: socket.socket) -> dict[str, Any]:
    frame = bytearray()
    while b"\n" not in frame:
        chunk = channel.recv(min(4096, CONTROL_FRAME_LIMIT + 1 - len(frame)))
        if not chunk:
            raise ConflictError("local Worker control channel closed")
        frame.extend(chunk)
        if len(frame) > CONTROL_FRAME_LIMIT:
            raise ConflictError("local Worker control frame is too large")
    encoded, remainder = bytes(frame).split(b"\n", 1)
    if remainder:
        raise ConflictError("local Worker control channel carried multiple frames")
    try:
        from .local_execution_handoff import decode
        value = decode(encoded)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ConflictError("local Worker control frame is malformed") from exc
    if not isinstance(value, dict):
        raise ConflictError("local Worker control frame must be an object")
    return value


@dataclass
class _PreparedWorker:
    worker: subprocess.Popen[bytes]
    birth_id: str
    control: socket.socket
    report_value: dict[str, Any]
    owner_session_config_path: Path
    activated: bool = False
    closed: bool = False
    rpc_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_resolution_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_started: bool = False
    cleanup_abandoned: bool = False
    relay: bool = False
    retained: Any = None
    broker: Any = None
    owner_epoch: str | None = None
    custody_scope: str | None = None
    host_only: bool = False
    activation: socket.socket | None = None
    preparation: dict[str, Any] | None = None
    launch_verifier: Any = None
    verified_launch: Any = None


@dataclass
class _AdoptedHandoffControl:
    """Nonchild retained control obligation; never a manufactured Popen."""
    control: socket.socket
    relay_actor: Any
    binding: dict[str, Any]
    result: dict[str, Any] | None = None
    rpc_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_unresolved: bool = True

    def verify(self):
        if self.relay_actor.verify() != self.binding["source_relay_reference"]["target"]:
            raise ConflictError("adopted relay private peer incarnation changed")


class CrossProcessWorkerPreparer(LocalWorkerPreparer):
    """Runtime-side transport for the installed Worker private ABI."""

    def __init__(self, *, profile: LocalWorkerProfile, config: Mapping[str, Any], environment: Mapping[str, str], timeout_seconds: float = 900.0, cleanup_timeout_seconds: float = 0.1):
        self.profile = profile
        self.config = dict(config)
        self.environment = dict(environment)
        self.timeout_seconds = float(timeout_seconds)
        self.cleanup_timeout_seconds = max(0.05, float(cleanup_timeout_seconds))
        if _host_only(profile):
            self.shutdown_timeout_seconds = self.cleanup_timeout_seconds * 2 + 0.5
        self._active: _PreparedWorker | None = None
        self._activation_binding = None
        self._generation_verifier = None
        self._adopted_handoff = None
        self._prepare_cancel = threading.Event()
        # The only uninterruptible handoff is spawn -> handle construction ->
        # publication. Cancellation waits for this tiny critical section so a
        # just-spawned child can never exist without an owner-visible handle.
        self._handoff_lock = threading.Lock()

    def set_prepare_cancel_event(self, event: threading.Event) -> None:
        self._prepare_cancel = event

    def cancel_current(self) -> None:
        """Interrupt a prepare RPC without waiting for its normal timeout."""
        self._prepare_cancel.set()
        if not self._handoff_lock.acquire(timeout=self.cleanup_timeout_seconds):
            return
        try:
            handle = self._active
        finally:
            self._handoff_lock.release()
        if handle is None or handle.closed:
            return
        try:
            self.abort(handle)
        except BaseException:
            # The owner has already fenced authority. The prepare caller will
            # observe the closed channel and run its own bounded abort path.
            pass

    def bind_runtime(self, *, endpoint: str, runtime_instance_id: str, credential_file: Path) -> None:
        self.config.update({
            "runtime_endpoint": str(endpoint).rstrip("/"),
            "runtime_instance_id": str(runtime_instance_id),
            "credential_file": str(credential_file),
        })

    @staticmethod
    def _birth(pid: int) -> str:
        try:
            identity = runtime_platform.process_identity(pid)
            value = identity.get("birth_id") if identity is not None else None
        except OSError as exc:
            raise ConflictError("prepared Worker birth identity is unavailable") from exc
        if not value:
            raise ConflictError("prepared Worker birth identity is unavailable")
        return value

    @staticmethod
    def _profile_payload(profile: LocalWorkerProfile) -> dict[str, Any]:
        payload = {
            name: str(getattr(profile, name)) if isinstance(getattr(profile, name), Path) else getattr(profile, name)
            for name in PROFILE_FIELDS
        }
        if profile.host_protocol is not None:
            from .verified_host_launch import validate_host_protocol, HostLaunchError
            if profile.engine_launch is None:
                raise ValidationError("host_protocol requires the explicit engine_launch path")
            try:
                payload["host_protocol"] = validate_host_protocol(profile.host_protocol)
            except HostLaunchError as exc:
                raise ValidationError(str(exc)) from exc
        return payload

    def _rpc_unlocked(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        if handle.closed or (handle.retained.poll() if (handle.relay or handle.host_only) else handle.worker.poll()) is not None:
            raise ConflictError("prepared Worker is not alive")
        if self._birth(handle.worker.pid) != handle.birth_id:
            raise ConflictError("prepared Worker identity changed")
        _frame_send(handle.control, payload)
        response = _frame_receive(handle.control)
        expected_version = "runtime.local-execution-control/v1" if handle.relay else CONTROL_VERSION
        if response.get("version") != expected_version:
            raise ConflictError("prepared Worker control version is invalid")
        if response.get("status") != "ok":
            raise ConflictError(str(response.get("error") or "prepared Worker rejected the operation"))
        return response

    def _rpc(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        with handle.rpc_lock:
            return self._rpc_unlocked(handle, payload)

    def prepare(self, profile: LocalWorkerProfile, *, operation_id: str, channel_id: str) -> _PreparedWorker:
        if _host_only(profile):
            return self._prepare_host_only(profile, operation_id=operation_id, channel_id=channel_id)
        if profile.engine_launch is not None:
            return self._prepare_relay(profile, operation_id=operation_id, channel_id=channel_id)
        if self._active is not None:
            self.abort(self._active)
        if self._prepare_cancel.is_set():
            raise ConflictError("local Worker preparation cancelled")
        parent, child = socket.socketpair()
        worker: subprocess.Popen[bytes] | None = None
        handle: _PreparedWorker | None = None
        try:
            with self._handoff_lock:
                if self._prepare_cancel.is_set():
                    raise ConflictError("local Worker preparation cancelled")
                executable = Path(profile.worker_executable)
                environment = dict(self.environment)
                environment.pop("PYTHONPATH", None)
                worker_environment = environment.pop("ASTRID_WORKER_ENVIRONMENT", "")
                if worker_environment:
                    env_root = Path(worker_environment).expanduser().resolve()
                    # A venv's ``bin/python`` carries the environment's package
                    # boundary through its adjacent pyvenv.cfg.  Its kernel
                    # executable may resolve to the base interpreter, which is
                    # checked independently by OSProcessInspector below.
                    candidate = runtime_platform.venv_python(env_root)
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        executable = candidate
                    environment["VIRTUAL_ENV"] = str(env_root)
                    environment["PATH"] = str(runtime_platform.venv_python(env_root).parent) + os.pathsep + environment.get("PATH", "")
                worker = runtime_platform.spawn_tree(
                    [str(executable), "-X", "utf8", "-m", "source.runtime.supervisor", "--prepared-control-fd", str(child.fileno())],
                    cwd=str(Path(self.config["support_root"])),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(child.fileno(),),
                )
                child.close()
                parent.settimeout(self.timeout_seconds)
                handle = _PreparedWorker(
                    worker,
                    self._birth(worker.pid),
                    parent,
                    {},
                    _session_config_path(environment),
                )
                # Publish Runtime custody before the first potentially blocking
                # control RPC. cancel_current() cannot pass the handoff lock
                # until this handle is visible, so no spawned child can be
                # missed by owner shutdown.
                self._active = handle
            if self._prepare_cancel.is_set():
                self.abort(handle)
                raise ConflictError("local Worker preparation cancelled")
            response = self._rpc(handle, {
                "version": CONTROL_VERSION,
                "command": "prepare",
                "operation_id": operation_id,
                "channel_id": channel_id,
                "profile": self._profile_payload(profile),
                "config": dict(self.config),
            })
            report = response.get("report")
            if not isinstance(report, dict):
                raise ConflictError("prepared Worker returned no process report")
            handle.report_value = report
            return handle
        except BaseException:
            child.close()
            if handle is not None:
                try:
                    self.abort(handle)
                except BaseException:
                    pass
            else:
                parent.close()
            if handle is None and worker is not None and worker.poll() is None:
                try:
                    runtime_platform.signal_tree(worker, runtime_platform.KILL)
                except OSError:
                    pass
                try:
                    worker.wait(timeout=self.cleanup_timeout_seconds)
                except (subprocess.TimeoutExpired, TimeoutError):
                    pass
            raise

    def _prepare_host_only(self, profile, *, operation_id, channel_id):
        from .local_execution_supervisor import host_prepare_request, RetainedProcess
        from .verified_host_launch import TrustedLocalHostLaunchVerifier, canonical
        from astrid_runtime.custody_broker import RoleBoundCustodyBroker, default_process_identity, custody_wrapper_argv
        if self._active is not None:
            self.abort(self._active)
        if self._prepare_cancel.is_set():
            raise ConflictError("host-only preparation cancelled")
        selected = _selected_profile_payload(profile)
        epoch = self.config.get("runtime_instance_id")
        owner = default_process_identity(os.getpid())
        if owner is None or not isinstance(epoch, str) or not epoch:
            raise ConflictError("host-only original Runtime owner is unavailable")
        owner = {key: owner[key] for key in ("pid", "uid", "birth_id")}
        owner.update(runtime_instance_id=epoch, coordinator_epoch=epoch)
        if not operation_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in operation_id):
            raise ConflictError("host-only operation identity is invalid")
        scope = profile.support_root / "local-execution-custody" / operation_id
        request = host_prepare_request(operation_id=operation_id, channel_id=channel_id, owner_epoch=epoch,
            runtime_owner=owner, profile=selected, custody_scope=str(scope))
        external_sources = None
        if profile.host_launch.get("additional_pack_roots"):
            from .external_pack_sources import OwnerSourceCapture
            external_sources = OwnerSourceCapture(preparation=request, config=self.config)
        parent, control_child = socket.socketpair()
        activation, activation_child = socket.socketpair()
        binding_parent, binding_child = socket.socketpair()
        broker = handle = None
        try:
            # Child materialization admissions use the existing default selector.
            # It selects work only; authenticated actual placement stays machine.
            target = {"kind": "default"}
            argv = [str(profile.host_executable), "-m", "astrid.core.execution.generic_host", "run", "--register",
                "--runtime-endpoint", self.config["runtime_endpoint"], "--runtime-instance-id", epoch,
                "--credential-file", self.config["credential_file"], "--executor-id", "astrid-pack-host",
                "--source-checkout", self.config["source_checkout"], "--support-root", str(profile.support_root),
                "--pack-root", self.config["pack_root"], "--boot-manifest-path", self.config["boot_manifest_path"],
                "--boot-manifest-hash", self.config["boot_manifest_hash"], "--ready-file", self.config["ready_file"],
                "--activation-fd", str(activation_child.fileno()), "--host-control-fd", str(control_child.fileno()),
                "--activation-operation-id", operation_id, "--activation-channel-id", channel_id,
                "--execution-target-json", json.dumps(target, separators=(",", ":")), "--require-target-attestation",
                "--max-concurrency", str(profile.host_launch["max_concurrency"])]
            if self.config.get("capability_matrix"):
                argv += ["--capability-matrix", self.config["capability_matrix"]]
            for extra in profile.host_launch.get("additional_pack_roots", []):
                if _pack_inventory(extra["path"]) != extra["files"]:
                    raise ConflictError("selected additional pack bytes differ")
                argv += ["--pack-root", extra["path"]]
            from .verified_host_launch import ENV_KEYS
            # Only the reviewed launch environment crosses this private owner
            # boundary; inherited credentials, Python knobs and product roots
            # cannot become import or selection authority.
            environment = {k: v for k, v in os.environ.items() if k in ENV_KEYS and not k.startswith("ASTRID_")}
            selected_environment = profile.host_launch["environment"]
            if set(selected_environment) - ENV_KEYS:
                raise ConflictError("host-only selected environment contains unapproved fields")
            environment.update(selected_environment)
            # Fixed product roots are owner-selected, not ambient authority.
            environment.update(ASTRID_OUTPUT_ROOT=str(profile.support_root / "host-output"), ASTRID_RUNTIME_DATA_ROOT=str(profile.realm_root))
            Path(environment["ASTRID_OUTPUT_ROOT"]).mkdir(parents=True, exist_ok=True)
            release = _installed_host_release(profile, self.config)
            verifier = (TrustedLocalHostLaunchVerifier(installed_release=release, external_sources=external_sources)
                if external_sources is not None else TrustedLocalHostLaunchVerifier(installed_release=release))
            verified = verifier.verify(preparation=request, config=self.config, host_argv=argv, environment=environment)
            mapped_argv, binding = verifier.claim(verified, preparation=request, config=self.config,
                host_argv=argv, environment=environment, binding_fd=binding_child.fileno())
            with self._handoff_lock:
                _create_host_custody_scope(scope)
                broker = RoleBoundCustodyBroker(role="host", identity_provider=default_process_identity,
                    ledger_root=scope / "host-admission", authority_scope_root=scope,
                    authority_journal=scope / "admissions.jsonl", owner_epoch=epoch, timeout=min(self.timeout_seconds, 60))
                environment.update(broker.child_environment(mapped_argv, start_new_session=True))
                process = runtime_platform.spawn_tree(custody_wrapper_argv(str(profile.host_executable)), start_new_session=False, cwd=str(profile.support_root),
                    env=environment, stdin=subprocess.DEVNULL, close_fds=True,
                    pass_fds=(control_child.fileno(), activation_child.fileno(), binding_child.fileno()))
                retained = RetainedProcess(process)
                handle = _PreparedWorker(process, "", parent, {}, scope / "host-launch.json", retained=retained,
                    broker=broker, owner_epoch=epoch, custody_scope=str(scope), host_only=True,
                    activation=activation, preparation=request, launch_verifier=verifier, verified_launch=verified)
                self._active = handle  # Before birth/seal/readiness can fail.
                for channel in (control_child, activation_child, binding_child):
                    channel.close()
                parent.settimeout(self.timeout_seconds); activation.settimeout(self.timeout_seconds)
            broker.wait_until_sealed(); retained.bind_actor()
            identity = retained.verify(); handle.birth_id = identity["birth_id"]
            verifier.bind_child(verified, child=process, identity=identity)
            binding_parent.sendall(binding); binding_parent.close()
            from astrid_runtime.custody_broker import _atomic_owner_json
            _atomic_owner_json(handle.owner_session_config_path, profile.host_launch)
            # The private preparation channel reports no engine allocation.
            _frame_send(parent, request)
            prepared = _frame_receive(parent)
            expected = {"version": request["version"], "status": "prepared", "operation_id": operation_id,
                "channel_id": channel_id, "owner_epoch": epoch, "execution_mode": "host_only_cpu",
                "processes": {"host": {"pid": process.pid, "birth_id": handle.birth_id}},
                "session_config_digest": profile.session_config_digest}
            if prepared != expected:
                raise ConflictError("host-only preparation response differs from original launch")
            handle.report_value = self._host_only_report(handle)
            return handle
        except BaseException as primary:
            for channel in (control_child, activation_child, binding_child, binding_parent):
                channel.close()
            if handle is None:
                parent.close(); activation.close()
                if broker is not None: broker.abort_before_spawn()
            else:
                try: self.abort(handle)
                except BaseException as cleanup:
                    self.cleanup_uncertain = "host-only startup cleanup unresolved"
                    primary.add_note(type(cleanup).__name__ + ": host-only cleanup remains retained")
            raise

    def _host_only_report(self, handle):
        from .local_worker import RELAY_PREPARATION_VERSION, _digest
        identity = handle.retained.verify()
        handle.launch_verifier.verify_child(handle.verified_launch, child=handle.worker, identity=identity)
        return {"version": RELAY_PREPARATION_VERSION, "execution_mode": "host_only_cpu",
            "operation_id": handle.preparation["operation_id"], "channel_id": handle.preparation["channel_id"],
            "processes": {"host": {"pid": handle.worker.pid, "birth_id": handle.birth_id}},
            "session_config_digest": self.profile.session_config_digest, "owner_epoch": handle.owner_epoch,
            "custody_scope": handle.custody_scope, "custody_capabilities": {"host": handle.broker.role_authority.reference()},
            "profile_binding_digest": _digest(_selected_profile_payload(self.profile))}

    def _host_only_abort(self, handle):
        with handle.cleanup_lock:
            if handle.closed: return
            bound = {k: handle.preparation[k] for k in ("version", "operation_id", "channel_id", "owner_epoch")}
            request = {**bound, "command": "abort_local_execution", "profile_digest": self.profile.profile_digest,
                "profile_binding_digest": self._host_only_report(handle)["profile_binding_digest"],
                "custody_scope": handle.custody_scope, "custody_capabilities": self._host_only_report(handle)["custody_capabilities"]}
            with handle.rpc_lock:
                handle.retained.verify()
                handle.control.settimeout(max(1.0, self.cleanup_timeout_seconds))
                _frame_send(handle.control, request); response = _frame_receive(handle.control)
            expected = {**{k: v for k, v in request.items() if k != "command"}, "status": "cleaned", "cleanup": {"host_children": "absent"}}
            if response != expected:
                self.cleanup_uncertain = "host-only child cleanup acknowledgement unresolved"
                raise ConflictError(self.cleanup_uncertain)
            # Full owned child cleanup was acknowledged, then reap original host.
            if handle.retained.poll() is None:
                handle.broker.signal(runtime_platform.TERM, expected_pid=handle.worker.pid)
            handle.retained.wait(max(1.0, self.cleanup_timeout_seconds))
            with handle.cleanup_resolution_lock:
                if handle.cleanup_abandoned:
                    raise ConflictError("host-only cleanup exceeded terminal shutdown custody")
                handle.control.close(); handle.activation.close(); handle.closed = True
                if self._active is handle: self._active = None

    def _prepare_relay(self, profile, *, operation_id, channel_id):
        from .local_execution_supervisor import host_prepare_request, RetainedProcess
        from astrid_runtime.custody_broker import RoleBoundCustodyBroker, default_process_identity, custody_wrapper_argv
        if self._active is not None:
            self.abort(self._active)
        if self._prepare_cancel.is_set():
            raise ConflictError("local execution preparation cancelled")
        selected = _selected_profile_payload(profile)
        epoch = self.config.get("runtime_instance_id")
        owner = default_process_identity(os.getpid())
        if owner is None or not isinstance(epoch, str) or not epoch:
            raise ConflictError("Runtime launch owner identity is unavailable")
        owner.update(runtime_instance_id=epoch, coordinator_epoch=epoch)
        owner.pop("parent_pid", None)
        # Operation IDs originate in Runtime. Reject path syntax before using
        # one to select this private, launch-specific protected scope.
        if not isinstance(operation_id, str) or not operation_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in operation_id):
            raise ConflictError("Runtime local execution operation identity is invalid")
        scope = profile.support_root / "local-execution-custody" / operation_id
        request = host_prepare_request(operation_id=operation_id, channel_id=channel_id, owner_epoch=epoch,
            runtime_owner=owner, profile=selected, custody_scope=str(scope))
        if _actual_executable(os.getpid()) != profile.worker_executable or _file_digest(profile.worker_executable) != profile.worker_artifact_digest:
            raise ConflictError("selected relay interpreter differs from current Runtime kernel artifact")
        parent, child = socket.socketpair()
        broker = None
        handle = None
        try:
            with self._handoff_lock:
                broker = RoleBoundCustodyBroker(role="relay", identity_provider=default_process_identity,
                    ledger_root=scope / "relay-admission", authority_scope_root=scope,
                    authority_journal=scope / "admissions.jsonl", owner_epoch=epoch,
                    timeout=min(self.timeout_seconds, 60.0))
                argv = [sys.executable, "-X", "utf8", "-I", "-m", "runtime_protocol.local_execution_supervisor", "--prepared-control-fd", str(child.fileno())]
                environment = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"} and not k.startswith("ASTRID_RUNTIME_CUSTODY_")}
                environment.update({k: v for k, v in self.environment.items() if k in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "XDG_RUNTIME_DIR", "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "ASTRID_EXECUTION_TARGET_JSON"}})
                environment.update(broker.child_environment(argv, start_new_session=True))
                process = runtime_platform.spawn_tree(custody_wrapper_argv(sys.executable), start_new_session=False, cwd=str(profile.support_root),
                    env=environment, stdin=subprocess.DEVNULL, close_fds=True, pass_fds=(child.fileno(),))
                retained = RetainedProcess(process)
                # Publish before birth/token/seal observations can fail.
                handle = _PreparedWorker(process, "", parent, {}, Path(profile.engine_launch["session_root"]) / "config.json",
                    relay=True, retained=retained, broker=broker, owner_epoch=epoch, custody_scope=str(scope))
                self._active = handle
                child.close()
                parent.settimeout(self.timeout_seconds)
                broker.wait_until_sealed()
                retained.bind_actor()
                handle.birth_id = retained.verify()["birth_id"]
            response = self._rpc(handle, {"version": "runtime.local-execution-control/v1", "command": "prepare", "preparation": request, "config": dict(self.config)})
            value = response.get("report")
            if not isinstance(value, dict):
                raise ConflictError("neutral relay returned no process report")
            handle.report_value = value
            return handle
        except BaseException as primary:
            child.close()
            if handle is None:
                parent.close()
                if broker is not None:
                    broker.abort_before_spawn()
            else:
                # Retain the launch obligation; failed sealing grants no PID
                # cleanup fallback and cannot be represented as closed.
                try:
                    self.abort(handle)
                except BaseException as cleanup:
                    primary.add_note("local execution cleanup remains unresolved: " + type(cleanup).__name__)
            raise

    def _relay_abort(self, handle):
        with handle.cleanup_lock:
            return self._relay_abort_locked(handle)

    def _relay_abort_locked(self, handle):
        if handle.closed:
            return
        response = self._rpc(handle, {"version": "runtime.local-execution-control/v1", "command": "abort"})
        if not isinstance(response.get("host_exit_code"), int) or isinstance(response["host_exit_code"], bool) or response.get("host_result", {}).get("status") != "cleaned":
            raise ConflictError("relay has no verified full host cleanup acknowledgement")
        if handle.retained.poll() is None:
            handle.broker.signal(runtime_platform.TERM, expected_pid=handle.worker.pid)
            try:
                handle.retained.wait(max(1.0, self.cleanup_timeout_seconds))
            except BaseException:
                handle.broker.signal(runtime_platform.KILL, expected_pid=handle.worker.pid)
                handle.retained.wait(max(1.0, self.cleanup_timeout_seconds))
        with handle.cleanup_resolution_lock:
            if handle.cleanup_abandoned:
                raise ConflictError("relay cleanup exceeded terminal shutdown custody")
            handle.control.close()
            handle.closed = True
            if self._active is handle:
                self._active = None

    def release_failed_cleanup_channels(self, handle):
        """Release terminal shutdown transport, retaining unresolved custody.

        Ordinary abort failures keep their descriptors for an authenticated
        retry. Once Runtime shutdown has exhausted that attempt, descriptors
        cannot remain live resources or allow late cleanup to claim success.
        """
        if not isinstance(handle, _PreparedWorker) or not (handle.host_only or handle.relay):
            return
        with handle.cleanup_resolution_lock:
            if handle.closed:
                return
            handle.cleanup_abandoned = True
            self.cleanup_uncertain = "retained child cleanup remains unresolved after shutdown"
            for channel in (handle.control, handle.activation):
                if channel is not None:
                    try:
                        channel.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    channel.close()

    def report(self, handle: _PreparedWorker) -> Mapping[str, Any]:
        if handle.host_only:
            handle.report_value = self._host_only_report(handle)
            return handle.report_value
        response = self._rpc(handle, {"version": "runtime.local-execution-control/v1" if handle.relay else CONTROL_VERSION, "command": "report"})
        report = response.get("report")
        if not isinstance(report, dict):
            raise ConflictError("prepared Worker returned no process report")
        handle.report_value = report
        return report

    def bind_activation_acceptor(self, handle, grant, acceptor):
        if handle is not self._active or not (handle.relay or handle.host_only) or handle.closed or not callable(acceptor):
            raise ConflictError("Runtime activation publisher lacks this retained relay")
        self._activation_binding = (handle, json.loads(json.dumps(dict(grant))), acceptor)

    def bind_retained_generation_verifier(self, handle, verifier):
        if handle is not self._active or not (handle.relay or handle.host_only) or not callable(verifier):
            raise ConflictError("generation verifier lacks the retained launch")
        self._generation_verifier = (handle, verifier)

    def activate(self, handle: _PreparedWorker, grant: Mapping[str, Any]) -> None:
        if handle.host_only:
            binding = self._activation_binding
            if binding is None or binding[0] is not handle or binding[1] != dict(grant):
                raise ConflictError("host-only activation lacks exact Runtime publisher")
            with handle.rpc_lock:
                handle.retained.verify()
                message = {**dict(grant), "host": {"pid": handle.worker.pid, "birth_id": handle.birth_id}}
                _frame_send(handle.activation, message)
                request = _frame_receive(handle.activation)
                recorded = binding[2](request)
                _frame_send(handle.activation, recorded)
                handle.activation.shutdown(socket.SHUT_WR)
                expected = {"version": "astrid.local-worker-activation-accepted/v1",
                    **{k: grant[k] for k in ("operation_id", "channel_id", "activation_id", "executor_incarnation", "evidence_digest")}, "host": message["host"]}
                if _frame_receive(handle.activation) != expected:
                    raise ConflictError("host-only activation acknowledgement differs")
                handle.retained.verify(); handle.activated = True
            return
        if not handle.relay:
            response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "activate", "grant": dict(grant)})
            if response.get("status") != "ok":
                raise ConflictError("prepared Worker rejected activation")
            handle.activated = True
            return
        from .local_execution_supervisor import send_frame, receive_frame, CONTROL_VERSION as relay_version
        binding = self._activation_binding
        if binding is None or binding[0] is not handle or binding[1] != dict(grant):
            raise ConflictError("local relay has no exact Runtime activation publisher")
        with handle.rpc_lock:
            handle.retained.verify()
            send_frame(handle.control, {"version": relay_version, "command": "activate", "grant": dict(grant)})
            response = receive_frame(handle.control)
            if set(response) != {"version", "status", "request"} or response.get("version") != relay_version or response.get("status") != "activation_requested":
                raise ConflictError("relay has no exact host activation request")
            recorded = binding[2](response["request"])
            # Publisher returns only after its protected file+directory fsync.
            send_frame(handle.control, {"version": relay_version, "command": "record_activation_receipt", "receipt": recorded})
            final = receive_frame(handle.control)
            expected = {"version": "astrid.local-worker-activation-accepted/v1", **{k: grant[k] for k in ("operation_id", "channel_id", "activation_id", "executor_incarnation", "evidence_digest")}, "host": response["request"]["host"]}
            if final != {"version": relay_version, "status": "ok", "accepted": expected}:
                raise ConflictError("relay final activation acknowledgement differs from recorded grant")
            handle.retained.verify()
            handle.activated = True

    def abort(self, handle: _PreparedWorker) -> None:
        if isinstance(handle, _AdoptedHandoffControl):
            # Neither EOF nor PID absence proves this nonchild relay exited.
            # Keep its control/custody obligation; no fabricated waitpid/Popen
            # or successful cleanup until a separate retained exit proof exists.
            raise ConflictError("adopted relay nonchild cleanup remains unresolved")
        if isinstance(handle, _PreparedWorker) and handle.closed:
            return
        if isinstance(handle, _PreparedWorker) and handle.host_only:
            return self._host_only_abort(handle)
        if isinstance(handle, _PreparedWorker) and handle.relay:
            return self._relay_abort(handle)
        if not isinstance(handle, _PreparedWorker) or handle.closed:
            return
        with handle.cleanup_lock:
            if handle.cleanup_started:
                return
            handle.cleanup_started = True
        failure: BaseException | None = None
        owned = False
        try:
            owned = self._birth(handle.worker.pid) == handle.birth_id
            acquired = handle.rpc_lock.acquire(timeout=self.cleanup_timeout_seconds)
            if acquired:
                try:
                    previous_timeout = handle.control.gettimeout()
                    handle.control.settimeout(self.cleanup_timeout_seconds)
                    try:
                        self._rpc_unlocked(handle, {"version": CONTROL_VERSION, "command": "abort"})
                    finally:
                        handle.control.settimeout(previous_timeout)
                finally:
                    handle.rpc_lock.release()
            handle.worker.wait(timeout=self.cleanup_timeout_seconds)
        except BaseException as exc:
            failure = exc
        finally:
            try:
                handle.control.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            handle.control.close()
            if owned and handle.worker.poll() is None:
                try:
                    runtime_platform.signal_tree(handle.worker, runtime_platform.TERM)
                except OSError:
                    pass
                try:
                    handle.worker.wait(timeout=self.cleanup_timeout_seconds)
                except (subprocess.TimeoutExpired, TimeoutError):
                    try:
                        runtime_platform.signal_tree(handle.worker, runtime_platform.KILL)
                    except OSError:
                        pass
                    try:
                        handle.worker.wait(timeout=self.cleanup_timeout_seconds)
                    except (subprocess.TimeoutExpired, TimeoutError):
                        pass
            handle.closed = True
            if self._active is handle:
                self._active = None
        if failure is not None:
            raise failure

    def stop_owned(self, receipt: Mapping[str, Any], handle: _PreparedWorker | None = None) -> bool:
        """Stop only PIDs whose current birth marker matches the exact receipt.

        This works after a daemon restart when the private control handle is
        gone. A missing or reused PID is already absent from this generation;
        an unobservable PID leaves the handover unresolved.
        """
        if _host_only(self.profile):
            retained = handle or self._active
            if not isinstance(retained, _PreparedWorker) or not retained.host_only or retained.closed:
                raise ConflictError("host-only cleanup requires original retained owner")
            from .local_worker import _receipt_identity_digest_valid
            expected = self._host_only_report(retained)
            if not _receipt_identity_digest_valid(self.profile, receipt, workspace_uuid=self.profile.workspace_uuid,
                    realm_root=self.profile.realm_root, support_root=self.profile.support_root) or any(
                    receipt.get(k) != expected[k] for k in ("owner_epoch", "custody_scope", "custody_capabilities", "profile_binding_digest")):
                raise ConflictError("host-only cleanup receipt differs from retained original owner")
            self._host_only_abort(retained)
            return True
        if self.profile.engine_launch is not None:
            retained = handle or self._active
            if not isinstance(retained, _PreparedWorker) or not retained.relay or retained.closed:
                raise ConflictError("relay capability recovery requires retained control")
            worker = receipt.get("worker")
            if not isinstance(worker, Mapping) or (worker.get("pid"), worker.get("birth_id")) != (retained.worker.pid, retained.birth_id) or receipt.get("custody_capabilities") != retained.report_value.get("custody_capabilities"):
                raise ConflictError("relay retained control differs from exact custody receipt")
            self.abort(retained)
            return True
        names = ("engine_listener", "engine", "host", "worker")
        processes = []
        for name in names:
            item = receipt.get(name)
            if not isinstance(item, Mapping) or not isinstance(item.get("pid"), int) or not isinstance(item.get("birth_id"), str):
                raise ConflictError("local Worker relinquish receipt has invalid process identity")
            processes.append((item["pid"], item["birth_id"]))
        if handle is not None and (handle.worker.pid, handle.birth_id) != processes[-1]:
            raise ConflictError("local Worker handle does not match relinquish receipt")
        expected_birth = dict(processes)

        def live() -> list[int]:
            remaining = []
            for pid, birth in processes:
                if handle is not None and pid == handle.worker.pid:
                    # Popen.poll reaps an exited child; an unreaped zombie
                    # still has the same birth marker in /proc or ps.
                    handle.worker.poll()
                try:
                    identity = runtime_platform.process_identity(pid)
                except ProcessLookupError:
                    continue
                except OSError as exc:
                    raise ConflictError("receipt-owned process state is unobservable") from exc
                current = identity.get("birth_id") if identity is not None else None
                if current == birth:
                    remaining.append(pid)
                elif current is None:
                    continue
            return remaining

        for pid in live():
            try:
                identity = runtime_platform.process_identity(pid)
                if identity is not None and identity.get("birth_id") == expected_birth[pid]:
                    runtime_platform.signal_process(identity, runtime_platform.TERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise ConflictError("receipt-owned process could not be safely stopped") from exc
        deadline = time.monotonic() + max(1.0, self.cleanup_timeout_seconds)
        while time.monotonic() < deadline and live():
            time.sleep(0.02)
        for pid in live():
            try:
                identity = runtime_platform.process_identity(pid)
                if identity is not None and identity.get("birth_id") == expected_birth[pid]:
                    runtime_platform.signal_process(identity, runtime_platform.KILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise ConflictError("receipt-owned process could not be safely terminated") from exc
        deadline = time.monotonic() + max(1.0, self.cleanup_timeout_seconds)
        while time.monotonic() < deadline and live():
            time.sleep(0.02)
        if live():
            raise ConflictError("receipt-owned local Worker processes remain alive")
        if handle is not None:
            try:
                handle.control.close()
            except OSError:
                pass
            handle.closed = True
            if self._active is handle:
                self._active = None
        return True

    def control_alive(self, handle: _PreparedWorker) -> bool:
        if not isinstance(handle, _PreparedWorker) or handle.closed or (handle.retained.poll() if (handle.relay or handle.host_only) else handle.worker.poll()) is not None:
            return False
        if not handle.rpc_lock.acquire(blocking=False):
            # A Runtime-owned RPC currently holds the channel. Its bounded
            # operation is itself positive control-channel activity.
            return True
        try:
            if self._birth(handle.worker.pid) != handle.birth_id:
                return False
            readable, _, exceptional = select.select([handle.control], [], [handle.control], 0)
            if exceptional or readable:
                # With no RPC in flight, either EOF or unsolicited bytes are
                # a protocol/control-channel failure. Do not leave bytes
                # perpetually buffered and mistake a closed peer for liveness.
                return False
            return True
        except (OSError, ValueError):
            return False
        finally:
            handle.rpc_lock.release()

    def current_handle(self) -> _PreparedWorker | None:
        handle = self._active
        return None if handle is None or handle.closed else handle

    def reconnect(self, receipt: Mapping[str, Any]) -> _PreparedWorker | None:
        if _host_only(self.profile):
            raise ConflictError("host-only nonchild reconnect is unsupported")
        if self.profile.engine_launch is not None:
            handle = self._active
            if handle is None or handle.closed or not handle.relay or not handle.activated:
                raise ConflictError("local relay capability recovery remains unresolved without retained control")
            self._verify_retained_relay_receipt(handle, receipt)
            report = self.report(handle)
            if (report.get("owner_epoch") != receipt.get("owner_epoch")
                    or report.get("profile_binding_digest") != receipt.get("profile_binding_digest")
                    or report.get("custody_scope") != receipt.get("custody_scope")
                    or report.get("custody_capabilities") != receipt.get("custody_capabilities")
                    or any(report.get("processes", {}).get(role) != {k: receipt.get(role, {}).get(k) for k in ("pid", "birth_id")} for role in ("worker", "host", "engine", "engine_listener"))):
                raise ConflictError("retained relay report differs from immutable receipt")
            self._verify_retained_relay_receipt(handle, receipt)
            return handle
        handle = self._active
        if handle is None or handle.closed or not handle.activated:
            return None
        response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "reconnect", "receipt": dict(receipt)})
        return handle if response.get("reconnected") is True else None

    def _verify_retained_relay_receipt(self, handle, receipt):
        from astrid_runtime.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority, _read_owner_file
        from .local_execution_handoff import decode, read_protected
        if (handle is not self._active or not handle.relay or handle.closed or not handle.activated
                or receipt.get("version") != "runtime.local-worker-receipt/v4"
                or receipt.get("owner_epoch") != handle.owner_epoch or receipt.get("custody_scope") != handle.custody_scope):
            raise ConflictError("reconnect lacks exact retained receipt/owner")
        handle.retained.verify()
        actor = AuthenticatedCleanupActor.current()
        caps = receipt.get("custody_capabilities")
        if not isinstance(caps, dict) or set(caps) != {"relay", "host", "engine", "engine_listener"}:
            raise ConflictError("reconnect lacks exact retained role graph")
        scope = Path(handle.custody_scope)
        owners = {"relay": actor.verify(), "host": caps["relay"]["target"], "engine": caps["host"]["target"], "engine_listener": caps["host"]["target"]}
        for role, ref in caps.items():
            RoleCustodyAuthority(scope, role).verify_reference(ref, expected_actor=owners[role], owner_epoch=handle.owner_epoch)
        record = read_protected(scope / "activation-record.json")
        if (record.get("evidence_digest") != receipt.get("evidence_digest") or record.get("executor_incarnation") != receipt.get("executor_incarnation")
                or record.get("custody_capabilities") != caps or record.get("original_owner_epoch") != handle.owner_epoch):
            raise ConflictError("reconnect immutable activation evidence differs")
        verifier = self._generation_verifier
        if verifier is None or verifier[0] is not handle or verifier[1]() != record.get("credential_generation"):
            raise ConflictError("reconnect credential generation changed")
        for path in (scope / "relay-handoff-state.json", self.profile.support_root / "local-execution-claim-fence.json"):
            if path.exists() or path.is_symlink():
                state = read_protected(path)
                if state.get("phase") not in (None, "owned", "finalized") or state.get("state") == "held":
                    raise ConflictError("retained reconnect is fenced by unresolved handoff")

    def handoff_command(self, handle, payload):
        if _host_only(self.profile):
            raise ConflictError("host-only handoff is unsupported")
        from .local_execution_handoff import validate_request, validate_reply
        from .local_execution_supervisor import CONTROL_VERSION as relay_version
        validate_request(dict(payload))
        if isinstance(handle, _AdoptedHandoffControl):
            return self._adopted_handoff_command(handle, dict(payload))
        if handle is not self._active or not handle.relay or handle.closed or not handle.activated:
            raise ConflictError("handoff lacks retained activated relay")
        handle.retained.verify()
        response = self._rpc(handle, {"version": relay_version, "command": "handoff", "request": dict(payload)})
        if set(response) != {"version", "status", "handoff"} or response.get("status") != "ok":
            raise ConflictError("relay handoff outcome remains unresolved")
        return validate_reply(response["handoff"], dict(payload))

    def adopt_fresh_handoff(self, request):
        from .local_execution_handoff import validate_request
        from .local_worker_handoff import connect_fresh_successor
        validate_request(request)
        if request["command"] != "handoff_adopt" or self._active is not None:
            raise ConflictError("fresh handoff adoption has no unoccupied successor")
        control, relay_actor = connect_fresh_successor(request["binding"], request["payload"]["sealed_record_digest"], timeout=min(self.timeout_seconds, 10.0))
        handle = _AdoptedHandoffControl(control, relay_actor, dict(request["binding"]))
        # Publish before the RPC can transfer custody or fail. A lost reply
        # retains the channel/operation and its protected ledger obligation.
        self._adopted_handoff = handle
        handle.result = self._adopted_handoff_command(handle, request)
        return handle

    def adopted_handoff_obligation(self):
        return self._adopted_handoff

    def _adopted_handoff_command(self, handle, request):
        from .local_execution_supervisor import CONTROL_VERSION as relay_version
        from .local_execution_handoff import validate_reply
        from astrid_runtime.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority
        if handle is not self._adopted_handoff or request["binding"] != handle.binding:
            raise ConflictError("adopted handoff control binding differs")
        with handle.rpc_lock:
            handle.verify()
            _frame_send(handle.control, {"version": relay_version, "command": "handoff", "request": request})
            reply = _frame_receive(handle.control)
            if set(reply) != {"version", "status", "handoff"} or reply["version"] != relay_version or reply["status"] != "ok":
                raise ConflictError("fresh handoff outcome remains unresolved")
            value = validate_reply(reply["handoff"], request)
            handle.verify()
            if value["status"] == "ok":
                ref = {**handle.binding["source_relay_reference"], "generation": handle.binding["source_relay_reference"]["generation"] + 1}
                RoleCustodyAuthority(Path(handle.binding["custody_scope"]), "relay").verify_reference(ref, expected_actor=AuthenticatedCleanupActor.current().verify(), owner_epoch=handle.binding["new_owner_epoch"])
            handle.result = value
            return value

    def adopt_control_descriptor(self, descriptor, receipt, request):
        # No fresh authenticated B accept/retained-child route exists on this
        # inherited A transport. Keep descriptor/child obligations untouched.
        raise ConflictError("successor adoption requires fresh authenticated B connection; stale A descriptor refused")



def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ConflictError(f"cannot independently read executable artifact {path}") from exc
    return "sha256:" + digest.hexdigest()


def _session_config_digest(path: Path) -> str:
    try:
        identity = path.lstat()
    except OSError as exc:
        raise ConflictError(f"cannot independently observe session configuration {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(identity.st_mode)
        or not runtime_platform.is_current_user(identity)
    ):
        raise ConflictError("owner session configuration is not a regular owner-controlled file")
    return _file_digest(path)


def _actual_executable(pid: int) -> Path:
    """Resolve the kernel-reported executable for one live process."""
    try:
        return Path(runtime_platform.process_executable(pid)).resolve()
    except OSError as exc:
        raise ConflictError("process executable is unavailable") from exc


def _owner_machine_id() -> str:
    value = platform.node().strip()
    if not value:
        raise ConflictError("cannot independently observe machine identity")
    return value


def _session_config_path(environment: Mapping[str, str]) -> Path:
    raw = str(environment.get("ASTRID_VIBECOMFY_SESSION_DIR") or "").strip()
    root = Path(raw).expanduser()
    if not raw or not root.is_absolute() or root.is_symlink():
        raise ConflictError("owner launch configuration has no safe VibeComfy session directory")
    return root / "config.json"


def _socket_address(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None:
    text = value.strip()
    if text.startswith("TCP "):
        text = text[4:]
    if "->" in text or text.startswith("*:"):
        return None
    try:
        if text.startswith("["):
            closing = text.index("]")
            address_text, port_text = text[1:closing], text[closing + 1 :]
            if not port_text.startswith(":"):
                return None
            port_text = port_text[1:]
        else:
            address_text, port_text = text.rsplit(":", 1)
        return ipaddress.ip_address(address_text), int(port_text)
    except (ValueError, TypeError):
        return None


def _listening_socket_owner(pid: int, endpoint: str) -> tuple[int, str]:
    if os.name == "nt":
        raise ConflictError("independent local Worker listener custody observation is unavailable on Windows")
    canonical = _engine_endpoint(endpoint)
    parsed = urlsplit(canonical)
    expected = (ipaddress.ip_address(parsed.hostname or ""), int(parsed.port or 0))
    result = subprocess.run(
        ["lsof", "-a", "-p", str(int(pid)), "-n", "-P", "-iTCP", "-sTCP:LISTEN", "-Fpn"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ConflictError(f"cannot independently observe listening sockets for process {pid}")
    owner = None
    for row in result.stdout.splitlines():
        if row.startswith("p") and row[1:].isdigit():
            owner = int(row[1:])
        elif row.startswith("n") and owner == int(pid) and _socket_address(row[1:]) == expected:
            return int(pid), canonical
    raise ConflictError(f"process {pid} does not independently own configured engine endpoint {canonical}")


class OSProcessInspector:
    """Independent owner-side observation; Worker reports are only selectors."""

    def __init__(self, profile: LocalWorkerProfile):
        self.profile = profile

    def _identity(self, pid: int, birth: str, executable: Path, digest: str, *, parent_pid: int | None, session_owner: bool) -> ProcessIdentity:
        if pid <= 0:
            raise ConflictError("observed process PID is invalid")
        try:
            observed = runtime_platform.process_identity(pid) or {}
            observed_birth = observed.get("birth_id")
        except OSError as exc:
            raise ConflictError("independent process identity observation failed") from exc
        if not observed_birth or observed_birth != birth:
            raise ConflictError("independent process birth identity disagrees with Worker report")
        observed_parent = int(observed["parent_pid"])
        if parent_pid is not None and observed_parent != parent_pid:
            raise ConflictError("independent process parent identity disagrees with Worker report")
        uid = int(observed["uid"])
        try:
            group = runtime_platform.process_group(pid)
            session = runtime_platform.session_id(pid)
        except OSError as exc:
            raise ConflictError("independent process group/session observation failed") from exc
        if session_owner and (group != pid or session != pid):
            raise ConflictError("observed process does not own its process group/session")
        if _actual_executable(pid) != executable:
            raise ConflictError("independent executable identity disagrees with profile")
        observed_digest = _file_digest(executable)
        if observed_digest != digest:
            raise ConflictError("independent executable artifact digest disagrees with profile")
        return ProcessIdentity(pid, observed_birth, uid, observed_parent, group, session, executable, observed_digest)

    def observe(self, handle: _PreparedWorker) -> LocalWorkerObservation:
        if _host_only(self.profile):
            from astrid_runtime.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority
            from .local_worker import _digest
            if not isinstance(handle, _PreparedWorker) or not handle.host_only or handle.closed:
                raise ConflictError("host-only observation lacks original retained handle")
            original = handle.retained.verify()
            handle.launch_verifier.verify_child(handle.verified_launch, child=handle.worker, identity=original)
            _verify_installed_host_records(self.profile, self.config if hasattr(self, "config") else self.profile.host_launch)
            from .verified_host_launch import source_checkout_closure
            if source_checkout_closure(self.profile.host_launch["source_checkout"])["digest"] != self.profile.host_protocol["source_closure_digest"]:
                raise ConflictError("host-only installed import closure changed")
            host = self._identity(handle.worker.pid, handle.birth_id,
                self.profile.host_os_executable or self.profile.host_executable,
                self.profile.host_os_artifact_digest or self.profile.host_artifact_digest,
                parent_pid=os.getpid(), session_owner=True)
            machine = _owner_machine_id()
            if machine != self.profile.machine_id:
                raise ConflictError("host-only machine identity differs")
            from astrid_runtime.custody_broker import _read_owner_file
            raw, _ = _read_owner_file(handle.owner_session_config_path)
            if _digest(json.loads(raw)) != self.profile.session_config_digest:
                raise ConflictError("host-only retained launch configuration differs")
            for extra in self.profile.host_launch.get("additional_pack_roots", []):
                if _pack_inventory(extra["path"]) != extra["files"]:
                    raise ConflictError("host-only additional pack inventory changed")
            reference = handle.broker.role_authority.reference()
            RoleCustodyAuthority(Path(handle.custody_scope), "host").verify_reference(reference,
                expected_actor=AuthenticatedCleanupActor.current().verify(), owner_epoch=handle.owner_epoch)
            return LocalWorkerObservation(machine, runtime_platform.current_user(), self.profile.workspace_uuid,
                self.profile.realm_root, self.profile.support_root, None, host, None, None, 0, "",
                self.profile.session_config_digest, handle.owner_epoch, handle.custody_scope, {"host": reference})
        report = getattr(handle, "report_value", None)
        if not isinstance(report, Mapping):
            raise ConflictError("Worker report is unavailable for independent observation")
        processes = report.get("processes")
        binding = report.get("engine_binding")
        if not isinstance(processes, Mapping) or not isinstance(binding, Mapping):
            raise ConflictError("Worker process report is incomplete")
        worker_data = processes.get("worker")
        host_data = processes.get("host")
        engine_data = processes.get("engine")
        listener_data = processes.get("engine_listener")
        if not all(isinstance(item, Mapping) for item in (worker_data, host_data, engine_data, listener_data)):
            raise ConflictError("Worker process report is incomplete")
        worker = self._identity(int(worker_data["pid"]), str(worker_data["birth_id"]), self.profile.worker_executable, self.profile.worker_artifact_digest, parent_pid=os.getpid(), session_owner=True)
        host = self._identity(int(host_data["pid"]), str(host_data["birth_id"]), self.profile.host_os_executable or self.profile.host_executable, self.profile.host_os_artifact_digest or self.profile.host_artifact_digest, parent_pid=worker.pid, session_owner=True)
        engine = self._identity(int(engine_data["pid"]), str(engine_data["birth_id"]), self.profile.engine_executable, self.profile.engine_artifact_digest, parent_pid=host.pid if self.profile.engine_launch is not None else worker.pid, session_owner=True)
        listener = self._identity(int(listener_data["pid"]), str(listener_data["birth_id"]), self.profile.engine_listener_executable, self.profile.engine_listener_artifact_digest, parent_pid=engine.pid, session_owner=False)
        reported_socket_owner = int(binding.get("socket_owner_pid", -1))
        observed_socket_owner, observed_endpoint = _listening_socket_owner(
            listener.pid, self.profile.engine_endpoint
        )
        if reported_socket_owner != observed_socket_owner:
            raise ConflictError("independent listener socket-owner observation disagrees with Worker report")
        if observed_socket_owner != listener.pid:
            raise ConflictError("independent listener socket-owner observation failed")
        observed_machine = _owner_machine_id()
        if observed_machine != self.profile.machine_id:
            raise ConflictError("independent machine identity disagrees with profile")
        config_path = getattr(handle, "owner_session_config_path", None)
        if not isinstance(config_path, Path):
            raise ConflictError("owner VibeComfy session configuration path is unavailable")
        observed_session_digest = _session_config_digest(config_path)
        if observed_session_digest != self.profile.session_config_digest:
            raise ConflictError("engine session configuration does not match profile")
        if str(report.get("session_config_digest")) != observed_session_digest:
            raise ConflictError("Worker session configuration claim disagrees with owner observation")
        custody = None
        if self.profile.engine_launch is not None:
            from astrid_runtime.custody_broker import RoleCustodyAuthority, current_process_audit_token, default_process_identity, _incarnation
            from .local_execution_supervisor import validate_role_reference
            custody = report.get("custody_capabilities")
            if not handle.relay or not isinstance(custody, Mapping) or set(custody) != {"relay", "host", "engine", "engine_listener"} or report.get("owner_epoch") != handle.owner_epoch or report.get("custody_scope") != handle.custody_scope:
                raise ConflictError("relay report lacks exact retained Runtime scope/epoch")
            if report.get("profile_binding_digest") != "sha256:" + hashlib.sha256(json.dumps(_selected_profile_payload(self.profile), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest():
                raise ConflictError("relay report selected profile binding differs")
            actors = {}
            for role, pid in (("relay", os.getpid()), ("host", worker.pid), ("engine", host.pid), ("engine_listener", host.pid)):
                observed = default_process_identity(pid)
                if observed is None:
                    raise ConflictError("retained cleanup actor is unavailable")
                actors[role] = _incarnation(observed, current_process_audit_token(pid))
            for role, identity in (("relay", worker), ("host", host), ("engine", engine), ("engine_listener", listener)):
                validate_role_reference(custody[role], role=role, scope_root=handle.custody_scope, process={"pid": identity.pid, "birth_id": identity.birth_id})
                RoleCustodyAuthority(Path(handle.custody_scope), role).verify_reference(custody[role],
                    expected_actor=actors[role], owner_epoch=handle.owner_epoch)
        return LocalWorkerObservation(
            machine_id=observed_machine,
            uid=runtime_platform.current_user(),
            workspace_uuid=self.profile.workspace_uuid,
            realm_root=self.profile.realm_root,
            support_root=self.profile.support_root,
            worker=worker,
            host=host,
            engine=engine,
            engine_listener=listener,
            engine_listener_socket_owner_pid=observed_socket_owner,
            engine_endpoint=observed_endpoint,
            session_config_digest=observed_session_digest,
            owner_epoch=handle.owner_epoch if self.profile.engine_launch is not None else None,
            custody_scope=handle.custody_scope if self.profile.engine_launch is not None else None,
            custody_capabilities=json.loads(json.dumps(custody)) if custody is not None else None,
        )


@dataclass
class LocalWorkerComposition:
    profiles: dict[str, LocalWorkerProfile]
    preparer: CrossProcessWorkerPreparer
    inspector: OSProcessInspector

    def bind_runtime(self, *, endpoint: str, runtime_instance_id: str, credential_file: Path) -> None:
        self.preparer.bind_runtime(endpoint=endpoint, runtime_instance_id=runtime_instance_id, credential_file=credential_file)

    def _retain(self):
        """Snapshot owner selection before live actors bind startup credentials.

        Retention copies declarations only; launch verification and mutable
        preparer/inspector ownership remain on their existing lifecycle path.
        """
        if (not isinstance(self.profiles, dict) or len(self.profiles) != 1
                or not isinstance(self.preparer, CrossProcessWorkerPreparer)
                or not isinstance(self.inspector, OSProcessInspector)
                or not isinstance(self.preparer.config, dict)):
            raise ValidationError("invalid owner-selected local worker composition")
        for key, profile in self.profiles.items():
            if (not isinstance(profile, LocalWorkerProfile) or key != profile.profile_id
                    or profile != self.preparer.profile or profile != self.inspector.profile):
                raise ValidationError("local worker composition selection differs")
            if _secure_profile(profile):
                _selected_profile_payload(profile)
        return _RetainedLocalWorkerComposition(
            _selection_bytes({key: asdict(profile) for key, profile in self.profiles.items()}),
            _selection_bytes(self.preparer.config),
        )


def _path(value: Any, label: str, *, directory: bool | None = None) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"worker profile {label} is required")
    target = Path(value).expanduser()
    if not target.is_absolute():
        raise ValidationError(f"worker profile {label} must be absolute")
    target = target.resolve()
    if directory is True and not target.is_dir():
        raise ValidationError(f"worker profile {label} must be an existing directory")
    if directory is False and not target.is_file():
        raise ValidationError(f"worker profile {label} must be an existing file")
    return target


def load_local_worker_composition(path: str | Path, *, workspace_uuid: str, realm_root: Path, support_root: Path, runtime_instance_id: str) -> LocalWorkerComposition:
    target = _path(str(path), "path", directory=False)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"worker profile is missing or invalid: {target}") from exc
    if not isinstance(raw, Mapping):
        raise ValidationError("worker profile must be an object")
    allowed = {
        "profile_id", "machine_id", "engine_endpoint", "worker_environment", "worker_executable", "host_executable",
        "engine_executable", "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
        "engine_artifact_digest", "engine_listener_artifact_digest", "session_config_digest", "profile_revision",
        "profile_digest", "release_digest", "source_checkout", "pack_root", "boot_manifest_path",
        "boot_manifest_hash", "capability_matrix", "environment", "worker_timeout_seconds",
        "engine_launch", "host_os_executable", "host_os_artifact_digest", "host_protocol", "execution_mode", "additional_pack_roots", "max_concurrency",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError("worker profile contains unsupported fields: " + ", ".join(unknown))
    mode = raw.get("execution_mode", "worker_engine")
    if mode not in {"worker_engine", "host_only_cpu"}:
        raise ValidationError("unsupported local execution mode")
    if mode != "host_only_cpu" and set(raw) & {"additional_pack_roots", "max_concurrency"}:
        raise ValidationError("additional pack declarations require host-only mode")
    if mode == "host_only_cpu":
        return _load_host_only_composition(raw, workspace_uuid=workspace_uuid, realm_root=realm_root,
            support_root=support_root, runtime_instance_id=runtime_instance_id)
    if "host_protocol" in raw:
        from .verified_host_launch import validate_host_protocol, HostLaunchError
        try:
            validate_host_protocol(raw["host_protocol"])
        except HostLaunchError as exc:
            raise ValidationError(str(exc)) from exc
        if raw.get("engine_launch") is None:
            raise ValidationError("host_protocol requires the explicit engine_launch path")
    worker_executable = _path(raw.get("worker_executable"), "worker_executable", directory=False)
    host_executable = _path(raw.get("host_executable"), "host_executable", directory=False)
    engine_executable = _path(raw.get("engine_executable"), "engine_executable", directory=False)
    listener_executable = _path(raw.get("engine_listener_executable"), "engine_listener_executable", directory=False)
    worker_environment = _path(raw.get("worker_environment"), "worker_environment", directory=True) if raw.get("engine_launch") is None else None
    environment = raw.get("environment", {})
    if not isinstance(environment, Mapping) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items()):
        raise ValidationError("worker profile environment must be a string mapping")
    try:
        engine_port = int(environment.get("ASTRID_VIBECOMFY_PORT", "8188"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("worker profile ASTRID_VIBECOMFY_PORT must be an integer") from exc
    if not 1 <= engine_port <= 65535:
        raise ValidationError("worker profile ASTRID_VIBECOMFY_PORT is outside the valid range")
    machine_id = str(raw.get("machine_id") or "").strip()
    if not machine_id:
        raise ValidationError("worker profile machine_id is required")
    profile = LocalWorkerProfile(
        profile_id=str(raw.get("profile_id") or "astrid"),
        workspace_uuid=str(workspace_uuid),
        realm_root=Path(realm_root).resolve(),
        support_root=Path(support_root).resolve(),
        machine_id=machine_id,
        worker_executable=worker_executable,
        host_executable=host_executable,
        engine_executable=engine_executable,
        engine_listener_executable=listener_executable,
        engine_endpoint=_engine_endpoint(str(raw.get("engine_endpoint") or "")),
        worker_artifact_digest=str(raw.get("worker_artifact_digest") or ""),
        host_artifact_digest=str(raw.get("host_artifact_digest") or ""),
        engine_artifact_digest=str(raw.get("engine_artifact_digest") or ""),
        engine_listener_artifact_digest=str(raw.get("engine_listener_artifact_digest") or ""),
        session_config_digest=str(raw.get("session_config_digest") or ""),
        profile_revision=str(raw.get("profile_revision") or ""),
        profile_digest=str(raw.get("profile_digest") or ""),
        release_digest=str(raw.get("release_digest") or ""),
        engine_launch=raw.get("engine_launch"),
        host_protocol=raw.get("host_protocol"),
        host_os_executable=_path(raw["host_os_executable"], "host_os_executable", directory=False) if raw.get("host_os_executable") else None,
        host_os_artifact_digest=raw.get("host_os_artifact_digest"),
    )
    if profile.engine_launch is not None:
        _selected_profile_payload(profile)
    if profile.engine_launch is None and profile.engine_endpoint != f"http://127.0.0.1:{engine_port}":
        raise ValidationError("worker profile engine_endpoint does not match the Worker launch port")
    source_checkout = _path(raw.get("source_checkout"), "source_checkout", directory=True)
    pack_root = _path(raw.get("pack_root"), "pack_root", directory=True)
    if not pack_root.is_relative_to(source_checkout):
        raise ValidationError("worker profile pack_root must be inside source_checkout")
    boot_manifest_path = _path(raw.get("boot_manifest_path"), "boot_manifest_path", directory=False)
    capability = raw.get("capability_matrix")
    capability_path = _path(capability, "capability_matrix", directory=False) if capability else None
    support = Path(support_root).resolve()
    config = {
        "host_python": str(host_executable),
        "source_checkout": str(source_checkout),
        "pack_root": str(pack_root),
        "runtime_endpoint": "http://127.0.0.1:0",
        "credential_file": str(support / "credentials" / "astrid-pack-host.token"),
        "support_root": str(support),
        "runtime_instance_id": str(runtime_instance_id),
        "ready_file": str(support / f"worker-{profile.profile_id}-ready.json"),
        "state_file": str(support / f"worker-{profile.profile_id}-state.json"),
        "boot_manifest_path": str(boot_manifest_path),
        "boot_manifest_hash": str(raw.get("boot_manifest_hash") or ""),
        "capability_matrix": str(capability_path) if capability_path else None,
        "readiness_profile_path": None,
        "readiness_profile_hash": None,
    }
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config=config,
        environment={**{str(k): str(v) for k, v in environment.items()}, **({"ASTRID_WORKER_ENVIRONMENT": str(worker_environment)} if worker_environment is not None else {})},
        timeout_seconds=float(raw.get("worker_timeout_seconds") or 900.0),
    )
    inspector = OSProcessInspector(profile)
    return LocalWorkerComposition({profile.profile_id: profile}, preparer, inspector)


def _pack_inventory(value):
    root = Path(value)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or any(p.is_symlink() for p in root.parents):
        raise ConflictError("additional pack root is not an exact admitted directory")
    rows = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).parts):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}: continue
        if path.is_symlink(): raise ConflictError("additional pack inventory contains an alias")
        if path.is_file(): rows[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not rows: raise ConflictError("additional pack inventory is empty")
    return rows


def _verify_installed_host_records(profile, config):
    """Observe current installation bytes against selected release RECORD pins."""
    import base64, csv, importlib.metadata, sysconfig
    from .verified_host_launch import raw_digest
    source = Path(config["source_checkout"])
    records = {}
    for package in ("astrid", "astrid-runtime"):
        distribution = importlib.metadata.distribution(package)
        if Path(distribution.locate_file("")).resolve() != source.resolve():
            raise ConflictError("host-only release is outside current installed root")
        record = distribution.read_text("RECORD")
        if not record: raise ConflictError("host-only installed release has no RECORD")
        records[package] = hashlib.sha256(record.encode()).hexdigest()
        for relative, checksum, size in csv.reader(record.splitlines()):
            if not checksum: continue
            target = Path(distribution.locate_file(relative)).resolve()
            if not target.is_relative_to(Path(sys.prefix).resolve()) or not target.is_file():
                raise ConflictError("installed release file escapes selected environment")
            algorithm, encoded = checksum.split("=", 1)
            if algorithm != "sha256" or hashlib.sha256(target.read_bytes()).digest() != base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)):
                raise ConflictError("installed release file differs from RECORD")
    if "sha256:" + raw_digest(records) != profile.release_digest:
        raise ConflictError("host-only installed release digest differs")
    return records


def _installed_host_release(profile, config):
    """Trusted local owner supplies the existing verifier's installed record."""
    import sysconfig
    from .verified_host_launch import installed_inventory, raw_digest, source_checkout_closure
    _verify_installed_host_records(profile, config)
    source = Path(config["source_checkout"])
    roots = [source, Path(sys.base_prefix), Path(sysconfig.get_path("stdlib")), Path(sysconfig.get_config_var("DESTSHARED"))]
    inventories = {}; entries = []
    for root in dict.fromkeys(roots):
        inventory = installed_inventory(root)
        identity = raw_digest(inventory); inventories[identity] = inventory
        entries.append({"path": str(root), "inventory_digest": identity})
    closure = source_checkout_closure(source)
    launcher = Path(__file__).with_name("verified_host_launch.py")
    return {"selected_profile_digest": raw_digest(_selected_profile_payload(profile)), "profile_digest": profile.profile_digest,
        "release_digest": profile.release_digest, "host_protocol": dict(profile.host_protocol), "source_checkout": str(source),
        "source_components": closure["components"], "inventories": inventories,
        "import_binding": {"schema_version": 1, "mode": "trusted-local-isolated-source/v1",
            "launcher": {"path": str(launcher), "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()},
            "python_runtime_inventory_digest": entries[1]["inventory_digest"], "import_roots": entries}}


def _selection_bytes(value):
    def encode(item):
        if isinstance(item, Path):
            return str(item)
        raise TypeError("local worker selection must contain JSON values or paths")
    try:
        return json.dumps(value, default=encode, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid owner-selected local worker selection") from exc


@dataclass(frozen=True, slots=True)
class _RetainedLocalWorkerComposition:
    """Private read-only selection; grants no launch, admission, or recipe result."""
    _profiles_json: bytes
    _config_json: bytes
    _installed_release_loader: Any = field(init=False, repr=False, compare=False)
    _verified_source_loader: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        from .verified_host_launch import _SourceLoader
        try:
            if type(self._profiles_json) is not bytes or type(self._config_json) is not bytes:
                raise ValueError("selection is not immutable bytes")
            profiles = self.profiles
            if len(profiles) != 1 or not isinstance(self.config, dict):
                raise ValueError("selection is missing")
            _path(self.config.get("source_checkout"), "source_checkout")
            for key, profile in profiles.items():
                if key != profile.profile_id:
                    raise ValueError("profile differs")
                if _secure_profile(profile):
                    _selected_profile_payload(profile)
        except (TypeError, ValueError, KeyError, AttributeError, ValidationError) as exc:
            raise ValidationError("invalid retained local worker composition") from exc
        # Fixed implementation references, never callbacks selected by a request.
        object.__setattr__(self, "_installed_release_loader", _installed_host_release)
        object.__setattr__(self, "_verified_source_loader", _SourceLoader)

    @property
    def profiles(self):
        paths = {"realm_root", "support_root", "worker_executable", "host_executable",
                 "engine_executable", "engine_listener_executable", "host_os_executable"}
        return {key: LocalWorkerProfile(**{
            name: Path(value) if name in paths and value is not None else value
            for name, value in profile.items()
        }) for key, profile in json.loads(self._profiles_json).items()}

    @property
    def config(self):
        return json.loads(self._config_json)

    def _installed_release(self, profile_id):
        profiles = self.profiles
        if profile_id not in profiles:
            raise ValidationError("local worker profile is not owner-selected")
        return json.loads(_selection_bytes(self._installed_release_loader(profiles[profile_id], self.config)))


def _retain_local_worker_composition(value, *, required=False):
    """Keep one private immutable selection across daemon/service construction.

    ``required`` records configured presence, never a verification assertion.
    """
    if value is None and not required:
        return None
    if type(value) is _RetainedLocalWorkerComposition:
        return value
    if not isinstance(value, LocalWorkerComposition):
        raise ValidationError("owner-selected local worker composition is required")
    retained = value._retain()
    if type(retained) is not _RetainedLocalWorkerComposition:
        raise ValidationError("invalid retained local worker composition")
    return retained


def _load_host_only_composition(raw, *, workspace_uuid, realm_root, support_root, runtime_instance_id):
    from .local_worker import _digest
    prohibited = {"worker_environment", "worker_executable", "worker_artifact_digest", "engine_executable", "engine_listener_executable",
        "engine_artifact_digest", "engine_listener_artifact_digest", "engine_endpoint", "engine_launch"}
    if set(raw) & prohibited:
        raise ValidationError("host-only profile cannot declare Worker/engine roles")
    source = _path(raw.get("source_checkout"), "source_checkout", directory=True)
    pack = _path(raw.get("pack_root"), "pack_root", directory=True)
    boot = _path(raw.get("boot_manifest_path"), "boot_manifest_path", directory=False)
    # Keep lexical launch spelling; independently pinned kernel executable is separate.
    executable = Path(str(raw.get("host_executable") or ""))
    if not executable.is_absolute() or not executable.is_file() or executable != Path(os.path.abspath(sys.executable)):
        raise ValidationError("host-only interpreter must be the selected installed Runtime environment")
    kernel = _path(raw.get("host_os_executable"), "host_os_executable", directory=False)
    launch = {"source_checkout": str(source), "pack_root": str(pack), "boot_manifest_path": str(boot),
        "boot_manifest_hash": raw.get("boot_manifest_hash"), "capability_matrix": raw.get("capability_matrix"),
        "environment": raw.get("environment", {}), "max_concurrency": raw.get("max_concurrency")}
    if "additional_pack_roots" in raw:
        launch["additional_pack_roots"] = raw["additional_pack_roots"]
    profile = LocalWorkerProfile(str(raw.get("profile_id") or "astrid"), str(workspace_uuid), Path(realm_root).resolve(), Path(support_root).resolve(),
        str(raw.get("machine_id") or ""), None, executable, None, None, "", "", str(raw.get("host_artifact_digest") or ""), "", "",
        str(raw.get("session_config_digest") or ""), str(raw.get("profile_revision") or ""), str(raw.get("profile_digest") or ""),
        str(raw.get("release_digest") or ""), host_os_executable=kernel, host_os_artifact_digest=raw.get("host_os_artifact_digest"),
        host_protocol=raw.get("host_protocol"), execution_mode="host_only_cpu", host_launch=launch)
    _selected_profile_payload(profile)
    if _digest(launch) != profile.session_config_digest:
        raise ValidationError("host-only selected configuration differs")
    config = {**launch, "host_python": str(executable), "runtime_endpoint": "http://127.0.0.1:0",
        "runtime_instance_id": runtime_instance_id, "credential_file": str(Path(support_root) / "credentials/astrid-pack-host.token"),
        "support_root": str(support_root), "ready_file": str(Path(support_root) / f"worker-{profile.profile_id}-ready.json")}
    return LocalWorkerComposition({profile.profile_id: profile}, CrossProcessWorkerPreparer(profile=profile, config=config,
        environment=launch["environment"], timeout_seconds=float(raw.get("worker_timeout_seconds") or 120), cleanup_timeout_seconds=2.0), OSProcessInspector(profile))


__all__ = ["CrossProcessWorkerPreparer", "LocalWorkerComposition", "OSProcessInspector", "load_local_worker_composition"]
