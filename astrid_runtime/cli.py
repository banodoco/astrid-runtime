"""The intentionally thin ``astrid-runtime`` command surface."""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import json
import os
import contextlib
import threading
import time
from pathlib import Path
from typing import Any, Mapping
import urllib.error
import urllib.request

from . import __version__
from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    BootstrapResult,
    DoorSettings,
    SourceProfile,
    _read_catalog,
    _read_support_json,
    _validate_loopback_endpoint,
    _validate_support_paths,
    bootstrap,
    connect,
    down,
    doctor,
    restart,
)
from .io import read_json
from .loopback_http import urlopen_loopback
from runtime_protocol import cancellation
from .paths import DATA_ROOT_ENV, RuntimePaths
from .runtime_boundary import LocalRuntimeBoundary, ForegroundRuntimeBoundary
from runtime_protocol import platform
from runtime_protocol import process_control
from .workspace import configure_workspace, inspect_workspace
from runtime_protocol.door import DEFAULT_DOOR_PORT, DEFAULT_HOSTED_ORIGIN, exact_https_origin
from runtime_protocol.errors import ConflictError, RuntimeErrorBase
from runtime_protocol.upgrade import DEFAULT_UPGRADE_TIMEOUT_SECONDS


class UnconfiguredBoundary:
    """Prevent accidental authority creation when no generated client is wired."""

    def start(self, **kwargs):
        raise BootstrapError("No runtime client is configured. Set ASTRID_RUNTIME_SOURCE_MANIFEST and provide the runtime client.")

    def connect(self, **kwargs):
        raise BootstrapError("No runtime client is configured.")

    def health(self, **kwargs):
        return False

    def validate_owner(self, **kwargs):
        return False

    def is_pid_alive(self, pid):
        return False


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="astrid-runtime", description="Neutral Astrid Runtime workspace bootstrap")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command")
    up = sub.add_parser("up", help="start or reconnect the selected runtime")
    _profile_args(up)
    up.add_argument("--wait", action="store_true", help="return only after this Runtime’s browser door is ready")
    run = sub.add_parser("run", help="run the daemon and browser door in the foreground for a service manager")
    _profile_args(run)
    connect_cmd = sub.add_parser("connect", help="connect to the selected live runtime without starting one")
    _profile_args(connect_cmd)
    status = sub.add_parser("status", help="read runtime discovery and health")
    _read_args(status)
    restart_cmd = sub.add_parser("restart", help="restart the selected runtime owner")
    _profile_args(restart_cmd)
    down_cmd = sub.add_parser("down", help="stop the selected runtime owner after lifecycle reconciliation")
    _profile_args(down_cmd)
    doc = sub.add_parser("doctor", help="read-only support-state diagnostics")
    _read_args(doc)
    start_worker = sub.add_parser("start-worker", help="owner-only verified local Worker launch")
    _read_args(start_worker)
    start_worker.add_argument("--profile", default="astrid", choices=["astrid"])
    start_worker.add_argument("--expected-workspace-uuid", required=True)

    tasks = sub.add_parser("tasks", help="manage named Runtime tasks")
    tasks_sub = tasks.add_subparsers(dest="tasks_command", required=True)
    clear = tasks_sub.add_parser("clear", help="cancel and settle exact named task ids")
    clear.add_argument("task_ids", nargs="+", help="exact task ids to clear")
    _read_args(clear)

    workspace = sub.add_parser("workspace", help="explicitly inspect, create, or attach the sole workspace")
    workspace_sub = workspace.add_subparsers(dest="workspace_command", required=True)
    workspace_inspect = workspace_sub.add_parser("inspect", help="read-only canonical workspace inspection")
    _read_args(workspace_inspect)
    workspace_inspect.add_argument("--realm-root", type=Path)
    workspace_inspect.add_argument("--expected-realm-id")
    workspace_create = workspace_sub.add_parser("create", help="create and select a fresh canonical workspace")
    _profile_args(workspace_create)
    workspace_create.add_argument("--realm-root", required=True, type=Path)
    workspace_create.add_argument("--realm-id")
    _process_control_arg(workspace_create)
    workspace_attach = workspace_sub.add_parser("attach", help="validate and select an existing canonical workspace")
    _profile_args(workspace_attach)
    workspace_attach.add_argument("--realm-root", required=True, type=Path)
    workspace_attach.add_argument("--realm-id", required=True)
    _process_control_arg(workspace_attach)
    workspace_adopt = workspace_sub.add_parser("adopt", help="clone and migrate a stopped workspace or authenticated backup into this installation")
    _profile_args(workspace_adopt)
    workspace_adopt.add_argument("--from", dest="source", required=True, type=Path, help="source data root, stopped realm root, or authenticated backup directory")
    workspace_adopt.add_argument("--realm-id", required=True)

    backup = sub.add_parser("backup", help="create a verified backup through the runtime")
    _read_args(backup)
    backup.add_argument("--destination", required=True, type=Path)
    restore = sub.add_parser("restore", help="restore a verified backup into an inactive destination")
    _read_args(restore)
    restore.add_argument("backup", type=Path)
    restore.add_argument("--destination", required=True, type=Path)

    relocate = sub.add_parser("relocate", help="plan or execute a verified support-root relocation")
    _profile_args(relocate)
    relocate.add_argument("--backup", type=Path, help="optional backup destination recorded in the plan")
    relocate.add_argument("--destination", required=True, type=Path)
    relocate.add_argument("--confirm", help="RELOCATE <selected-realm-id> to execute")
    relocate.add_argument("--plan", action="store_true", help="emit a read-only plan")

    upgrade = sub.add_parser("upgrade", help="stop, upgrade/reconcile, verify, and optionally relocate the Astrid runtime")
    _profile_args(upgrade, data_root_required=True)
    upgrade.add_argument("--destination", type=Path, help="optional support root for the verified relocation cutover")
    upgrade.add_argument("--timeout", type=float, default=DEFAULT_UPGRADE_TIMEOUT_SECONDS, help="bounded offline upgrade/reconciliation budget in seconds")

    checkpoint = sub.add_parser("checkpoint", help="persist a nonce-bound recovery checkpoint")
    _read_args(checkpoint)
    _attempt_args(checkpoint)
    checkpoint.add_argument("--nonce", required=True)
    checkpoint.add_argument("--authorization", required=True)
    checkpoint.add_argument("--state", default="{}", help="checkpoint JSON object or @path")
    prepare = sub.add_parser("prepare-reboot", help="issue or reuse a nonce for checkpoint recovery")
    _read_args(prepare)
    _attempt_args(prepare)
    reboot = sub.add_parser("reboot", help="execute a prepared recovery reboot (disabled by default)")
    _read_args(reboot)
    reboot.add_argument("--checkpoint-id", required=True)
    reboot.add_argument("--nonce", required=True)
    reboot.add_argument("--authorization", required=True)
    reboot.add_argument("--runtime-epoch", required=True, type=int)
    reboot.add_argument("--command", dest="reboot_command", choices=["reboot", "resume"], default="reboot")
    resume = sub.add_parser("resume", help="resume a nonce-bound recovery checkpoint")
    _read_args(resume)
    resume.add_argument("--checkpoint-id", required=True)
    resume.add_argument("--nonce", required=True)
    resume.add_argument("--authorization", required=True)
    resume.add_argument("--runtime-epoch", required=True, type=int)
    recovery = sub.add_parser("recovery", help="recover the selected realm or inspect recovery state")
    _read_args(recovery)
    recovery.add_argument("--expected-realm-id", dest="expected_realm_id")
    recovery.add_argument("--expected-version", type=int)
    recovery.add_argument("--confirm", dest="confirmation")
    recovery.add_argument("--non-interactive", action="store_true")
    return root


DOOR_PORT_ENV = "ASTRID_RUNTIME_DOOR_PORT"


def _hosted_origin(value: str) -> str:
    if value == "off":
        return value
    try:
        return exact_https_origin(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _door_port(value: str) -> int:
    if not value.isdigit() or not 0 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError(f"door port must be an integer from 0 to 65535, got {value!r}")
    return int(value)


def _profile_args(command: argparse.ArgumentParser, *, data_root_required: bool = False) -> None:
    command.add_argument("--profile", default="astrid", choices=["astrid"])
    command.add_argument("--display-name", default="Astrid Workspace")
    command.add_argument("--source-manifest", type=Path)
    command.add_argument("--data-root", type=Path, required=data_root_required, help=f"explicit support root (or {DATA_ROOT_ENV})")
    command.add_argument("--hosted-origin", type=_hosted_origin, default=DEFAULT_HOSTED_ORIGIN, help="the hosted page the browser door answers, or 'off' for no door")
    command.add_argument("--door-port", type=_door_port, default=os.environ.get(DOOR_PORT_ENV, str(DEFAULT_DOOR_PORT)), help=f"the browser door's loopback port (default {DOOR_PORT_ENV} or {DEFAULT_DOOR_PORT})")
    command.add_argument("--json", action="store_true")


def _process_control_arg(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--process-control", choices=["strict", "sandbox"],
        help="how Runtime may signal processes: strict (default; pidfds only on Linux) or sandbox "
             "(also works where seccomp denies pidfd_open and process-group kill, e.g. OpenShell); "
             "omit to keep the current setting")


def _read_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--json", action="store_true")
    command.add_argument("--home", type=Path, help="override the support home (mainly for disposable roots)")
    command.add_argument("--data-root", type=Path, help=f"explicit support root (or {DATA_ROOT_ENV})")


def _attempt_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--attempt-id", required=True)
    command.add_argument("--lease-id", required=True)
    command.add_argument("--fence", required=True, type=int)
    command.add_argument("--runtime-epoch", required=True, type=int)


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _emit(value: Any, *, json_mode: bool) -> None:
    rendered = _json_value(value)
    if json_mode:
        print(json.dumps(rendered, indent=2, sort_keys=True))
        return
    if isinstance(rendered, Mapping):
        for key in sorted(rendered):
            item = rendered[key]
            if isinstance(item, (dict, list)):
                item = json.dumps(item, sort_keys=True)
            print(f"{key}: {item}")
    else:
        print(rendered)


def _paths(args: argparse.Namespace) -> RuntimePaths:
    home = args.home if getattr(args, "home", None) else os.environ.get("ASTRID_RUNTIME_HOME")
    return RuntimePaths.current(home, data_root=getattr(args, "data_root", None))


def _config(args: argparse.Namespace, paths: RuntimePaths) -> BootstrapConfig:
    manifest = getattr(args, "source_manifest", None)
    if manifest is None:
        configured = os.environ.get("ASTRID_RUNTIME_SOURCE_MANIFEST")
        manifest = Path(configured) if configured else None
    origin = getattr(args, "hosted_origin", "off")
    door = None if origin == "off" else DoorSettings(origin=origin, port=args.door_port)
    return BootstrapConfig(profile=getattr(args, "profile", "astrid"), display_name=getattr(args, "display_name", "Astrid Workspace"), source_manifest=manifest, door=door)


def _emit_ready(result: BootstrapResult, *, json_mode: bool) -> None:
    """The bootstrap result, then the one line a person needs: the page to open."""
    _emit(result, json_mode=json_mode)
    if not json_mode and result.door_origin:
        print(f"\nOpen {result.door_origin}")


def _credential(paths: RuntimePaths, *, advise_start: bool = True) -> str:
    # Product traffic uses the Astrid-scoped credential in app support.  An
    # operator command needs the daemon-issued owner credential, which is
    # scoped to admin/worker lifecycle operations and remains inside the
    # runtime support directory.  Never promote the product token's scope in
    # the launcher.
    owner = paths.runtime_support / "credentials" / "owner.token"
    try:
        token = platform.read_private_file(owner).decode("utf-8").strip()
    except OSError as exc:
        if platform.sys.platform == "win32" and not isinstance(exc, FileNotFoundError):
            raise BootstrapError(f"Runtime owner credential access refused: {exc}") from exc
        token = ""
    if not token:
        if not advise_start:
            raise BootstrapError("No Runtime owner credential is available; tasks clear requires an existing owner and will not start Runtime.")
        raise BootstrapError("No runtime owner credential is available; run astrid-runtime up --profile astrid.")
    return token


BACKUP_TRANSPORT_TIMEOUT_SECONDS = 900.0


def _client(paths: RuntimePaths, *, timeout: float | None = None):
    _validate_support_paths(paths)
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("endpoint"):
        raise BootstrapError("No runtime discovery is available; run astrid-runtime up --profile astrid.")
    try:
        from astrid_runtime_client import WorkspaceClient
    except ImportError as exc:
        raise BootstrapError("The installed generated workspace client is unavailable; install astrid-runtime-client.") from exc
    kwargs = {} if timeout is None else {"timeout": timeout}
    return WorkspaceClient(_validate_loopback_endpoint(str(discovery["endpoint"])), _credential(paths), **kwargs)


def _typed_health(paths: RuntimePaths) -> Mapping[str, Any]:
    value = _client(paths).health()
    return _json_value(value)


def _start_local_worker(paths: RuntimePaths, *, profile_id: str, expected_workspace_uuid: str) -> Mapping[str, Any]:
    _validate_support_paths(paths)
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("endpoint"):
        raise BootstrapError("No runtime discovery is available; run astrid-runtime up --profile astrid.")
    endpoint = _validate_loopback_endpoint(str(discovery["endpoint"])).rstrip("/")
    payload = json.dumps({
        "profile_id": profile_id,
        "expected_workspace_uuid": expected_workspace_uuid,
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/v1/control/local-worker/start",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {_credential(paths)}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen_loopback(request, timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except Exception:
            detail = {"message": str(exc)}
        raise BootstrapError(str(detail.get("message") or detail)) from exc
    if not isinstance(value, Mapping):
        raise BootstrapError("Runtime returned invalid local Worker launch metadata.")
    return value


def _load_state(raw: str) -> Mapping[str, Any]:
    if raw.startswith("@"):
        raw = Path(raw[1:]).read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, Mapping):
        raise ValueError("--state must contain a JSON object")
    return value


def _door_json(endpoint: str, origin: str, path: str) -> Mapping[str, Any]:
    request = urllib.request.Request(endpoint.rstrip("/") + path,
        headers={"Origin": origin, "Accept": "application/json"})
    def read(timeout):
        with urlopen_loopback(request, timeout=timeout) as response:
            return json.loads(response.read(1024 * 1024).decode("utf-8"))
    value = cancellation.retry_timeouts(read, 2.0)
    if not isinstance(value, Mapping):
        raise BootstrapError("browser door returned invalid metadata")
    return value


def _wait_for_door(paths: RuntimePaths, result: BootstrapResult, boundary: LocalRuntimeBoundary) -> None:
    cancellation.check()
    if not result.door_endpoint or not result.door_origin:
        raise BootstrapError("the selected Runtime has no browser door; restart it with the hosted origin enabled")
    endpoint = _validate_loopback_endpoint(result.door_endpoint)
    expected = _read_support_json(paths.discovery_path) or {}
    instance = expected.get("runtime_instance_id")
    if (not instance or not result.runtime_instance_id
            or instance != result.runtime_instance_id
            or expected.get("active_realm") != result.realm_id):
        raise BootstrapError("Runtime discovery changed before the browser door became ready")
    deadline = time.monotonic() + boundary.wait_seconds
    reason = "browser door is unavailable"
    while time.monotonic() < deadline:
        cancellation.check()
        current = _read_support_json(paths.discovery_path) or {}
        if any(current.get(key) != expected.get(key) for key in
               ("pid", "process_birth_id", "runtime_instance_id", "active_realm", "door_endpoint", "door_origin")):
            raise BootstrapError("Runtime identity changed while waiting for the browser door")
        try:
            health = _door_json(endpoint, result.door_origin, "/api/runtime/v1/health")
            cancellation.check()
            realm = _door_json(endpoint, result.door_origin, "/api/runtime/v1/realm")
            cancellation.check()
            if health.get("runtime_instance_id") != instance or realm.get("realm_id") != result.realm_id:
                raise BootstrapError("browser door belongs to a different Runtime instance or realm")
            if health.get("status") == "ok":
                return
            reason = str(health.get("status") or "browser door is not ready")
        except BootstrapError:
            raise
        except (OSError, ValueError) as exc:
            reason = str(exc)
        if not boundary.is_pid_alive(int(expected.get("pid") or 0)):
            raise BootstrapError("Runtime exited before its browser door became ready: " + reason)
        if cancellation.active():
            cancellation.pause(0.05)
        else:
            time.sleep(0.05)
    raise BootstrapError("browser door did not become ready before the startup deadline: " + reason)


def _run_foreground(paths: RuntimePaths, config: BootstrapConfig, *, json_mode: bool) -> int:
    from runtime_protocol.logs import RotatingLog
    logs = platform.log_dir(paths.home)
    logs.mkdir(parents=True, exist_ok=True)
    platform.owner_only(logs)
    log_path = logs / "runtime.log"
    boundary = ForegroundRuntimeBoundary()
    boundary._log_directory = logs
    stopped = threading.Event()
    restore = platform.install_stop_handlers(lambda *_: stopped.set())
    failure = None
    startup_ready = False
    try:
        with RotatingLog(log_path) as log:
            platform.owner_only(log_path)
            with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                try:
                    with cancellation.startup_scope(stopped):
                        result = bootstrap(paths, boundary, config)
                        cancellation.check()
                        boundary.check_running()
                        if config.door is not None or result.door_endpoint or result.door_origin:
                            _wait_for_door(paths, result, boundary)
                        startup_ready = True
                        cancellation.check()
                        _emit_ready(result, json_mode=json_mode)
                    while not stopped.wait(0.2):
                        boundary.check_running()
                except Exception as exc:
                    if not (startup_ready and stopped.is_set() and isinstance(exc, cancellation.StartupCancelled)):
                        failure = str(exc)
                        print("Runtime failed: " + failure, flush=True)
                finally:
                    try:
                        boundary.stop()
                    except Exception as exc:
                        failure = failure or str(exc)
                        print("Runtime shutdown failed: " + str(exc), flush=True)
    except Exception as exc:
        failure = str(exc)
    finally:
        restore()
    if failure:
        _emit({"ok": False, "error": failure, "log": str(log_path)}, json_mode=True)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        paths = _paths(args)
    except (OSError, ValueError) as exc:
        if args.command == "tasks" and args.tasks_command == "clear":
            from .task_clear import _error_row, _result
            outcomes = {task_id: _error_row(task_id, "failed", str(exc)) for task_id in args.task_ids}
            _emit(_result(args.task_ids, outcomes), json_mode=args.json)
            return 1
        _emit({"ok": False, "error": str(exc)}, json_mode=True)
        return 1
    if args.command not in {"workspace", "doctor", "status", "tasks"}:
        # Any other command may stop or signal the Runtime it manages, so it
        # follows the installed process-control setting from the start.
        try:
            process_control.configure_from(paths.runtime_support)
        except (ConflictError, OSError) as exc:
            _emit({"ok": False, "error": str(exc)}, json_mode=True)
            return 1
    if args.command == "workspace":
        try:
            boundary = LocalRuntimeBoundary()
            if args.workspace_command == "inspect":
                result = inspect_workspace(
                    paths,
                    boundary,
                    realm_root=args.realm_root,
                    expected_realm_id=args.expected_realm_id,
                )
            elif args.workspace_command == "adopt":
                from .workspace_adopt import adopt_workspace
                result = adopt_workspace(paths, boundary, _config(args, paths), source=args.source, realm_id=args.realm_id)
            else:
                result = configure_workspace(
                    paths,
                    boundary,
                    _config(args, paths),
                    mode=args.workspace_command,
                    realm_root=args.realm_root,
                    realm_id=args.realm_id,
                    process_control=args.process_control,
                )
            _emit(result, json_mode=args.json)
            return 0 if result.get("ok") else 1
        except (BootstrapError, RuntimeErrorBase, OSError, ValueError) as exc:
            _emit({"ok": False, "error": str(exc)}, json_mode=True)
            return 1
    if args.command == "doctor":
        # Doctor is read-only but must still use the concrete process boundary
        # to distinguish a live, matching owner from a stale/reused PID.
        result = doctor(paths, LocalRuntimeBoundary())
        _emit(result, json_mode=args.json)
        return 0 if result["healthy"] else 1
    if args.command == "tasks" and args.tasks_command == "clear":
        from .task_clear import clear_tasks

        result = clear_tasks(
            paths, args.task_ids,
            credential_reader=lambda current: _credential(current, advise_start=False),
            client_factory=_client,
        )
        _emit(result, json_mode=args.json)
        return 0 if result["ok"] else 1
    if args.command == "run":
        config = _config(args, paths)
        try:
            return _run_foreground(paths, config, json_mode=args.json)
        except Exception as exc:
            _emit({"ok": False, "error": str(exc), "log": str(platform.log_dir(paths.home) / "runtime.log")}, json_mode=True)
            return 1
    if args.command == "up":
        config = _config(args, paths)
        try:
            if args.wait and config.door is None:
                raise BootstrapError("up --wait requires the browser door; enable --hosted-origin")
            boundary = LocalRuntimeBoundary()
            result = bootstrap(paths, boundary, config)
            if args.wait:
                _wait_for_door(paths, result, boundary)
        except Exception as exc:
            # Operator-facing startup must be a stable boundary: client,
            # import, protocol, filesystem, and OS failures are represented as
            # one structured error with no traceback.  KeyboardInterrupt is a
            # BaseException and intentionally remains interruptible.
            _emit({"ok": False, "error": str(exc)}, json_mode=True)
            return 1
        _emit_ready(result, json_mode=args.json)
        return 0
    try:
        if args.command == "connect":
            config = _config(args, paths)
            boundary = LocalRuntimeBoundary()
            result = connect(paths, boundary, config)
            _emit(result, json_mode=args.json)
            return 0
        if args.command in {"restart", "down"}:
            config = _config(args, paths)
            boundary = LocalRuntimeBoundary()
            source = config.resolve_source_profile(paths)
            catalog = _read_catalog(paths)
            realm_id = str(catalog.get("selected_realm_id") or "")
            realm = next((item for item in catalog.get("realms", []) if str(item.get("realm_id")) == realm_id), None)
            discovery = _read_support_json(paths.discovery_path) or {}
            if not realm or not discovery.get("pid"):
                raise BootstrapError("No selected runtime owner to restart; run astrid-runtime up --profile astrid.")
            boundary.prepare_restart(source_profile=source, realm_id=realm_id, realm_root=Path(str(realm["data_root"])), support_root=paths.runtime_support, pid=int(discovery["pid"]))
            if args.command == "restart":
                _emit_ready(restart(paths, boundary, config), json_mode=args.json)
            else:
                _emit(down(paths, boundary), json_mode=args.json)
            return 0
        if args.command == "status":
            _validate_support_paths(paths)
            discovery = _read_support_json(paths.discovery_path)
            result = {"discovery": discovery, "support": doctor(paths, LocalRuntimeBoundary())}
            if discovery is not None and not result["support"].get("pid_alive", False):
                result["stale_discovery"] = True
            if discovery and discovery.get("endpoint"):
                try:
                    result["health"] = _typed_health(paths)
                except Exception as exc:
                    result["health_error"] = str(exc)
            _emit(result, json_mode=args.json)
            return 0 if result["support"].get("healthy") and not result.get("stale_discovery") else 1
        if args.command == "start-worker":
            result = _start_local_worker(
                paths,
                profile_id=args.profile,
                expected_workspace_uuid=args.expected_workspace_uuid,
            )
            _emit(result, json_mode=args.json)
            return 0
        if args.command == "backup":
            _emit(_client(paths, timeout=BACKUP_TRANSPORT_TIMEOUT_SECONDS).create_backup(str(args.destination.expanduser().resolve())), json_mode=args.json)
            return 0
        if args.command == "restore":
            _emit(_client(paths).restore_backup(str(args.backup.expanduser().resolve()), str(args.destination.expanduser().resolve())), json_mode=args.json)
            return 0
        if args.command == "relocate":
            from .relocation import plan_relocation, relocate

            if args.plan or not args.confirm:
                _emit(plan_relocation(paths, args.destination, args.backup), json_mode=args.json)
                return 0
            result = relocate(
                paths, LocalRuntimeBoundary(), _config(args, paths), _client(paths),
                destination=args.destination, backup=args.backup, confirmation=args.confirm,
            )
            _emit(result, json_mode=args.json)
            return 0
        if args.command == "upgrade":
            from .operator_upgrade import upgrade_workspace

            config = _config(args, paths)
            result = upgrade_workspace(
                paths, LocalRuntimeBoundary(), config,
                destination=args.destination, timeout_seconds=args.timeout,
            )
            _emit(result, json_mode=args.json)
            return 0
        if args.command == "checkpoint":
            client = _client(paths)
            value = client.checkpoint_attempt(args.attempt_id, lease_id=args.lease_id, fence=args.fence, nonce=args.nonce, authorization=args.authorization, state=_load_state(args.state), runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "prepare-reboot":
            value = _client(paths).prepare_reboot(args.attempt_id, lease_id=args.lease_id, fence=args.fence, runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "reboot":
            if args.reboot_command == "reboot" and os.environ.get("ASTRID_RUNTIME_ENABLE_REAL_REBOOT") != "1":
                raise BootstrapError("real reboot is safe-disabled; set ASTRID_RUNTIME_ENABLE_REAL_REBOOT=1 in an explicitly configured test/host environment")
            value = _client(paths).request_reboot(checkpoint_id=args.checkpoint_id, nonce=args.nonce, authorization=args.authorization, runtime_epoch=args.runtime_epoch, command=args.reboot_command)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "resume":
            value = _client(paths).resume_attempt(checkpoint_id=args.checkpoint_id, nonce=args.nonce, authorization=args.authorization, runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "recovery":
            if not args.expected_realm_id or args.expected_version is None:
                raise ValueError("recovery requires --expected-realm-id and --expected-version")
            if bool(args.confirmation) == bool(args.non_interactive):
                raise ValueError("recovery requires exactly one of --confirm 'RECOVER <realm_id>' or --non-interactive")
            value = _client(paths).recover_realm(expected_realm_id=args.expected_realm_id, expected_version=args.expected_version, confirmation=args.confirmation, noninteractive=args.non_interactive)
            _emit(value, json_mode=args.json)
            return 0
    except (BootstrapError, ValueError, OSError) as exc:
        error = str(exc)
        if isinstance(exc, BootstrapError) and exc.details is not None:
            error = {"message": error, "details": exc.details}
        _emit({"ok": False, "error": error}, json_mode=True)
        return 1
    except Exception as exc:
        # Generated clients expose typed ApiError; keep that import lazy so
        # ``astrid-runtime doctor`` remains usable without client installation.
        _emit({"ok": False, "error": str(exc)}, json_mode=True)
        return 1
    parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
