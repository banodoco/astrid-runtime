"""F1 admission, durable acceptance and read-only job status.

Preparation and short record updates run in the selected installation, so a
standalone Runtime has no agent import dependency. Runtime never stops an owner
or writes installer records or the C2 journal itself.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

from runtime_protocol import platform
from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.lifecycle import assert_interruption_safe
from .identity import normalize_startup_identity
from .paths import INSTALL_RECORD_OWNER, _install_record_path

MANIFEST_URL = "https://astrid.haus/install-manifest.json"
BOOTSTRAP_URL = "https://astrid.haus/install"
WINDOWS_BOOTSTRAP_URL = "https://astrid.haus/install.ps1"
MAX_METADATA_BYTES = 1024 * 1024
_STATUS_REASONS = frozenset({"busy", "autostart-off", "unsupported-service-manager"})


class UpdateRefusal(ConflictError):
    def __init__(self, reason, message):
        super().__init__(message, details={"reason": reason})


def _path(value):
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise ValueError("absolute managed path required")
    result = Path(os.path.abspath(value))
    for part in (result, *result.parents):
        if part.is_symlink() or (getattr(part.lstat(), "st_file_attributes", 0) &
                                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise ValueError("linked managed path")
    return result


def _bytes(path, limit=MAX_METADATA_BYTES):
    _path(str(path))
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("ordinary metadata file required")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("metadata is too large")
    return raw


def _json(path, snapshots):
    raw = _bytes(path)
    snapshots[path] = raw
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("metadata object required")
    return value


def _assert_autostart_supported(selected):
    preferences = selected.get("preferences") if isinstance(selected, dict) else None
    if isinstance(preferences, dict):
        autostart = preferences.get("autostart")
        if autostart is False or (isinstance(autostart, str) and autostart.casefold() == "off"):
            raise UpdateRefusal(
                "autostart-off",
                "In-app update is unavailable while saved autostart is off; this installer cannot preserve that choice yet.",
            )


class UpdateAdmission:
    def __init__(self, daemon, launcher=None):
        self.daemon = daemon
        # Tests may inject a launcher. Production delegates launch to the
        # selected installation's Python helper, which owns OS job creation.
        self.launcher = launcher if launcher is not None else getattr(daemon, "update_launcher", None)
        self._lock = threading.Lock()

    def status(self):
        """Project update availability without admitting or reconciling an update."""
        home = Path.home()
        if self._lock.locked():
            return read_update_status(home, available=False, reason="busy")
        reason = None
        available = True
        try:
            # A pending journal is status evidence, not permission for GET to
            # recover it. POST reaches the Agent's locked reconciler instead.
            selection = self._selection(allow_pending=True)
            if sys.platform == "linux":
                availability = self._status_availability(*selection[2:5])
                if availability["available"] is False:
                    available = False
                    candidate = availability.get("reason")
                    reason = candidate if candidate in _STATUS_REASONS else None
        except UpdateRefusal as refusal:
            available = False
            candidate = refusal.details.get("reason")
            reason = candidate if candidate in _STATUS_REASONS else None
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            available = False
        if available and _installer_lock_held(home):
            available, reason = False, "busy"
        return read_update_status(home, available=available, reason=reason)

    def _status_availability(self, python, agent, runtime):
        """Read the Agent capability without invoking admission or recovery."""
        try:
            availability = self._helper(python, agent, runtime, {"action": "availability"})
        except UpdateRefusal as refusal:
            reason = refusal.details.get("reason")
            return {"available": False, **({"reason": reason} if reason in _STATUS_REASONS else {})}
        except (OSError, subprocess.SubprocessError):
            return {"available": False}
        if not isinstance(availability, dict) or type(availability.get("available")) is not bool:
            return {"available": False}
        if availability["available"]:
            return {"available": True}
        reason = availability.get("reason")
        return {"available": False, **({"reason": reason} if reason in _STATUS_REASONS else {})}

    def _helper(self, python, agent, runtime, payload):
        script = ("import sys; sys.path[:0]=sys.argv[1:3]; "
                  "from astrid.installer.update_job import main; main()")
        env = {key: value for key, value in os.environ.items()
               if key not in {"ASTRID_INSTALL_MANIFEST_URL", "PYTHONPATH", "PYTHONHOME"}}
        result = subprocess.run([str(python), "-I", "-B", "-c", script, str(agent), str(runtime)],
                                input=json.dumps(payload), text=True, capture_output=True,
                                timeout=300, env=env)
        failure_reason = "update-record-failed" if payload.get("action") == "accept" else "inputs-unavailable"
        failure_message = ("The update request could not be saved safely." if failure_reason == "update-record-failed"
                           else "Update inputs are unavailable or invalid.")
        try:
            value = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError):
            raise UpdateRefusal(failure_reason, failure_message) from None
        if result.returncode:
            helper_reason = value.get("reason") if isinstance(value, dict) else None
            helper_message = value.get("message") if isinstance(value, dict) else None
            if helper_reason in _STATUS_REASONS:
                raise UpdateRefusal(helper_reason, helper_message or failure_message)
            raise UpdateRefusal(failure_reason, failure_message)
        if not isinstance(value, dict):
            raise UpdateRefusal(failure_reason, failure_message)
        return value

    def _selection(self, *, allow_pending=False):
        daemon = self.daemon
        identity = normalize_startup_identity(daemon.startup_identity)
        if identity["managed_by"] == "source":
            raise UpdateRefusal("source", "This Astrid runs from source checkouts; update those instead.")
        if identity["managed_by"] == "pinokio":
            raise UpdateRefusal("pinokio", "Update Astrid using Pinokio's Update button.")
        if daemon.startup_identity_instance_id != daemon.instance_id:
            raise ValueError("startup identity is not bound to the live owner")
        snapshots = {}
        selection_path = _install_record_path(Path.home())
        selected = _json(selection_path, snapshots)
        _assert_autostart_supported(selected)
        if selected.get("owner") != INSTALL_RECORD_OWNER or selected.get("uninstalled"):
            raise ValueError("installer ownership required")
        root = _path(selected.get("program_root"))
        data = _path(selected.get("data_root"))
        if (_path(selected.get("realm_root")) != daemon.root
                or selected.get("realm_id") != daemon.service.realm["id"]
                or daemon.support_root != data / "runtime"):
            raise ValueError("selected workspace does not match the live owner")
        marker = _json(root / "install.json", snapshots)
        for record in (selected, marker):
            if (record.get("owner") != INSTALL_RECORD_OWNER or record.get("managed_by") is not None
                    or _path(record.get("data_root")) != data):
                raise ValueError("installer owner, management or data root mismatch")
        journal = root / "update-transaction.json"
        if journal.exists() or journal.is_symlink():
            transaction = _json(journal, snapshots)
            if not allow_pending and transaction.get("step") not in {"complete", "rolled_back"}:
                raise UpdateRefusal("recovery-needed", "The installer must recover its pending update first. Run the install line.")
        pointer = _bytes(root / "current")
        snapshots[root / "current"] = pointer
        name = pointer.decode("utf-8").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise ValueError("invalid current version")
        folder = root / "versions" / name
        version = _json(folder / "version.json", snapshots)
        manifest = _json(folder / "manifest.json", snapshots)
        release = manifest.get("release", 0)
        if type(release) is not int or release < 0 or release != identity["release"]:
            raise ValueError("installed release differs from the live owner")
        if normalize_startup_identity(version.get("identity", identity)) != identity:
            raise ValueError("version identity differs from the live owner")
        if "identity" in selected and normalize_startup_identity(selected["identity"]) != identity:
            raise ValueError("selection identity differs from the live owner")
        if _path(version.get("root")) != folder:
            raise ValueError("current version is outside the managed directory")
        profile_path = _path(version.get("profile"))
        if not profile_path.is_relative_to(folder):
            raise ValueError("profile is outside the selected version")
        profile = _json(profile_path, snapshots)
        if profile.get("profile") != "astrid":
            raise ValueError("selected profile is not astrid")
        agent = _path(profile.get("source_checkout"))
        runtime = _path(profile.get("runtime_checkout"))
        if (not agent.is_relative_to(folder) or not runtime.is_relative_to(folder)
                or agent != Path(daemon._identity_agent_checkout or "")
                or runtime != Path(daemon._identity_runtime_checkout or "")):
            raise ValueError("selected checkouts do not match the live owner")
        python = Path(version.get("python", ""))
        # A venv interpreter itself may be a link; its containing directories
        # must belong to this selected version.
        if not python.is_absolute() or not _path(str(python.parent)).is_relative_to(folder) or not python.is_file():
            raise ValueError("selected Python is outside the version")
        return selection_path, snapshots, python, agent, runtime, release

    @contextmanager
    def _installer_idle(self, selection_path):
        lock_path = _installer_lock_path(selection_path)
        # Do not create installer state on refusal. An absent lock has no
        # active holder; future execution must reacquire the real installer lock.
        if not lock_path.exists() and not lock_path.is_symlink():
            yield
            return
        _path(str(lock_path))
        with lock_path.open("r+b") as stream:
            try:
                platform.lock_file(stream.fileno(), blocking=False)
            except BlockingIOError:
                raise UpdateRefusal("installer-busy", "The Astrid installer is already running.") from None
            try:
                yield
            finally:
                platform.unlock_file(stream.fileno())

    def request(self):
        if not self._lock.acquire(blocking=False):
            raise UpdateRefusal("update-busy", "An update request is already being prepared.")
        try:
            selection_path, snapshots, python, agent, runtime, installed = self._selection(allow_pending=True)
            selected_record = json.loads(snapshots[selection_path])
            _assert_autostart_supported(selected_record)
            root = Path(selected_record["program_root"])
            data = Path(selected_record["data_root"])
            old_version_name = snapshots[root / "current"].decode("utf-8").strip()
            old_version = json.loads(snapshots[root / "versions" / old_version_name / "version.json"])
            temporary_base = Path(tempfile.gettempdir()).resolve(strict=True)
            temporary = Path(tempfile.mkdtemp(prefix="astrid-update-", dir=temporary_base))
            platform.private_directory(temporary)
            accepted = False
            operation_id = None
            try:
                with self._installer_idle(selection_path):
                    # C1 owns the blocker report and the final destructive fence.
                    # This is only its read-only preflight; no stop authority here.
                    assert_interruption_safe(self.daemon.root)
                    request = {"directory": str(temporary), "installed_release": installed,
                               "manifest_url": MANIFEST_URL,
                               "bootstrap_url": WINDOWS_BOOTSTRAP_URL if sys.platform == "win32" else BOOTSTRAP_URL}
                    metadata = self._helper(python, agent, runtime, request)
                    # Validate selected bytes again in the parent at the point
                    # of consumption; helper metadata is not upstream verification.
                    from hashlib import sha256
                    for input_name in ("manifest", "bootstrap"):
                        path = temporary / input_name
                        if not platform.is_owner_only(path):
                            raise ValueError("selected input is no longer private")
                        raw = _bytes(path, limit=2 * MAX_METADATA_BYTES)
                        if sha256(raw).hexdigest() != metadata[input_name + "_sha256"]:
                            raise ValueError("selected input changed")
                    target = metadata["release"]
                    if type(target) is not int or target <= installed:
                        raise ValueError("target release must be an integer newer than installed")
                    for path, raw in snapshots.items():
                        if _bytes(path) != raw:
                            raise ValueError("selected installation changed during preparation")
                    from uuid import uuid4
                    operation_id = uuid4().hex
                    job_name = "astrid-update-" + operation_id
                    log_path = root / "logs" / (job_name + ".log")
                    durable = {
                        "action": "accept", "root": str(root), "data_root": str(data),
                        "selection_path": str(selection_path), "old_instance_id": self.daemon.instance_id,
                        "old_identity": self.daemon.startup_identity, "old_version": old_version,
                        "metadata": {
                            "manifest_path": str(temporary / "manifest"),
                            "bootstrap_path": str(temporary / "bootstrap"),
                            "manifest_sha256": metadata["manifest_sha256"],
                            "bootstrap_sha256": metadata["bootstrap_sha256"],
                            "release": target,
                        },
                        "job_name": job_name, "operation_id": operation_id, "log_path": str(log_path),
                    }
                # The helper owns the K2 lock/write. Release the F1a read-only
                # probe lock first so accept can reacquire the real installer lock.
                try:
                    job = self._helper(python, agent, runtime, durable)
                except Exception:
                    current = _read_bounded_object(root / "install.json") or {}
                    current_job = current.get("update_job")
                    if isinstance(current_job, dict) and current_job.get("operation_id") == operation_id:
                        accepted = True
                        raise UpdateRefusal("accept-acknowledgement-unknown", "The update request was saved; check update status before taking another action.") from None
                    raise
                if not isinstance(job, dict):
                    raise UpdateRefusal("busy", "The update acceptance result is incomplete; no job was launched.")
                returned_operation = job.get("operation_id")
                returned_state = job.get("state")
                if returned_operation != operation_id:
                    # The Agent may have reconciled an older operation under
                    # the installer lock. That explicit recovery ends this
                    # request; only a newly accepted matching ID may launch.
                    if returned_state in {"updated", "rolled_back", "failed"}:
                        return {"accepted": False, "state": returned_state,
                                "operation_id": returned_operation,
                                "message": job.get("message") or job.get("result")}
                    raise UpdateRefusal("busy", "The unresolved update was not safely reconciled; no job was launched.")
                if returned_state not in {"accepted", "launching", "active"}:
                    raise UpdateRefusal("busy", "The update is not accepted for launch.")
                accepted = True
                # Launcher acknowledgement can be lost after OS acceptance.
                # Keep the durable job active and never retry it here.
                try:
                    if self.launcher is not None:
                        launch_result = self.launcher(job)
                    else:
                        launch_result = self._helper(
                            python, agent, runtime,
                            {"action": "launch", "root": str(root), "operation_id": operation_id},
                        )
                    if isinstance(launch_result, dict) and launch_result.get("launch_status") in {"failed", "refused"}:
                        reason = str(launch_result.get("launch_error") or "The operating system rejected the update job.")
                        raise UpdateRefusal("launch-failed", "Update launch failed: " + " ".join(reason.split())[:180])
                    if isinstance(launch_result, dict) and launch_result.get("launch_status") in {"unknown", "launching"}:
                        raise UpdateRefusal("launch-acknowledgement-unknown", "The update may have launched; check update status before taking another action.")
                except UpdateRefusal as exc:
                    if exc.details.get("reason") in {"launch-failed", "updater-unavailable"}:
                        raise
                    raise UpdateRefusal("launch-acknowledgement-unknown", "The update was accepted; check update status before taking another action.") from None
                except Exception:
                    raise UpdateRefusal("launch-acknowledgement-unknown", "The update was accepted; check update status before taking another action.") from None
                return {"accepted": True, "state": job.get("state", "accepted"),
                        "operation_id": operation_id, "message": "Update accepted."}
            finally:
                # Inputs belong to the durable job after acceptance; cleanup
                # remains with the worker/job lifecycle owner.
                if not accepted:
                    shutil.rmtree(temporary, ignore_errors=True)
        except ConflictError:
            raise
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            raise UpdateRefusal("selection-or-inputs-invalid", "The selected installation or update inputs do not match this running Astrid.") from None
        finally:
            self._lock.release()


def update_admission(daemon):
    if daemon is None:
        raise AuthorizationError("update owner context is unavailable")
    return daemon.update_admission


_JOB_STATES = {"accepted", "launching", "active", "updated", "rolled_back", "failed", "recovery-needed"}
def _read_bounded_object(path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
            return None
        raw = path.read_bytes()
        if len(raw) > MAX_METADATA_BYTES:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def read_update_status(home=None, *, available=False, reason=None):
    """Read the authoritative accepted job and C2 journal without recovery."""
    def none():
        result = {"available": bool(available), "state": "none"}
        if not available and reason in _STATUS_REASONS:
            result["reason"] = reason
        return result

    def recovery_needed():
        return {"available": bool(available), "state": "recovery-needed", "result": "Recovery needed."}

    home = Path(home) if home is not None else Path.home()
    selected = _read_bounded_object(_install_record_path(home)) or {}
    if selected.get("owner") != INSTALL_RECORD_OWNER:
        return none()
    root_text = selected.get("program_root")
    if not isinstance(root_text, str) or not Path(root_text).is_absolute():
        return none()
    try:
        root = _path(root_text)
    except (OSError, ValueError):
        return none()
    try:
        install_path = _path(str(root / "install.json"))
    except (OSError, ValueError):
        return none()
    install = _read_bounded_object(install_path)
    if install is None:
        return recovery_needed()
    if (install.get("owner") != INSTALL_RECORD_OWNER
            or install.get("data_root") != selected.get("data_root")):
        return recovery_needed()
    job = install.get("update_job")
    journal_path = root / "update-transaction.json"
    journal_exists = journal_path.exists() or journal_path.is_symlink()
    transaction = _read_bounded_object(journal_path) if journal_exists else None
    journal_corrupt = (journal_exists and (transaction is None
                       or not isinstance(transaction.get("step"), str) or not transaction.get("step")))
    if not isinstance(job, dict):
        if journal_corrupt or (transaction and transaction.get("step") not in {"complete", "rolled_back"}):
            return recovery_needed()
        return none()
    state = job.get("state")
    if state not in _JOB_STATES:
        state = "recovery-needed"
    operation_id = job.get("operation_id")
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        state = "recovery-needed"
    transaction = transaction or {}
    step = transaction.get("step")
    terminal_steps = {"complete", "rolled_back"}
    journal_job = transaction.get("update_job")
    if isinstance(journal_job, dict) and "operation_id" in journal_job:
        matched = (journal_job.get("operation_id") == operation_id
                   and (job.get("transaction_id") is None
                        or job.get("transaction_id") == transaction.get("operation_id")))
    else:
        matched = (job.get("transaction_id") is not None
                   and job.get("transaction_id") == transaction.get("operation_id"))
    if journal_corrupt:
        state = "recovery-needed"
    elif (state == "accepted"
          or (state == "launching" and job.get("launch_status") != "acknowledged")):
        # A durable acceptance or registration is not proof of a native launch
        # acknowledgement. It stays unresolved until an explicit Update asks
        # the installer to reconcile it.
        state = "recovery-needed"
    elif step and step not in terminal_steps:
        state = "active" if matched and _installer_lock_held(home) else "recovery-needed"
    elif step in terminal_steps and matched and state in {"accepted", "active"}:
        # C2 finished but its durable F1 result did not. A held installer lock
        # means the worker still owns the final result write; after release,
        # report the unresolved handoff without inferring success or rollback.
        state = "active" if _installer_lock_held(home) else "recovery-needed"
    outcome = state if state in {"updated", "rolled_back", "failed"} else None
    api_state = "active" if state in {"accepted", "launching", "active"} else "terminal" if outcome else state
    result = "Recovery needed." if state == "recovery-needed" else job.get("result") or job.get("message") or (outcome or api_state)
    if not isinstance(result, str):
        result = state
    result = " ".join(result.split())[:240]
    output = {"available": bool(available), "state": api_state, "operation_id": str(operation_id or "")[:80],
              "result": result}
    if outcome:
        output["outcome"] = outcome
    for key in ("target_release", "accepted_at"):
        if isinstance(job.get(key), (int, str)):
            output[key] = job[key]
    job_name = job.get("job_name")
    if isinstance(job_name, str) and job_name:
        output["job_name"] = " ".join(job_name.split())[:160]
    for key, limit in (("launch_status", 80), ("launch_error", 240),
                       ("cleanup_status", 80), ("cleanup_error", 240)):
        value = job.get(key)
        if isinstance(value, str) and value:
            output[key] = " ".join(value.split())[:limit]
    residue = job.get("cleanup_residue", job.get("residue"))
    if isinstance(residue, str) and residue:
        output["cleanup_residue"] = " ".join(residue.split())[:160]
    elif isinstance(residue, list):
        items = [" ".join(item.split())[:120] for item in residue if isinstance(item, str) and item.strip()]
        if items:
            output["cleanup_residue"] = items[:5]
    historical_residue = install.get("update_job_residue")
    if isinstance(historical_residue, list):
        rows = []
        for item in historical_residue[-5:]:
            if not isinstance(item, dict):
                continue
            row = {}
            for key, limit in (("operation_id", 32), ("cleanup_status", 80),
                               ("cleanup_error", 200), ("residue", 160)):
                value = item.get(key)
                if isinstance(value, str) and value:
                    row[key] = " ".join(value.split())[:limit]
            descriptor = item.get("descriptor")
            if isinstance(descriptor, dict) and isinstance(descriptor.get("name"), str):
                row["job_name"] = " ".join(descriptor["name"].split())[:160]
            if row:
                rows.append(row)
        if rows:
            output["owned_residue"] = rows
    log = job.get("log_path")
    if isinstance(log, str) and Path(log).is_absolute():
        try:
            log_path = Path(os.path.abspath(log))
            if log_path.is_relative_to(root):
                safe = True
                for candidate in (log_path, *log_path.parents):
                    if candidate == root:
                        break
                    if candidate.exists() or candidate.is_symlink():
                        if candidate.is_symlink():
                            safe = False
                            break
                if (safe and len(str(log_path)) <= 1024 and log_path.is_file() and not log_path.is_symlink()
                        and stat.S_ISREG(log_path.stat().st_mode) and platform.is_owner_only(log_path)):
                    output["log_path"] = str(log_path)
        except (OSError, ValueError):
            pass
    if state == "none":
        output.pop("result", None)
    return output


def _installer_lock_path(selection_path):
    parent = selection_path.parent
    if sys.platform == "win32":
        parent = parent / "Astrid Installer"
    return parent / "astrid-install.lock"


def _installer_lock_held(home):
    lock_path = _installer_lock_path(_install_record_path(Path(home)))
    if lock_path.is_symlink() or not lock_path.is_file():
        return False
    try:
        _path(str(lock_path))
        with lock_path.open("r+b") as stream:
            try:
                platform.lock_file(stream.fileno(), blocking=False)
            except BlockingIOError:
                return True
            platform.unlock_file(stream.fileno())
            return False
    except (OSError, ValueError):
        # Inability to determine lock ownership is not evidence of a worker.
        return False
