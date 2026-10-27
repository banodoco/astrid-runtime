"""Read-only F1 admission. Execution/capability publication belongs to F1b/c.

Preparation runs in the selected installation, so a standalone Runtime has no
agent import dependency. This module never stops an owner or writes a journal.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading

from runtime_protocol import platform
from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.lifecycle import assert_interruption_safe
from .identity import normalize_startup_identity
from .paths import _install_record_path

MANIFEST_URL = "https://astrid.haus/install-manifest.json"
BOOTSTRAP_URL = "https://astrid.haus/install"
WINDOWS_BOOTSTRAP_URL = "https://astrid.haus/install.ps1"
MAX_METADATA_BYTES = 1024 * 1024


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


class UpdateAdmission:
    def __init__(self, daemon):
        self.daemon = daemon
        self._lock = threading.Lock()

    def status(self):
        # Bounded and independent of workspace/schema negotiation. No disk,
        # network, recovery, job creation or eligibility probing on GET.
        return {"available": False, "state": "none", "reason": "updater-unavailable"}

    def _selection(self):
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
        if selected.get("owner") != "haus.astrid.runtime" or selected.get("uninstalled"):
            raise ValueError("installer ownership required")
        root = _path(selected.get("program_root"))
        data = _path(selected.get("data_root"))
        if (_path(selected.get("realm_root")) != daemon.root
                or selected.get("realm_id") != daemon.service.realm["id"]
                or daemon.support_root != data / "runtime"):
            raise ValueError("selected workspace does not match the live owner")
        marker = _json(root / "install.json", snapshots)
        for record in (selected, marker):
            if (record.get("owner") != "haus.astrid.runtime" or record.get("managed_by") is not None
                    or _path(record.get("data_root")) != data):
                raise ValueError("installer owner, management or data root mismatch")
        journal = root / "update-transaction.json"
        if journal.exists() or journal.is_symlink():
            transaction = _json(journal, snapshots)
            if transaction.get("step") not in {"complete", "rolled_back"}:
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
        parent = selection_path.parent
        if sys.platform == "win32":
            parent = parent / "Astrid Installer"
        lock_path = parent / "astrid-install.lock"
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
            selection_path, snapshots, python, agent, runtime, installed = self._selection()
            with self._installer_idle(selection_path):
                # C1 owns the blocker report and the final destructive fence.
                # This is only its read-only preflight; no stop authority here.
                assert_interruption_safe(self.daemon.root)
                # The trusted OS temp base may be an alias (e.g. /var on macOS).
                # Canonicalize only that base; selected paths and input files
                # still pass the strict link and byte-identity checks below.
                temporary_base = Path(tempfile.gettempdir()).resolve(strict=True)
                with tempfile.TemporaryDirectory(prefix="astrid-update-", dir=temporary_base) as temporary:
                    platform.private_directory(Path(temporary))
                    request = {"directory": temporary, "installed_release": installed,
                               "manifest_url": MANIFEST_URL,
                               "bootstrap_url": WINDOWS_BOOTSTRAP_URL if sys.platform == "win32" else BOOTSTRAP_URL}
                    script = ("import sys; sys.path[:0]=sys.argv[1:3]; "
                              "from astrid.installer.update_job import main; main()")
                    env = {key: value for key, value in os.environ.items()
                           if key not in {"ASTRID_INSTALL_MANIFEST_URL", "PYTHONPATH", "PYTHONHOME"}}
                    result = subprocess.run([str(python), "-I", "-B", "-c", script, str(agent), str(runtime)],
                                            input=json.dumps(request), text=True, capture_output=True,
                                            timeout=300, env=env)
                    if result.returncode:
                        raise UpdateRefusal("inputs-unavailable", "Update inputs are unavailable or invalid.")
                    # Validate selected bytes again in the parent at the point
                    # of consumption; helper metadata is not upstream verification.
                    metadata = json.loads(result.stdout)
                    from hashlib import sha256
                    for name in ("manifest", "bootstrap"):
                        path = Path(temporary) / name
                        if not platform.is_owner_only(path):
                            raise ValueError("selected input is no longer private")
                        raw = _bytes(path, limit=2 * MAX_METADATA_BYTES)
                        if sha256(raw).hexdigest() != metadata[name + "_sha256"]:
                            raise ValueError("selected input changed")
                    target = metadata["release"]
                    if type(target) is not int or target <= installed:
                        raise ValueError("target release must be an integer newer than installed")
                    for path, raw in snapshots.items():
                        if _bytes(path) != raw:
                            raise ValueError("selected installation changed during preparation")
                    # There is deliberately no launcher/capability until F1b/c
                    # provide a complete independent execution path.
                    raise UpdateRefusal("updater-unavailable", "The update launcher is not installed. Run the install line to update Astrid.")
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
