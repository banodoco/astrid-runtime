"""Native per-user support paths for the Runtime.

The production default is intentionally boring and explicit.  Tests and local
development can inject ``home`` (or individual roots) without changing any
runtime behaviour.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from runtime_protocol import platform


DATA_ROOT_ENV = "ASTRID_RUNTIME_DATA_ROOT"
INSTALL_RECORD_OWNER = "haus.astrid.runtime"


def _install_record_path(home: Path) -> Path:
    """Return the installer selection record path for the current platform."""
    if platform.sys.platform == "win32":
        local_app_data = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return local_app_data / "astrid-install.json"
    if platform.sys.platform == "linux":
        return Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share") / "astrid-install.json"
    return home / ".local" / "share" / "astrid-install.json"


def _installed_data_root(home: Path) -> Path | None:
    """Read the installer's selected data root, ignoring unavailable records."""
    path = _install_record_path(home)
    if path.is_symlink():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("owner") != INSTALL_RECORD_OWNER:
        return None
    r1_selected = "r1_data_root" in record
    raw = record.get("r1_data_root") if r1_selected else record.get("data_root")
    if not isinstance(raw, str) or not raw.strip():
        if r1_selected:
            raise ValueError("install record contains an invalid r1_data_root")
        return None
    root = Path(raw).expanduser()
    if not root.is_absolute():
        if r1_selected:
            raise ValueError("install record contains an invalid r1_data_root")
        return None
    return root


@dataclass(frozen=True)
class RuntimePaths:
    home: Path
    app_support: Path
    runtime_support: Path
    catalog_path: Path
    discovery_path: Path
    credentials_dir: Path
    realms_dir: Path
    source_profiles_dir: Path
    instance_lock_path: Path
    bootstrap_lock_path: Path
    process_control_path: Path

    @classmethod
    def current(
        cls,
        home: Path | str | None = None,
        *,
        data_root: Path | str | None = None,
    ) -> "RuntimePaths":
        """Resolve the native per-user support paths without using the cwd.

        An explicit data root is used as supplied.
        """
        home_path = Path(home).expanduser() if home is not None else Path.home()
        configured_root = data_root if data_root is not None else os.environ.get(DATA_ROOT_ENV)
        if configured_root:
            app_support = Path(configured_root).expanduser()
            if not app_support.is_absolute():
                raise ValueError(f"{DATA_ROOT_ENV} must be an absolute path")
        else:
            app_support = _installed_data_root(home_path) or platform.data_root(home_path)
        runtime = app_support / "runtime"
        return cls(
            home=home_path,
            app_support=app_support,
            runtime_support=runtime,
            catalog_path=runtime / "catalog.json",
            discovery_path=runtime / "discovery.json",
            credentials_dir=app_support / "credentials",
            realms_dir=runtime / "realms",
            source_profiles_dir=runtime / "source-profiles",
            instance_lock_path=runtime / "instance.lock",
            bootstrap_lock_path=runtime / "bootstrap.lock",
            process_control_path=runtime / "process-control.json",
        )

    @classmethod
    def sandbox(cls, root: Path | str) -> "RuntimePaths":
        """An injectable macOS-shaped fixture filesystem rooted at ``root``."""

        home = Path(root)
        return cls.current(home, data_root=home / "Library" / "Application Support" / "Astrid Runtime")

    def ensure_support_dirs(self) -> None:
        for directory in (
            self.app_support,
            self.runtime_support,
            self.credentials_dir,
            self.realms_dir,
            self.source_profiles_dir,
        ):
            platform.private_directory(directory)
