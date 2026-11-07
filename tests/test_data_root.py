import json
from pathlib import Path

import pytest

from astrid_runtime import RuntimePaths
from astrid_runtime import paths as paths_module
from astrid_runtime.cli import parser


def test_explicit_data_root_is_used_without_mac_support_suffix(tmp_path):
    root = tmp_path / "Astrid" / ".astrid-data"
    paths = RuntimePaths.current(tmp_path / "home", data_root=root)

    assert paths.app_support == root
    assert paths.runtime_support == root / "runtime"
    assert paths.realms_dir == root / "runtime" / "realms"
    assert paths.credentials_dir == root / "credentials"
    assert "Library" not in paths.runtime_support.parts


def test_relative_data_root_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        RuntimePaths.current(tmp_path, data_root=".astrid-data")


def test_lifecycle_commands_accept_data_root(tmp_path):
    args = parser().parse_args(["status", "--data-root", str(tmp_path / ".astrid-data")])
    assert args.data_root == tmp_path / ".astrid-data"


def test_environment_data_root_and_explicit_precedence_are_isolated(tmp_path, monkeypatch):
    configured = tmp_path / "configured"
    home = tmp_path / "home"
    record = home / ".local" / "share" / "astrid-install.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"owner": "haus.astrid.runtime", "data_root": str(tmp_path / "installed")}))
    monkeypatch.setenv("ASTRID_RUNTIME_DATA_ROOT", str(configured))
    assert RuntimePaths.current(home).app_support == configured
    assert RuntimePaths.current(data_root=tmp_path / "explicit").app_support == tmp_path / "explicit"
    assert RuntimePaths.sandbox(tmp_path / "sandbox").app_support != configured
    assert not configured.exists()


def test_install_record_data_root_is_used_without_environment_override(tmp_path, monkeypatch):
    home = tmp_path / "home"
    record = home / ".local" / "share" / "astrid-install.json"
    record.parent.mkdir(parents=True)
    configured = tmp_path / "installed-data"
    record.write_text(json.dumps({"owner": "haus.astrid.runtime", "data_root": str(configured)}))
    monkeypatch.delenv("ASTRID_RUNTIME_DATA_ROOT", raising=False)

    assert RuntimePaths.current(home).app_support == configured


def test_corrupt_install_record_falls_through_to_default(tmp_path, monkeypatch):
    home = tmp_path / "home"
    record = home / ".local" / "share" / "astrid-install.json"
    record.parent.mkdir(parents=True)
    record.write_text("{")
    monkeypatch.delenv("ASTRID_RUNTIME_DATA_ROOT", raising=False)

    assert RuntimePaths.current(home).app_support == paths_module.platform.data_root(home)


def test_default_data_root_is_used_without_environment_or_install_record(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.delenv("ASTRID_RUNTIME_DATA_ROOT", raising=False)

    assert RuntimePaths.current(home).app_support == paths_module.platform.data_root(home)


@pytest.mark.parametrize(
    ("system", "expected_suffix"),
    [
        ("linux", Path(".local/share/astrid-install.json")),
        ("darwin", Path(".local/share/astrid-install.json")),
        ("win32", Path("Astrid Installer/astrid-install.json")),
    ],
)
def test_install_record_path_matches_installer_per_os(tmp_path, monkeypatch, system, expected_suffix):
    home = tmp_path / "home"
    monkeypatch.setattr(paths_module.platform.sys, "platform", system)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    expected = (
        tmp_path / "local-app-data" / expected_suffix
        if system == "win32"
        else home / expected_suffix
    )
    assert paths_module._install_record_path(home) == expected


@pytest.mark.parametrize("system", ["linux", "darwin", "win32"])
def test_installer_lock_is_the_selection_records_sibling(tmp_path, monkeypatch, system):
    from astrid_runtime import update

    home = tmp_path / "home"
    local = tmp_path / "local-app-data"
    monkeypatch.setattr(paths_module.platform.sys, "platform", system)
    monkeypatch.setattr(update.sys, "platform", system)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    expected = (local / "Astrid Installer" if system == "win32" else home / ".local" / "share") / "astrid-install.lock"
    assert update._installer_lock_path(paths_module._install_record_path(home)) == expected


def test_windows_selection_record_passes_the_private_parent_rule(tmp_path, monkeypatch):
    """Model read_private: only protected installer directories admit reads."""
    import importlib

    from runtime_protocol import windows_security

    bootstrap = importlib.import_module("astrid_runtime.bootstrap")

    local = tmp_path / "local-app-data"
    monkeypatch.setattr(paths_module.platform.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    protected = {local / "Astrid Installer"}

    def read_private(path):
        path = Path(path)
        if path.parent not in protected:
            raise PermissionError("unsafe Windows owner/DACL: a protected, non-NULL DACL is required")
        return path.read_bytes()

    monkeypatch.setattr(windows_security, "read_private", read_private)
    record = paths_module._install_record_path(tmp_path / "home")
    record.parent.mkdir(parents=True)
    record.write_text('{"owner": "haus.astrid.runtime", "managed_by": "pinokio"}', encoding="utf-8")

    _raw, selected = bootstrap._private_handoff_json(record)
    assert selected["managed_by"] == "pinokio"
    legacy = local / "astrid-install.json"
    legacy.write_text(record.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(bootstrap.BootstrapError, match="unavailable"):
        bootstrap._private_handoff_json(legacy)


def test_install_record_path_follows_xdg_data_home_on_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(paths_module.platform.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert paths_module._install_record_path(tmp_path / "home") == tmp_path / "xdg" / "astrid-install.json"


def test_symlinked_install_record_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(paths_module.platform.sys, "platform", "darwin")
    home = tmp_path / "home"
    target = tmp_path / "elsewhere.json"
    target.write_text('{"owner": "haus.astrid.runtime", "data_root": "/tmp/x"}', encoding="utf-8")
    record = home / ".local" / "share" / "astrid-install.json"
    record.parent.mkdir(parents=True)
    record.symlink_to(target)
    assert paths_module._installed_data_root(home) is None
