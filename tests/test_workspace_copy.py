from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from astrid_runtime.paths import RuntimePaths
from astrid_runtime.workspace_adopt import WorkspaceAdoptError, adopt_workspace
from astrid_runtime import workspace_copy
from tests.test_workspace_adopt import _setup, _Boundary


def setup_copy(tmp_path):
    realm, _, config = _setup(tmp_path)
    old = tmp_path / "old"
    paths = RuntimePaths.current(data_root=tmp_path / "old-r1")
    (old / "credentials").mkdir()
    (old / "credentials" / "astrid.json").write_text('{"token":"existing"}')
    (old / "support" / "empty").mkdir(parents=True)
    return old, realm, paths, config


def call(old, paths, config):
    return adopt_workspace(paths, _Boundary(), config, source=old, realm_id="film", read_only_source=True, no_start=True)


def inventory(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return workspace_copy._inventory(fd)
    finally:
        os.close(fd)


def test_offline_receipt_and_full_read_only_tree(tmp_path, monkeypatch):
    old, realm, paths, config = setup_copy(tmp_path)
    for directory, dirs, files in os.walk(old, topdown=False):
        for name in files:
            os.chmod(Path(directory) / name, 0o400)
        os.chmod(directory, 0o500)
    before = inventory(old)
    for name in ("bootstrap", "_verify_running", "configure_workspace", "_owner_fence"):
        monkeypatch.setattr("astrid_runtime.workspace_adopt." + name, lambda *a, **k: pytest.fail("unexpected runtime or source operation"))
    result = call(old, paths, config)
    assert inventory(old) == before
    assert result["ok"] is True and result["source_unchanged"] is True and result["started"] is False
    assert result["source"] == str(realm) and result["destination"] == str(paths.realms_dir / "film")
    assert result["source_inventory_sha256"] == result["post_inventory_sha256"] == result["destination_inventory_sha256"] == before[1]
    assert result["sqlite_digest_sha256"] == before[2]
    assert json.loads((paths.app_support / workspace_copy.RECEIPT).read_text()) == result
    assert (paths.app_support / "credentials" / "astrid.json").read_text() == '{"token":"existing"}'
    assert (paths.app_support / "support" / "empty").is_dir()
    assert not (paths.app_support / "runtime" / "discovery.json").exists()


@pytest.mark.parametrize("method", ["copied", "cloned"])
def test_source_mutation_refuses_for_all_copy_methods(tmp_path, monkeypatch, method):
    old, realm, paths, config = setup_copy(tmp_path)
    original = workspace_copy._copy_tree
    depth = 0
    def copy_and_mutate(source, target):
        nonlocal depth
        depth += 1
        try:
            original(source, target)
        finally:
            depth -= 1
        if depth:
            return
        (old / "credentials" / "astrid.json").write_text('{"token":"changed!"}')
    monkeypatch.setattr(workspace_copy, "_copy_tree", copy_and_mutate)
    if method == "cloned":
        # Emulate a clone result with an independent copy: the full candidate
        # verification is required for either transport.
        def fake_clone(source, target, name):
            workspace_copy.copy_file_at(source, name, target, name)
            return "cloned"
        monkeypatch.setattr(workspace_copy, "_clone_or_copy", fake_clone)
    with pytest.raises(WorkspaceAdoptError, match="Astrid changed while updating"):
        call(old, paths, config)
    assert not paths.app_support.exists()
    assert not list(old.parent.glob('.old-r1.adopt-*'))


def test_existing_destination_is_never_changed(tmp_path):
    old, realm, paths, config = setup_copy(tmp_path)
    paths.app_support.mkdir()
    marker = paths.app_support / "user-data"
    marker.write_text("retain")
    with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
        call(old, paths, config)
    assert marker.read_text() == "retain"


def test_flag_pair_required(tmp_path):
    old, realm, paths, config = setup_copy(tmp_path)
    with pytest.raises(WorkspaceAdoptError, match="must be used together"):
        adopt_workspace(paths, _Boundary(), config, source=old, realm_id="film", read_only_source=True)
    assert not paths.app_support.exists()


def test_corrupt_clone_fails_before_migration(tmp_path, monkeypatch):
    old, realm, paths, config = setup_copy(tmp_path)
    def corrupt(source, target, name):
        workspace_copy.copy_file_at(source, name, target, name)
        if name == "astrid.json":
            fd = os.open(name, os.O_WRONLY, dir_fd=target)
            try:
                os.write(fd, b"X")
            finally:
                os.close(fd)
        return "cloned"
    monkeypatch.setattr(workspace_copy, "_clone_or_copy", corrupt)
    monkeypatch.setattr(workspace_copy, "migrate_canonical_to_current", lambda *a, **k: pytest.fail("unverified copy was migrated"))
    with pytest.raises(WorkspaceAdoptError, match="Astrid changed while updating"):
        call(old, paths, config)
    assert not paths.app_support.exists()


def test_cli_forwards_both_flags(monkeypatch, tmp_path, capsys):
    from astrid_runtime import cli, workspace_adopt
    seen = {}
    def adopt(*args, **kwargs):
        seen.update(kwargs)
        return {"ok": True}
    monkeypatch.setattr(workspace_adopt, "adopt_workspace", adopt)
    assert cli.main(["workspace", "adopt", "--from", str(tmp_path / "old"), "--realm-id", "film", "--read-only-source", "--no-start", "--data-root", str(tmp_path / "old-r1"), "--json"]) == 0
    assert seen["read_only_source"] is True and seen["no_start"] is True
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_installed_r1_selection_preserves_legacy_and_fails_closed(tmp_path, monkeypatch):
    from astrid_runtime import paths as paths_module
    record = tmp_path / "install.json"
    monkeypatch.setattr(paths_module, "_install_record_path", lambda home: record)
    monkeypatch.delenv(paths_module.DATA_ROOT_ENV, raising=False)
    payload = {"owner": paths_module.INSTALL_RECORD_OWNER, "data_root": str(tmp_path / "old"), "r1_data_root": str(tmp_path / "old-r1")}
    record.write_text(json.dumps(payload))
    assert RuntimePaths.current(home=tmp_path).app_support == tmp_path / "old-r1"
    assert RuntimePaths.current(home=tmp_path, data_root=tmp_path / "explicit").app_support == tmp_path / "explicit"
    assert json.loads(record.read_text()) == payload
    payload["r1_data_root"] = "relative"
    record.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="invalid r1_data_root"):
        RuntimePaths.current(home=tmp_path)


@pytest.mark.parametrize("mutation", ["database", "add-directory", "delete", "mode"])
def test_whole_root_mutations_refuse(tmp_path, monkeypatch, mutation):
    old, realm, paths, config = setup_copy(tmp_path)
    original = workspace_copy._copy_tree
    depth = 0
    def copy_and_mutate(source, target):
        nonlocal depth
        depth += 1
        try:
            original(source, target)
        finally:
            depth -= 1
        if depth:
            return
        if mutation == "database":
            with (realm / "realm.sqlite3").open("r+b") as f:
                f.seek(200)
                byte = f.read(1)
                f.seek(200)
                f.write(bytes([byte[0] ^ 1]))
        elif mutation == "add-directory":
            (old / "support" / "added").mkdir()
        elif mutation == "delete":
            (old / "credentials" / "astrid.json").unlink()
        else:
            os.chmod(old / "credentials" / "astrid.json", 0o400)
    monkeypatch.setattr(workspace_copy, "_copy_tree", copy_and_mutate)
    with pytest.raises(WorkspaceAdoptError, match="Astrid changed while updating"):
        call(old, paths, config)
    assert not paths.app_support.exists()


def test_sqlite_never_opens_the_source(tmp_path, monkeypatch):
    import sqlite3
    old, realm, paths, config = setup_copy(tmp_path)
    connect = sqlite3.connect
    def checked(database, *args, **kwargs):
        assert not str(database).startswith(str(old) + "/")
        return connect(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, "connect", checked)
    call(old, paths, config)


def test_competing_destination_is_preserved(tmp_path, monkeypatch):
    old, realm, paths, config = setup_copy(tmp_path)
    original = workspace_copy._publish
    def race(parent, source, destination):
        paths.app_support.mkdir()
        (paths.app_support / "user").write_text("keep")
        original(parent, source, destination)
    monkeypatch.setattr(workspace_copy, "_publish", race)
    with pytest.raises(OSError):
        call(old, paths, config)
    assert (paths.app_support / "user").read_text() == "keep"


def test_mutation_after_copy_before_publication_refuses(tmp_path, monkeypatch):
    old, realm, paths, config = setup_copy(tmp_path)
    migrate = workspace_copy.migrate_canonical_to_current
    def mutate_during_migration(*args, **kwargs):
        result = migrate(*args, **kwargs)
        (old / "support" / "late").write_text("new")
        return result
    monkeypatch.setattr(workspace_copy, "migrate_canonical_to_current", mutate_during_migration)
    with pytest.raises(WorkspaceAdoptError, match="Astrid changed while updating"):
        call(old, paths, config)
    assert not paths.app_support.exists()


def test_uncertain_publication_retains_destination_and_refuses_retry(tmp_path, monkeypatch):
    old, realm, paths, config = setup_copy(tmp_path)
    publish = workspace_copy._publish
    def publish_then_fail(*args):
        publish(*args)
        raise OSError("publication outcome uncertain")
    monkeypatch.setattr(workspace_copy, "_publish", publish_then_fail)
    with pytest.raises(OSError, match="publication outcome uncertain"):
        call(old, paths, config)
    receipt = paths.app_support / workspace_copy.RECEIPT
    assert receipt.exists()
    with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
        call(old, paths, config)
    assert receipt.exists()
