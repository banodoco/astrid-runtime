from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import hashlib

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


def full_manifest(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        st = path.lstat()
        result[str(path.relative_to(root))] = (st.st_mode, st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                                                st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                                                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
    return result


def test_flagged_busy_owner_refuses_without_source_mutation_or_signal(tmp_path, monkeypatch):
    from runtime_protocol import platform
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    real_open = os.open
    lock_opens = []
    def checked_open(path, flags, *args, **kwargs):
        if path == "owner.lock" and kwargs.get("dir_fd") is not None:
            lock_opens.append(flags)
            assert flags & os.O_ACCMODE == os.O_RDONLY
            assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
            assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", checked_open)
    monkeypatch.setattr(os, "kill", lambda *a: pytest.fail("unexpected signal"))
    monkeypatch.setattr(os, "killpg", lambda *a: pytest.fail("unexpected signal"))
    for module in ("astrid_runtime.workspace_adopt", "runtime_protocol.upgrade"):
        monkeypatch.setattr(module + "._owner_fence", lambda *a: pytest.fail("unexpected source owner fence"))
    with (realm / "owner.lock").open("rb") as owner:
        platform.lock_file(owner.fileno(), blocking=False)
        with pytest.raises(WorkspaceAdoptError, match="owner lock is busy"):
            call(old, paths, config)
    assert not paths.app_support.exists()
    assert not list(old.parent.glob(".old-r1.adopt-*"))
    assert lock_opens
    assert full_manifest(old) == before


def test_owner_becoming_busy_before_publication_refuses(tmp_path, monkeypatch):
    from runtime_protocol import platform
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    bind = workspace_copy._bind_candidate_recovery
    with (realm / "owner.lock").open("rb") as owner:
        def bind_then_hold(*args):
            bind(*args)
            platform.lock_file(owner.fileno(), blocking=False)
        monkeypatch.setattr(workspace_copy, "_bind_candidate_recovery", bind_then_hold)
        with pytest.raises(WorkspaceAdoptError, match="owner lock is busy"):
            call(old, paths, config)
    assert not paths.app_support.exists()
    assert not list(old.parent.glob(".old-r1.adopt-*"))
    assert full_manifest(old) == before


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "denied"])
def test_existing_lock_inspection_is_noncreating_and_fail_closed(tmp_path, monkeypatch, kind):
    old, realm, paths, config = setup_copy(tmp_path)
    lock = realm / "owner.lock"
    if kind != "denied":
        lock.unlink()
    if kind == "symlink":
        lock.symlink_to(old / "credentials" / "astrid.json")
    elif kind == "fifo":
        os.mkfifo(lock)
    elif kind == "denied":
        real_open = os.open
        def deny(path, flags, *args, **kwargs):
            if path == "owner.lock" and kwargs.get("dir_fd") is not None:
                raise PermissionError("inspection denied")
            return real_open(path, flags, *args, **kwargs)
        monkeypatch.setattr(os, "open", deny)
    before = full_manifest(old)
    if kind == "missing":
        assert call(old, paths, config)["ok"] is True
        assert not lock.exists()
    else:
        with pytest.raises(WorkspaceAdoptError, match="source owner lock"):
            call(old, paths, config)
        assert not paths.app_support.exists()
    assert full_manifest(old) == before


def test_v26_published_recovery_resolves_and_passes_startup(tmp_path, monkeypatch):
    from runtime_protocol import v33_lifecycle as lifecycle
    from runtime_protocol.errors import ConflictError
    from runtime_protocol.store import RealmStore
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    bind = workspace_copy._bind_candidate_recovery
    retained = {}
    def capture_recovery(*args):
        archive, record = lifecycle.activation(args[1])
        retained["record"] = record.copy()
        retained["bytes"] = {str(p.relative_to(archive)): p.read_bytes()
                             for p in archive.rglob("*") if p.is_file() and p.name != "activation.json"}
        return bind(*args)
    monkeypatch.setattr(workspace_copy, "_bind_candidate_recovery", capture_recovery)
    result = call(old, paths, config)
    published = paths.realms_dir / "film"
    archive, record = lifecycle.activation(published)
    assert result["source_version"] == 26
    assert result["migration"]["recovery_set"] == str(archive)
    assert archive.is_relative_to(paths.app_support)
    assert record["realm_root"] == str(published)
    assert record["state"] == "backfill_complete"
    assert {**retained["record"], "realm_root": str(published)} == record
    assert {str(p.relative_to(archive)): p.read_bytes()
            for p in archive.rglob("*") if p.is_file() and p.name != "activation.json"} == retained["bytes"]
    assert json.loads((paths.app_support / workspace_copy.RECEIPT).read_text()) == result
    assert ".adopt-" not in json.dumps(result)
    lifecycle.verify_tree(archive / "realm", record["inventory"])
    lifecycle.check_startup(published)
    RealmStore(published).close()
    with pytest.raises(ConflictError, match="provider/baseline verification is pending"):
        lifecycle.require_ready(published)
    assert full_manifest(old) == before


@pytest.mark.parametrize("point", ["binding", "published_validation"])
def test_interrupted_binding_or_published_validation_retains_safe_state(tmp_path, monkeypatch, point):
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    if point == "binding":
        write = workspace_copy.lifecycle.write_record
        def interrupt(path, value):
            if Path(path).name == workspace_copy.lifecycle.MARKER and str(value.get("archive", "")).startswith(str(paths.app_support)):
                raise OSError("interrupted binding")
            return write(path, value)
        monkeypatch.setattr(workspace_copy.lifecycle, "write_record", interrupt)
    else:
        validate = workspace_copy.lifecycle.check_startup
        def interrupt(root):
            if Path(root).is_relative_to(paths.app_support):
                raise OSError("interrupted published validation")
            return validate(root)
        monkeypatch.setattr(workspace_copy.lifecycle, "check_startup", interrupt)
    with pytest.raises(OSError, match="interrupted"):
        call(old, paths, config)
    assert paths.app_support.exists() == (point == "published_validation")
    if paths.app_support.exists():
        with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
            call(old, paths, config)
    assert full_manifest(old) == before


@pytest.mark.parametrize("damage", ["archive_reference", "realm_reference", "image"])
def test_published_recovery_validation_refuses_corruption_and_retains_both_roots(tmp_path, monkeypatch, damage):
    from runtime_protocol.errors import ConflictError
    lifecycle = workspace_copy.lifecycle
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    publish = workspace_copy._publish
    def publish_then_damage(*args):
        publish(*args)
        published = paths.realms_dir / "film"
        archive, record = lifecycle.activation(published)
        if damage == "archive_reference":
            binding = lifecycle.read_record(published / lifecycle.MARKER)
            lifecycle.write_record(published / lifecycle.MARKER,
                                   {**binding, "archive": str(paths.app_support / "missing-archive")})
        elif damage == "realm_reference":
            lifecycle.write_record(archive / "activation.json", {**record, "realm_root": str(old)})
        else:
            image = archive / "realm" / "realm.sqlite3"
            image.write_bytes(image.read_bytes() + b"corruption")
    monkeypatch.setattr(workspace_copy, "_publish", publish_then_damage)
    with pytest.raises(ConflictError):
        call(old, paths, config)
    assert paths.app_support.exists()
    retained = full_manifest(paths.app_support)
    with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
        call(old, paths, config)
    assert full_manifest(paths.app_support) == retained
    assert full_manifest(old) == before


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX interruption fixture")
@pytest.mark.parametrize("point", ["binding", "publication"])
def test_abrupt_exit_during_binding_or_after_publication(tmp_path, monkeypatch, point):
    from runtime_protocol import v33_lifecycle as lifecycle
    old, realm, paths, config = setup_copy(tmp_path)
    before = full_manifest(old)
    if point == "binding":
        write = lifecycle.write_record
        def exit_during_binding(path, value):
            if Path(path).name == lifecycle.MARKER and str(value.get("archive", "")).startswith(str(paths.app_support)):
                os._exit(77)
            return write(path, value)
        monkeypatch.setattr(lifecycle, "write_record", exit_during_binding)
    else:
        publish = workspace_copy._publish
        def exit_after_publication(*args):
            publish(*args)
            os._exit(77)
        monkeypatch.setattr(workspace_copy, "_publish", exit_after_publication)
    pid = os.fork()
    if pid == 0:
        try:
            call(old, paths, config)
        finally:
            os._exit(78)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 77
    assert full_manifest(old) == before
    if point == "binding":
        assert not paths.app_support.exists()
        assert list(old.parent.glob(".old-r1.adopt-*"))
    else:
        assert paths.app_support.exists()
        lifecycle.check_startup(paths.realms_dir / "film")
        with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
            call(old, paths, config)


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


def test_copied_cas_remains_independent_after_adoption(tmp_path):
    old, realm, paths, config = setup_copy(tmp_path)
    payload = b"immutable CAS data"
    digest = hashlib.sha256(payload).hexdigest()
    source = realm / "cas" / "sha256" / digest[:2] / digest[2:]
    source.parent.mkdir(exist_ok=True)
    source.write_bytes(payload)
    os.chmod(source, 0o644)
    before = full_manifest(old)

    receipt = call(old, paths, config)
    assert full_manifest(old) == before
    assert receipt["source_inventory_sha256"] == receipt["destination_inventory_sha256"] == receipt["post_inventory_sha256"]

    target = paths.realms_dir / "film" / "cas" / "sha256" / digest[:2] / digest[2:]
    assert not os.path.samefile(source, target)
    target.chmod(0o600)
    target.write_bytes(b"changed only in R1")
    assert full_manifest(old) == before


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
    before = full_manifest(old)
    publish = workspace_copy._publish
    def publish_then_fail(*args):
        publish(*args)
        raise OSError("publication outcome uncertain")
    monkeypatch.setattr(workspace_copy, "_publish", publish_then_fail)
    with pytest.raises(OSError, match="publication outcome uncertain"):
        call(old, paths, config)
    receipt = paths.app_support / workspace_copy.RECEIPT
    assert receipt.exists()
    published = full_manifest(paths.app_support)
    with pytest.raises(WorkspaceAdoptError, match="destination already exists"):
        call(old, paths, config)
    assert receipt.exists()
    assert full_manifest(old) == before
    assert full_manifest(paths.app_support) == published
    workspace_copy.lifecycle.check_startup(paths.realms_dir / "film")
