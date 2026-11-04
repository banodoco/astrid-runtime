"""Offline, detected-stability copy of a complete R0 data root into R1."""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import uuid

from runtime_protocol import platform
from runtime_protocol.dirfd import copy_file_at, open_directory_chain, pin_directory, close_pinned, validate_parent
from runtime_protocol.store import RealmStore, SCHEMA_VERSION
from runtime_protocol.upgrade import inspect_canonical_schema, migrate_canonical_to_current
from runtime_protocol.backup import BACKUP_INTEGRITY_TIMEOUT_SECONDS
from runtime_protocol import v33_lifecycle as lifecycle
from .bootstrap import _commit_source_profile_metadata, _validate_source_profile
from .paths import RuntimePaths
from .workspace import _opaque_realm_id, _root

RETRY = "Astrid changed while updating; your data is untouched; quit Astrid and run the install line again"
RECEIPT = "adopt-receipt.r1.json"


def _check_owner_not_busy(realm):
    """Inspect the supported lifetime lock without creating or changing it."""
    from .workspace_adopt import WorkspaceAdoptError
    directory = open_directory_chain(realm)
    try:
        try:
            fd = os.open("owner.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            # LEGACY-R0-OWNERSHIP-EVIDENCE: absence is not proof of a stop.
            return
        except OSError as exc:
            raise WorkspaceAdoptError("source owner lock cannot be inspected; stop the old runtime first") from exc
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode)
                    or _identity(opened) != _identity(os.stat("owner.lock", dir_fd=directory, follow_symlinks=False))):
                raise WorkspaceAdoptError("source owner lock is not a regular file")
            try:
                platform.lock_file(fd, exclusive=True, blocking=False)
            except OSError as exc:
                raise WorkspaceAdoptError("source owner lock is busy or cannot be inspected; stop the old runtime first") from exc
            platform.unlock_file(fd)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _bind_candidate_recovery(candidate, realm, destination, final_realm):
    """Validate private recovery evidence, then bind its records to publication."""
    state = lifecycle.activation(realm)
    if state is None:
        return
    archive, record = state
    try:
        relative_archive = archive.relative_to(candidate)
    except ValueError as exc:
        raise ValueError("recovery archive is outside the candidate") from exc
    if ".." in relative_archive.parts:
        raise ValueError("recovery archive is outside the candidate")
    lifecycle.check_startup(realm)
    lifecycle.verify_tree(archive / "realm", record["inventory"])
    binding = lifecycle.read_record(realm / lifecycle.MARKER)
    record["realm_root"] = str(final_realm.resolve())
    binding["archive"] = str(destination / relative_archive)
    lifecycle.write_record(archive / "activation.json", record)
    lifecycle.write_record(realm / lifecycle.MARKER, binding)


def _relocate_result(value, candidate, destination):
    if isinstance(value, dict):
        return {k: _relocate_result(v, candidate, destination) for k, v in value.items()}
    if isinstance(value, list):
        return [_relocate_result(v, candidate, destination) for v in value]
    if isinstance(value, str) and (value == str(candidate) or value.startswith(str(candidate) + os.sep)):
        return str(destination) + value[len(str(candidate)):]
    return value


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _digest_fd(fd):
    digest = hashlib.sha256()
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _inventory(fd):
    """Inventory full namespace without following links, checking each read for churn."""
    entries = []
    def walk(directory, rel):
        before = os.fstat(directory)
        entries.append([rel, "dir", stat.S_IMODE(before.st_mode), before.st_size, before.st_mtime_ns, None])
        for name in sorted(os.listdir(directory)):
            name.encode("utf-8", "strict")
            if name in (".", "..") or "/" in name or "\\" in name:
                raise ValueError("unsafe source name")
            path = f"{rel}/{name}" if rel else name
            st = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    if _identity(st) != _identity(os.fstat(child)):
                        raise ValueError(RETRY)
                    walk(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    if _identity(st) != _identity(os.fstat(child)):
                        raise ValueError(RETRY)
                    digest = _digest_fd(child)
                    if _identity(st) != _identity(os.fstat(child)):
                        raise ValueError(RETRY)
                finally:
                    os.close(child)
                entries.append([path, "file", stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, digest])
            else:
                raise ValueError(f"unsafe source entry: {path}")
        if _identity(before) != _identity(os.fstat(directory)):
            raise ValueError(RETRY)
    walk(fd, "")
    entries.sort(key=lambda row: row[0].encode("utf-8"))
    encoded = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sqlite = [row for row in entries if row[1] == "file" and (row[0].endswith((".sqlite", ".sqlite3", ".db", ".sqlite-wal", ".sqlite3-wal", ".db-wal", ".sqlite-shm", ".sqlite3-shm", ".db-shm", ".sqlite-journal", ".sqlite3-journal", ".db-journal")))]
    sqlite_hash = hashlib.sha256(json.dumps(sqlite, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return entries, hashlib.sha256(b"astrid-full-root-inventory-v1\n" + encoded).hexdigest(), sqlite_hash


def _clone_or_copy(source, target, name):
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "clonefileat"):
        result = libc.clonefileat(source, os.fsencode(name), target, os.fsencode(name), 1)
        if result == 0:
            return "cloned"
        import errno
        error = ctypes.get_errno()
        if error not in (errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EINVAL):
            raise OSError(error, os.strerror(error), name)
    source_file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source)
    try:
        source_stat = os.fstat(source_file)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("unsafe source entry")
        target_file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
        try:
            while chunk := os.read(source_file, 1024 * 1024):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(target_file, view):]
            os.fchmod(target_file, stat.S_IMODE(source_stat.st_mode))
            os.fsync(target_file)
        finally:
            os.close(target_file)
    finally:
        os.close(source_file)
    return "copied"


def _copy_tree(source, target):
    for name in sorted(os.listdir(source)):
        st = os.stat(name, dir_fd=source, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(name, 0o700, dir_fd=target)
            sf = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source)
            df = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target)
            try:
                _copy_tree(sf, df)
                os.fchmod(df, stat.S_IMODE(st.st_mode))
                os.utime(df, ns=(st.st_atime_ns, st.st_mtime_ns))
                os.fsync(df)
            finally:
                os.close(sf); os.close(df)
        elif stat.S_ISREG(st.st_mode):
            _clone_or_copy(source, target, name)
            os.utime(name, ns=(st.st_atime_ns, st.st_mtime_ns), dir_fd=target, follow_symlinks=False)
        else:
            raise ValueError(f"unsafe source entry: {name}")
    os.fsync(target)


def _publish(parent_fd, old, new):
    # Neither POSIX rename nor a prior existence check alone prevents replacing
    # an independently created empty directory. Require an exclusive primitive.
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(parent_fd, os.fsencode(old), parent_fd, os.fsencode(new), 1)
    elif sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(parent_fd, os.fsencode(old), parent_fd, os.fsencode(new), 4)
    else:
        raise ValueError("exclusive destination publication is unsupported on this platform")
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), new)
    os.fsync(parent_fd)


def _make_candidate_removable(fd):
    os.fchmod(fd, 0o700)
    for name in os.listdir(fd):
        entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(entry.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _make_candidate_removable(child)
            finally:
                os.close(child)


def adopt_copy(paths, config, *, source, realm_id):
    from .workspace_adopt import WorkspaceAdoptError, _source_root
    if os.name == "nt":
        raise WorkspaceAdoptError("offline adoption is not supported on Windows until exclusive publication is qualified")
    realm_id = _opaque_realm_id(realm_id, generate=False)
    if realm_id in (".", ".."):
        raise WorkspaceAdoptError("invalid realm id")
    root = _root(source, must_exist=True)
    if (root / "realm.sqlite3").exists():
        raise WorkspaceAdoptError("offline adoption requires a full data root")
    destination = Path(os.path.abspath(paths.app_support))
    if destination != root.with_name(root.name + "-r1"):
        raise WorkspaceAdoptError("destination must be the sibling <old_data_root>-r1")
    if os.path.lexists(destination):
        raise WorkspaceAdoptError("destination already exists; refusing to replace or reuse it")
    manifest_path = config.source_manifest
    manifest_before = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() if manifest_path else None
    source_profile = config.resolve_source_profile(paths)
    _validate_source_profile(source_profile, expected_profile=config.profile)
    if manifest_path and hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() != manifest_before:
        raise WorkspaceAdoptError("source profile manifest changed during adoption")
    parent, source_fd, root_stat = pin_directory(root)
    parent_fd = open_directory_chain(root.parent)
    candidate = None
    candidate_stat = None
    published = False
    try:
        realm = _source_root(root, realm_id)
        _check_owner_not_busy(realm)
        before, before_hash, sqlite_hash = _inventory(source_fd)
        if any(row[0] in (RECEIPT, "update-journal.r1.json") for row in before):
            raise WorkspaceAdoptError("source contains a reserved R1 record")
        rel_realm = realm.relative_to(root)
        operation = uuid.uuid4().hex
        candidate = Path(tempfile.mkdtemp(prefix=f".{destination.name}.adopt-{operation}-", dir=root.parent))
        candidate_stat = candidate.stat()
        candidate_fd = open_directory_chain(candidate)
        try:
            try:
                _copy_tree(source_fd, candidate_fd)
            except (OSError, ValueError) as exc:
                try:
                    changed = _inventory(source_fd)[0] != before
                except (OSError, ValueError, UnicodeError):
                    changed = True
                if changed:
                    raise WorkspaceAdoptError(RETRY) from exc
                raise
            os.fchmod(candidate_fd, stat.S_IMODE(root_stat.st_mode))
            os.utime(candidate_fd, ns=(root_stat.st_atime_ns, root_stat.st_mtime_ns))
            copied, copied_hash, copied_sqlite = _inventory(candidate_fd)
            if before != copied or before_hash != copied_hash or sqlite_hash != copied_sqlite:
                raise WorkspaceAdoptError(RETRY)
        finally:
            os.close(candidate_fd)
        try:
            after, after_hash, after_sqlite = _inventory(source_fd)
        except (OSError, ValueError, UnicodeError) as exc:
            raise WorkspaceAdoptError(RETRY) from exc
        validate_parent(root, parent)
        named = os.stat(root.name, dir_fd=parent["_parent_fd"], follow_symlinks=False)
        if _identity(root_stat) != _identity(named) or before != after or sqlite_hash != after_sqlite:
            raise WorkspaceAdoptError(RETRY)
        # Only the private candidate is made writable and passed to SQLite.
        for directory, dirs, files in os.walk(candidate):
            os.chmod(directory, 0o700)
            for name in files:
                os.chmod(Path(directory) / name, 0o600)
        copied_realm = candidate / rel_realm
        final_realm = destination / "runtime" / "realms" / realm_id
        target_realm = candidate / "runtime" / "realms" / realm_id
        if copied_realm != target_realm:
            target_realm.parent.mkdir(parents=True, exist_ok=True)
            if target_realm.exists():
                raise WorkspaceAdoptError("candidate realm conflicts with standard destination")
            os.rename(copied_realm, target_realm)
        identity = inspect_canonical_schema(target_realm, expected_realm_id=realm_id)
        migration = migrate_canonical_to_current(target_realm, confirmation=f"MIGRATE CANONICAL {realm_id}", expected_realm_id=realm_id)
        final = inspect_canonical_schema(target_realm, expected_realm_id=realm_id)
        report = RealmStore.inspect_realm(target_realm, deep=True, timeout_seconds=BACKUP_INTEGRITY_TIMEOUT_SECONDS)
        if int(final["version"]) != SCHEMA_VERSION or not report.get("ok"):
            raise WorkspaceAdoptError("copied realm failed final integrity checks")
        _bind_candidate_recovery(candidate, target_realm, destination, final_realm)
        migration = _relocate_result(migration, candidate, destination)
        candidate_paths = RuntimePaths.current(data_root=candidate)
        candidate_paths.ensure_support_dirs()
        for name in ("discovery.json", "instance.lock", "bootstrap.lock", "adopt-journal.json"):
            p = candidate_paths.runtime_support / name
            if p.exists():
                p.unlink()
        catalog = {"version": 1, "selected_realm_id": realm_id, "realms": [{"realm_id": realm_id, "display_name": config.display_name, "data_root": str(final_realm), "selection_source": "attach", "source_profile": source_profile.profile}], "source_profiles": {source_profile.profile: source_profile.as_dict()}}
        _commit_source_profile_metadata(candidate_paths, source_profile, catalog)
        # Flush the private payload before the last source observation so a
        # long flush cannot hide a source change made before publication.
        for directory, dirs, files in os.walk(candidate, topdown=False):
            for name in files:
                fd = os.open(Path(directory) / name, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            platform.fsync_directory(Path(directory))
        manifest_hash = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest() if manifest_path else hashlib.sha256(json.dumps(source_profile.as_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if manifest_path and manifest_hash != manifest_before:
            raise WorkspaceAdoptError("source profile manifest changed during adoption")
        # Repeat after all candidate work, immediately before durable publication.
        _check_owner_not_busy(realm)
        try:
            last, last_hash, last_sqlite = _inventory(source_fd)
        except (OSError, ValueError, UnicodeError) as exc:
            raise WorkspaceAdoptError(RETRY) from exc
        validate_parent(root, parent)
        if before != last or sqlite_hash != last_sqlite or _identity(root_stat) != _identity(os.stat(root.name, dir_fd=parent["_parent_fd"], follow_symlinks=False)):
            raise WorkspaceAdoptError(RETRY)
        receipt = {"ok": True, "source_unchanged": True, "started": False, "realm_id": realm_id, "source": str(realm), "destination": str(final_realm), "receipt_version": 1, "operation_id": operation, "source_data_root": str(root), "source_root_device": root_stat.st_dev, "source_root_inode": root_stat.st_ino, "source_inventory_sha256": before_hash, "destination_inventory_sha256": copied_hash, "post_inventory_sha256": last_hash, "sqlite_digest_sha256": sqlite_hash, "source_manifest_sha256": manifest_hash, "verified_at": datetime.now(timezone.utc).isoformat(), "source_version": int(identity["version"]), "target_version": SCHEMA_VERSION, "migration": migration}
        data = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(candidate / RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data); f.flush(); os.fsync(f.fileno())
        except BaseException:
            raise
        platform.fsync_directory(candidate)
        validate_parent(root, parent)
        if (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino) != (os.fstat(parent["_parent_fd"]).st_dev, os.fstat(parent["_parent_fd"]).st_ino):
            raise WorkspaceAdoptError("destination parent changed")
        _publish(parent_fd, candidate.name, destination.name)
        published = True
        validate_parent(root, parent)
        recovery = lifecycle.activation(final_realm)
        if recovery is None and migration.get("recovery_set"):
            raise WorkspaceAdoptError("published migration recovery marker is missing")
        if recovery is not None:
            lifecycle.check_startup(final_realm)
            lifecycle.verify_tree(recovery[0] / "realm", recovery[1]["inventory"])
            if migration.get("recovery_set") and migration["recovery_set"] != str(recovery[0]):
                raise WorkspaceAdoptError("published recovery path does not match migration receipt")
        return receipt
    finally:
        os.close(source_fd); close_pinned(parent); os.close(parent_fd)
        if candidate is not None and not published and candidate_stat is not None:
            try:
                st = candidate.lstat()
                if stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == (candidate_stat.st_dev, candidate_stat.st_ino):
                    fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        owned = (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (candidate_stat.st_dev, candidate_stat.st_ino)
                        if owned:
                            _make_candidate_removable(fd)
                    finally:
                        os.close(fd)
                    if owned:
                        shutil.rmtree(candidate)
            except FileNotFoundError:
                pass
