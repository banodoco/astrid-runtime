"""Adopt a stopped canonical realm or authenticated backup without changing its source."""

from __future__ import annotations

import contextlib
import json
from runtime_protocol.dirfd import filesystem as os
from runtime_protocol import platform
from pathlib import Path
import shutil
import stat
import tempfile
import time
import uuid
from typing import Any

from .bootstrap import BootstrapConfig, BootstrapError, RuntimeBoundary, _bootstrap_mutex, _read_catalog, _validate_support_paths, bootstrap
from .io import atomic_write_json
from .paths import RuntimePaths
from .workspace import _opaque_realm_id, _root, configure_workspace
from .operator_upgrade import _verify_running
from runtime_protocol.backup import BACKUP_INTEGRITY_TIMEOUT_SECONDS, _inspect_consolidated_realm, _file_record_at, _json_at, _open_relative, _verify_backup_pinned, _verify_manifested_realm
from runtime_protocol.dirfd import close_pinned, copy_file_at, mkdir_chain_at, open_directory_chain, pin_directory, validate_parent
from runtime_protocol.errors import OwnerBusyError, RuntimeErrorBase
from runtime_protocol.fsclone import clone_file, clone_or_copy_file
from runtime_protocol.store import RealmStore, SCHEMA_VERSION  # the current canonical schema, never a pinned number
from runtime_protocol.upgrade import _file_digest, _owner_fence, inspect_canonical_schema, migrate_canonical_to_current


class WorkspaceAdoptError(BootstrapError):
    """Adoption stopped before changing source or selecting an unsafe realm."""


_LIVE_SOURCE = ("source realm is live; stop the old runtime first: astrid-runtime down --profile astrid, "
                "or take a backup with astrid-runtime backup --destination DIR and adopt --from DIR")


@contextlib.contextmanager
def _pinned_backup_source(root: Path, realm_id: str):
    """Retain source descriptors and authenticated evidence across the copy."""
    parent = None
    source_fd = -1
    try:
        try:
            parent, source_fd, source_stat = pin_directory(root)
            verified = _verify_backup_pinned(root, directory_identity=parent, directory_fd=source_fd, older_schema=True)
            if verified["manifest"]["realm"]["id"] != realm_id:
                raise WorkspaceAdoptError("backup holds a different realm than the requested one")
            backup = {"fd": source_fd, "parent": parent, "stat": source_stat, "verified": verified,
                      "manifest_record": _file_record_at(source_fd, "manifest.json")}
            _validate_backup_source(root, backup)
        except (RuntimeErrorBase, OSError) as exc:
            raise WorkspaceAdoptError(f"backup did not verify: {exc}") from exc
        yield backup
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        close_pinned(parent)


def _validate_backup_source(root: Path, backup: dict) -> None:
    validate_parent(root, backup["parent"])
    actual = os.stat(root.name, dir_fd=backup["parent"]["_parent_fd"], follow_symlinks=False)
    expected = backup["stat"]
    if (actual.st_dev, actual.st_ino, actual.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
        raise WorkspaceAdoptError("backup directory changed after verification")
    verified = backup["verified"]
    if (_file_record_at(backup["fd"], "manifest.json") != backup["manifest_record"]
            or _json_at(backup["fd"], "manifest.json") != verified["manifest"]
            or _file_record_at(backup["fd"], "cas-manifest.json") != verified["manifest"]["files"]["cas-manifest.json"]
            or _json_at(backup["fd"], "cas-manifest.json") != verified["cas_manifest"]):
        raise WorkspaceAdoptError("backup manifest changed after verification")


def _materialize_backup(root: Path, temporary: Path, backup: dict) -> dict[str, int]:
    """Copy only manifested files through retained, no-follow directories."""
    _validate_backup_source(root, backup)
    verified = backup["verified"]
    objects = verified["cas_manifest"]["objects"]
    files = [(Path("realm.sqlite3"), int(verified["manifest"]["files"]["realm.sqlite3"]["size"]))]
    files.extend((Path("cas/sha256") / obj["digest"][:2] / obj["digest"][2:], int(obj["size"])) for obj in objects)
    destination_fd = open_directory_chain(temporary)
    try:
        for relative in ("cas/sha256", "staging"):
            os.close(mkdir_chain_at(destination_fd, relative))
        for relative, _size in files:
            source_parent = os.dup(backup["fd"]) if relative.parent == Path(".") else _open_relative(backup["fd"], relative.parent, directory=True)
            target_parent = os.dup(destination_fd) if relative.parent == Path(".") else mkdir_chain_at(destination_fd, relative.parent)
            try:
                copy_file_at(source_parent, relative.name, target_parent, relative.name)
                os.chmod(relative.name, 0o600, dir_fd=target_parent, follow_symlinks=False)
            finally:
                os.close(source_parent)
                os.close(target_parent)
        # A backup has no writer lock. Both copies and the source must still
        # match the retained evidence; ownerlessness never grants immutability.
        _verify_manifested_realm(destination_fd, verified["manifest"], verified["cas_manifest"])
        _report, realm = _inspect_consolidated_realm(destination_fd, older_schema=True)
        if realm["id"] != verified["manifest"]["realm"]["id"]:
            raise WorkspaceAdoptError("copied backup realm identity mismatch")
        _verify_manifested_realm(backup["fd"], verified["manifest"], verified["cas_manifest"])
        _validate_backup_source(root, backup)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    return {"bytes_cloned": 0, "bytes_copied": sum(size for _, size in files)}


def adopt_workspace(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig, *, source: str | Path, realm_id: str) -> dict[str, Any]:
    root = _root(source, must_exist=True)
    # An incomplete/unsafe manifest must fail verification rather than being
    # reclassified as a stopped realm.
    if any((root / name).exists() or (root / name).is_symlink() for name in ("manifest.json", "cas-manifest.json")):
        with _pinned_backup_source(root, realm_id) as backup:
            return _adopt_workspace(paths, boundary, config, source=root, realm_id=realm_id, backup=backup)
    return _adopt_workspace(paths, boundary, config, source=source, realm_id=realm_id)


def _source_root(source: str | Path, realm_id: str) -> Path:
    source = _root(source, must_exist=True)
    if (source / "realm.sqlite3").is_file():
        return source
    catalog_path = source / "runtime" / "catalog.json"
    if catalog_path.exists():
        catalog = _read_catalog(RuntimePaths.current(data_root=source))
        selected = catalog.get("selected_realm_id")
        realms = catalog.get("realms", [])
        if selected != realm_id or len(realms) != 1:
            raise WorkspaceAdoptError("source data root does not select the requested realm")
        candidate = _root(realms[0]["data_root"], must_exist=True)
        if not candidate.is_relative_to(source):
            raise WorkspaceAdoptError("source realm must be inside the supplied data root")
        return candidate
    return _root(source / "runtime" / "realms" / realm_id, must_exist=True)


def _source_files(root: Path) -> list[tuple[Path, Path, int]]:
    """Freeze a symlink-free file inventory; reject device nodes and other surprises."""
    files: list[tuple[Path, Path, int]] = []
    def visit(directory: Path) -> None:
        for entry in os.scandir(directory):
            path = Path(entry.path)
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                visit(path)
            elif stat.S_ISREG(mode):
                files.append((path, path.relative_to(root), entry.stat(follow_symlinks=False).st_size))
            else:
                raise WorkspaceAdoptError(f"source contains an unsafe filesystem entry: {path}")
    visit(root)
    if not any(relative == Path("realm.sqlite3") for _, relative, _ in files):
        raise WorkspaceAdoptError("source realm database is missing")
    if not any(relative == Path("owner.lock") for _, relative, _ in files):
        raise WorkspaceAdoptError("source owner.lock is missing; refusing to create a file in the source")
    return files


def _journal(path: Path, **fields: Any) -> None:
    previous: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        previous = json.loads(path.read_text(encoding="utf-8"))
    history = list(previous.get("history", []))
    history.append({"state": fields["state"], "at": time.time()})
    payload = {**previous, **fields, "history": history, "version": 1}
    if fields["state"] != "failed":
        payload.pop("error", None)
    atomic_write_json(path, payload)


def _mirror_directories(root: Path, temporary: Path) -> None:
    """Recreate the realm's directory tree with its modes, empty ones included.

    Admission requires storage roots such as cas/sha256 and staging/ to exist
    (and the Runtime keeps them 0700); copying only regular files would drop
    empty directories and widen modes.
    """
    for directory in sorted(path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()):
        target = temporary / directory.relative_to(root)
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, directory.stat().st_mode & 0o777)


def _materialize(root: Path, temporary: Path, files: list[tuple[Path, Path, int]]) -> dict[str, int]:
    counts = {"bytes_cloned": 0, "bytes_copied": 0}
    _mirror_directories(root, temporary)
    for source, relative, size in files:
        target = temporary / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        method = clone_or_copy_file(source, target)
        # A clone is identical by construction (the source is fenced, so it
        # can't change underneath); only a byte copy needs a content check.
        if method == "cloned":
            if target.stat().st_size != size:
                raise WorkspaceAdoptError(f"clone size mismatch: {relative}")
        elif _file_digest(source) != _file_digest(target):
            raise WorkspaceAdoptError(f"copy integrity mismatch: {relative}")
        counts["bytes_cloned" if method == "cloned" else "bytes_copied"] += size
    return counts


def _inspect_source_snapshot(root: Path, realm_id: str) -> dict[str, object]:
    """Inspect SQLite sidecars on a private copy; ordinary read-only SQLite may checkpoint the source WAL."""
    with tempfile.TemporaryDirectory(prefix="astrid-runtime-adopt-inspect-") as scratch:
        snapshot = Path(scratch)
        for name in ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal"):
            candidate = root / name
            if candidate.exists() or candidate.is_symlink():
                if not stat.S_ISREG(candidate.lstat().st_mode):
                    raise WorkspaceAdoptError(f"source SQLite component is unsafe: {name}")
                clone_or_copy_file(candidate, snapshot / name)
        return inspect_canonical_schema(snapshot, expected_realm_id=realm_id)


def _finish_adoption_migration(root: Path, journal_path: Path, realm_id: str) -> dict:
    """Resume at the real schema boundary, with both activation archives retained."""
    from runtime_protocol import adoption_lifecycle, v33_lifecycle, v34_lifecycle
    from runtime_protocol.upgrade import migrate_canonical_to_v33

    # Hybrid refusal precedes owner/SQLite/journal writes, including on retries.
    identity = inspect_canonical_schema(root, expected_realm_id=realm_id)
    adoption_lifecycle.activation(root)
    pending = v34_lifecycle.activation(root)
    if pending:
        v34_lifecycle.verify_recovery(*pending)
    with _owner_fence(root):
        identity = inspect_canonical_schema(root, expected_realm_id=realm_id)
        prior = json.loads(journal_path.read_text())
        historical = prior.get('historical_migration') or {}
        _journal(journal_path, state='activating')
        if identity['version'] < 33 or (identity['version'] == 33 and
                (old := v33_lifecycle.activation(root)) and old[1]['state'] not in {'backfill_complete', 'ready'}):
            historical = migrate_canonical_to_v33(root, confirmation=f'MIGRATE CANONICAL {realm_id}',
                                                  expected_realm_id=realm_id)
            _journal(journal_path, state='backfill_complete', historical_migration=historical)
        result = migrate_canonical_to_current(root, confirmation=f'MIGRATE CANONICAL {realm_id}',
                                               expected_realm_id=realm_id)
        pending = v34_lifecycle.activation(root)
        if pending and pending[1]['state'] != 'ready':
            v34_lifecycle.activate(root, admit=False)
        custody_steps = result.get('steps', [])
        if not custody_steps and pending and pending[1]['source']['version'] == 33:
            custody_steps = [{'source_schema_version': 33, 'target_schema_version': 34}]
        result = {**result, 'source_schema_version': prior['source_version'],
                  'changed': prior['source_version'] != SCHEMA_VERSION,
                  'steps': [*historical.get('steps', []), *custody_steps],
                  'historical_recovery_set': historical.get('recovery_set')}
        _journal(journal_path, state='migrated', migration=result)
        return result


def _adopt_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig,
    *,
    source: str | Path,
    realm_id: str,
    backup: dict | None = None,
) -> dict[str, Any]:
    """Clone, migrate, select, and start one realm or backup; reruns resume published work."""
    started = time.monotonic()
    realm_id = _opaque_realm_id(realm_id, generate=False)
    if realm_id in {".", ".."}:
        raise WorkspaceAdoptError("realm id cannot be a filesystem dot component")
    _validate_support_paths(paths)
    root = Path(source) if backup else _source_root(source, realm_id)
    backup_identity = backup["verified"]["manifest"]["manifest_sha256"] if backup else None
    destination = paths.realms_dir / realm_id
    if root == destination or destination.is_relative_to(root) or root.is_relative_to(destination):
        raise WorkspaceAdoptError("source and destination realms must be separate")
    catalog = _read_catalog(paths)
    journal_path = paths.runtime_support / "adopt-journal.json"
    if journal_path.is_symlink():
        raise WorkspaceAdoptError("adoption journal must not be a symlink")
    prior = json.loads(journal_path.read_text(encoding="utf-8")) if journal_path.is_file() and not journal_path.is_symlink() else {}
    if prior.get("source") == str(root) and prior.get("backup_identity") != backup_identity:
        raise WorkspaceAdoptError("backup identity differs from the previous adoption")
    selected = catalog.get("realms", [])
    already_attached = bool(selected and len(selected) == 1 and catalog.get("selected_realm_id") == realm_id and selected[0].get("data_root") == str(destination))
    if (selected or catalog.get("selected_realm_id")) and not (already_attached and prior.get("source") == str(root) and prior.get("destination") == str(destination)):
        raise WorkspaceAdoptError("destination already has a workspace selection")
    resume = destination.exists()
    if resume and (prior.get("source") != str(root) or prior.get("destination") != str(destination) or prior.get("realm_id") != realm_id or prior.get("state") not in {"materializing", "materialized", "activating", "backfill_complete", "migrated", "published", "attached", "started", "complete", "failed"}):
        raise WorkspaceAdoptError("destination realm already exists and is not a resumable adoption")
    if destination.is_symlink():
        raise WorkspaceAdoptError("destination realm must not be a symlink")
    from runtime_protocol import adoption_lifecycle
    adopted = None
    if resume:
        # Inspect the actual schema before any support journal or owner write.
        inspect_canonical_schema(destination, expected_realm_id=realm_id)
        adopted = adoption_lifecycle.activation(destination)
        if prior.get('state') in {'materializing', 'materialized', 'activating', 'backfill_complete', 'migrated'} and not adopted:
            raise WorkspaceAdoptError('incomplete adoption has no matching admission fence')
    try:
        with contextlib.nullcontext() if backup else _owner_fence(root):
            if backup:
                _validate_backup_source(root, backup)
                identity = {"version": backup["verified"]["manifest"]["schema"]["version"]}
            else:
                _source_files(root)
                identity = _inspect_source_snapshot(root, realm_id)
    except OwnerBusyError as exc:
        raise WorkspaceAdoptError(_LIVE_SOURCE) from exc
    paths.ensure_support_dirs()
    with _bootstrap_mutex(paths):
        if _read_catalog(paths).get("realms") and not already_attached:
            raise WorkspaceAdoptError("destination acquired a workspace selection during adoption")
        try:
            with contextlib.nullcontext() if backup else _owner_fence(root):
                # Classification and inventory are repeated after the lock, so
                # a stopped source cannot be swapped between preflight and copy.
                files = [] if backup else _source_files(root)
                if not resume:
                    # Reclaim an unpublished tree before checking fallback space.
                    if prior.get("source") == str(root) and prior.get("destination") == str(destination) and prior.get("temporary"):
                        stale = Path(prior["temporary"])
                        if stale.parent == paths.realms_dir and stale.name.startswith(f".{realm_id}.adopt-") and stale.is_dir() and not stale.is_symlink():
                            shutil.rmtree(stale)
                    operation_id = uuid.uuid4().hex
                    db_size = int(backup["verified"]["manifest"]["files"]["realm.sqlite3"]["size"]) if backup else (root / "realm.sqlite3").stat().st_size
                    # Budget byte-copy fallback even on clone-capable volumes,
                    # plus migration writes, while retaining the free-disk floor.
                    copy_bytes = db_size + sum(int(obj["size"]) for obj in backup["verified"]["cas_manifest"]["objects"]) if backup else sum(size for _, _, size in files)
                    required = copy_bytes + 2 * db_size + 64 * 1024 * 1024
                    free = shutil.disk_usage(paths.realms_dir).free
                    if free < required + 4 * 1024 ** 3:
                        raise WorkspaceAdoptError(f"byte-copy fallback and migration need {required} free bytes plus the 4 GiB floor; only {free} available")
                if backup:
                    _validate_backup_source(root, backup)
                    identity = {"version": backup["verified"]["manifest"]["schema"]["version"]}
                else:
                    identity = _inspect_source_snapshot(root, realm_id)
                if resume:
                    inspect_canonical_schema(destination, expected_realm_id=realm_id)
                    counts = dict(prior.get("counts") or {})
                    migration = prior.get("migration")
                    if adopted and prior.get('state') in {'materializing', 'materialized', 'activating', 'backfill_complete', 'migrated'}:
                        migration = migration or _finish_adoption_migration(destination, journal_path, realm_id)
                        if inspect_canonical_schema(destination, expected_realm_id=realm_id)['version'] != SCHEMA_VERSION:
                            raise WorkspaceAdoptError('adoption recovery did not reach the current schema')
                        report = RealmStore.inspect_realm(destination, deep=True, timeout_seconds=BACKUP_INTEGRITY_TIMEOUT_SECONDS)
                        if not report.get('ok'):
                            raise WorkspaceAdoptError(f'adopted realm failed final integrity checks: {report}')
                        _journal(journal_path, state='published')
                else:
                    temporary = paths.realms_dir / f".{realm_id}.adopt-{operation_id}"
                    if destination.exists():
                        raise WorkspaceAdoptError("destination realm already exists")
                    _journal(journal_path, operation_id=operation_id, state="planned", source=str(root), backup_identity=backup_identity, destination=str(destination), realm_id=realm_id, source_version=identity["version"], temporary=str(temporary))
                    try:
                        temporary.mkdir(mode=0o700)
                        _journal(journal_path, state="copying")
                        if backup:
                            try:
                                counts = _materialize_backup(root, temporary, backup)
                            except (RuntimeErrorBase, OSError) as exc:
                                raise WorkspaceAdoptError(f"backup changed or failed copy verification: {exc}") from exc
                        else:
                            counts = _materialize(root, temporary, files)
                        _journal(journal_path, state="copied", counts=counts)
                        candidate = temporary
                        if int(identity['version']) < SCHEMA_VERSION:
                            # This is publication of an unadmitted copy, before
                            # either migration archive is created. No activation
                            # record is relocated or rebound across a rename.
                            adoption_lifecycle.begin(temporary, destination, journal_path, operation_id, realm_id)
                            _journal(journal_path, state='materializing')
                            os.rename(temporary, destination)
                            platform.fsync_directory(destination.parent)
                            candidate = destination
                            adopted = adoption_lifecycle.activation(destination)
                            _journal(journal_path, state='materialized')
                            migration = _finish_adoption_migration(destination, journal_path, realm_id)
                        else:
                            migration = migrate_canonical_to_current(temporary, confirmation=f"MIGRATE CANONICAL {realm_id}", expected_realm_id=realm_id)
                        final = inspect_canonical_schema(candidate, expected_realm_id=realm_id)
                        if int(final["version"]) != SCHEMA_VERSION:
                            raise WorkspaceAdoptError(f"adopted realm did not reach canonical v{SCHEMA_VERSION} (got v{final['version']})")
                        report = RealmStore.inspect_realm(candidate, deep=True, timeout_seconds=BACKUP_INTEGRITY_TIMEOUT_SECONDS)
                        if not report.get("ok"):
                            raise WorkspaceAdoptError(f"adopted realm failed final integrity checks: {report}")
                        _journal(journal_path, state="migrated", migration=migration)
                        if candidate == temporary:
                            os.rename(temporary, destination)
                            platform.fsync_directory(destination.parent)
                        _journal(journal_path, state="published")
                    except Exception:
                        if temporary.is_dir() and not temporary.is_symlink():
                            shutil.rmtree(temporary)
                        if not destination.exists():
                            _journal(journal_path, state="failed")
                        raise
        except OwnerBusyError as exc:
            raise WorkspaceAdoptError(_LIVE_SOURCE) from exc

    # Attach owns catalog writes; bootstrap owns runtime launch and verification.
    previous_token = os.environ.get(adoption_lifecycle.TOKEN)
    try:
        if adopted:
            os.environ[adoption_lifecycle.TOKEN] = adopted['operation_id']
        configure_workspace(paths, boundary, config, mode="attach", realm_root=destination, realm_id=realm_id)
        _journal(journal_path, state="attached")
        launch = bootstrap(paths, boundary, config)
        verification = _verify_running(paths, boundary, launch)
        _journal(journal_path, state="complete", verification=verification)
    except Exception as exc:
        _journal(journal_path, state="failed", error=str(exc))
        raise WorkspaceAdoptError(f"realm materialized at {destination}; finish with astrid-runtime up after resolving: {exc}") from exc
    finally:
        if previous_token is None:
            os.environ.pop(adoption_lifecycle.TOKEN, None)
        else:
            os.environ[adoption_lifecycle.TOKEN] = previous_token
    return {"ok": True, "source": str(root), "source_kind": "backup" if backup else "realm", "destination": str(destination), "realm_id": realm_id,
            "source_version": int(identity["version"]), "target_version": SCHEMA_VERSION, **counts,
            "elapsed_seconds": round(time.monotonic() - started, 3), "migration": migration, "verification": verification}


__all__ = ["WorkspaceAdoptError", "adopt_workspace"]
