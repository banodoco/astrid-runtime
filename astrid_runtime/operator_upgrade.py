"""One guarded operator workflow for upgrading and relocating Astrid runtime data."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path
import time
import uuid
from dataclasses import asdict, is_dataclass, replace
from contextlib import contextmanager
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    SourceProfile,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_locked,
    _bootstrap_mutex,
    _canonical_realm_root,
    _lock_matches,
    _read_catalog,
    _read_support_json,
    _selected_realm,
)
from .io import atomic_write_json, remove_file
from .paths import RuntimePaths
from .refusal import refusal_from
from .relocation import _reject_live_pack_host, relocate
from runtime_protocol.upgrade import (
    DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    _open_readonly,
    _owner_fence,
    inspect_canonical_schema,
    inspect_realm_schema,
    migrate_canonical_to_current,
    upgrade_realm,
)
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence
from runtime_protocol.util import now


class OperatorUpgradeError(BootstrapError):
    """A guarded upgrade workflow could not safely advance."""


_JOURNAL_VERSION = 1


def _realm_from_catalog(paths: RuntimePaths) -> tuple[str, Path]:
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    if not realm:
        raise OperatorUpgradeError("upgrade requires one selected Astrid realm")
    realm_id = str(realm.get("realm_id") or "")
    root = Path(str(realm.get("data_root") or "")).expanduser()
    if not realm_id:
        raise OperatorUpgradeError("selected Astrid realm root is missing or unsafe")
    try:
        root = _canonical_realm_root(root)
    except BootstrapError as exc:
        raise OperatorUpgradeError("selected Astrid realm root is missing or unsafe") from exc
    return realm_id, root


def _schema_kind(root: Path, *, expected_realm_id: str) -> str:
    try:
        result = inspect_realm_schema(root, expected_realm_id=expected_realm_id)
        return (f"v{result['version']}" if result["version"] < 31 and str(result["kind"]).startswith("C")
                else "v23" if result["version"] == 23 else str(result["kind"]))
    except Exception as exc:
        raise OperatorUpgradeError(str(exc)) from exc


def _assert_idle(root: Path) -> dict[str, Any]:
    try:
        from runtime_protocol.v33_lifecycle import sqlite_observation
        with sqlite_observation(root) as observed:
            report = inspect_interruption_state(observed)
        if not report["safe"]:
            refusal = OperatorUpgradeError(
                "Runtime interruption refused while work is active or unreconciled.",
                details=report,
            )
            message, details = refusal_from(refusal)
            raise OperatorUpgradeError(message, details=details)
        return report
    except OperatorUpgradeError:
        raise
    except Exception as exc:
        message, details = refusal_from(exc)
        raise OperatorUpgradeError(message, details=details) from exc


def _is_lifecycle_refusal(exc: BaseException) -> bool:
    """Return whether an error carries the structured lifecycle refusal report."""
    details = getattr(exc, "details", None)
    return (
        isinstance(details, Mapping)
        and details.get("safe") is False
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    return {}


def _journal(paths: RuntimePaths, *, operation_id: str, state: str, journal_root: Path | None = None, **details: Any) -> Path:
    path = (journal_root or paths.runtime_support) / "upgrade-journal.json"
    if not path.parent.is_dir():
        raise OperatorUpgradeError(f"cannot persist upgrade journal because support root is unavailable: {path.parent}")
    previous = _read_support_json(path) or {}
    history = list(previous.get("history", [])) if isinstance(previous.get("history"), list) else []
    history.append({"state": state, "updated_at": time.time(), **details})
    # Later steps must retain the identity recorded before the first mutation.
    # A stopped/activated journal otherwise loses the roots needed to associate
    # it with the installer's retained backup after an uncatchable interruption.
    identity = {}
    if previous.get("operation_id") == operation_id:
        identity = {
            key: previous[key]
            for key in ("realm_id", "realm_root", "source_support_root", "schema_before", "recovery_set")
            if key in previous
        }
        if any(key in details and details[key] != value for key, value in identity.items()):
            raise OperatorUpgradeError("upgrade transaction identity changed during the operation")
    payload = {
        "version": _JOURNAL_VERSION,
        "operation": "astrid-runtime-upgrade/v1",
        "operation_id": operation_id,
        "state": state,
        "updated_at": time.time(),
        "history": history,
        **identity,
        **details,
    }
    atomic_write_json(path, payload)
    return path


def _owner_record(paths: RuntimePaths, realm_id: str, realm_root: Path, boundary: RuntimeBoundary) -> dict[str, Any] | None:
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("pid"):
        marker = _read_support_json(paths.instance_lock_path)
        if marker and int(marker.get("pid", 0) or 0) > 0:
            if boundary.is_pid_alive(int(marker["pid"])):
                raise OperatorUpgradeError("runtime owner identity is incomplete; use astrid-runtime restart before upgrading")
        return None
    if str(discovery.get("active_realm")) != realm_id:
        raise OperatorUpgradeError("runtime discovery does not match the selected realm")
    required = ("endpoint", "pid", "runtime_instance_id", "process_birth_id", "realm_root")
    if any(not discovery.get(key) for key in required):
        raise OperatorUpgradeError("runtime owner identity is incomplete; refusing to signal it")
    canonical_root = _canonical_realm_root(realm_root)
    if _canonical_realm_root(str(discovery["realm_root"])) != canonical_root:
        raise OperatorUpgradeError("runtime discovery root does not match the selected realm")
    pid = int(discovery["pid"])
    instance_id = str(discovery["runtime_instance_id"])
    birth_id = str(discovery["process_birth_id"])
    if not _lock_matches(paths, pid, instance_id, realm_id, birth_id, canonical_root):
        raise OperatorUpgradeError("runtime owner lock does not match discovery")
    if not boundary.validate_owner(
        endpoint=str(discovery["endpoint"]), pid=pid, instance_id=instance_id,
        owner_lock=paths.instance_lock_path, process_birth_id=birth_id,
        expected_realm_id=realm_id, expected_realm_root=canonical_root,
    ):
        raise OperatorUpgradeError("runtime endpoint or process identity does not match discovery")
    metadata = boundary.endpoint_metadata(
        endpoint=str(discovery["endpoint"]),
        credential_file=paths.runtime_support / "credentials" / "owner.token",
    )
    if str(metadata.get("runtime_instance_id") or "") != instance_id or str(metadata.get("realm_id") or "") != realm_id:
        raise OperatorUpgradeError("runtime authenticated endpoint identity does not match discovery")
    return discovery


def _verify_running(
    paths: RuntimePaths, boundary: RuntimeBoundary, result: Any, *, timeout_seconds: float | None = None,
) -> dict[str, Any]:
    discovery = _read_support_json(paths.discovery_path) or {}
    endpoint = str(discovery.get("endpoint") or getattr(result, "endpoint", ""))
    pid = int(discovery.get("pid") or getattr(result, "pid", 0) or 0)
    instance = str(discovery.get("runtime_instance_id") or getattr(result, "runtime_instance_id", ""))
    if not endpoint or pid <= 0 or not instance or not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance):
        raise OperatorUpgradeError("runtime restarted but failed the health check")
    token_path = paths.runtime_support / "credentials" / "owner.token"
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise OperatorUpgradeError("runtime restarted but owner credential is unavailable") from exc
    if not token:
        raise OperatorUpgradeError("runtime restarted but owner credential is empty")
    connection = boundary.connect(endpoint=endpoint, credential=token, timeout_seconds=timeout_seconds)
    report = _mapping(connection.doctor())
    if not report or not bool(report.get("ok")):
        raise OperatorUpgradeError("runtime restarted but integrity verification failed")
    return {"health": True, "integrity": dict(report)}


@contextmanager
def _installer_mutex(paths):
    """Share the installer lifetime lock, or an offline support-root lock."""
    from .paths import _install_record_path
    from .update import _installer_lock_path
    from runtime_protocol import platform
    selection = _install_record_path(paths.home)
    lock = _installer_lock_path(selection) if selection.exists() else paths.runtime_support / "upgrade-installer.lock"
    if lock.is_symlink():
        raise OperatorUpgradeError("installer lifetime lock must not be a symlink")
    with lock.open("a+") as handle:
        try:
            platform.owner_only(lock)
            platform.lock_file(handle.fileno(), blocking=False)
        except OSError as exc:
            raise OperatorUpgradeError("another installer owns the installation lifetime lock") from exc
        try:
            yield
        finally:
            platform.unlock_file(handle.fileno())


def _capture_installation(paths, archive, record):
    """Bind catalog, supported local App/outbox state and prior executable."""
    from runtime_protocol import v33_lifecycle as lifecycle
    prior = _read_support_json(paths.source_profiles_dir / "astrid.json")
    if not prior:
        raise OperatorUpgradeError("prior executable selection is unavailable; preserve the installation")
    source = SourceProfile.from_mapping(prior)
    checkout = Path(source.runtime_checkout).resolve()
    if not (checkout / "runtime_protocol" / "__init__.py").is_file():
        raise OperatorUpgradeError("prior Runtime executable source is unavailable; preserve the installation")
    # The selected executable is retained independently of mutable checkout/selection.
    executable_inventory = lifecycle.snapshot_tree(checkout, archive / "executable",
        exclude=(".git", ".venv", "__pycache__", ".pytest_cache"))
    support_inventory = lifecycle.snapshot_tree(paths.app_support, archive / "support",
        exclude=("runtime/realms", "runtime/upgrade-journal.json", "runtime/bootstrap.lock",
                 "runtime/discovery.json", "runtime/instance.lock", "runtime/process-control.json", "runtime/upgrade-installer.lock"))
    from .paths import _install_record_path
    selection = _install_record_path(paths.home)
    selection_fact = None
    if selection.exists():
        if selection.is_symlink():
            raise OperatorUpgradeError("installed selection must not be a symlink")
        copied_selection = archive / "installed-selection.json"
        shutil.copy2(selection, copied_selection)
        with copied_selection.open("r+b") as handle:
            os.fsync(handle.fileno())
        selection_fact = {"path": str(selection), **lifecycle._file_fact(copied_selection)}
    environment = None
    if source.runtime_environment:
        # Preserve the selected environment, resolving venv interpreter links.
        environment = archive / "environment"
        shutil.copytree(source.runtime_environment, environment, symlinks=False)
        environment_inventory = {p.relative_to(environment).as_posix(): lifecycle._file_fact(p)
                                 for p in lifecycle._files(environment)}
        for path in lifecycle._files(environment):
            with path.open("r+b") as handle:
                os.fsync(handle.fileno())
        lifecycle.verify_tree(environment, environment_inventory)
    else:
        environment_inventory = None
    executable = Path(sys.executable).resolve()
    lifecycle.phase(archive, record, record["state"], operator_owned=True, prior_profile=prior,
        support_inventory=support_inventory, executable_inventory=executable_inventory,
        installation_selection=selection_fact, environment_inventory=environment_inventory, interpreter={"path": str(executable), **lifecycle._file_fact(executable)},
        scope="full realm/sidecars/CAS, local support/catalog/selection/outbox, prior Runtime executable/environment; disconnected App clients require their external update guard")


def _restore_installation(paths, realm_root, archive):
    from runtime_protocol import v33_lifecycle as lifecycle
    record = lifecycle.read_record(archive / "activation.json")
    if record.get("format") == "astrid-v34-activation/v1":
        from runtime_protocol.v34_lifecycle import rollback
        rollback(realm_root, archive)
    lifecycle.verify_tree(archive / "support", record["support_inventory"])
    lifecycle.verify_tree(archive / "executable", record["executable_inventory"])
    if record.get("environment_inventory") is not None:
        lifecycle.verify_tree(archive / "environment", record["environment_inventory"])
    else:
        interpreter = record["interpreter"]
        if lifecycle._file_fact(Path(interpreter["path"])) != {k: interpreter[k] for k in ("size", "sha256")}:
            raise OperatorUpgradeError("prior interpreter changed; recovery requires the matching environment")
    if record.get("prior_launch_started"):
        # A lost acknowledgement after launching the prior executable may
        # conceal authorized old-version writes. Preserve current work and
        # verify it; never restore the pre-update image a second time.
        lifecycle.verify_sqlite_image(realm_root, realm_id=record["realm_id"], fingerprint=record["source"]["fingerprint"])
        selected = _read_support_json(paths.source_profiles_dir / "astrid.json") or {}
        if selected.get("runtime_checkout") != str(archive / "executable"):
            raise OperatorUpgradeError("prior launch selection is uncertain; preserve both images for recovery")
        return BootstrapConfig(source_profile=SourceProfile.from_mapping(selected))
    if record["state"] != "restored":
        lifecycle.restore(realm_root, archive)
    else:
        lifecycle.verify_sqlite_image(realm_root, realm_id=record["realm_id"], fingerprint=record["source"]["fingerprint"])
        lifecycle.finish_restore_marker(realm_root, archive, record)
    # Restore all captured support files and remove new files within that scope.
    excluded = ("runtime/realms", "runtime/upgrade-journal.json", "runtime/bootstrap.lock",
                "runtime/discovery.json", "runtime/instance.lock", "runtime/process-control.json", "runtime/upgrade-installer.lock")
    for path in list(lifecycle._files(paths.app_support, exclude=excluded)):
        path.unlink()
    lifecycle.snapshot_tree(archive / "support", paths.app_support)
    remove_file(paths.discovery_path)
    remove_file(paths.instance_lock_path)
    if record.get("installation_selection"):
        selected = record["installation_selection"]
        original = archive / "installed-selection.json"
        if lifecycle._file_fact(original) != {k: selected[k] for k in ("size", "sha256")}:
            raise OperatorUpgradeError("retained installer selection is corrupt")
        from runtime_protocol import platform
        fd, temporary = platform.private_temporary(Path(selected["path"]).parent, ".restore-selection-")
        with os.fdopen(fd, "wb") as handle:
            handle.write(original.read_bytes()); handle.flush(); os.fsync(handle.fileno())
        platform.durable_replace(temporary, selected["path"])
    prior = SourceProfile.from_mapping(record["prior_profile"])
    prior = replace(prior, runtime_checkout=str(archive / "executable"),
                    runtime_environment=str(archive / "environment") if record.get("environment_inventory") is not None else None)
    # The restored selection names the retained matching executable, not the candidate.
    atomic_write_json(paths.source_profiles_dir / "astrid.json", prior.as_dict())
    catalog = dict(_read_catalog(paths))
    catalog["source_profiles"] = {**catalog.get("source_profiles", {}), "astrid": prior.as_dict()}
    atomic_write_json(paths.catalog_path, catalog)
    return BootstrapConfig(source_profile=prior)


def _stop_selected(paths, boundary, realm_id, realm_root, config):
    owner = _owner_record(paths, realm_id, realm_root, boundary)
    if owner:
        source = config.resolve_source_profile(paths)
        boundary.prepare_restart(source_profile=source, realm_id=realm_id, realm_root=realm_root,
                                 support_root=paths.runtime_support, pid=int(owner["pid"]))
        with interruption_fence(realm_root) as idle:
            boundary.stop_owner(endpoint=str(owner["endpoint"]), pid=int(owner["pid"]),
                instance_id=str(owner["runtime_instance_id"]), process_birth_id=str(owner["process_birth_id"]),
                realm_id=realm_id, owner_lock=paths.instance_lock_path,
                discovery_path=paths.discovery_path, require_health=False)
        remove_file(paths.discovery_path)
        remove_file(paths.instance_lock_path)


def _start_operation(paths, boundary, config, operation_id):
    previous = os.environ.get("ASTRID_V33_OPERATOR_OPERATION")
    os.environ["ASTRID_V33_OPERATOR_OPERATION"] = operation_id
    try:
        return _bootstrap_locked(paths, boundary, config)
    finally:
        if previous is None:
            os.environ.pop("ASTRID_V33_OPERATOR_OPERATION", None)
        else:
            os.environ["ASTRID_V33_OPERATOR_OPERATION"] = previous


def recover_workspace(paths, boundary, config, *, timeout_seconds=DEFAULT_UPGRADE_TIMEOUT_SECONDS):
    """Explicit full-set recovery; observational update status never calls this."""
    with _bootstrap_mutex(paths), _installer_mutex(paths):
        journal = _read_support_json(paths.runtime_support / "upgrade-journal.json")
        if not journal or journal.get("state") in {"complete", "rolled_back"}:
            raise OperatorUpgradeError("there is no incomplete upgrade to recover")
        realm_id, realm_root = _realm_from_catalog(paths)
        if journal.get("realm_id") != realm_id or journal.get("realm_root") != str(realm_root):
            raise OperatorUpgradeError("recovery selection differs from the recorded upgrade")
        archive = Path(journal["recovery_set"]) if journal.get("recovery_set") else None
        if archive is not None:
            from runtime_protocol import v33_lifecycle as records
            record = records.read_record(archive / "activation.json")
            if record.get("format") == "astrid-v34-activation/v1":
                # Classify before stopping or mutating anything. Hybrids have
                # no automatic recovery authority and must remain untouched.
                current = inspect_realm_schema(realm_root, expected_realm_id=realm_id)
                if current["kind"] not in {"U33", "V34"}:
                    raise OperatorUpgradeError("custody recovery requires an intact U33 or V34 schema")
                if record.get("target_profile") != config.resolve_source_profile(paths).as_dict():
                    raise OperatorUpgradeError("custody recovery requires the recorded candidate executable")
                records.verify_tree(archive / "support", record["support_inventory"])
                records.verify_tree(archive / "executable", record["executable_inventory"])
                _stop_selected(paths, boundary, realm_id, realm_root, config)
                from runtime_protocol import v34_lifecycle as custody_lifecycle
                custody_lifecycle.migrate(realm_root, confirmation=f"MIGRATE CANONICAL {realm_id}", expected_realm_id=realm_id, timeout_seconds=timeout_seconds)
                custody_lifecycle.activate(realm_root, admit=False)
                prior_token = os.environ.get("ASTRID_V33_ACTIVATION")
                os.environ["ASTRID_V33_ACTIVATION"] = record["operation_id"]
                try:
                    result = _start_operation(paths, boundary, config, journal["operation_id"])
                    verification = _verify_running(paths, boundary, result, timeout_seconds=timeout_seconds)
                finally:
                    if prior_token is None:
                        os.environ.pop("ASTRID_V33_ACTIVATION", None)
                    else:
                        os.environ["ASTRID_V33_ACTIVATION"] = prior_token
                record = records.read_record(archive / "activation.json")
                if not record.get("provider_verified"):
                    raise OperatorUpgradeError("candidate did not freshly verify its Timeline provider/baseline inventory")
                custody_lifecycle.phase(realm_root, archive, record, "ready")
                _journal(paths, operation_id=journal["operation_id"], state="complete", verification=verification)
                return {"ok": True, "state": "complete", "operation_id": journal["operation_id"], "verification": verification}
        _stop_selected(paths, boundary, realm_id, realm_root, config)
        with _owner_fence(realm_root):
            prior_config = _restore_installation(paths, realm_root, archive) if archive else config
        if archive is not None:
            from runtime_protocol import v33_lifecycle as lifecycle
            record = lifecycle.read_record(archive / "activation.json")
            lifecycle.phase(archive, record, "restored", prior_launch_started=True)
        result = _start_operation(paths, boundary, prior_config, journal["operation_id"])
        verification = _verify_running(paths, boundary, result, timeout_seconds=timeout_seconds)
        _journal(paths, operation_id=journal["operation_id"], state="rolled_back", verification=verification)
        return {"ok": True, "state": "rolled_back", "operation_id": journal["operation_id"], "verification": verification}


def upgrade_workspace(
    paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig, *,
    destination: str | Path | None = None,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Own preflight → stop → recovery set → schema/backfill → verified startup."""
    from runtime_protocol import v33_lifecycle as lifecycle
    if config.profile != "astrid":
        raise OperatorUpgradeError("only the astrid profile is supported")
    if not hasattr(boundary, "prepare_restart") or not hasattr(boundary, "stop_owner"):
        raise OperatorUpgradeError("runtime boundary lacks the birth-checked stop handoff")
    from .bootstrap import _validate_support_paths
    _validate_support_paths(paths)
    realm_id, realm_root = _realm_from_catalog(paths)
    config.resolve_source_profile(paths)
    _reject_live_pack_host(paths)
    try:
        identity = inspect_realm_schema(realm_root, expected_realm_id=realm_id)
    except Exception as exc:
        raise OperatorUpgradeError(str(exc)) from exc
    if int(identity['version']) < 33:
        raise OperatorUpgradeError(
            'finish the separate round-1b U33 activation with its owning Runtime before custody upgrade',
            details={'reason': 'round1b_activation_required',
                     'next_action': 'finish_v33_activation_then_migrate_v34'})
    kind = _schema_kind(realm_root, expected_realm_id=realm_id)
    custody_upgrade = int(identity["version"]) >= 33
    idle = _assert_idle(realm_root)
    operation_id = uuid.uuid4().hex
    archive = None
    stopped = False
    migration = None
    with _bootstrap_mutex(paths), _installer_mutex(paths):
        if _realm_from_catalog(paths) != (realm_id, realm_root):
            raise OperatorUpgradeError("selected realm changed after preflight")
        prior_journal = _read_support_json(paths.runtime_support / "upgrade-journal.json")
        if prior_journal and prior_journal.get("state") not in {"complete", "rolled_back", "failed"}:
            raise OperatorUpgradeError("an upgrade operation is already in progress or needs recovery: " + str(prior_journal.get("operation_id")))
        _journal(paths, operation_id=operation_id, state="planned", realm_id=realm_id,
                 source_support_root=str(paths.app_support), realm_root=str(realm_root), schema_before=kind)
        try:
            _journal(paths, operation_id=operation_id, state="stopping", idle=idle)
            _stop_selected(paths, boundary, realm_id, realm_root, config)
            stopped = True
            _journal(paths, operation_id=operation_id, state="stopped", idle=idle)
            with _owner_fence(realm_root), lifecycle.sqlite_observation(realm_root) as original_sqlite:
                # Reclassify while holding BOTH admission and lifetime fences and
                # SQLite's writer lock; a stale detached preflight never authorizes DDL.
                connection = sqlite3.connect(realm_root / "realm.sqlite3", timeout=timeout_seconds)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    from runtime_protocol.v33_manifest import canonical_manifest, legacy_manifest
                    current = (legacy_manifest if identity["version"] == 23 else canonical_manifest)(connection, expected_realm_id=realm_id)
                    stat_now = (realm_root / "realm.sqlite3").stat()
                    if (current["fingerprint"] != identity["fingerprint"] or
                            (stat_now.st_dev, stat_now.st_ino) != identity["source_file_identity"][:2]):
                        raise OperatorUpgradeError("realm changed between preflight and exclusive ownership")
                    if custody_upgrade:
                        from runtime_protocol import v34_lifecycle as custody_lifecycle
                        previous = lifecycle.activation(realm_root)
                        if previous and previous[1]["state"] != "ready":
                            raise OperatorUpgradeError("complete the prior round-1b activation before custody migration")
                        archive, record = custody_lifecycle.begin(realm_root, identity, original_sqlite)
                    else:
                        archive, record = lifecycle.begin(realm_root, identity, sqlite_image=original_sqlite,
                            recovery_root=paths.app_support.parent / ".astrid-v33-recovery" / operation_id)
                    _capture_installation(paths, archive, record)
                    lifecycle.phase(archive, record, record["state"], target_profile=config.resolve_source_profile(paths).as_dict())
                    _journal(paths, operation_id=operation_id, state="backup_verified", recovery_set=str(archive))
                finally:
                    connection.close()
                if kind == "v23":
                    migration = upgrade_realm(realm_root, timeout_seconds=timeout_seconds,
                        confirmation=f"UPGRADE {realm_id}", retain_backup=True, archive_root=realm_root.parent / "v23-archives")
                else:
                    migration = migrate_canonical_to_current(realm_root, timeout_seconds=timeout_seconds,
                        confirmation=f"MIGRATE CANONICAL {realm_id}", expected_realm_id=realm_id)
            if custody_upgrade:
                # Admission opens only after the committed V34 schema and its
                # full recovery set have been independently verified offline.
                from runtime_protocol import v34_lifecycle as custody_lifecycle
                custody_lifecycle.activate(realm_root, admit=False)
            _journal(paths, operation_id=operation_id, state="activated", migration=migration)
            # Persistent marker restricts custody transfer to this operation.
            previous_token = os.environ.get("ASTRID_V33_ACTIVATION")
            os.environ["ASTRID_V33_ACTIVATION"] = record["operation_id"]
            try:
                result = _start_operation(paths, boundary, config, operation_id)
                verification = _verify_running(paths, boundary, result, timeout_seconds=timeout_seconds)
            finally:
                if previous_token is None:
                    os.environ.pop("ASTRID_V33_ACTIVATION", None)
                else:
                    os.environ["ASTRID_V33_ACTIVATION"] = previous_token
            # A real service must verify/register its provider before activation.
            record = lifecycle.read_record(archive / "activation.json")
            if record["state"] not in ({"activation_verified", "ready"} if custody_upgrade else {"provider_verified", "ready"}):
                raise OperatorUpgradeError("candidate did not verify its Timeline provider/baseline inventory")
            if custody_upgrade:
                if not record.get("provider_verified"):
                    raise OperatorUpgradeError("candidate did not freshly verify its Timeline provider/baseline inventory")
                custody_lifecycle.phase(realm_root, archive, record, "ready")
            else:
                lifecycle.phase(archive, record, "ready", ready_at=now())
            _journal(paths, operation_id=operation_id, state="restarted", migration=migration, verification=verification)
            _journal(paths, operation_id=operation_id, state="complete", migration=migration, verification=verification)
        except Exception as exc:
            recovery_error = None
            restored = False
            try:
                if stopped and archive is not None:
                    _stop_selected(paths, boundary, realm_id, realm_root, config)
                    with _owner_fence(realm_root):
                        prior_config = _restore_installation(paths, realm_root, archive)
                    record = lifecycle.read_record(archive / "activation.json")
                    lifecycle.phase(archive, record, "restored", prior_launch_started=True)
                    result = _start_operation(paths, boundary, prior_config, operation_id)
                    _verify_running(paths, boundary, result, timeout_seconds=timeout_seconds)
                    restored = True
            except Exception as recovery_exc:
                recovery_error = str(recovery_exc)
            _journal(paths, operation_id=operation_id, state="rolled_back" if restored else "recovery_required",
                     error=str(exc), recovery_error=recovery_error)
            message, details = refusal_from(exc)
            raise OperatorUpgradeError(message, details=details if isinstance(details, Mapping) else None) from exc
    relocation_result = None
    if destination is not None:
        relocation_result = relocate(paths, boundary, config, None, destination=destination, confirmation=f"RELOCATE {realm_id}")
    return {"ok": True, "operation_id": operation_id, "realm_id": realm_id, "schema_before": kind,
            "migration": migration, "verification": verification, "recovery_set": str(archive), "relocation": relocation_result}


__all__ = ["OperatorUpgradeError", "upgrade_workspace", "recover_workspace"]
