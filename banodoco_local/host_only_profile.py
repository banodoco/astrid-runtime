"""Provision the existing CPU Host selection from this installed environment.

This describes a selection only. Runtime preparation and activation still belong
to the retained owner and are never produced by setup.
"""
from __future__ import annotations

import csv
import hashlib
import importlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import sys
import sysconfig
import tempfile
from typing import Any, Mapping

from .bootstrap import BootstrapError, SourceProfile, _validate_source_profile
from .io import atomic_write_json
from runtime_protocol.local_worker import _selected_profile_payload
from runtime_protocol.local_worker_composition import (
    _actual_executable, _owner_machine_id, _pack_inventory, _installed_record_bytes,
    _verify_installed_host_records, load_local_worker_composition,
)
from runtime_protocol.verified_host_launch import (
    CURRENT_ROLES_VERSION, HOST_MODULE, raw_digest, source_checkout_closure, installed_host_closure,
    HOST_DISTRIBUTIONS,
)

PRODUCER_VERSION = "host-only-installed/v1"
_PACKAGES = {
    "astrid": ("astrid", "banodoco_workspace_client"),
    "banodoco-workspace-runtime": ("banodoco_local", "runtime_protocol"),
}


def _path(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise BootstrapError("profile setup paths must be canonical absolute paths")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise BootstrapError("profile setup paths must be symlink-free")
    return path


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _installed_inputs() -> tuple[Path, dict[str, Any]]:
    """Observe metadata AND import origins; never infer an install from a path."""
    root = _path(sysconfig.get_path("purelib"))
    if not root.is_relative_to(Path(sys.prefix)) or not root.is_dir():
        raise BootstrapError("installed package root is outside the selected environment")
    for name, modules in _PACKAGES.items():
        dist = metadata.distribution(name)
        if Path(dist.locate_file("")).resolve() != root:
            raise BootstrapError("packages must share the selected installed root")
        direct = dist.read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable"):
            raise BootstrapError("editable installs cannot produce a Host profile")
        record = dist.read_text("RECORD")
        if not record:
            raise BootstrapError("installed package has no RECORD")
        rows = {str(Path(dist.locate_file(row[0])).resolve()): row[1]
                for row in csv.reader(record.splitlines())}
        if name == "astrid":
            for relative in ("schemas/astrid-intent/astrid-intent.schema.json",
                             "astrid/core/rendering/schemas/v1/plan.json",
                             "astrid/packs/rendering/pack.yaml"):
                resource = _path(root / relative)
                if not resource.is_file() or not rows.get(str(resource), "").startswith("sha256="):
                    raise BootstrapError("required installed resource is missing from RECORD")
        for module_name in modules:
            module = importlib.import_module(module_name)
            origin = _path(str(module.__file__))
            package = root / module_name
            if origin != package / "__init__.py":
                raise BootstrapError("raw or mixed package import origin")
            # RECORD coverage matters as well as hashes: a removed row must
            # not turn an installed source/resource into an unverified input.
            for file in package.rglob("*"):
                _path(file)
                if file.is_file() and "__pycache__" not in file.parts and file.suffix not in {".pyc", ".pyo"}:
                    if not rows.get(str(file), "").startswith("sha256="):
                        raise BootstrapError("installed package file is missing from RECORD")
        _installed_record_bytes(dist)
    closure = installed_host_closure(root)
    for name, modules in HOST_DISTRIBUTIONS.items():
        if name in _PACKAGES:
            continue
        for module_name in modules:
            if module_name == "_yaml":
                continue  # optional native compatibility package, still covered
            module = importlib.import_module(module_name.removesuffix(".py"))
            expected = root / module_name if module_name.endswith(".py") else root / module_name / "__init__.py"
            if _path(str(module.__file__)) != expected:
                raise BootstrapError("raw or mixed Host dependency import origin")
    return root, closure["distributions"]


def _boot_inputs():
    from astrid.packs.shots.conformance import VIBE_PROFILE_REGISTRY, vibe_profile_specs
    return VIBE_PROFILE_REGISTRY, vibe_profile_specs()


def _identity(raw: Mapping[str, Any], *, workspace_uuid: str, realm_root: Path,
              support_root: Path) -> tuple[str, str]:
    selection = {k: v for k, v in raw.items() if k not in {"profile_revision", "profile_digest"}}
    matrix = raw["capability_matrix"]
    payload = {"producer": PRODUCER_VERSION, "selection": selection,
               "workspace_uuid": workspace_uuid, "realm_root": str(realm_root),
               "support_root": str(support_root),
               "capability_matrix_digest": _hash(_path(matrix)) if matrix else None}
    revision = PRODUCER_VERSION + ":" + raw_digest(payload)
    return revision, "sha256:" + raw_digest({"revision": revision, "inputs": payload})


def qualify_host_only_profile(path: Path | str, *, workspace_uuid: str,
                              realm_root: Path, support_root: Path):
    """Generator-to-loader qualification, without starting any service/process.

    Existing loaders validate the typed selection. These setup checks also
    measure the installed inputs that the retained launch independently checks.
    """
    path = _path(path); realm_root = _path(realm_root); support_root = _path(support_root)
    composition = load_local_worker_composition(path, workspace_uuid=workspace_uuid,
        realm_root=realm_root, support_root=support_root, runtime_instance_id="setup-qualification")
    raw = json.loads(path.read_text())
    if raw.get("execution_mode") != "host_only_cpu":
        raise BootstrapError("setup requires host_only_cpu")
    profile = composition.profiles[raw["profile_id"]]
    _selected_profile_payload(profile)
    root, _ = _installed_inputs()
    if raw["source_checkout"] != str(root) or raw["pack_root"] != str(root / "astrid" / "packs"):
        raise BootstrapError("profile source/pack root differs from installed packages")
    _verify_installed_host_records(profile, profile.host_launch)
    if (raw["host_artifact_digest"] != _hash(Path(sys.executable))
            or raw["host_os_executable"] != str(_actual_executable(os.getpid()))
            or raw["host_os_artifact_digest"] != _hash(_actual_executable(os.getpid()))):
        raise BootstrapError("selected interpreter/kernel artifact differs")
    if raw["machine_id"] != _owner_machine_id():
        raise BootstrapError("selected machine differs")
    if raw["host_protocol"]["source_closure_digest"] != source_checkout_closure(root)["digest"]:
        raise BootstrapError("selected source closure differs")
    for extra in raw.get("additional_pack_roots", []):
        if _pack_inventory(extra["path"]) != extra["files"]:
            raise BootstrapError("additional pack inventory differs")
    from astrid.core._shared.boot_manifest import (
        build_manifest, load_boot_manifest_hash, manifest_hash, normalize_sha256_digest,
    )
    registry, fixtures = _boot_inputs()
    boot_hash = "sha256:" + normalize_sha256_digest(load_boot_manifest_hash(raw["boot_manifest_path"], support_root=support_root))
    current_hash = "sha256:" + normalize_sha256_digest(manifest_hash(build_manifest(registry=registry, fixtures=fixtures)))
    if raw["boot_manifest_hash"] != boot_hash or boot_hash != current_hash:
        raise BootstrapError("selected boot manifest differs from installed registry/fixtures")
    revision, digest = _identity(raw, workspace_uuid=workspace_uuid, realm_root=realm_root, support_root=support_root)
    if (raw["profile_revision"], raw["profile_digest"]) != (revision, digest):
        raise BootstrapError("generated profile identity differs")
    return composition


def provision_host_only_profile(*, worker_profile: Path, source_manifest: Path,
                               workspace_uuid: str, realm_root: Path, support_root: Path,
                               max_concurrency: int, capability_matrix: Path | None,
                               environment: Mapping[str, str] | None = None,
                               additional_pack_roots: tuple[Path, ...] = (), renderer_selection=None) -> SourceProfile:
    """Atomically provision a private worker profile and existing SourceProfile.

    Run with the selected installed Runtime interpreter. No checkout/environment
    override is accepted. None explicitly selects an empty capability matrix.
    """
    worker_profile = _path(worker_profile); source_manifest = _path(source_manifest)
    realm_root = _path(realm_root); support_root = _path(support_root)
    if not isinstance(workspace_uuid, str) or not workspace_uuid.strip():
        raise BootstrapError("workspace identity must be explicitly selected")
    if not worker_profile.is_relative_to(support_root) or not source_manifest.is_relative_to(support_root):
        raise BootstrapError("profile outputs must be within the selected support root")
    if len({worker_profile, source_manifest, support_root / "boot-manifest.json"}) != 3:
        raise BootstrapError("profile outputs must be distinct")
    if type(max_concurrency) is not int or not 1 <= max_concurrency <= 16:
        raise BootstrapError("Host concurrency must be explicitly bounded")
    root, records = _installed_inputs()
    if capability_matrix is not None:
        capability_matrix = _path(capability_matrix)
        from astrid.core.execution.capability_ledger import load_capability_ledger
        load_capability_ledger(capability_matrix)
    support_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if support_root.stat().st_uid != os.getuid() or support_root.stat().st_mode & 0o077:
        raise BootstrapError("profile support root must be private and owner-controlled")
    registry, fixtures = _boot_inputs()
    from astrid.core._shared.boot_manifest import stamp_boot_manifest, manifest_hash, normalize_sha256_digest
    boot = support_root / "boot-manifest.json"
    manifest = stamp_boot_manifest(boot, support_root=support_root, registry=registry, fixtures=fixtures)
    launch = {"source_checkout": str(root), "pack_root": str(root / "astrid" / "packs"),
              "boot_manifest_path": str(boot), "boot_manifest_hash": "sha256:" + normalize_sha256_digest(manifest_hash(manifest)),
              "capability_matrix": str(capability_matrix) if capability_matrix else None,
              "environment": dict(environment or {}), "max_concurrency": max_concurrency}
    if renderer_selection is not None:
        from astrid.core.execution.host_renderer_selection import HostRendererSelection
        if type(renderer_selection) is not HostRendererSelection:
            raise BootstrapError("renderer setup requires an already admitted typed selection")
        launch["renderer_selection"] = renderer_selection.payload()
    if additional_pack_roots:
        launch["additional_pack_roots"] = [{"path": str(_path(p)), "files": _pack_inventory(p)} for p in additional_pack_roots]
    kernel = _actual_executable(os.getpid())
    raw = {**launch, "execution_mode": "host_only_cpu", "profile_id": "astrid", "machine_id": _owner_machine_id(),
           "host_executable": os.path.abspath(sys.executable), "host_artifact_digest": _hash(Path(sys.executable)),
           "host_os_executable": str(kernel), "host_os_artifact_digest": _hash(kernel),
           "release_digest": "sha256:" + raw_digest(records), "session_config_digest": "sha256:" + raw_digest(launch),
           "host_protocol": {"version": CURRENT_ROLES_VERSION, "module": HOST_MODULE,
                             "source_closure_digest": source_checkout_closure(root)["digest"]}}
    raw["profile_revision"], raw["profile_digest"] = _identity(raw, workspace_uuid=workspace_uuid, realm_root=realm_root, support_root=support_root)
    worker_profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".host-profile-", dir=worker_profile.parent) as temporary:
        candidate = Path(temporary) / "profile.json"
        atomic_write_json(candidate, raw)
        qualify_host_only_profile(candidate, workspace_uuid=workspace_uuid, realm_root=realm_root, support_root=support_root)
        atomic_write_json(worker_profile, raw)
    source = SourceProfile(profile="astrid", runtime_checkout=str(root), source_checkout=str(root),
                           runtime_environment=str(Path(sys.prefix)), worker_profile=str(worker_profile),
                           capability_digest=_hash(capability_matrix) if capability_matrix else "",
                           source_digest="sha256:" + raw["host_protocol"]["source_closure_digest"])
    _validate_source_profile(source)
    atomic_write_json(source_manifest, source.as_dict())
    return source
