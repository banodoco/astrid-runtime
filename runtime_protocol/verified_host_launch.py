"""Private, trusted launch verification and isolated source loader.

This file is also a standalone stdlib-only launcher. It does not import Runtime
or Astrid at bootstrap. No production release is selected by default. The
strict provider requires protection; the explicitly injected trusted-local
provider measures a reviewed installation without hostile-writer assurance. Profile/host/manifest claims cannot
create a retained verified result.
"""
from __future__ import annotations

import hashlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading

CURRENT_ROLES_VERSION = "runtime.local-execution-current-roles/v1"
HOST_MODULE = "astrid.core.execution.generic_host"
MODE = "isolated-source/v1"
TRUSTED_LOCAL_MODE = "trusted-local-isolated-source/v1"
LIMIT = 64 * 1024 * 1024
ENV_KEYS = frozenset({"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "XDG_RUNTIME_DIR", "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "ASTRID_EXECUTION_TARGET_JSON"})
_COMPONENTS = {
    "host": "astrid/core/execution/generic_host.py", "core": "astrid/core",
    "sdk": "astrid/sdk", "launcher": "astrid/omp_agent.py",
    "astrid_entrypoint": "astrid/__init__.py", "astrid_version": "astrid/version.py",
    "astrid_main": "astrid/__main__.py", "astrid_runtime_cli": "astrid/runtime_cli.py",
    "vendored_workspace_client": "astrid_runtime_client",
}


class HostLaunchError(RuntimeError):
    """Selection or retained import authority is unresolved."""


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise HostLaunchError("invalid import binding JSON") from exc


def raw_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _raw(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_host_protocol(value):
    if (not isinstance(value, dict) or set(value) != {"version", "module", "source_closure_digest"}
            or value["version"] != CURRENT_ROLES_VERSION or value["module"] != HOST_MODULE
            or not _raw(value["source_closure_digest"])):
        raise HostLaunchError("selected host_protocol shape/version/module/closure is invalid")
    return json.loads(canonical(value))


def _absolute(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise HostLaunchError("import binding path is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise HostLaunchError("import binding path is not canonical absolute")
    return path


def _no_alias(path):
    # This bounded mode disallows aliases even where they stay within a root.
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise HostLaunchError("import materialization contains a symlink")


def read_source(path, expected):
    """Read once with no-follow and stable inode, returning the verified bytes."""
    path = _absolute(str(path)); _no_alias(path)
    if not _raw(expected):
        raise HostLaunchError("import source pin is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
            raise HostLaunchError("import source is not a bounded regular file")
        data = bytearray()
        while True:
            part = os.read(descriptor, min(1024 * 1024, LIMIT + 1 - len(data)))
            if not part: break
            data.extend(part)
            if len(data) > LIMIT: raise HostLaunchError("import source exceeds its bound")
        after = os.fstat(descriptor); current = path.stat(follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise HostLaunchError("import source changed while being read")
        data = bytes(data)
        if hashlib.sha256(data).hexdigest() != expected:
            raise HostLaunchError("import source differs from its reviewed pin")
        return data
    finally:
        os.close(descriptor)


def source_checkout_closure(checkout):
    """Independent parity implementation; never imports the selected host."""
    root = _absolute(str(checkout)); _no_alias(root)
    measured = []
    for name, relative in _COMPONENTS.items():
        path = root / relative
        _no_alias(path)
        if not path.exists(): raise HostLaunchError("source closure component is missing")
        if path.is_file():
            value = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            entries = []
            for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).parts):
                if child.is_symlink(): raise HostLaunchError("source closure contains a symlink")
                if child.is_file() and "__pycache__" not in child.parts:
                    entries.append((child.relative_to(path).as_posix(), hashlib.sha256(child.read_bytes()).hexdigest()))
            value = raw_digest(entries)
        measured.append({"component": name, "path": relative, "sha256": value})
    measured.sort(key=lambda entry: entry["component"])
    return {"schema_version": 1, "components": measured, "digest": raw_digest(measured)}


def _inventory(value):
    if not isinstance(value, dict) or set(value) != {"root", "files"}:
        raise HostLaunchError("reviewed inventory shape is invalid")
    root = _absolute(value["root"]); _no_alias(root)
    files = value["files"]
    if not isinstance(files, dict) or not files or len(files) > 200000:
        raise HostLaunchError("reviewed inventory file map is invalid")
    for relative, pin in files.items():
        path = Path(relative) if isinstance(relative, str) else None
        if (path is None or not relative or path.is_absolute() or ".." in path.parts
                or path.as_posix() != relative or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
                or not _raw(pin)):
            raise HostLaunchError("reviewed inventory has an unsupported file representation")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink(): raise HostLaunchError("reviewed inventory contains an alias")
        if path.is_file(): actual.add(path.relative_to(root).as_posix())
    if actual != set(files):
        raise HostLaunchError("materialized inventory has missing or unexpected files")
    for relative, pin in files.items(): read_source(root / relative, pin)
    return json.loads(canonical(value))


def _mapping(import_roots, inventories, runtime_inventory, *, trusted_local=False):
    mapping = {}; runtime_root = Path(runtime_inventory["root"])
    source_root = Path(import_roots[0]["path"]) if import_roots else None
    for entry in import_roots:
        if not isinstance(entry, dict) or set(entry) != {"path", "inventory_digest"} or not _raw(entry["inventory_digest"]):
            raise HostLaunchError("ordered import root shape is invalid")
        inventory = inventories.get(entry["inventory_digest"])
        if inventory is None or entry["path"] != inventory["root"]:
            raise HostLaunchError("import root lacks independently retained inventory")
        root = _absolute(entry["path"])
        for relative, pin in inventory["files"].items():
            path = root / relative; parts = Path(relative).parts
            if path.suffix == ".py":
                package = path.name == "__init__.py"
                names = parts[:-1] if package else (*parts[:-1], path.stem)
                if not names or any(not part.isidentifier() for part in names): continue
                name = ".".join(names); kind = "source"
            else:
                suffix = next((s for s in importlib.machinery.EXTENSION_SUFFIXES if relative.endswith(s)), None)
                if suffix is None: continue
                names = (*parts[:-1], path.name[:-len(suffix)])
                if any(not part.isidentifier() for part in names): continue
                name = ".".join(names); package = False; kind = "extension"
                # Native code requires the externally protected runtime map;
                # source/dependency roots cannot smuggle native representations.
                if not trusted_local and (not path.is_relative_to(runtime_root) or runtime_inventory["files"].get(path.relative_to(runtime_root).as_posix()) != pin):
                    raise HostLaunchError("native dependency is outside protected Python runtime inventory")
            if trusted_local and name.split('.')[0] in {"astrid", "astrid_runtime_client"} and root != source_root:
                # These selected namespaces are closed over the first, exact
                # installed host root. An older site copy cannot fill gaps.
                continue
            if name in mapping:
                previous = mapping[name]
                if trusted_local:
                    # Retain one explicit origin using reviewed root order.
                    # In a single directory CPython prefers a native module to
                    # its Python implementation; neither remains a fallback.
                    if (kind == "extension" and previous["kind"] == "source"
                            and Path(previous["path"]).parent == path.parent):
                        mapping[name] = {"path": str(path), "sha256": pin, "package": package, "kind": kind}
                    continue
                raise HostLaunchError("import mapping has duplicate module origins")
            mapping[name] = {"path": str(path), "sha256": pin, "package": package, "kind": kind}
    for name, item in list(mapping.items()):
        for length in range(1, len(name.split('.'))):
            ancestor = ".".join(name.split('.')[:length])
            if ancestor not in mapping and trusted_local:
                # Explicit directories derived solely from this retained file
                # inventory; ambient namespace discovery remains disabled.
                child = Path(item["path"])
                directory = child.parent
                for _ in range(len(name.split('.')) - length - (0 if item["package"] else 1)):
                    directory = directory.parent
                mapping[ancestor] = {"path": str(directory), "sha256": None,
                                     "package": True, "kind": "namespace"}
            if ancestor not in mapping or not mapping[ancestor]["package"]:
                raise HostLaunchError("namespace/package initializer is not mapped")
    if HOST_MODULE not in mapping or mapping[HOST_MODULE]["package"]:
        raise HostLaunchError("selected GenericHost module is not mapped")
    return mapping


def _distribution_metadata(import_roots, inventories):
    """Bind installed metadata from reviewed roots, never ambient discovery."""
    result = []
    names = set()
    for entry in import_roots:
        inventory = inventories[entry["inventory_digest"]]
        root = _absolute(entry["path"])
        directories = sorted({Path(relative).parts[0] for relative in inventory["files"]
            if len(Path(relative).parts) > 1 and Path(relative).parts[0].endswith(".dist-info")})
        distributions = []
        for directory in directories:
            relative = directory + "/METADATA"
            if relative not in inventory["files"]:
                raise HostLaunchError("reviewed distribution has no pinned METADATA")
            candidate = _MappedDistribution(root, directory, inventory["files"])
            name = candidate.metadata["Name"]
            if not name or not candidate.version:
                raise HostLaunchError("reviewed distribution identity is incomplete")
            normalized = re.sub(r"[-_.]+", "-", name).lower()
            if normalized in {"astrid", "astrid-runtime-client"} and str(root) != import_roots[0]["path"]:
                raise HostLaunchError("selected distribution is outside the selected host root")
            if normalized in names:
                raise HostLaunchError("reviewed distribution has duplicate origins")
            names.add(normalized)
            distributions.append({"directory": directory, "name": normalized})
        if distributions:
            result.append({"root": str(root), "files": inventory["files"],
                           "distributions": distributions})
    return result


class _VerifiedLaunch:
    __slots__ = ("_issuer", "_key")
    def __init__(self, issuer, key): self._issuer, self._key = issuer, key
    def __reduce__(self): raise TypeError("verified launches cannot be serialized")


class HostLaunchVerifier:
    """Trusted caller injection, with no default release/materialization authority.

    Resolver and protection checker are trusted code, not profile-supplied paths
    or self-advertised host responses. Tests inject explicitly fake authorities.
    A protection lease must cover executable startup/native and source files
    until the retained child has exited; a hash observation cannot replace it.
    """
    _mode = MODE
    _read = staticmethod(read_source)
    _inventory = staticmethod(_inventory)

    def _import_mapping(self, roots, inventories, runtime):
        return _mapping(roots, inventories, runtime)

    def _runtime_relative(self, interpreter, runtime):
        root = Path(runtime["root"])
        if not interpreter.is_relative_to(root):
            raise HostLaunchError("selected interpreter is outside protected runtime")
        return interpreter.relative_to(root).as_posix()

    def _observation(self, record, profile):
        return self._protection(json.loads(canonical(record)))

    def __init__(self, *, authority_resolver=None, protected_materialization=None):
        self._resolver = authority_resolver
        self._protection = protected_materialization
        self._issued = {}
        self._lock = threading.RLock()

    def _validate_environment(self, profile, config, environment):
        if (not isinstance(environment, dict) or set(environment) - ENV_KEYS
                or any(not isinstance(v, str) or "\0" in v for v in environment.values())):
            raise HostLaunchError("isolated host environment contains import overrides or invalid values")

    def verify(self, *, preparation, config, host_argv, environment):
        profile = preparation["profile"]
        protocol = validate_host_protocol(profile.get("host_protocol"))
        if self._resolver is None or self._protection is None:
            raise HostLaunchError("no independently reviewed installed host authority is selected")
        record = json.loads(canonical(self._resolver(json.loads(canonical(profile)))))
        if not isinstance(record, dict):
            raise HostLaunchError("trusted resolver returned no reviewed release")
        required = {"selected_profile_digest", "profile_digest", "release_digest", "host_protocol", "source_checkout", "source_components", "import_binding", "inventories"}
        if (set(record) != required or record["selected_profile_digest"] != raw_digest(profile)
                or any(record[k] != profile[k] for k in ("profile_digest", "release_digest"))
                or canonical(record["host_protocol"]) != canonical(protocol)
                or record["source_checkout"] != config["source_checkout"]):
            raise HostLaunchError("reviewed release differs from retained profile/protocol/source")
        # Reject invalid launch input before walking the selected installation.
        # The independently retained release/profile equality above still comes
        # first; this check cannot establish launch authority by itself.
        self._validate_environment(profile, config, environment)
        binding = record["import_binding"]
        if (not isinstance(binding, dict) or set(binding) != {"schema_version", "mode", "launcher", "python_runtime_inventory_digest", "import_roots"}
                or type(binding["schema_version"]) is not int or binding["schema_version"] != 1 or binding["mode"] != self._mode
                or not isinstance(binding["launcher"], dict) or set(binding["launcher"]) != {"path", "sha256"}
                or not _raw(binding["python_runtime_inventory_digest"]) or not isinstance(binding["import_roots"], list)
                or not binding["import_roots"]):
            raise HostLaunchError("reviewed isolated import binding is invalid")
        if not isinstance(record["inventories"], dict): raise HostLaunchError("reviewed inventories are invalid")
        # External protection comes BEFORE measurement and remains retained.
        lease = self._observation(record, profile)
        if lease is None or not callable(getattr(lease, "verify", None)):
            raise HostLaunchError("materialization protection is not independently retained")
        lease.verify()
        inventories = {}
        for identity, candidate in record["inventories"].items():
            if not _raw(identity) or raw_digest(candidate) != identity:
                raise HostLaunchError("reviewed inventory digest mismatch")
            inventories[identity] = self._inventory(candidate)
        runtime = inventories.get(binding["python_runtime_inventory_digest"])
        if runtime is None: raise HostLaunchError("Python runtime inventory is missing")
        interpreter = _absolute(profile["host_executable"])
        interpreter_pin = runtime["files"].get(self._runtime_relative(interpreter, runtime))
        if not interpreter_pin or profile["host_artifact_digest"] != "sha256:" + interpreter_pin:
            raise HostLaunchError("selected interpreter pin differs from reviewed runtime")
        self._read(interpreter, interpreter_pin)
        if "host_os_executable" in profile:
            kernel_path = _absolute(profile["host_os_executable"])
            kernel_pin = runtime["files"].get(self._runtime_relative(kernel_path, runtime))
            if not kernel_pin or profile.get("host_os_artifact_digest") != "sha256:" + kernel_pin:
                raise HostLaunchError("selected kernel interpreter pin differs from reviewed runtime")
            self._read(kernel_path, kernel_pin)
        launcher = binding["launcher"]
        self._read(_absolute(launcher["path"]), launcher["sha256"])
        closure = source_checkout_closure(config["source_checkout"])
        if closure["digest"] != protocol["source_closure_digest"] or canonical(closure["components"]) != canonical(record["source_components"]):
            raise HostLaunchError("materialized source closure differs from reviewed components")
        mapping = self._import_mapping(binding["import_roots"], inventories, runtime)
        expected_host = str(Path(config["source_checkout"]) / "astrid/core/execution/generic_host.py")
        if mapping[HOST_MODULE]["path"] != expected_host:
            raise HostLaunchError("actual GenericHost mapping differs from supplied checkout")
        source_inventory = next((inventories[e["inventory_digest"]] for e in binding["import_roots"] if e["path"] == config["source_checkout"]), None)
        if source_inventory is None: raise HostLaunchError("source checkout has no retained import inventory")
        if host_argv[:3] != [str(interpreter), "-m", HOST_MODULE]:
            raise HostLaunchError("selected host argv module/interpreter is invalid")
        argv_tail = list(host_argv[3:]) + ["--source-closure-digest", protocol["source_closure_digest"]]
        payload = {"schema_version": 1, "mode": self._mode, "module": HOST_MODULE, "mapping": mapping, "host_argv": argv_tail}
        if self._mode == TRUSTED_LOCAL_MODE:
            payload["distribution_metadata"] = _distribution_metadata(binding["import_roots"], inventories)
        if len(canonical(payload)) > LIMIT: raise HostLaunchError("retained launcher binding exceeds its bound")
        context = {"preparation": preparation, "config": config, "host_argv": host_argv, "environment": environment}
        lease.verify()
        result = _VerifiedLaunch(self, object())
        with self._lock:
            self._issued[result._key] = {"context": canonical(context), "payload": canonical(payload), "launcher": dict(launcher), "lease": lease, "record": record, "state": "verified", "protocol": protocol["version"]}
        return result

    def claim(self, result, *, preparation, config, host_argv, environment, binding_fd):
        """Consume once for this exact launch, before spawning or any v2 traffic."""
        with self._lock:
            if type(result) is not _VerifiedLaunch or result._issuer is not self or result._key not in self._issued:
                raise HostLaunchError("launch proof is not this verifier's retained result")
            record = self._issued[result._key]
            if record["state"] != "verified": raise HostLaunchError("launch proof was already attempted")
            record["state"] = "failed"
            context = {"preparation": preparation, "config": config, "host_argv": host_argv, "environment": environment}
            if canonical(context) != record["context"] or type(binding_fd) is not int or binding_fd < 0:
                raise HostLaunchError("launch changed after verification")
            record["lease"].verify()
            self._read(Path(record["launcher"]["path"]), record["launcher"]["sha256"])
            record["state"] = "claimed"
            return ([host_argv[0], "-X", "utf8", "-I", "-S", record["launcher"]["path"], "--binding-fd", str(binding_fd)], record["payload"])

    def bind_child(self, result, *, child, identity):
        with self._lock:
            if type(result) is not _VerifiedLaunch or result._issuer is not self or result._key not in self._issued:
                raise HostLaunchError("child lacks retained verified launch")
            record = self._issued[result._key]
            if record["state"] != "claimed":
                raise HostLaunchError("verified launch child identity is invalid or reused")
            record["state"] = "failed"
            if type(identity.get("pid")) is not int or identity["pid"] != child.pid or not identity.get("birth_id"):
                raise HostLaunchError("verified launch child identity is invalid or reused")
            record["lease"].verify(); record.update(state="bound", child=child, identity=canonical(identity))
            return record["protocol"]

    def verify_child(self, result, *, child, identity):
        with self._lock:
            record = self._issued.get(result._key) if type(result) is _VerifiedLaunch and result._issuer is self else None
            if record is None or record["state"] != "bound":
                raise HostLaunchError("verified launch child/session binding changed")
            if record["child"] is not child or record["identity"] != canonical(identity):
                record["state"] = "failed"
                raise HostLaunchError("verified launch child/session binding changed")
            try:
                record["lease"].verify()
            except BaseException:
                record["state"] = "failed"
                raise


INVENTORY_MEMBER_LIMIT = 2 * 1024 * 1024 * 1024


def _stream_member_digest(path, expected):
    """Verify one inventory member by streaming sha256; never accumulates bytes.

    Same no-follow and stable-inode checks as read_source, but the bound is the
    inventory sanity bound, not the 64 MiB import-source bound.
    """
    path = _absolute(str(path)); _no_alias(path)
    if not _raw(expected):
        raise HostLaunchError("installed inventory pin is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > INVENTORY_MEMBER_LIMIT:
            raise HostLaunchError("installed inventory member is not a bounded regular file")
        digest = hashlib.sha256(); total = 0
        while True:
            part = os.read(descriptor, 1024 * 1024)
            if not part: break
            total += len(part)
            if total > INVENTORY_MEMBER_LIMIT:
                raise HostLaunchError("installed inventory member exceeds its bound")
            digest.update(part)
        after = os.fstat(descriptor); current = path.stat(follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise HostLaunchError("installed inventory member changed while being read")
        if digest.hexdigest() != expected:
            raise HostLaunchError("installed inventory member differs from its reviewed pin")
    finally:
        os.close(descriptor)


def _sha256_file(path):
    """Chunked sha256 for the installed-inventory measurement (no whole-file read)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def _local_member_digest(path, expected):
    """Inventory member check: same path resolution as _local_read, streamed digest."""
    return _stream_member_digest(_absolute(str(Path(path).resolve(strict=True))), expected)


def _local_read(path, expected):
    """Observe the selected installation, allowing its recorded Python aliases.

    This is a version/hash check, not protection against a hostile same-user
    writer between checks or native loading. Source compilation still consumes
    the verified bytes themselves. No chmod/hash is called tamper prevention.
    """
    return read_source(_absolute(str(Path(path).resolve(strict=True))), expected)


def installed_inventory(root):
    """Exact installed non-bytecode inventory, for trusted caller review.

    Bytecode is excluded because the isolated launcher never uses it. .pth and
    other data remain inventoried, but site startup never executes .pth files.
    Calling this measurement does not adopt the resulting record.
    """
    root = _absolute(str(root))
    files = {}; aliases = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).parts):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            aliases[path.relative_to(root).as_posix()] = {"target": os.readlink(path),
                "kind": "file" if path.is_file() else "directory" if path.is_dir() else "broken"}
        if path.is_file():
            files[path.relative_to(root).as_posix()] = _sha256_file(path)
    # rglob does not traverse directory aliases. Record their literal targets,
    # but never silently make their contents an import root. -S omits the
    # stdlib's ordinary aliased site directory in favor of the explicit roots.
    result = {"root": str(root), "files": files}
    if aliases: result["aliases"] = aliases
    return result


def _local_inventory(value):
    if (not isinstance(value, dict) or not {"root", "files"} <= set(value)
            or set(value) - {"root", "files", "aliases"}):
        raise HostLaunchError("installed inventory shape is invalid")
    root = _absolute(value["root"])
    if "aliases" in value and not isinstance(value["aliases"], dict):
        raise HostLaunchError("installed alias inventory is invalid")
    if not isinstance(value["files"], dict) or not value["files"] or len(value["files"]) > 200000:
        raise HostLaunchError("installed inventory file map is invalid")
    for relative, pin in value["files"].items():
        path = Path(relative) if isinstance(relative, str) else None
        if (path is None or not relative or path.is_absolute() or ".." in path.parts
                or path.as_posix() != relative or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"} or not _raw(pin)):
            raise HostLaunchError("installed inventory has an unsupported file representation")
        _local_member_digest(root / relative, pin)
    if installed_inventory(root) != value:
        raise HostLaunchError("installed inventory has missing, changed or unexpected files")
    return json.loads(canonical(value))


class _LocalInstallationObservation:
    """Retained launch observation; deliberately offers no protection lease."""
    def __init__(self, profile, launcher):
        self._pins = [(profile["host_executable"], profile["host_artifact_digest"][7:]),
                      (launcher["path"], launcher["sha256"])]
        if "host_os_executable" in profile:
            self._pins.append((profile["host_os_executable"], profile["host_os_artifact_digest"][7:]))
    def verify(self):
        for path, pin in self._pins:
            _local_read(path, pin)


class TrustedLocalHostLaunchVerifier(HostLaunchVerifier):
    """Explicit trusted single-user installed-release selection.

    Only trusted host composition supplies this reviewed constructor record;
    profile, task, environment and self-advertised host data cannot enable it.
    Actual process authentication/retained custody remains the session's job.
    This provider does not claim immutable source/native/OS or TOCTOU defense.
    The stricter HostLaunchVerifier remains separate and closed by default.
    """
    _mode = TRUSTED_LOCAL_MODE
    _read = staticmethod(_local_read)
    _inventory = staticmethod(_local_inventory)

    def __init__(self, *, installed_release):
        retained = json.loads(canonical(installed_release))
        self._installed_release = canonical(retained)
        super().__init__(authority_resolver=lambda _: json.loads(self._installed_release),
                         protected_materialization=lambda _: None)

    def _validate_environment(self, profile, config, environment):
        if profile.get("execution_mode") != "host_only_cpu":
            return super()._validate_environment(profile, config, environment)
        if not isinstance(environment, dict):
            raise HostLaunchError("host-only environment must be a mapping")
        support = _absolute(profile.get("support_root"))
        realm = _absolute(profile.get("realm_root"))
        expected = {"ASTRID_OUTPUT_ROOT": str(support / "host-output"),
                    "ASTRID_RUNTIME_DATA_ROOT": str(realm)}
        if config.get("support_root") != str(support) or any(environment.get(k) != v for k, v in expected.items()):
            raise HostLaunchError("host-only environment differs from selected owner roots")
        return super()._validate_environment(profile, config, {k: v for k, v in environment.items() if k not in expected})

    def _observation(self, record, profile):
        return _LocalInstallationObservation(profile, record["import_binding"]["launcher"])

    def _runtime_relative(self, interpreter, runtime):
        selected = interpreter.resolve(strict=True)
        root = Path(runtime["root"]).resolve(strict=True)
        if not selected.is_relative_to(root):
            raise HostLaunchError("selected installed interpreter is outside its recorded runtime")
        return selected.relative_to(root).as_posix()

    def _import_mapping(self, roots, inventories, runtime):
        return _mapping(roots, inventories, runtime, trusted_local=True)


class _SourceLoader(importlib.abc.Loader):
    def __init__(self, item, *, trusted_local=False):
        self.item = item
        self.path = item['path']
        self._trusted_local = trusted_local
        self._read = _local_read if trusted_local else read_source
    def create_module(self, spec): return None
    def get_resource_reader(self, fullname):
        if not self._trusted_local or not self.item['package']:
            return None
        # Standard data resources belong to the already inventoried selected
        # package. This is ordinary trusted-local file access, not a sandbox or
        # a post-launch tamper guarantee. It adds no import-root fallback.
        from importlib.resources.readers import FileReader
        return FileReader(self)
    def exec_module(self, module):
        item = self.item
        data = self._read(Path(item["path"]), item["sha256"])
        module.__file__ = item["path"]
        module.__cached__ = None
        if item["package"]: module.__path__ = [str(Path(item["path"]).parent)]
        # Compile the verified bytes themselves; never ordinary import reopen,
        # nor a cached bytecode representation, after checking a pathname.
        code = compile(data, item["path"], "exec", dont_inherit=True)
        exec(code, module.__dict__)


class _MappedDistribution(importlib.metadata.Distribution):
    def __init__(self, root, directory, files):
        self.root, self.directory, self._file_pins = root, directory, files

    def read_text(self, filename):
        relative = self.directory + "/" + filename
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            raise HostLaunchError("distribution metadata path escapes its binding")
        pin = self._file_pins.get(relative)
        if pin is None:
            return None
        return _local_read(self.root / relative, pin).decode("utf-8")

    def locate_file(self, filename):
        relative = str(filename)
        path = Path(relative)
        if (path.is_absolute() or ".." in path.parts
                or path.as_posix() != relative or relative not in self._file_pins):
            raise HostLaunchError("distribution resource is outside its reviewed inventory")
        _local_read(self.root / relative, self._file_pins[relative])
        return self.root / relative


class MappedImports(importlib.abc.MetaPathFinder):
    def __init__(self, mapping, *, trusted_local=False, distribution_metadata=None):
        self.mapping = mapping
        self.trusted_local = trusted_local
        self._bind_distribution_metadata(distribution_metadata)

    def _bind_distribution_metadata(self, distribution_metadata):
        # On a cold isolated launch, metadata parsing lazily imports stdlib
        # email modules. Bind only after this exact importer is active so the
        # parsing imports obey the same reviewed mapping as the host.
        if distribution_metadata is not None and not isinstance(distribution_metadata, list):
            raise HostLaunchError("distribution metadata binding must be a list")
        if distribution_metadata and not self.trusted_local:
            raise HostLaunchError("strict import mapping cannot adopt installed metadata")
        self.distributions = []
        names = set()
        for row in distribution_metadata or []:
            if (not isinstance(row, dict) or set(row) != {"root", "files", "distributions"}
                    or not isinstance(row["files"], dict) or not isinstance(row["distributions"], list)):
                raise HostLaunchError("distribution metadata binding is invalid")
            root = _absolute(row["root"])
            for item in row["distributions"]:
                if (not isinstance(item, dict) or set(item) != {"directory", "name"}
                        or not isinstance(item["directory"], str)
                        or Path(item["directory"]).name != item["directory"]
                        or not item["directory"].endswith(".dist-info")
                        or not isinstance(item["name"], str) or not item["name"]):
                    raise HostLaunchError("distribution identity binding is invalid")
                candidate = _MappedDistribution(root, item["directory"], row["files"])
                name = candidate.metadata["Name"]
                if (not name or re.sub(r"[-_.]+", "-", name).lower() != item["name"]
                        or not candidate.version or item["name"] in names):
                    raise HostLaunchError("distribution identity differs from reviewed binding")
                names.add(item["name"])
                self.distributions.append((item["name"], candidate))

    def find_distributions(self, context=importlib.metadata.DistributionFinder.Context()):
        name = re.sub(r"[-_.]+", "-", context.name).lower() if context.name else None
        # The caller's context.path never supplies discovery authority.
        return (distribution for selected, distribution in self.distributions
                if name is None or name == selected)

    def find_spec(self, fullname, path=None, target=None):
        item = self.mapping.get(fullname)
        if item is None:
            for importer in (importlib.machinery.BuiltinImporter, importlib.machinery.FrozenImporter):
                spec = importer.find_spec(fullname)
                if spec is not None: return spec
            raise ModuleNotFoundError("module is outside the reviewed import mapping: " + fullname)
        if item["kind"] == "source": loader = _SourceLoader(item, trusted_local=self.trusted_local)
        elif item["kind"] == "namespace":
            spec = importlib.machinery.ModuleSpec(fullname, loader=None, is_package=True)
            spec.submodule_search_locations = [item["path"]]
            return spec
        elif item["kind"] == "extension":
            # Strict mode requires retained protection. Trusted-local mode
            # only observes the pinned installed bytes and assumes no hostile
            # same-user writer; native loading has no hash-based TOCTOU defense.
            (_local_read if self.trusted_local else read_source)(Path(item["path"]), item["sha256"])
            loader = importlib.machinery.ExtensionFileLoader(fullname, item["path"])
        else: raise ImportError("unsupported import representation")
        return importlib.util.spec_from_file_location(fullname, item["path"], loader=loader,
            submodule_search_locations=[str(Path(item["path"]).parent)] if item["package"] else None)


def _custody_fd_diag(point):
    """Diagnostic only (lane/M-GPU/p1-runtime-custody-diag): fd numbers and socket state, never contents."""
    try:
        import json as _json, os as _os, select as _select, socket as _socket, stat as _stat, sys as _sys, time as _time
        fds = []
        for fd in range(32):
            try:
                st = _os.fstat(fd)
            except OSError:
                continue
            entry = {"fd": fd, "sock": _stat.S_ISSOCK(st.st_mode), "ino": st.st_ino}
            if entry["sock"]:
                peer = _socket.socket(fileno=_os.dup(fd))
                try:
                    entry["type"] = peer.getsockopt(_socket.SOL_SOCKET, _socket.SO_TYPE)
                    entry["err"] = peer.getsockopt(_socket.SOL_SOCKET, _socket.SO_ERROR)
                    ready, _, _ = _select.select([peer], [], [], 0)
                    entry["readable"] = bool(ready)
                    if ready:
                        entry["eof"] = peer.recv(1, _socket.MSG_PEEK) == b""
                finally:
                    peer.close()
            fds.append(entry)
        record = {"point": point, "monotonic": _time.monotonic(), "pid": _os.getpid(), "fds": fds}
        _sys.stderr.write("astrid.custody_fd_diag " + _json.dumps(record, sort_keys=True) + "\n")
        _sys.stderr.flush()
    except Exception as exc:
        import sys as _sys2
        _sys2.stderr.write("astrid.custody_fd_diag error " + type(exc).__name__ + "\n")


def launch_from_binding(payload):
    fields = {"schema_version", "mode", "module", "mapping", "host_argv"}
    if isinstance(payload, dict) and payload.get("mode") == TRUSTED_LOCAL_MODE:
        fields.add("distribution_metadata")
    if (not isinstance(payload, dict) or set(payload) != fields
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["mode"] not in (MODE, TRUSTED_LOCAL_MODE) or payload["module"] != HOST_MODULE
            or not isinstance(payload["mapping"], dict) or HOST_MODULE not in payload["mapping"]
            or not isinstance(payload["host_argv"], list) or any(not isinstance(x, str) or "\0" in x for x in payload["host_argv"])):
        raise HostLaunchError("retained launcher payload is invalid")
    mapping = payload["mapping"]
    # Reject a selected module that was executed before the mapping was set.
    if any(name in sys.modules for name in mapping if name.split('.')[0] in {"astrid", "astrid_runtime_client"}):
        raise HostLaunchError("selected packages were imported before isolated mapping")
    finder = MappedImports(mapping, trusted_local=payload["mode"] == TRUSTED_LOCAL_MODE)
    sys.path[:] = []
    sys.path_hooks[:] = []
    sys.path_importer_cache.clear()
    sys.meta_path[:] = [finder]
    finder._bind_distribution_metadata(payload.get("distribution_metadata"))
    sys.dont_write_bytecode = True
    # Import parents under the same policy, without ambient package initializers.
    __import__(HOST_MODULE.rpartition('.')[0])
    item = mapping[HOST_MODULE]
    module = type(sys)("__main__")
    module.__package__ = HOST_MODULE.rpartition('.')[0]
    module.__spec__ = importlib.util.spec_from_file_location(HOST_MODULE, item["path"], loader=_SourceLoader(item))
    sys.modules['__main__'] = module
    sys.argv[:] = [item["path"], *payload["host_argv"]]
    _custody_fd_diag("launcher_before_exec_module")
    _SourceLoader(item, trusted_local=payload["mode"] == TRUSTED_LOCAL_MODE).exec_module(module)


def _main():
    if not sys.flags.isolated or not sys.flags.no_site or len(sys.argv) != 3 or sys.argv[1] != "--binding-fd":
        raise HostLaunchError("launcher requires the exact isolated binding descriptor mode")
    fd = int(sys.argv[2]); payload = bytearray()
    try:
        while True:
            chunk = os.read(fd, min(1024 * 1024, LIMIT + 1 - len(payload)))
            if not chunk: break
            payload.extend(chunk)
            if len(payload) > LIMIT: raise HostLaunchError("launcher binding exceeds its bound")
    finally: os.close(fd)
    value = json.loads(bytes(payload))
    if canonical(value) != bytes(payload): raise HostLaunchError("launcher binding is not exact canonical JSON")
    launch_from_binding(value)


if __name__ == "__main__": _main()
