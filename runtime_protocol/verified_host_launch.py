"""Private, trusted G1b launch verification and isolated source loader.

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
import sysconfig
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
    "vendored_workspace_client": "banodoco_workspace_client",
}

# An installed directory is a selector, never an import grant. Keep this small
# Host closure explicit; optional format/CLI/docs/test extras are not selected.
HOST_DISTRIBUTIONS = {
    "astrid": ("astrid", "banodoco_workspace_client", "schemas"),
    "banodoco-workspace-runtime": ("banodoco_local", "runtime_protocol"),
    "jsonschema": ("jsonschema",), "attrs": ("attr", "attrs"),
    "jsonschema-specifications": ("jsonschema_specifications",),
    "referencing": ("referencing",), "rpds-py": ("rpds",),
    "typing-extensions": ("typing_extensions.py",),
    "pyyaml": ("yaml", "_yaml"), "pillow": ("PIL",),
    "python-dotenv": ("dotenv",),
}


def installed_host_closure(root):
    """Select RECORD-covered Host distributions without importing their code.

    This is an observation of trusted local installed artifacts, not a resolver,
    installer, or hostile-writer defense. Unsupported new dependency metadata
    fails closed and needs an explicit closure policy update.
    """
    import base64
    import csv
    root = _absolute(str(root))
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise HostLaunchError("installed Host origin contains a symlink")
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    selected = {}
    for dist in importlib.metadata.distributions(path=[str(root)]):
        name = normalize(dist.metadata.get("Name", ""))
        if name not in HOST_DISTRIBUTIONS:
            continue
        if name in selected:
            raise HostLaunchError("installed Host distribution has duplicate origins")
        selected[name] = dist
    if set(selected) != set(HOST_DISTRIBUTIONS):
        raise HostLaunchError("missing installed Host dependency: " + ", ".join(sorted(set(HOST_DISTRIBUTIONS) - set(selected))))
    files = {}; identities = {}
    for name, dist in sorted(selected.items()):
        if Path(dist.locate_file("")).resolve() != root or not dist.version:
            raise HostLaunchError("installed Host distribution origin/version differs")
        record_entries = [str(p) for p in dist.files or () if str(p).endswith(".dist-info/RECORD")]
        if len(record_entries) != 1:
            raise HostLaunchError("installed Host distribution has no unique RECORD")
        record_relative = record_entries[0]
        directory = Path(record_relative).parent
        if len(directory.parts) != 1:
            raise HostLaunchError("installed Host RECORD origin escapes selected root")
        def read(relative):
            path = root / relative
            if any(p.is_symlink() for p in (path, *path.parents)):
                raise HostLaunchError("installed Host file contains a symlink")
            return _bounded_source(path)
        record_bytes = read(record_relative)
        if record_bytes.decode().splitlines() != (dist.read_text("RECORD") or "").splitlines():
            raise HostLaunchError("installed Host RECORD metadata differs")
        covered = {}
        for row in csv.reader(record_bytes.decode().splitlines()):
            if len(row) != 3:
                raise HostLaunchError("installed Host RECORD row is invalid")
            relative, checksum, size = row
            path = Path(relative)
            # Wheel entry-point scripts outside site-packages are not child
            # import inputs. Never follow them or admit them as module roots.
            if ".." in path.parts and not path.is_absolute():
                continue
            if path.is_absolute() or str(path) != relative or not path.parts:
                raise HostLaunchError("installed Host RECORD path is invalid")
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            if path.parts[0] not in (*HOST_DISTRIBUTIONS[name], str(directory)):
                raise HostLaunchError("installed Host RECORD contains an undeclared package")
            if relative in covered or relative in files:
                raise HostLaunchError("installed Host RECORD has duplicate file ownership")
            content = read(relative)
            pin = hashlib.sha256(content).hexdigest()
            if relative != record_relative:
                expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
                if checksum != expected or size != str(len(content)):
                    raise HostLaunchError("installed Host file differs from RECORD or lacks coverage")
            elif checksum or size:
                raise HostLaunchError("installed Host RECORD self identity is invalid")
            covered[relative] = pin
        if record_relative not in covered or str(directory / "METADATA") not in covered:
            raise HostLaunchError("installed Host metadata/RECORD coverage is absent")
        direct = dist.read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable"):
            raise HostLaunchError("editable installed Host origin is forbidden")
        # Bind the original metadata, canonical origin, and every covered byte.
        identities[name] = {"name": name, "version": dist.version,
            "origin": str(root / directory), "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "files": covered}
        files.update(covered)
    for name, dist in selected.items():
        if name in {"astrid", "banodoco-workspace-runtime"}:
            # Their full optional SDK surface is not the eager Host closure.
            continue
        for requirement in dist.requires or ():
            spec, _, marker = requirement.partition(";")
            if marker:
                marker = marker.strip()
                if re.fullmatch(r"extra\s*==\s*['\"][\w-]+['\"]", marker):
                    continue
                match = re.fullmatch(r"python_version\s*<\s*['\"](\d+)\.(\d+)['\"]", marker)
                if not match:
                    raise HostLaunchError("unreviewed Host dependency marker")
                if sys.version_info[:2] >= tuple(map(int, match.groups())):
                    continue
            match = re.fullmatch(r"\s*([\w.-]+)\s*(?:>=\s*(\d+(?:\.\d+)*))?\s*", spec)
            if not match or normalize(match[1]) not in selected:
                raise HostLaunchError("missing or unreviewed transitive Host dependency")
            if match[2]:
                version = selected[normalize(match[1])].version
                if not re.fullmatch(r"\d+(?:\.\d+)*", version):
                    raise HostLaunchError("unreviewed Host dependency version")
                actual, minimum = (tuple(map(int, v.split('.'))) for v in (version, match[2]))
                length = max(len(actual), len(minimum))
                if actual + (0,) * (length-len(actual)) < minimum + (0,) * (length-len(minimum)):
                    raise HostLaunchError("installed Host transitive dependency version is incompatible")
    # No unrecorded source, resource, metadata or native artifact may acquire
    # authority, including additions inside an otherwise admitted package.
    for path in root.rglob("*"):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise HostLaunchError("installed Host origin contains a symlink")
        if path.is_file() and str(path.relative_to(root)) not in files:
            if path.suffix == ".pth" and path.parent == root:
                continue  # -S never executes it; it grants no mapped imports.
            raise HostLaunchError("installed Host has an undeclared file outside RECORD coverage")
    for name, modules in HOST_DISTRIBUTIONS.items():
        for module in modules:
            if module in {"schemas", "_yaml"}:
                continue
            relative = module if module.endswith(".py") else module + "/__init__.py"
            if relative not in identities[name]["files"]:
                raise HostLaunchError("installed Host required module lacks RECORD coverage")
    return {"distributions": identities, "files": files}


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
    if not _raw(expected):
        raise HostLaunchError("import source pin is invalid")
    return _bounded_source(path, expected)


def _bounded_source(path, expected=None):
    """Shared bounded measurement; only the producer may omit an expected pin."""
    path = _absolute(str(path)); _no_alias(path)
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
        if expected is not None and hashlib.sha256(data).hexdigest() != expected:
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
            for child in sorted(path.rglob("*")):
                if child.is_symlink(): raise HostLaunchError("source closure contains a symlink")
                if child.is_file() and "__pycache__" not in child.parts:
                    entries.append((str(child.relative_to(path)), hashlib.sha256(child.read_bytes()).hexdigest()))
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
                or str(path) != relative or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
                or not _raw(pin)):
            raise HostLaunchError("reviewed inventory has an unsupported file representation")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink(): raise HostLaunchError("reviewed inventory contains an alias")
        if path.is_file(): actual.add(str(path.relative_to(root)))
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
                if not trusted_local and (not path.is_relative_to(runtime_root) or runtime_inventory["files"].get(str(path.relative_to(runtime_root))) != pin):
                    raise HostLaunchError("native dependency is outside protected Python runtime inventory")
            if trusted_local and name.split('.')[0] in {"astrid", "banodoco_workspace_client", "banodoco_local", "runtime_protocol"} and root != source_root:
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
            if normalized in {"astrid", "banodoco-workspace-client", "banodoco-workspace-runtime"} and str(root) != import_roots[0]["path"]:
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
        return str(interpreter.relative_to(root))

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

    def _validate_inventory_selection(self, record, profile, config):
        return None

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
        selected_python = self._validate_inventory_selection(record, profile, config)
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
            if selected_python is not None:
                payload["selected_python"] = selected_python
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
            return ([host_argv[0], "-I", "-S", record["launcher"]["path"], "--binding-fd", str(binding_fd)], record["payload"])

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


def _local_read(path, expected):
    """Observe the selected installation, allowing its recorded Python aliases.

    This is a version/hash check, not protection against a hostile same-user
    writer between checks or native loading. Source compilation still consumes
    the verified bytes themselves. No chmod/hash is called tamper prevention.
    """
    return read_source(_absolute(str(Path(path).resolve(strict=True))), expected)


def _python_path_binding(path):
    pending = [path]; aliases = {}; visited = set()
    while pending:
        current = pending.pop()
        for candidate in (current, *current.parents):
            if candidate in visited: continue
            visited.add(candidate)
            if candidate.is_symlink():
                target = os.readlink(candidate); aliases[str(candidate)] = target
                pending.append(Path(os.path.abspath(candidate.parent / target)))
    return {"lexical": str(path), "resolved": str(path.resolve(strict=True)),
            "aliases": [{"path": p, "target": target} for p, target in sorted(aliases.items())]}


def selected_python_layout(source):
    """Trusted current interpreter facts, never caller-selected exclusions.

    Python 3.11's -S child may report the base prefix. Capture the installed
    package root in the owner, before that launch, and retain it explicitly.
    """
    base = Path(sys.base_prefix).resolve(strict=True)
    paths = sysconfig.get_paths(vars={"base": str(base), "platbase": str(base),
        "installed_base": str(base), "installed_platbase": str(base)})
    exclusions = sorted({str(_absolute(paths[name])) for name in ("purelib", "platlib")})
    roots = {"installed-packages": str(_absolute(str(source))), "python-runtime": str(base),
        "python-stdlib": str(_absolute(sysconfig.get_path("stdlib"))),
        "python-extensions": str(_absolute(sysconfig.get_config_var("DESTSHARED")))}
    if any(Path(roots[role]).resolve().is_relative_to(Path(p).resolve())
           for role in roots for p in exclusions):
        raise HostLaunchError("selected Python root aliases into excluded ambient packages")
    boundaries = []
    for raw in exclusions:
        path = Path(raw)
        kind = "symlink" if path.is_symlink() else "directory" if path.is_dir() else "absent" if not path.exists() else "file"
        boundaries.append({"path": raw, "kind": kind,
            "target": os.readlink(path) if kind == "symlink" else None,
            "resolved": str(path.resolve())})
    # Bind absence too: a newly appearing zip is new bootstrap authority.
    startup = {}
    for path in dict.fromkeys((Path(sys.prefix) / "pyvenv.cfg", base / "pyvenv.cfg",
                              Path(roots["python-stdlib"]).parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip")):
        if path.is_symlink() and not path.exists():
            raise HostLaunchError("selected Python startup alias is broken")
        if path.exists():
            resolved = path.resolve(strict=True)
            if (any(resolved.is_relative_to(Path(p).resolve()) for p in exclusions)
                    or not any(resolved.is_relative_to(root) for root in (base, Path(sys.prefix).resolve()))):
                raise HostLaunchError("selected Python startup file escapes admitted runtime")
            startup[str(path)] = {"binding": _python_path_binding(path),
                "sha256": hashlib.sha256(_bounded_source(resolved)).hexdigest()}
        else:
            startup[str(path)] = None
    executable = Path(os.path.abspath(sys.executable))
    return {"version": 1, "roots": roots, "excluded_roots": boundaries, "startup_files": startup,
            "interpreter": _python_path_binding(executable),
            "root_bindings": {role: _python_path_binding(Path(raw)) for role, raw in roots.items()}}


def _selected_inventory_policy(root, role, layout):
    if type(role) is not str or role not in layout["roots"] or str(root) != layout["roots"][role]:
        raise HostLaunchError("unknown selected Python inventory role or root")
    return {"role": role, "layout": layout}


def _excluded(path, layout):
    return any(path.is_relative_to(Path(row["path"])) or
               path.is_relative_to(Path(row["resolved"])) for row in layout["excluded_roots"])


def installed_inventory(root, *, python_role=None, selected_source=None):
    """Exact installed non-bytecode inventory, for trusted caller review.

    Bytecode is excluded because the isolated launcher never uses it. .pth and
    other data remain inventoried, but site startup never executes .pth files.
    Calling this measurement does not adopt the resulting record.
    """
    root = _absolute(str(root))
    layout = selected_python_layout(selected_source) if python_role is not None else None
    policy = _selected_inventory_policy(root, python_role, layout) if layout is not None else None
    if python_role == "installed-packages":
        closure = installed_host_closure(root)
        return {"root": str(root), "files": closure["files"],
                "distributions": closure["distributions"], "selection": policy}
    files = {}; aliases = {}
    def walk(directory):
        for path in sorted(directory.iterdir()):
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            # Structural pruning happens before enumerating or reading the
            # subtree. A different alias may never re-admit excluded code.
            if layout is not None and _excluded(path, layout):
                continue
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if layout is not None and (_excluded(resolved, layout) or
                        not any(resolved.is_relative_to(Path(p).resolve()) for p in layout["roots"].values())):
                    raise HostLaunchError("selected Python alias escapes admitted roots")
                yield path
            elif path.is_dir():
                yield from walk(path)
            else:
                yield path
    for path in walk(root):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            aliases[str(path.relative_to(root))] = {"target": os.readlink(path),
                "kind": "file" if path.is_file() else "directory" if path.is_dir() else "broken"}
        if path.is_file():
            files[str(path.relative_to(root))] = hashlib.sha256(_bounded_source(path.resolve(strict=True))).hexdigest()
    # rglob does not traverse directory aliases. Record their literal targets,
    # but never silently make their contents an import root. -S omits the
    # stdlib's ordinary aliased site directory in favor of the explicit roots.
    result = {"root": str(root), "files": files}
    if aliases: result["aliases"] = aliases
    if policy is not None: result["selection"] = policy
    return result


def _local_inventory(value):
    if (not isinstance(value, dict) or not {"root", "files"} <= set(value)
            or set(value) - {"root", "files", "aliases", "selection", "distributions"}):
        raise HostLaunchError("installed inventory shape is invalid")
    root = _absolute(value["root"])
    selection = value.get("selection")
    role = source = None
    if selection is not None:
        if not isinstance(selection, dict) or set(selection) != {"role", "layout"}:
            raise HostLaunchError("selected Python inventory selection is invalid")
        role = selection["role"]
        try:
            source = selection["layout"]["roots"]["installed-packages"]
            layout = selected_python_layout(source)
        except (KeyError, TypeError) as exc:
            raise HostLaunchError("selected Python inventory layout is invalid") from exc
        if selection != _selected_inventory_policy(root, role, layout):
            raise HostLaunchError("selected Python inventory boundary changed")
    if "aliases" in value and not isinstance(value["aliases"], dict):
        raise HostLaunchError("installed alias inventory is invalid")
    if not isinstance(value["files"], dict) or not value["files"] or len(value["files"]) > 200000:
        raise HostLaunchError("installed inventory file map is invalid")
    for relative, pin in value["files"].items():
        path = Path(relative) if isinstance(relative, str) else None
        if (path is None or not relative or path.is_absolute() or ".." in path.parts
                or str(path) != relative or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".pyo"} or not _raw(pin)):
            raise HostLaunchError("installed inventory has an unsupported file representation")
        if selection is not None and (_excluded(root / relative, layout) or _excluded((root / relative).resolve(), layout)):
            raise HostLaunchError("selected Python inventory includes excluded ambient code")
        if selection is not None and not any((root / relative).resolve().is_relative_to(Path(p).resolve())
                                             for p in layout["roots"].values()):
            raise HostLaunchError("selected Python file escapes admitted roots")
        _local_read(root / relative, pin)
    if installed_inventory(root, python_role=role, selected_source=source) != value:
        raise HostLaunchError("installed inventory has missing, changed or unexpected files")
    return json.loads(canonical(value))


class _LocalInstallationObservation:
    """Retained launch observation; deliberately offers no protection lease."""
    def __init__(self, profile, launcher, layout=None):
        self._layout = layout
        self._release_digest = profile.get("release_digest")
        self._renderer = profile.get("host_launch", {}).get("renderer_selection")
        self._renderer_binding = None
        self._pins = [(profile["host_executable"], profile["host_artifact_digest"][7:]),
                      (launcher["path"], launcher["sha256"])]
        if "host_os_executable" in profile:
            self._pins.append((profile["host_os_executable"], profile["host_os_artifact_digest"][7:]))
    def verify(self):
        if self._layout is not None and selected_python_layout(self._layout["roots"]["installed-packages"]) != self._layout:
            raise HostLaunchError("selected Python startup or inclusion boundary changed")
        if self._layout is not None:
            closure = installed_host_closure(self._layout["roots"]["installed-packages"])
            if "sha256:" + raw_digest(closure["distributions"]) != self._release_digest:
                raise HostLaunchError("selected Host dependency release changed")
        if self._renderer is not None:
            from astrid.core.execution.host_renderer_selection import validate_renderer_selection
            try:
                self._renderer_binding = validate_renderer_selection(self._renderer, retained=self._renderer_binding)
            except (ValueError, OSError) as exc:
                raise HostLaunchError("selected renderer closure changed") from exc
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
                    "BANODOCO_LOCAL_DATA_ROOT": str(realm)}
        if config.get("support_root") != str(support) or any(environment.get(k) != v for k, v in expected.items()):
            raise HostLaunchError("host-only environment differs from selected owner roots")
        return super()._validate_environment(profile, config, {k: v for k, v in environment.items() if k not in expected})

    def _observation(self, record, profile):
        layout = selected_python_layout(record["source_checkout"]) if profile.get("execution_mode") == "host_only_cpu" else None
        return _LocalInstallationObservation(profile, record["import_binding"]["launcher"], layout)

    def _validate_inventory_selection(self, record, profile, config):
        if profile.get("execution_mode") != "host_only_cpu":
            return None
        layout = selected_python_layout(config["source_checkout"])
        if profile["host_executable"] != layout["interpreter"]["lexical"]:
            raise HostLaunchError("selected Python interpreter differs from current owner")
        roles = {}
        if not isinstance(record["inventories"], dict):
            raise HostLaunchError("host-only selected inventories are invalid")
        for pin, inventory in record["inventories"].items():
            if not isinstance(inventory, dict) or "root" not in inventory:
                raise HostLaunchError("host-only selected inventory is invalid")
            selection = inventory.get("selection")
            if not isinstance(selection, dict) or set(selection) != {"role", "layout"}:
                raise HostLaunchError("host-only inventory lacks selected Python role")
            role = selection["role"]
            if selection != _selected_inventory_policy(Path(inventory["root"]), role, layout) or role in roles:
                raise HostLaunchError("host-only inventory has changed or duplicate selection")
            if role == "installed-packages" and "sha256:" + raw_digest(inventory.get("distributions")) != profile["release_digest"]:
                raise HostLaunchError("host-only dependency selection differs from selected release")
            roles[role] = pin
        if set(roles) != set(layout["roots"]):
            raise HostLaunchError("host-only inventory selection is incomplete")
        imports = []
        for role in ("installed-packages", "python-stdlib", "python-extensions"):
            entry = {"path": layout["roots"][role], "inventory_digest": roles[role]}
            if not any(e["path"] == entry["path"] for e in imports): imports.append(entry)
        binding = record["import_binding"]
        if binding["import_roots"] != imports or binding["python_runtime_inventory_digest"] != roles["python-runtime"]:
            raise HostLaunchError("host-only import roots differ from selected Python roles")
        return layout

    def _runtime_relative(self, interpreter, runtime):
        selected = interpreter.resolve(strict=True)
        root = Path(runtime["root"]).resolve(strict=True)
        if not selected.is_relative_to(root):
            raise HostLaunchError("selected installed interpreter is outside its recorded runtime")
        return str(selected.relative_to(root))

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
        if path.is_absolute() or ".." in path.parts or str(path) != relative:
            raise HostLaunchError("distribution metadata path escapes its binding")
        pin = self._file_pins.get(relative)
        if pin is None:
            return None
        return _local_read(self.root / relative, pin).decode("utf-8")

    def locate_file(self, filename):
        relative = str(filename)
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or str(path) != relative or relative not in self._file_pins:
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


def launch_from_binding(payload):
    fields = {"schema_version", "mode", "module", "mapping", "host_argv"}
    if isinstance(payload, dict) and payload.get("mode") == TRUSTED_LOCAL_MODE:
        fields.add("distribution_metadata")
        if "selected_python" in payload:
            fields.add("selected_python")
    if (not isinstance(payload, dict) or set(payload) != fields
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["mode"] not in (MODE, TRUSTED_LOCAL_MODE) or payload["module"] != HOST_MODULE
            or not isinstance(payload["mapping"], dict) or HOST_MODULE not in payload["mapping"]
            or not isinstance(payload["host_argv"], list) or any(not isinstance(x, str) or "\0" in x for x in payload["host_argv"])):
        raise HostLaunchError("retained launcher payload is invalid")
    mapping = payload["mapping"]
    # Reject a selected module that was executed before the mapping was set.
    if any(name in sys.modules for name in mapping if name.split('.')[0] in {"astrid", "banodoco_workspace_client"}):
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
    # Private retained owner input for the existing confined-child factory.
    # It cannot be selected by Host CLI, task arguments, CWD or environment.
    if "selected_python" in payload:
        module.__dict__["_RETAINED_SELECTED_PYTHON"] = json.loads(canonical(payload["selected_python"]))
    sys.modules['__main__'] = module
    # Host collaborators import the canonical name. Keep one execution and one
    # retained owner binding while preserving the CLI's __main__ entry point.
    # Both names refer to the same source already admitted by this mapping.
    sys.modules[HOST_MODULE] = module
    setattr(sys.modules[module.__package__], HOST_MODULE.rsplit('.', 1)[1], module)
    sys.argv[:] = [item["path"], *payload["host_argv"]]
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
