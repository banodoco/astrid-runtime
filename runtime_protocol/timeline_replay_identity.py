"""Attest the executing verifier for the optional on-disk replay checkpoint."""
from __future__ import annotations

import base64
import hashlib
import json
import marshal
import os
import re
import stat
import sys
from importlib import import_module
from importlib.machinery import ExtensionFileLoader, SourceFileLoader
from importlib.util import MAGIC_NUMBER, cache_from_source
from pathlib import Path
from types import CodeType, FunctionType

SCHEMA_DISTRIBUTIONS = (
    "attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "typing-extensions",
)
_SCHEMA_MODULES = ("attr", "attrs", "jsonschema", "jsonschema_specifications",
                   "referencing", "rpds", "typing_extensions")
_REPLAY_MODULES = (
    "contract_metadata", "idempotency", "timeline_commit", "timeline_commit_auth",
    "timeline_commit_port", "timeline_commit_producer", "timeline_commit_store",
    "timeline_commit_validation", "timeline_materialization", "util",
)
_RUNTIME_MODULES = frozenset(f"runtime_protocol.{name}" for name in _REPLAY_MODULES)
_BUNDLE = "runtime_protocol/schemas/timeline-commit-bundle.json"
_installation = None
_MODULE_CODE = sys._getframe().f_code


def capture_replay_installation(package_file):
    """Pin installer-owned inputs before any replay code or schema engine imports."""
    global _installation
    prefix = Path(sys.prefix)
    if (sys.platform != "linux" or sys.implementation.name != "cpython"
            or prefix.name != "py" or prefix.parent.parent.name != "versions"):
        return
    try:
        installation = _Installation(prefix, Path(package_file).parent.parent)
        for path, loaded in ((Path(package_file), sys._getframe(1).f_code), (Path(__file__), _MODULE_CODE)):
            if installation._compiled(path) != loaded:
                raise ValueError("executing verifier bootstrap differs from its installed wheel")
        _installation = installation
    except Exception:
        # A checkpoint is optional even when installer metadata or files are
        # malformed. Normal import and semantic replay still decide admission.
        _installation = None


def installed_identity():
    if _installation is None:
        return None
    try:
        return _installation.identity()
    except Exception:
        # Refuse to relabel any proofs already earned in this interpreter.
        _installation.unavailable = True
        return None


def _file_identity(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("unprotected verifier installation")
    # uv may hard-link wheel contents. Changes to the same inode (including
    # its owner/mode) still move ctime even if a tool preserves its mtime.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _sha256(data):
    return hashlib.sha256(data).digest()


def _top_module(name):
    return (name or "").partition(".")[0]


def _codes(code):
    yield code
    for value in code.co_consts:
        if isinstance(value, CodeType):
            yield from _codes(value)


def _function(value):
    if isinstance(value, (staticmethod, classmethod)):
        value = value.__func__
    return value if isinstance(value, FunctionType) else getattr(value, "__wrapped__", None)


def _bindings(module):
    """Keep callable and code identities, including method and decorated bindings."""
    for name, value in tuple(vars(module).items()):
        yield vars(module), name, name, value
        if isinstance(value, type) and value.__module__ == module.__name__:
            for attribute, method in tuple(vars(value).items()):
                if _function(method) is not None:
                    yield vars(value), attribute, f"{value.__qualname__}.{attribute}", method


class _Installation:
    def __init__(self, prefix, site):
        from importlib.metadata import Distribution

        build = prefix.parent
        if (not re.fullmatch(r"[0-9a-f]{12}", build.name)
                or site.resolve(strict=True) != site
                or site != prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
                or any(_top_module(name) in _SCHEMA_MODULES for name in sys.modules)):
            raise ValueError("unverified verifier launch")

        self.files = {}
        self.directories = {}
        self.root = build.parent.parent
        self.site = site
        self.unavailable = False

        version = json.loads(self._read(build / "version.json"))
        manifest = json.loads(self._read(build / "manifest.json"))
        profile = json.loads(self._read(build / "profile.json"))
        config = self._read(prefix / "pyvenv.cfg").decode()
        system_packages = [line.partition("=")[2].strip().lower() for line in config.splitlines()
                           if line.partition("=")[0].strip() == "include-system-site-packages"]
        runtime_sha = manifest["runtime"]["sha"]
        profile_source = Path(profile["source_checkout"])
        if (not re.fullmatch(r"[0-9a-f]{40}", runtime_sha)
                or system_packages != ["false"]
                or version["root"] != str(build) or version["profile"] != str(build / "profile.json")
                or version["python"] != sys.executable or Path(sys.executable).parent != prefix / "bin"
                or version["identity"]["release"] != manifest.get("release", 0)
                or profile["runtime_environment"] != str(prefix)
                or profile["runtime_checkout"] != str(build / "r")
                or site not in profile_source.parents):
            raise ValueError("unverified installer selection")
        self._protect_directory(build / "r")
        self._protect_directory(prefix / "bin")
        self._protect_directory(profile_source)

        hashes = {}
        self.source_hashes = {}
        for name in ("astrid-runtime", *SCHEMA_DISTRIBUTIONS):
            dist, = Distribution.discover(name=name, path=[str(site)])
            paths = [path for path in dist.files if path.parts[0] != ".."]
            record, = [path for path in paths if path.name == "RECORD"]
            if not record.parts[0].endswith(".dist-info"):
                raise ValueError("unverified installed wheel record")
            for path in paths:
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("unconfined wheel record")
                if path.name == "direct_url.json":
                    direct_url = json.loads(self._read(site / path))
                    if direct_url.get("dir_info", {}).get("editable"):
                        raise ValueError("editable verifier installation")
                if path.suffix == ".pyc" or (name == "astrid-runtime" and path.parts[0] != "runtime_protocol"
                                            and path.parts[0] != record.parts[0]):
                    continue
                expected = path.hash
                if expected is None and path != record:
                    raise ValueError("unrecorded verifier installation input")
                actual = _sha256(self._read(site / path))
                if expected and (expected.mode != "sha256" or
                                 expected.value != base64.urlsafe_b64encode(actual).rstrip(b"=").decode()):
                    raise ValueError("verifier installation differs from wheel record")
                if path.parts[0] != record.parts[0]:
                    key = path.as_posix()
                    hashes[key] = actual.hex()
                    self.source_hashes[site / path] = actual
        self.fingerprint = [build.name, runtime_sha, hashes]
        self.python_caches = {}
        for path in self.source_hashes:
            if path.suffix == ".py":
                cache = Path(cache_from_source(path))
                try:
                    self.python_caches[cache] = _file_identity(cache)
                except FileNotFoundError:
                    pass
        self.loaded = None
        self.bundle = None
        self.schema = None

    def _protect_directory(self, directory):
        if directory not in self.directories:
            if not directory.is_relative_to(self.root):
                raise ValueError("verifier installation escapes its root")
            if directory != self.root:
                self._protect_directory(directory.parent)
            self.directories[directory] = _file_identity(directory, directory=True)

    def _read(self, path):
        self._protect_directory(path.parent)
        before = _file_identity(path)
        with path.open("rb") as source:
            data = source.read()
        if _file_identity(path) != before:
            raise ValueError("verifier installation moved during read")
        self.files[path] = before
        return data

    def _unchanged(self):
        for path, identity in self.directories.items():
            # Ordinary Python imports can add __pycache__ directories.
            # Directory identity, ownership and permissions must stay fixed.
            if _file_identity(path, directory=True)[:3] != identity[:3]:
                return False
        return all(_file_identity(path) == identity for path, identity in self.files.items())

    def _compiled(self, path):
        source = path.read_bytes()
        if _sha256(source) != self.source_hashes[path]:
            raise ValueError("loaded verifier source moved")
        code = compile(source, str(path), "exec", dont_inherit=True, optimize=sys.flags.optimize)
        cache = Path(cache_from_source(path))
        # A timestamp-valid but stale pyc can change module initialization
        # without changing the code of any function subsequently exported.
        # Check early caches as well as ones present after importing.
        if cache in self.python_caches or cache.exists():
            if not cache.is_relative_to(self.site):
                raise ValueError("verifier bytecode cache is outside the installed wheel")
            bytecode = self._read(cache)
            if (self.python_caches.get(cache, self.files[cache]) != self.files[cache]
                    or bytecode[:4] != MAGIC_NUMBER or marshal.loads(bytecode[16:]) != code):
                raise ValueError("cached verifier bytecode differs from installed source")
        return code

    def _assert_native_loaded(self, module, path):
        # The extension was absent before its wheel bytes/identity were
        # pinned. Linux also identifies the file backing the executable map.
        device, inode = self.files[path][:2]
        expected = (os.major(device), os.minor(device), inode)
        for line in Path("/proc/self/maps").read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and fields[5] == str(path) and "x" in fields[1]:
                major, minor = (int(part, 16) for part in fields[3].split(":"))
                if (major, minor, int(fields[4])) == expected:
                    return
        raise ValueError(f"unverified native verifier dependency {module.__name__}")

    def _loaded_modules(self):
        modules = {}
        for name, module in tuple(sys.modules.items()):
            if (_top_module(name) in _SCHEMA_MODULES
                    or name in _RUNTIME_MODULES):
                modules[name] = module
        return modules

    def _bind_loaded(self):
        from . import timeline_commit_validation as validation

        for name in _REPLAY_MODULES:
            import_module(f"runtime_protocol.{name}")
        bundle, registry = validation._schema_resources()
        validators = [validation._validator(definition) for definition in ("CommitContext", "PreparedCommit")]
        modules = self._loaded_modules()
        installed_code = {}
        for module in modules.values():
            spec = module.__spec__
            path = Path(spec.origin)
            if module.__file__ != spec.origin or path not in self.source_hashes:
                raise ValueError("loaded verifier module is outside its installed wheel")
            if type(spec.loader) is ExtensionFileLoader:
                self._assert_native_loaded(module, path)
                continue
            if type(spec.loader) is not SourceFileLoader:
                raise ValueError("unverified verifier module loader")
            if module.__cached__ != cache_from_source(path):
                raise ValueError("unverified verifier bytecode cache")
            code = self._compiled(path)
            declarations = {}
            for function_code in _codes(code):
                declarations.setdefault(function_code.co_qualname, set()).add(function_code)
            installed_code[str(path)] = declarations

        bindings = []
        for module in modules.values():
            module_code = installed_code.get(module.__file__, {})
            for namespace, name, declaration, value in _bindings(module):
                function = _function(value)
                code = getattr(function, "__code__", None)
                actual_code = set()
                while code is not None:
                    indexed = installed_code.get(code.co_filename)
                    if indexed is not None and code not in indexed.get(code.co_qualname, ()):
                        raise ValueError("executing verifier code differs from its installed wheel")
                    actual_code.add(code)
                    bindings.append((namespace, name, value, function, code))
                    function = getattr(function, "__wrapped__", None)
                    code = getattr(function, "__code__", None)
                declared = module_code.get(declaration, ())
                # Some declarations are intentionally rebound or generated by
                # attrs/jsonschema. Where the live name is still a function
                # from this module, its definition must include the installed
                # implementation, even if its code reports a different file.
                if (declared and getattr(value, "__module__", None) == module.__name__
                        and _function(value) is not None
                        and not any(code in declared for code in actual_code)):
                    raise ValueError(f"executing verifier binding differs: {module.__name__}.{declaration}")
                if (_top_module(getattr(value, "__module__", "")) in _SCHEMA_MODULES
                        or getattr(value, "__module__", "") in modules):
                    bindings.append((namespace, name, value, None, None))
        self.loaded = modules, bindings
        self.schema = validation, bundle, registry, validators
        self.bundle = json.loads((self.site / _BUNDLE).read_bytes())
        self.metaschemas = {}
        package = self.site / "jsonschema_specifications" / "schemas"
        for path in self.source_hashes:
            if path.is_relative_to(package):
                resource = json.loads(path.read_bytes())
                uri = resource.get("$id", resource.get("id")).rstrip("#")
                self.metaschemas[uri] = resource
        if not self.metaschemas:
            raise ValueError("missing installed JSON Schema resources")
        self.schema_engines = [sys.modules["jsonschema"].Draft202012Validator,
                               *(type(validator) for validator in validators)]
        self.keywords = [engine.VALIDATORS.copy() for engine in self.schema_engines]
        self.type_checkers = [engine.TYPE_CHECKER for engine in self.schema_engines]
        self.compiled_keywords = [tuple(validator._validators) for validator in validators]

    def _schema_matches(self):
        validation, bundle, registry, validators = self.schema
        active_bundle, active_registry = validation._schema_resources()
        if active_bundle is not bundle or active_registry is not registry or bundle != self.bundle:
            return False
        for uri, expected in self.bundle["resources"].items():
            if registry.contents(uri) != expected:
                return False
        specifications = sys.modules["jsonschema_specifications"].REGISTRY
        if set(specifications) != set(self.metaschemas):
            return False
        if not all(specifications.contents(uri) == expected for uri, expected in self.metaschemas.items()):
            return False
        for engine, keywords, types in zip(self.schema_engines, self.keywords, self.type_checkers):
            if engine.VALIDATORS != keywords or engine.TYPE_CHECKER is not types:
                return False
        for definition, validator, keywords in zip(
                ("CommitContext", "PreparedCommit"), validators, self.compiled_keywords):
            if (validation._validator(definition) is not validator
                    or tuple(validator._validators) != keywords
                    or validator.format_checker is not None):
                return False
            if validator.schema != {"$ref": self.bundle["root"] + "#/$defs/" + definition}:
                return False
            resolver = validation._validator_resolver(validator).resolver
            for uri, expected in self.bundle["resources"].items():
                if resolver.lookup(uri).contents != expected:
                    return False
        return True

    def identity(self):
        if self.unavailable:
            return None
        if self.loaded is None:
            if not self._unchanged():
                self.unavailable = True
                return None
            self._bind_loaded()
        modules, bindings = self.loaded
        current = self._loaded_modules()
        if (current != modules or not self._unchanged() or not self._schema_matches()
                or any(namespace.get(name) is not value
                       or (function is not None and function.__code__ is not code)
                       for namespace, name, value, function, code in bindings)):
            self.unavailable = True
            return None
        return self.fingerprint
