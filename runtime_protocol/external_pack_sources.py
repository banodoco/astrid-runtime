"""Private owner grants and captured external source bytes for local launches."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import threading
from pathlib import Path

from . import platform
from .errors import AuthorizationError
from .verified_host_launch import (
    HostLaunchError,
    _absolute,
    _no_alias,
    canonical,
    raw_digest,
    read_source,
)

SOURCE_LIMIT = 8 * 1024 * 1024
FILE_LIMIT = 1024
RESERVED = frozenset({"astrid", "astrid_runtime_client", "runtime_protocol"})


def _relative(value):
    if (not isinstance(value, str) or not value or str(Path(value)) != value
            or Path(value).is_absolute() or ".." in Path(value).parts or "\0" in value):
        raise HostLaunchError("external source subpath is invalid")
    return value


def _state_path(support_root):
    root = _absolute(str(support_root)); _no_alias(root)
    return root / "external-pack-sources" / "grants.json"


def _read_state(path):
    from .local_execution_handoff import read_protected
    _no_alias(path)
    if not platform.is_owner_only(path.parent, directory=True):
        raise HostLaunchError("external source owner state is not private")
    try:
        return read_protected(path)
    except (OSError, ValueError, RuntimeError) as exc:
        raise HostLaunchError("external source owner state is not an owner-only file") from exc


def _write_owner_grants(service, grants, *, identity):
    """In-process owner configuration only; never exposed as a protocol route."""
    service._require_placement_recovery_owner(identity)
    if identity.get("actor") != "owner":
        raise AuthorizationError("external source configuration requires the owner")
    if service.support_root is None:
        raise HostLaunchError("external sources require private Runtime support state")
    _validate_grants(grants)
    from .local_execution_handoff import write_protected
    path = _state_path(service.support_root)
    _no_alias(path)
    write_protected(path, {"workspace_uuid": service.realm["id"], "grants": grants})


def _validate_grants(grants):
    if not isinstance(grants, list) or len(grants) > 16:
        raise HostLaunchError("external source grants are invalid")
    roots = []
    for grant in grants:
        if (not isinstance(grant, dict) or set(grant) != {"repository", "checkout", "revision", "subpath", "tree", "root", "files", "definitions"}
                or not isinstance(grant["repository"], str) or not grant["repository"]
                or any(not isinstance(grant[k], str) or not re.fullmatch(r"[0-9a-f]{40}", grant[k]) for k in ("revision", "tree"))):
            raise HostLaunchError("external repository grant is invalid")
        checkout = _absolute(grant["checkout"])
        root = _absolute(grant["root"])
        if root != checkout / _relative(grant["subpath"]):
            raise HostLaunchError("external root differs from repository subpath")
        if any(root.is_relative_to(other) or other.is_relative_to(root) for other in roots):
            raise HostLaunchError("external source grants overlap")
        roots.append(root)
        files = grant["files"]
        if not isinstance(files, dict) or not files or len(files) > FILE_LIMIT:
            raise HostLaunchError("external source inventory exceeds its bound")
        for relative, pin in files.items():
            _relative(relative)
            top = Path(relative).parts[0]
            if (top.split(".")[0] in RESERVED or "__pycache__" in Path(relative).parts
                    or Path(relative).suffix in {".pyc", ".pyo"}
                    or not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin)):
                raise HostLaunchError("external source inventory contains a collision or invalid pin")
        definitions = grant["definitions"]
        if not isinstance(definitions, list) or not definitions or len(definitions) > FILE_LIMIT:
            raise HostLaunchError("external selected definitions are missing")
        seen = set()
        for definition in definitions:
            if (not isinstance(definition, dict) or set(definition) != {"path", "capability_kind", "capability_id", "definition_digest"}
                    or not isinstance(definition["path"], str) or definition["path"] not in files
                    or any(not isinstance(definition[k], str) or not definition[k] for k in ("capability_kind", "capability_id"))
                    or not isinstance(definition["definition_digest"], str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", definition["definition_digest"])):
                raise HostLaunchError("external selected definition is invalid")
            key = (definition["capability_kind"], definition["capability_id"])
            if key in seen:
                raise HostLaunchError("external selected definition is duplicated")
            seen.add(key)


def _git(checkout, *args):
    # No caller Git environment, replacements, includes, hooks or checkout.
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1")
    try:
        result = subprocess.run(["git", "--no-replace-objects", "-C", str(checkout), *args],
            env=environment, stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostLaunchError("external repository identity is unavailable") from exc
    if len(result.stdout) > SOURCE_LIMIT:
        raise HostLaunchError("external repository object exceeds its bound")
    return result.stdout


def _object(checkout, kind, identity):
    size = _git(checkout, "cat-file", "-s", identity).strip()
    if not size.isdigit() or int(size) > SOURCE_LIMIT:
        raise HostLaunchError("external repository object exceeds its bound")
    data = _git(checkout, "cat-file", kind, identity)
    if hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest() != identity:
        raise HostLaunchError("external repository object identity differs")
    return data


def _tree(checkout, identity):
    data = _object(checkout, "tree", identity)
    entries = {}
    while data:
        mode_name, separator, rest = data.partition(b"\0")
        if not separator or len(rest) < 20:
            raise HostLaunchError("external repository tree is invalid")
        mode, name = mode_name.split(b" ", 1)
        name = name.decode("utf-8")
        if name in entries or "/" in name or name in {"", ".", ".."}:
            raise HostLaunchError("external repository tree name is invalid")
        entries[name] = (mode, rest[:20].hex())
        data = rest[20:]
        if len(entries) > FILE_LIMIT:
            raise HostLaunchError("external repository tree exceeds its bound")
    return entries


def _identity(path, *, ancestor=False):
    value = path.lstat()
    identity = [value.st_dev, value.st_ino]
    if not ancestor:
        identity += [value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    return identity


def _capture(grant):
    checkout = _absolute(grant["checkout"]); root = _absolute(grant["root"])
    _no_alias(checkout); _no_alias(checkout / ".git"); _no_alias(root)
    if _git(checkout, "rev-parse", "--show-toplevel").decode().strip() != str(checkout):
        raise HostLaunchError("external repository checkout differs")
    if _git(checkout, "config", "--no-includes", "--local", "--get", "remote.origin.url").decode().strip() != grant["repository"]:
        raise HostLaunchError("external repository origin differs")
    if _git(checkout, "rev-parse", "--verify", "HEAD").decode().strip() != grant["revision"]:
        raise HostLaunchError("external repository revision differs")
    commit = _object(checkout, "commit", grant["revision"])
    first = commit.split(b"\n", 1)[0]
    if not re.fullmatch(b"tree [0-9a-f]{40}", first):
        raise HostLaunchError("external repository commit tree is invalid")
    tree = first[5:].decode()
    for part in Path(grant["subpath"]).parts:
        entry = _tree(checkout, tree).get(part)
        if entry is None or entry[0] != b"40000":
            raise HostLaunchError("external repository subpath differs")
        tree = entry[1]
    if tree != grant["tree"]:
        raise HostLaunchError("external repository tree differs")
    blobs = {}; pending = [(tree, "")]; visited = 0
    while pending:
        tree, prefix = pending.pop(); visited += 1
        if visited > FILE_LIMIT:
            raise HostLaunchError("external repository tree exceeds its bound")
        for name, (mode, identity) in _tree(checkout, tree).items():
            relative = prefix + name
            if mode == b"40000": pending.append((identity, relative + "/"))
            elif mode in {b"100644", b"100755"}: blobs[relative] = identity
            else: raise HostLaunchError("external repository contains symlink or foreign materialization")
            if len(blobs) > FILE_LIMIT:
                raise HostLaunchError("external repository inventory exceeds its bound")
    anchors = {str(path): _identity(path, ancestor=True) for path in root.parents}
    materialization = {str(root): _identity(root)}
    actual = set()
    for entries, path in enumerate(root.rglob("*"), 1):
        if entries > FILE_LIMIT * 4:
            raise HostLaunchError("external source directories exceed their bound")
        _no_alias(path)
        if Path(path.relative_to(root)).parts[0].split(".")[0] in RESERVED:
            raise HostLaunchError("external source materialization contains a package collision")
        materialization[str(path)] = _identity(path)
        if not path.is_dir():
            if not stat.S_ISREG(path.lstat().st_mode):
                raise HostLaunchError("external source is not regular")
            actual.add(str(path.relative_to(root)))
        if len(actual) > FILE_LIMIT:
            raise HostLaunchError("external source inventory exceeds its bound")
    if actual != set(grant["files"]) or actual != set(blobs):
        raise HostLaunchError("external source inventory differs from exact repository tree")
    contents = {}; total = 0
    for relative, pin in grant["files"].items():
        if (root / relative).stat().st_size > SOURCE_LIMIT:
            raise HostLaunchError("external source file exceeds its bound")
        data = read_source(root / relative, pin); total += len(data)
        if total > SOURCE_LIMIT:
            raise HostLaunchError("external captured source exceeds its bound")
        if hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != blobs[relative]:
            raise HostLaunchError("external source bytes differ from repository tree")
        contents[relative] = base64.b64encode(data).decode("ascii")
    if (any(_identity(Path(path)) != identity for path, identity in materialization.items())
            or any(_identity(Path(path), ancestor=True) != identity for path, identity in anchors.items())):
        raise HostLaunchError("external source materialization changed during capture")
    return {**grant, "contents": contents, "materialization": materialization, "ancestors": anchors}


class OwnerSourceCapture:
    """Retained bytes scoped to one original launch; claims cannot create grants."""

    def __init__(self, *, preparation, config):
        self._context = canonical({"preparation": preparation, "config": config})
        self._path = _state_path(config["support_root"])
        state = _read_state(self._path)
        if not isinstance(state, dict) or set(state) != {"workspace_uuid", "grants"} or state["workspace_uuid"] != preparation["profile"]["workspace_uuid"]:
            raise HostLaunchError("external source owner scope differs")
        _validate_grants(state["grants"])
        self._state = canonical(state)
        selected = preparation["profile"]["host_launch"]["additional_pack_roots"]
        self._grants = []
        for extra in selected:
            matches = [g for g in state["grants"] if g["root"] == extra["path"] and g["files"] == extra["files"]]
            if len(matches) != 1:
                raise HostLaunchError("selected external source has no owner grant")
            self._grants.append(matches[0])
        self._payload = canonical({"scope": {k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch", "custody_scope")},
            "selected_profile_digest": raw_digest(preparation["profile"]),
            "sources": [_capture(g) for g in self._grants]})
        self._claimed = False
        self._lock = threading.Lock()
        self.verify(preparation=preparation, config=config)

    @property
    def payload(self):
        return self._payload

    def __reduce__(self):
        raise TypeError("external source captures cannot be serialized")

    def verify(self, *, preparation, config):
        if canonical({"preparation": preparation, "config": config}) != self._context:
            raise HostLaunchError("external source launch scope changed")
        if canonical(_read_state(self._path)) != self._state:
            raise HostLaunchError("external source owner grant changed")
        if canonical([_capture(g) for g in self._grants]) != canonical(json.loads(self.payload)["sources"]):
            raise HostLaunchError("external source changed after capture")

    def claim(self, *, preparation, config):
        with self._lock:
            if self._claimed:
                raise HostLaunchError("external source capture already claimed")
            self._claimed = True
            self.verify(preparation=preparation, config=config)
            return self.payload
