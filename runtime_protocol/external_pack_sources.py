"""Custody grants and captured external source bytes for local launches.

There is exactly one production grant path: the grant for an installed pack is
DERIVED from the same selected installed collection the Runtime already uses for
admission (``config["installed_pack_root"]``, the daemon's ``selected_pack_root``).
Grants are derived at custody build for EVERY installed pack of that collection
whose record verifies (launch-time discovery), selected or not; each pack that
does not verify is excluded with a named refusal recorded in discovery.json.
A grant is derived only when the install record verifies end to end:

  collection/.group.json admissions[pack_id]  (packId, sourceDigest, definitionsDigest)
    -> sha256(pack/.build/definitions.json) == definitionsDigest
    -> definitions.json source.kind == "git" with repository, revision, tree
    -> pack/PIN commit == definitions.revision and PIN digest == sourceDigest

Every refusal is named. A source outside that collection, a local-folder
install (no git provenance) or any edited record is refused. The derived grant
is persisted to the private owner state (grants.json) because the Agent's
custody check re-reads it; no caller, claim or profile can write that file.
"""
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


def _read_state(path, *, missing_ok=False):
    """The owner state, or a refusal naming the state file; never a silent reset."""
    from .local_execution_handoff import read_protected
    _no_alias(path)
    if missing_ok:
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise HostLaunchError(f"external source owner state {path} is unreadable; refusing to overwrite it") from exc
    if not platform.is_owner_only(path.parent, directory=True):
        raise HostLaunchError(f"external source owner state {path} is not private")
    try:
        return read_protected(path)
    except Exception as exc:
        raise HostLaunchError(f"external source owner state {path} is unreadable or corrupt; refusing to overwrite it") from exc


GROUP_STATE = ".group.json"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")


def _json_file(path, label):
    _no_alias(path)
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or path.lstat().st_size > SOURCE_LIMIT:
            raise HostLaunchError(f"{label} is not a bounded regular file")
        data = path.read_bytes()
    except OSError as exc:
        raise HostLaunchError(f"{label} is missing or unreadable") from exc

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique), data
    except (ValueError, UnicodeError) as exc:
        raise HostLaunchError(f"{label} is not unambiguous JSON") from exc


def _installed_inventory(root):
    """Pin every installed file; each size is checked before any byte is read."""
    _no_alias(root)
    files = {}; total = 0
    for path in sorted(root.rglob("*")):
        _no_alias(path)
        if path.is_dir():
            continue
        relative = str(path.relative_to(root))
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise HostLaunchError(f"installed pack file {relative} is not a regular file")
        if len(files) >= FILE_LIMIT:
            raise HostLaunchError("external source inventory exceeds its bound")
        total += metadata.st_size
        if metadata.st_size > SOURCE_LIMIT or total > SOURCE_LIMIT:
            raise HostLaunchError(f"installed pack file {relative} exceeds the {SOURCE_LIMIT}-byte source bound")
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not files:
        raise HostLaunchError("installed pack is empty")
    return files


def _installed_pack_names(installed_root):
    """The installed pack directories of one collection, bounded and sorted."""
    installed_root = Path(_absolute(str(installed_root)))
    _no_alias(installed_root)
    try:
        names = [entry.name for entry in os.scandir(installed_root)
            if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False)]
    except OSError as exc:
        raise HostLaunchError("installed pack collection is unreadable") from exc
    if len(names) > FILE_LIMIT:
        raise HostLaunchError("installed pack collection exceeds its bound")
    return sorted(names)


def _installed_pack_count(installed_root):
    """The real number of installed packs: the grant bound for this collection."""
    return len(_installed_pack_names(installed_root))


def installed_collection_present(installed_root):
    """Whether a selected installed collection exists (an alias still counts, and is refused later)."""
    if not isinstance(installed_root, str) or not installed_root:
        return False
    try:
        return os.path.lexists(_absolute(installed_root))
    except HostLaunchError:
        return True


def _refusal(pack_id, root, reason):
    return {"pack_id": pack_id, "root": str(root),
        "reason": f"installed pack {pack_id} is excluded from host discovery: {reason}"}


def discover_installed_grants(installed_root, names=None):
    """Launch-time discovery: a grant for every installed pack whose record verifies.

    Each pack directory of the selected installed collection goes through the
    single verifier (_derive_installed_grant). A pack that does not verify is
    excluded with a named refusal; it never fails discovery of the others.
    ``names`` is the collection scan the caller already took (one count per
    launch); without it the collection is scanned here.
    Returns (grants, refusals), both ordered by pack name.
    """
    installed_root = Path(_absolute(str(installed_root)))
    grants, refusals = [], []
    for name in (_installed_pack_names(installed_root) if names is None else sorted(names)):
        try:
            grants.append(_derive_installed_grant(installed_root, name))
        except HostLaunchError as exc:
            refusals.append(_refusal(name, installed_root / name, str(exc)))
    return grants, refusals


def _derive_installed_grant(installed_root, pack_id):
    """The single grant derivation: install record -> grant, or a named refusal."""
    if not isinstance(pack_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", pack_id):
        raise HostLaunchError("installed pack identity is invalid")
    installed_root = Path(_absolute(str(installed_root)))
    root = installed_root / pack_id
    state, _ = _json_file(installed_root / GROUP_STATE, "installed group record")
    admission = state.get("admissions", {}).get(pack_id) if isinstance(state, dict) and isinstance(state.get("admissions"), dict) else None
    if (not isinstance(admission, dict) or admission.get("packId", pack_id) != pack_id
            or not isinstance(admission.get("sourceDigest"), str) or not _HEX64.fullmatch(admission["sourceDigest"])):
        raise HostLaunchError("installed pack admission does not verify")
    recorded = admission.get("definitionsDigest")
    if not isinstance(recorded, str) or not _HEX64.fullmatch(recorded):
        raise HostLaunchError("installed pack admission binds no definitions record")
    build = root / ".build"
    if (build / "admission.json").exists():
        browser, _ = _json_file(build / "admission.json", "installed pack browser admission")
        if (not isinstance(browser, dict) or browser.get("packId") != pack_id
                or browser.get("sourceDigest") != admission["sourceDigest"]):
            raise HostLaunchError("installed pack admission does not verify")
    definitions, raw = _json_file(build / "definitions.json", "installed pack definitions record")
    if hashlib.sha256(raw).hexdigest() != recorded:
        raise HostLaunchError("installed pack definitions record differs from its admission digest")
    if not isinstance(definitions, dict) or definitions.get("version") != 1 or not isinstance(definitions.get("source"), dict):
        raise HostLaunchError("installed pack definitions record is invalid")
    source = definitions["source"]
    if source.get("kind") == "folder":
        raise HostLaunchError("installed pack came from a local folder and has no source repository provenance")
    if source.get("kind") != "git" or any(source.get(k) != definitions.get(k) for k in ("repository", "revision", "tree")):
        raise HostLaunchError("installed pack definitions source provenance is inconsistent")
    repository, revision, tree = definitions["repository"], definitions["revision"], definitions["tree"]
    if (not isinstance(repository, str) or not repository or not isinstance(revision, str) or not _HEX40.fullmatch(revision)
            or not isinstance(tree, str) or not _HEX40.fullmatch(tree)):
        raise HostLaunchError("installed pack definitions source provenance is invalid")
    pin, _ = _json_file(root / "PIN", "installed pack PIN")
    if not isinstance(pin, dict) or pin.get("commit") != revision:
        raise HostLaunchError("installed pack definitions revision differs from the install source commit")
    if pin.get("digest") not in (None, admission["sourceDigest"]):
        raise HostLaunchError("installed pack PIN differs from its admission")
    grant = {"repository": repository, "checkout": str(installed_root), "revision": revision,
        "subpath": pack_id, "tree": tree, "root": str(root), "files": _installed_inventory(root),
        "definitions": definitions.get("definitions")}
    try:
        _validate_grants([grant], limit=1)
    except HostLaunchError as exc:
        raise HostLaunchError(f"installed pack definitions are invalid: {exc}") from exc
    return grant


def _current_grant(installed_root, stored):
    """Re-derive a stored grant from the current install, or None (dropped)."""
    if (not isinstance(stored, dict) or stored.get("checkout") != str(installed_root)
            or not isinstance(stored.get("subpath"), str)):
        return None
    try:
        current = _derive_installed_grant(installed_root, stored["subpath"])
    except HostLaunchError:
        return None
    return current if current["root"] == stored.get("root") else None


def _check_grant_count(grants, limit):
    """The collection bound, refused by name: a pack set that grew or shrank
    while this launch derived its grants (``packs add``/``packs remove``)."""
    if limit is not None and isinstance(grants, list) and len(grants) > limit:
        raise HostLaunchError(f"installed pack collection changed during launch: {len(grants)} grants "
            f"exceed the {limit} installed packs counted at discovery; retry the launch")


def _persist_derived_grants(support_root, workspace_uuid, grants, installed_root, *, limit=None):
    """Persist the current grants where the Agent re-reads them.

    The whole read-merge-write runs under an exclusive lock on a sibling lock
    file, so two launches in one workspace serialize: the second always reads
    the first's published grant before it merges. The write is a temporary
    file in the same directory, fsynced, then os.replace (write_protected).
    Grants are keyed by root. Stored grants are only history: each one is kept
    only while its root still derives from the current installed collection,
    so history can never refuse a launch. Unreadable state is a named refusal.
    ``limit`` is the launch's one collection count (taken with its discovery
    scan); without it the collection is counted here.
    """
    from .local_execution_handoff import write_protected
    path = _state_path(support_root)
    _no_alias(path)
    installed = Path(_absolute(str(installed_root))) if installed_root else None
    if limit is None:
        limit = _installed_pack_count(installed) if installed is not None else 0
    platform.private_directory(path.parent)
    with platform.file_lock(path.with_name(path.name + ".lock")):
        previous = _read_state(path, missing_ok=True)
        merged = {}
        if previous is not None:
            if (not isinstance(previous, dict) or not isinstance(previous.get("grants"), list)
                    or not isinstance(previous.get("workspace_uuid"), str)):
                raise HostLaunchError(f"external source owner state {path} is corrupt; refusing to overwrite it")
            if previous["workspace_uuid"] == workspace_uuid and installed is not None:
                for stored in previous["grants"]:
                    current = _current_grant(installed, stored)
                    if current is not None:
                        merged[current["root"]] = current
        merged.update({g["root"]: g for g in grants})
        ordered = [merged[k] for k in sorted(merged)]
        _check_grant_count(ordered, limit)
        _validate_grants(ordered, limit=limit)
        write_protected(path, {"workspace_uuid": workspace_uuid, "grants": ordered})


def _discovery_path(support_root):
    return _state_path(support_root).with_name("discovery.json")


def _record_discovery(support_root, workspace_uuid, installed_root, refusals):
    """Record the launch-time discovery refusals for diagnostics.

    The record is separate from grants.json (whose shape the Agent re-reads),
    written atomically under the same grants lock. It is diagnostics only: it
    never grants or refuses anything.
    """
    from .local_execution_handoff import write_protected
    state = _state_path(support_root)
    path = _discovery_path(support_root)
    _no_alias(path)
    platform.private_directory(path.parent)
    with platform.file_lock(state.with_name(state.name + ".lock")):
        write_protected(path, {"workspace_uuid": workspace_uuid, "installed_pack_root": installed_root,
            "refusals": list(refusals)})


def _validate_grants(grants, *, limit=None):
    """``limit`` is the real installed-pack count of the selected collection.

    The Agent host re-validates the shape of the launcher's private capture,
    already bounded at capture, with ``_validate_grants(grants)``; that call
    has no collection to count, so ``None`` applies no count bound.
    """
    if not isinstance(grants, list) or (limit is not None and len(grants) > limit):
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
    if (checkout / GROUP_STATE).exists():
        # Installed collection: provenance is the verified install record, not a git read.
        if _derive_installed_grant(checkout, Path(grant["subpath"]).name) != grant:
            raise HostLaunchError("installed pack differs from its derived custody grant")
        return _materialize(grant, root, None)
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
    return _materialize(grant, root, blobs)


def _materialize(grant, root, blobs):
    """Pin and read every file; ``blobs`` (git object ids) is None for installed packs."""
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
    if actual != set(grant["files"]) or (blobs is not None and actual != set(blobs)):
        raise HostLaunchError("external source inventory differs from exact repository tree")
    contents = {}; total = 0
    for relative, pin in grant["files"].items():
        if (root / relative).stat().st_size > SOURCE_LIMIT:
            raise HostLaunchError("external source file exceeds its bound")
        data = read_source(root / relative, pin); total += len(data)
        if total > SOURCE_LIMIT:
            raise HostLaunchError("external captured source exceeds its bound")
        if blobs is not None and hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != blobs[relative]:
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
        selected = preparation["profile"]["host_launch"].get("additional_pack_roots") or []
        # THE grant lookup: every selected source must be a pack of the selected
        # installed collection; its grant is derived from the install record.
        installed = config.get("installed_pack_root")
        derived = []
        for extra in selected:
            if not isinstance(installed, str) or not installed:
                raise HostLaunchError("selected external source has no owner grant: no installed pack collection is selected")
            path = _absolute(extra["path"])
            if path.parent != _absolute(installed):
                raise HostLaunchError("selected external source has no owner grant: it is outside the selected installed pack collection")
            derived.append(_derive_installed_grant(installed, path.name))
        # Launch-time discovery: every installed pack whose record verifies is
        # granted at custody build, selected or not; the rest are named refusals.
        # The collection is scanned and counted ONCE, before the persist: the
        # same count bounds the persist and the check below, so a ``packs
        # remove`` in between cannot turn into a generic grant refusal (N1).
        has_collection = isinstance(installed, str) and bool(installed)
        names = _installed_pack_names(installed) if has_collection else []
        limit = len(names)
        discovered, refusals = (discover_installed_grants(installed, names) if has_collection else ([], []))
        workspace = preparation["profile"]["workspace_uuid"]
        _persist_derived_grants(config["support_root"], workspace, [*derived, *discovered], installed, limit=limit)
        state = _read_state(self._path)
        if not isinstance(state, dict) or set(state) != {"workspace_uuid", "grants"} or state["workspace_uuid"] != workspace:
            raise HostLaunchError("external source owner scope differs")
        _check_grant_count(state["grants"], limit)
        _validate_grants(state["grants"], limit=limit)
        self._workspace = state["workspace_uuid"]
        self._support_root = config["support_root"]
        self._installed = installed if has_collection else None
        self._collection_identity = _identity(Path(_absolute(installed)), ancestor=True) if has_collection else None
        self._grants = []
        for extra in selected:
            matches = [g for g in state["grants"] if g["root"] == extra["path"] and g["files"] == extra["files"]]
            if len(matches) != 1:
                raise HostLaunchError("selected external source has no owner grant")
            self._grants.append(matches[0])
        self._selected_roots = frozenset(g["root"] for g in self._grants)
        captured = [_capture(g) for g in self._grants]
        chosen = {g["root"] for g in self._grants}
        for grant in discovered:
            if grant["root"] in chosen:
                continue
            if grant not in state["grants"]:
                refusals.append(_refusal(grant["subpath"], grant["root"], "its owner grant changed during discovery"))
                continue
            try:
                source = _capture(grant)
            except HostLaunchError as exc:
                refusals.append(_refusal(grant["subpath"], grant["root"], str(exc)))
                continue
            self._grants.append(grant); captured.append(source); chosen.add(grant["root"])
        self._refusals = tuple(sorted(refusals, key=lambda r: r["pack_id"]))
        if self._installed is not None:
            _record_discovery(config["support_root"], workspace, installed, self._refusals)
        self._scope = {k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch", "custody_scope")}
        self._profile_digest = raw_digest(preparation["profile"])
        self._captured = captured
        self._payload = self._render_payload()
        self._pinned = False
        self._claimed = False
        self._lock = threading.Lock()
        self.verify(preparation=preparation, config=config)

    def _render_payload(self):
        return canonical({"scope": self._scope, "selected_profile_digest": self._profile_digest,
            "sources": self._captured})

    @property
    def payload(self):
        """The captured bytes. Reading them fixes the launch set (see ``pin``)."""
        self._pinned = True
        return self._payload

    @property
    def launch_roots(self):
        """Every granted root this launch carries: selected first, then discovered."""
        return [g["root"] for g in self._grants]

    def pin(self, *, preparation, config):
        """Re-verify, exclude changed unselected packs, then fix the launch set.

        The host argv carries a --pack-root for each returned root and the
        verified launch pins this payload, so after the pin no pack can be
        dropped any more: every carried pack is then verified strictly.
        """
        with self._lock:
            self.verify(preparation=preparation, config=config)
            self._pinned = True
            return self.launch_roots

    @property
    def refusals(self):
        """Named refusals for installed packs excluded at discovery (diagnostics)."""
        return [dict(r) for r in self._refusals]

    def __reduce__(self):
        raise TypeError("external source captures cannot be serialized")

    def verify(self, *, preparation, config):
        """Selected packs, the owner scope and the collection itself are verified
        strictly: any change refuses the whole launch. Until the launch is pinned
        (``pin``), an unselected discovered pack that changed after capture is
        excluded on its own with a named refusal and the others still launch (N2);
        once pinned, the argv and payload carry it, so it is verified strictly."""
        if canonical({"preparation": preparation, "config": config}) != self._context:
            raise HostLaunchError("external source launch scope changed")
        current = _read_state(self._path)
        if not isinstance(current, dict) or current.get("workspace_uuid") != self._workspace:
            raise HostLaunchError("external source owner grant changed")
        if self._installed is not None:
            try:
                root = Path(_absolute(self._installed))
                _no_alias(root)
                same = _identity(root, ancestor=True) == self._collection_identity
            except (HostLaunchError, OSError) as exc:
                raise HostLaunchError("installed pack collection changed after capture") from exc
            if not same:
                raise HostLaunchError("installed pack collection changed after capture")
        excluded = []
        for index, (grant, source) in enumerate(zip(self._grants, self._captured)):
            strict = self._pinned or grant["root"] in self._selected_roots
            if grant not in current.get("grants", []):
                if strict:
                    raise HostLaunchError("external source owner grant changed")
                excluded.append((index, "its owner grant changed after capture"))
                continue
            try:
                same = canonical(_capture(grant)) == canonical(source)
                reason = "it changed after capture"
            except HostLaunchError as exc:
                if strict:
                    raise
                same, reason = False, f"it changed after capture: {exc}"
            if not same:
                if strict:
                    raise HostLaunchError("external source changed after capture")
                excluded.append((index, reason))
        if excluded:
            dropped = {index for index, _ in excluded}
            refusals = [*self._refusals, *(_refusal(self._grants[i]["subpath"], self._grants[i]["root"], reason)
                for i, reason in excluded)]
            self._grants = [g for i, g in enumerate(self._grants) if i not in dropped]
            self._captured = [c for i, c in enumerate(self._captured) if i not in dropped]
            self._refusals = tuple(sorted(refusals, key=lambda r: r["pack_id"]))
            self._payload = self._render_payload()
            _record_discovery(self._support_root, self._workspace, self._installed, self._refusals)

    def claim(self, *, preparation, config):
        with self._lock:
            if self._claimed:
                raise HostLaunchError("external source capture already claimed")
            self._claimed = True
            self._pinned = True
            self.verify(preparation=preparation, config=config)
            return self.payload
