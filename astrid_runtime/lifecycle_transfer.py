"""Private provisional lifecycle transfer facade and observational ledger.

Installation authority is a caller precondition. This module does not establish
admission, native provenance, a writer, or recovery authority.
"""

try:
    import fcntl
except ImportError:  # The facade still imports on unsupported platforms.
    fcntl = None

import hashlib
import json
import os
import re
import stat
import sys
import threading
from pathlib import Path

from ._realm_fence import FenceUnavailable, _identity, _open_directory
from ._transfer_session import ProvisionalTransferSession


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_SOURCE = 64 * 1024 * 1024
_LEDGER = "lifecycle-transfer-ledger.json"
_LEDGER_TEMP = ".lifecycle-transfer-ledger.tmp"
_LEDGER_LIMIT = 128 * 1024
_LEDGER_ENTRIES = 128
_LEDGER_PHASE = "observed"
_RECOVERY = "recovery_required"
_RECOVERY_REASONS = frozenset(("unknown_identity", "binding_changed", "incomplete_census",
                               "restart_unfenced", "lease_uncertain", "durability_failed",
                               "recovery_required"))


def _closed(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise FenceUnavailable("malformed closed binding")
    return value


def _text(value):
    if type(value) is not str or not value or len(value) > 4096 or "\x00" in value:
        raise FenceUnavailable("malformed binding value")
    return value


def _digest(value, pattern=_HEX):
    if type(value) is not str or not pattern.fullmatch(value):
        raise FenceUnavailable("malformed binding digest")
    return value


def _file_id(value):
    if (type(value) is not list or len(value) != 2
            or any(type(part) is not int or part < 0 for part in value)):
        raise FenceUnavailable("malformed file identity")
    return tuple(value)


def _path(value):
    _text(value)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise FenceUnavailable("binding path must be absolute and normalized")
    return path


def _object(value):
    _closed(value, ("path", "file_id"))
    return (_path(value["path"]), _file_id(value["file_id"]))


def _source(value):
    _closed(value, ("repository_sha", "version_document_digest", "profile_digest",
                    "manifest_digest", "module"))
    _digest(value["repository_sha"], _SHA)
    for key in ("version_document_digest", "profile_digest", "manifest_digest"):
        _digest(value[key])
    module = _closed(value["module"], ("path", "file_id", "sha256"))
    return (_path(module["path"]), _file_id(module["file_id"]), _digest(module["sha256"]))


def _check_directory(bound):
    path, expected = bound
    fd = _open_directory(path)
    try:
        if _identity(os.fstat(fd)) != expected:
            raise FenceUnavailable("bound directory identity changed")
    finally:
        os.close(fd)


def _check_source(source):
    path, expected, digest = source
    parent = _open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or _identity(before) != expected
                or _identity(named) != expected or before.st_size > _MAX_SOURCE):
            raise FenceUnavailable("bound source identity changed")
        hasher = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > _MAX_SOURCE:
                raise FenceUnavailable("bound source too large")
            hasher.update(block)
        after = os.fstat(fd)
        named_after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        current_parent = _open_directory(path.parent)
        try:
            parent_unchanged = _identity(os.fstat(current_parent)) == _identity(os.fstat(parent))
        finally:
            os.close(current_parent)
        if (not parent_unchanged or hasher.hexdigest() != digest or _identity(named_after) != expected
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise FenceUnavailable("bound source content changed")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _parse_binding(binding):
    _closed(binding, ("version", "operation_id", "attempt_id", "transfer_id", "generation",
                      "controller", "installation", "program", "data", "support", "realm",
                      "old_source", "candidate_source", "prior_selection_digest",
                      "journal_digest", "manager", "publications", "origin", "prior_state",
                      "root_lineage", "role"))
    if binding["version"] != "astrid.lifecycle-transfer/v1":
        raise FenceUnavailable("unsupported binding version")
    for key in ("operation_id", "attempt_id", "transfer_id", "generation"):
        _text(binding[key])
    controller = _closed(binding["controller"], ("pid", "uid", "birth"))
    if any(type(controller[k]) is not int or controller[k] < 0 for k in ("pid", "uid")):
        raise FenceUnavailable("malformed controller identity")
    _text(controller["birth"])
    directories = tuple(_object(binding[k]) for k in ("installation", "program", "data", "support"))
    realm = _closed(binding["realm"], ("uuid", "root", "owner_file_id"))
    _text(realm["uuid"])
    root = _object(realm["root"])
    owner_id = _file_id(realm["owner_file_id"])
    sources = (_source(binding["old_source"]), _source(binding["candidate_source"]))
    for key in ("prior_selection_digest", "journal_digest"):
        _digest(binding[key])
    manager = _closed(binding["manager"], ("kind", "namespace", "target", "definition_digest"))
    for key in ("kind", "namespace", "target"):
        _text(manager[key])
    _digest(manager["definition_digest"])
    publications = _closed(binding["publications"], ("instance", "discovery", "incarnation"))
    for name in ("instance", "discovery"):
        item = _closed(publications[name], ("status", "digest"))
        if item["status"] not in ("absent", "present") or type(item["status"]) is not str:
            raise FenceUnavailable("malformed publication status")
        if item["status"] == "absent":
            if item["digest"] is not None:
                raise FenceUnavailable("malformed publication digest")
        else:
            _digest(item["digest"])
    if publications["incarnation"] is not None:
        _text(publications["incarnation"])
    if type(binding["origin"]) is not str or binding["origin"] not in ("stopped-r0", "live-r1"):
        raise FenceUnavailable("malformed origin")
    state = _closed(binding["prior_state"], ("running", "loaded", "enabled"))
    if any(type(state[k]) is not bool for k in state):
        raise FenceUnavailable("malformed prior state")
    lineage = binding["root_lineage"]
    if type(lineage) is not list or not lineage or len(lineage) > 32:
        raise FenceUnavailable("malformed root lineage")
    for item in lineage:
        _file_id(item)
    if type(binding["role"]) is not str or binding["role"] not in ("offline-backup", "migration", "candidate", "rollback-r1"):
        raise FenceUnavailable("malformed role")
    return directories, root, owner_id, sources


class ProvisionalFence:
    """An opaque live-session reference; it is not admission or a receipt."""

    def __init__(self, session):
        self._session = session

    def revalidate(self):
        self._session._revalidate()


class TransferSession:
    """Own the R2 fence until close; no descriptor aliases are exported."""

    def __init__(self, paths, binding):
        if sys.platform not in ("linux", "darwin"):
            raise FenceUnavailable("unsupported transfer platform")
        try:
            self._directories, self._root, self._owner_id, self._sources = _parse_binding(binding)
            # Keep an immutable commitment to every closed field, including fields
            # this provisional boundary cannot independently verify yet.
            encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self._binding_digest = hashlib.sha256(encoded).hexdigest()
            self._operation_id = binding["operation_id"]
            self._generation = binding["generation"]
            self._support = _path(str(paths.runtime_support))
            self._bootstrap = _path(str(paths.bootstrap_lock_path))
            if self._directories[3][0] != self._support or self._bootstrap != self._support / "bootstrap.lock":
                raise FenceUnavailable("support binding mismatch")
        except (AttributeError, TypeError, ValueError) as exc:
            raise FenceUnavailable("malformed transfer input") from exc
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._custody = None
        self._fence = None
        self._closed = False
        self._poisoned = False

    def _check(self):
        if self._closed or self._poisoned or os.getpid() != self._pid:
            raise FenceUnavailable("transfer session unavailable")

    def _validate_binding(self):
        for directory in (*self._directories, self._root):
            _check_directory(directory)
        for source in self._sources:
            _check_source(source)
        if self._custody is not None:
            self._custody.revalidate()
            realm = self._custody._realm
            if (_identity(os.fstat(realm._directory_fd)) != self._root[1]
                    or _identity(os.fstat(realm._owner_fd)) != self._owner_id
                    or _identity(os.fstat(self._custody._support_fd)) != self._directories[3][1]):
                raise FenceUnavailable("held identity differs from binding")

    def _revalidate_locked(self):
        self._check()
        try:
            self._validate_binding()
        except (OSError, FenceUnavailable) as exc:
            self._poisoned = True
            raise FenceUnavailable("transfer binding changed or unavailable") from exc

    def _revalidate(self):
        with self._mutex:
            self._check()
            if self._custody is None:
                raise FenceUnavailable("provisional fence not acquired")
            self._revalidate_locked()

    def pin_and_acquire_original(self):
        with self._mutex:
            self._check()
            if self._custody is not None:
                self._revalidate_locked()
                return self._fence
            self._revalidate_locked()
            try:
                self._custody = ProvisionalTransferSession(
                    _Paths(self._support, self._bootstrap), self._root[0])
                self._revalidate_locked()
            except BaseException:
                if self._custody is not None:
                    self._custody.close()
                    self._custody = None
                self._poisoned = True
                raise
            self._fence = ProvisionalFence(self)
            return self._fence

    @property
    def binding_digest(self):
        """The commitment the caller must include in each ledger request."""
        return self._binding_digest

    def _ledger_directory(self):
        fd = _open_directory(self._support)
        try:
            info = os.fstat(fd)
            if (_identity(info) != self._directories[3][1] or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise FenceUnavailable("ledger support binding changed")
            # Serialize cooperating readers/writers without creating a lock file.
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = _open_directory(self._support)
            try:
                if _identity(os.fstat(current)) != _identity(info):
                    raise FenceUnavailable("ledger support binding changed")
            finally:
                os.close(current)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _verify_ledger_directory(self, directory):
        held = os.fstat(directory)
        current = _open_directory(self._support)
        try:
            if (_identity(os.fstat(current)) != _identity(held)
                    or _identity(held) != self._directories[3][1]
                    or held.st_uid != os.geteuid() or held.st_mode & 0o077):
                raise FenceUnavailable("binding_changed")
        finally:
            os.close(current)

    def _read_ledger(self, directory):
        try:
            os.stat(_LEDGER_TEMP, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FenceUnavailable("recovery_required: interrupted ledger write")
        try:
            fd = os.open(_LEDGER, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            named = os.stat(_LEDGER, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_mode & 0o077 or before.st_nlink != 1
                    or _identity(before) != _identity(named) or before.st_size > _LEDGER_LIMIT):
                raise FenceUnavailable("recovery_required: invalid ledger file")
            data = b""
            while len(data) <= _LEDGER_LIMIT:
                block = os.read(fd, min(65536, _LEDGER_LIMIT + 1 - len(data)))
                if not block:
                    break
                data += block
            after = os.fstat(fd)
            named_after = os.stat(_LEDGER, dir_fd=directory, follow_symlinks=False)
            if (len(data) > _LEDGER_LIMIT or _identity(named_after) != _identity(before)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise FenceUnavailable("recovery_required: ledger changed")
            try:
                ledger = json.loads(data)
                if _encode_ledger(ledger) != data:
                    raise ValueError("noncanonical ledger")
                _validate_ledger(ledger)
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
                raise FenceUnavailable("recovery_required: invalid ledger") from exc
            return ledger
        finally:
            os.close(fd)

    def _check_ledger_binding(self, ledger):
        if (ledger["operation_id"] != self._operation_id
                or ledger["generation"] != self._generation
                or ledger["binding_digest"] != self._binding_digest):
            raise FenceUnavailable("binding_changed")

    def query(self):
        """Read recorded ledger facts only; this does not check native state or custody."""
        with self._mutex:
            self._check()
            directory = None
            try:
                directory = self._ledger_directory()
                ledger = self._read_ledger(directory)
                if ledger is None:
                    return {"phase": _LEDGER_PHASE, "requests": []}
                self._check_ledger_binding(ledger)
                return {"phase": _ledger_phase(ledger), "requests": ledger["requests"]}
            except OSError as exc:
                raise FenceUnavailable("recovery_required: ledger unavailable") from exc
            finally:
                if directory is not None:
                    os.close(directory)

    def record_request(self, *, operation_id, generation, request_id, expected_phase, binding_digest):
        """Sequence a ledger-only request; no lifecycle action or authority is conferred."""
        request = {"operation_id": operation_id, "generation": generation,
                   "request_id": request_id, "expected_phase": expected_phase,
                   "binding_digest": binding_digest}
        return self._record(request)

    def require_recovery(self, *, operation_id, generation, request_id, expected_phase,
                         binding_digest, reason):
        """Durably block progress on uncertainty; this creates no native authority.

        The reason is a reported uncertainty, not a verified native observation.
        Recovery or a new generation requires the separate native protocol.
        """
        request = {"operation_id": operation_id, "generation": generation,
                   "request_id": request_id, "expected_phase": expected_phase,
                   "binding_digest": binding_digest, "action": "require_recovery",
                   "reason": reason}
        return self._record(request)

    def request_transition(self, *, operation_id, generation, request_id, expected_phase,
                           binding_digest, target_phase):
        """Record an explicit refusal of transitions lacking their required producers."""
        request = {"operation_id": operation_id, "generation": generation,
                   "request_id": request_id, "expected_phase": expected_phase,
                   "binding_digest": binding_digest, "action": "transition",
                   "target_phase": target_phase}
        return self._record(request)

    def _record(self, request):
        _validate_request(request)
        operation_id = request["operation_id"]
        generation = request["generation"]
        request_id = request["request_id"]
        expected_phase = request["expected_phase"]
        binding_digest = request["binding_digest"]
        with self._mutex:
            self._check()
            directory = None
            try:
                self._revalidate_locked()
                directory = self._ledger_directory()
                ledger = self._read_ledger(directory)
                if ledger is not None:
                    # Check reused IDs before other envelope mismatches.
                    for entry in ledger["requests"]:
                        if entry["request"]["request_id"] == request_id:
                            if entry["request"] != request:
                                raise FenceUnavailable("binding_changed")
                            self._check_ledger_binding(ledger)
                            # A previous rename may have succeeded before a failed fsync.
                            fd = os.open(_LEDGER, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         dir_fd=directory)
                            try:
                                _sync_file(fd)
                                os.fsync(directory)
                            finally:
                                os.close(fd)
                            self._revalidate_locked()
                            self._verify_ledger_directory(directory)
                            return dict(entry["result"])
                    self._check_ledger_binding(ledger)
                if (operation_id != self._operation_id or generation != self._generation
                        or binding_digest != self._binding_digest):
                    raise FenceUnavailable("binding_changed")
                if expected_phase != (_ledger_phase(ledger) if ledger else _LEDGER_PHASE):
                    raise FenceUnavailable("stale_phase")
                if ledger is None:
                    ledger = {"version": 1, "operation_id": self._operation_id,
                              "generation": self._generation, "binding_digest": self._binding_digest,
                              "requests": []}
                if len(ledger["requests"]) >= _LEDGER_ENTRIES:
                    raise FenceUnavailable("recovery_required: ledger full")
                result = {"code": "recorded", "stage": "ledger_only",
                          "lifecycle_side_effect": False, "sequence": len(ledger["requests"]) + 1}
                if request.get("action") == "require_recovery":
                    result.update(code=_RECOVERY, stage="recovery_required", phase=_RECOVERY)
                elif request.get("action") == "transition":
                    result.update(code=_transition_refusal(request["target_phase"]), stage="transition_refused")
                ledger["requests"].append({"request": request, "result": result})
                data = _encode_ledger(ledger)
                if len(data) > _LEDGER_LIMIT:
                    raise FenceUnavailable("recovery_required: ledger full")
                _write_ledger(directory, data)
                self._revalidate_locked()
                self._verify_ledger_directory(directory)
                return dict(result)
            except OSError as exc:
                raise FenceUnavailable("durability_failed") from exc
            finally:
                if directory is not None:
                    os.close(directory)

    def close(self):
        with self._mutex:
            if os.getpid() != self._pid:
                raise FenceUnavailable("transfer session belongs to another process")
            self._closed = True
            if self._custody is not None:
                custody, self._custody = self._custody, None
                custody.close()

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *exc):
        self.close()


class _Paths:
    def __init__(self, support, bootstrap):
        self.runtime_support = support
        self.bootstrap_lock_path = bootstrap


def begin_transfer(paths, *, binding):
    """Create a session without acquiring realm write permission."""
    return TransferSession(paths, binding)


def _encode_ledger(ledger):
    return json.dumps(ledger, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _validate_request(request):
    keys = ("operation_id", "generation", "request_id", "expected_phase", "binding_digest")
    if type(request) is dict and "action" in request:
        if request["action"] == "require_recovery":
            _closed(request, (*keys, "action", "reason"))
            if type(request["reason"]) is not str or request["reason"] not in _RECOVERY_REASONS:
                raise FenceUnavailable("unsupported_transfer")
        elif request["action"] == "transition":
            _closed(request, (*keys, "action", "target_phase"))
            if type(request["target_phase"]) is not str or not 0 < len(request["target_phase"]) <= 256:
                raise FenceUnavailable("unsupported_transfer")
        else:
            raise FenceUnavailable("unsupported_transfer")
    else:
        _closed(request, keys)
    for key in ("operation_id", "generation", "request_id", "expected_phase"):
        value = _text(request[key])
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise FenceUnavailable("malformed ledger request") from exc
        if size > 256:
            raise FenceUnavailable("malformed ledger request")
    _digest(request["binding_digest"])


def _ledger_phase(ledger):
    return _RECOVERY if any(e["request"].get("action") == "require_recovery"
                            for e in ledger["requests"]) else _LEDGER_PHASE


def _transition_refusal(target):
    if target in ("writer_claimed", "ready", "commit_intent", "commit_decided",
                  "committed", "rollback_intent", "rollback_decided", "rolled_back_stopped"):
        return "lease_uncertain"
    if target == "restart_fenced":
        return "restart_unfenced"
    if target == "held_admitted":
        return "incomplete_census"
    if target in ("prepared", "held_provisional", "preparing_data", "selected", "recovery_required"):
        return "recovery_required"
    return "unsupported_transfer"


def _validate_ledger(ledger):
    if type(ledger) is not dict or set(ledger) != {"version", "operation_id", "generation", "binding_digest", "requests"}:
        raise ValueError("invalid ledger fields")
    if type(ledger["version"]) is not int or ledger["version"] != 1 or type(ledger["requests"]) is not list or len(ledger["requests"]) > _LEDGER_ENTRIES:
        raise ValueError("invalid ledger version or length")
    seen = set()
    phase = _LEDGER_PHASE
    for sequence, entry in enumerate(ledger["requests"], 1):
        if type(entry) is not dict or set(entry) != {"request", "result"}:
            raise ValueError("invalid ledger entry")
        request = entry["request"]
        try:
            _validate_request(request)
        except FenceUnavailable as exc:
            raise ValueError("invalid request") from exc
        if (request["request_id"] in seen or request["operation_id"] != ledger["operation_id"]
                or request["generation"] != ledger["generation"]
                or request["binding_digest"] != ledger["binding_digest"]
                or request["expected_phase"] != phase):
            raise ValueError("inconsistent ledger request")
        seen.add(request["request_id"])
        result = entry["result"]
        expected = {"code": "recorded", "stage": "ledger_only",
                    "lifecycle_side_effect": False, "sequence": sequence}
        if request.get("action") == "require_recovery":
            phase = _RECOVERY
            expected.update(code=_RECOVERY, stage="recovery_required", phase=_RECOVERY)
        elif request.get("action") == "transition":
            expected.update(code=_transition_refusal(request["target_phase"]), stage="transition_refused")
        if (type(result) is not dict or result != expected
                or result.get("lifecycle_side_effect") is not False
                or type(result.get("sequence")) is not int):
            raise ValueError("invalid ledger result")
    if not ledger["requests"]:
        raise ValueError("empty ledger")


def _sync_file(fd):
    # macOS fsync alone need not flush hardware caches. Refuse if full sync is
    # unavailable rather than acknowledge a weaker persistence guarantee.
    if sys.platform == "darwin":
        full_sync = getattr(fcntl, "F_FULLFSYNC", None)
        if full_sync is None:
            raise OSError("full file sync unavailable")
        fcntl.fcntl(fd, full_sync)
    else:
        os.fsync(fd)


def _write_ledger(directory, data):
    # An interrupted temporary file blocks later writes until recovery; it is
    # never overwritten, and repeated crashes cannot accumulate unbounded files.
    name = _LEDGER_TEMP
    fd = None
    created = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        created = True
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short ledger write")
            offset += written
        _sync_file(fd)
        os.close(fd)
        fd = None
        os.replace(name, _LEDGER, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        if created:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
