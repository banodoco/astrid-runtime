"""38-04: Linux observation parity, exit witnesses and census races."""
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from runtime_protocol import linux_process_binding as linux
from runtime_protocol import platform, process_binding
from tests.lanes import requires_linux_procfs_census


BOOT = "b38142f7-84c5-487d-95a4-8180cbff3972"


@requires_linux_procfs_census
def test_native_live_and_unreaped_child_birth_parity():
    child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"],
                             stdin=subprocess.PIPE)
    try:
        own = platform.process_identity(os.getpid())
        expected = platform.process_identity(child.pid)
        assert own and expected
        assert platform.process_birth_matches(expected["birth_id"], expected["birth_id"]) is True
        ticks = process_binding.birth_ticks(child.pid)
        assert ticks and ticks.isascii() and ticks.isdigit()
        assert expected["birth_id"].startswith("proc-start-ticks:" + ticks + ";")
        assert process_binding.zombie_birth(child.pid) is None
        live = process_binding.census()
        assert live.status in ("complete", "partial"), live.failure
        assert live.live[os.getpid()] == own
        assert live.live[child.pid] == expected
        assert child.pid not in live.exited
        assert child.pid not in live.unverified_parents

        child.stdin.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG):
                break
            time.sleep(0.01)
        else:
            pytest.fail("child did not exit before deadline")
        # waitid(WNOWAIT) preserves the original PID until our sole waiter reaps.
        assert platform.process_identity(child.pid) is None
        assert process_binding.birth_ticks(child.pid) is None
        assert process_binding.zombie_birth(child.pid) == expected["birth_id"]
        exited = process_binding.census()
        assert child.pid not in exited.live
        assert exited.exited[child.pid] == expected["birth_id"]
        assert child.wait(timeout=5) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if child.stdin is not None:
            child.stdin.close()


def _record(pid, ppid, ticks, kind="live"):
    return ({"pid": pid, "uid": 501, "parent_pid": ppid,
             "process_group": 20, "session_id": 20,
             "birth_id": platform.linux_birth_id(str(ticks), boot_id=BOOT, pidns_inode=7)},
            kind, str(ticks))


def _census_fixture(monkeypatch, observations, final_pids=None):
    # Only dispatch selection is simulated: pure census logic runs on every OS.
    monkeypatch.setattr(process_binding, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(linux, "_census_boot", lambda root: BOOT)
    first = set(observations)
    scans = iter((first, first if final_pids is None else final_pids))
    monkeypatch.setattr(linux, "_census_pids", lambda root: next(scans))
    rows = {pid: iter(values) for pid, values in observations.items()}

    def read(root, pid, boot):
        assert boot == BOOT
        value = next(rows[pid])
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(linux, "_read_census_record", read)


def test_census_separates_live_zombie_and_dying(monkeypatch):
    parent = _record(20, 0, 100)
    live = _record(21, 20, 101)
    zombie = _record(22, 20, 102, "exited")
    dying = _record(23, 20, 103, "dying")
    _census_fixture(monkeypatch, {20: [parent, parent], 21: [live, live],
                                 22: [zombie, zombie], 23: [dying]})
    result = process_binding.census()
    assert result.status == "partial"
    assert result.failure
    assert result.live == {20: parent[0], 21: live[0]}
    assert result.exited == {22: zombie[0]["birth_id"]}
    assert 23 in result.unknown
    assert result.unverified_parents == ()


def test_complete_census_reports_no_unknown_rows(monkeypatch):
    parent = _record(20, 0, 100)
    child = _record(21, 20, 101)
    _census_fixture(monkeypatch, {20: [parent, parent], 21: [child, child]})
    result = process_binding.census()
    assert result.status == "complete"
    assert result.failure is None
    assert result.unknown == {}
    assert result.unverified_parents == ()


def test_recycled_parent_and_reparented_child_cannot_supply_continuity(monkeypatch):
    parent = _record(20, 0, 100)
    replacement = _record(20, 0, 200)
    child = _record(21, 20, 101)
    reparented = _record(22, 20, 102)
    fresh = _record(22, 1, 102)
    _census_fixture(monkeypatch, {20: [parent, replacement], 21: [child, child],
                                 22: [reparented, fresh]})
    result = process_binding.census()
    assert result.status == "partial"
    assert set(result.unknown) == {20, 22}
    assert result.live == {21: child[0]}
    assert result.unverified_parents == (21,)
    assert result.exited == {}


def test_parent_newer_than_child_cannot_supply_continuity(monkeypatch):
    parent = _record(20, 0, 200)
    child = _record(21, 20, 101)
    _census_fixture(monkeypatch, {20: [parent, parent], 21: [child, child]})
    result = process_binding.census()
    assert result.status == "partial"
    assert result.unverified_parents == (21,)


def test_denied_vanished_and_new_rows_are_explicit(monkeypatch):
    live = _record(20, 0, 100)
    _census_fixture(monkeypatch, {20: [live, live], 21: [PermissionError("denied")],
                                 22: [None]}, final_pids={20, 21, 23})
    result = process_binding.census()
    assert result.status == "partial"
    assert result.live == {20: live[0]}
    assert set(result.unknown) == {21, 22, 23}
    assert result.exited == {}


def test_unavailable_census_is_not_an_empty_success(monkeypatch):
    monkeypatch.setattr(process_binding, "sys", SimpleNamespace(platform="linux"))
    def denied(root):
        raise PermissionError("boot denied")

    monkeypatch.setattr(linux, "_census_boot", denied)
    result = process_binding.census()
    assert result.status == "unavailable"
    assert "boot denied" in result.failure
    assert not result.live and not result.exited
    with pytest.raises(OSError, match="boot denied"):
        process_binding.zombie_birth(20)


@requires_linux_procfs_census
def test_proc_record_does_not_splice_reparented_topology(monkeypatch, tmp_path):
    proc = tmp_path / "20"
    proc.mkdir()
    (proc / "status").write_bytes(b"Uid:\t501\t501\t501\t501\n")
    snapshots = iter([("42", 10, 20, 20, "live"), ("42", 1, 20, 20, "live")])
    monkeypatch.setattr(linux, "_read_census_stat", lambda directory, pid: next(snapshots))
    with pytest.raises(OSError, match="topology changed"):
        linux._read_census_record(tmp_path, 20, None)


def test_birth_builder_preserves_partial_scope_without_promoting_it():
    scoped = platform.linux_birth_id("42", boot_id=BOOT, pidns_inode=7)
    assert scoped == f"proc-start-ticks:42;boot:{BOOT};pidns:7"
    for partial in (platform.linux_birth_id("42"),
                    platform.linux_birth_id("42", boot_id=BOOT),
                    platform.linux_birth_id("42", pidns_inode=7)):
        assert platform.process_birth_matches(partial, scoped) is None
    with pytest.raises(ValueError, match="start tick"):
        platform.linux_birth_id("bad")


def test_status_uid_is_effective_not_real_saved_or_filesystem():
    assert linux._parse_census_uid([b"Name: worker\n", b"Uid:\t1001\t1002\t1003\t1004\n"]) == 1002


@pytest.mark.parametrize("lines", [
    [],
    [b"Uid: 1 2 3"],
    [b"Uid: 1 -2 3 4"],
    [b"Uid: 1 root 3 4"],
    [b"Uid: 1 4294967295 3 4"],
    [b"Uid: 1 2 3 4", b"Uid: 5 6 7 8"],
], ids=["absent", "short", "negative", "nonnumeric", "out-of-range", "duplicate"])
def test_malformed_status_uid_is_not_an_observation(lines):
    with pytest.raises(OSError, match="status uid"):
        linux._parse_census_uid(lines)


@requires_linux_procfs_census
def test_proc_record_uses_status_uid_not_directory_owner(monkeypatch, tmp_path):
    proc = tmp_path / "20"
    proc.mkdir()
    actual_owner = proc.stat().st_uid
    effective_uid = 1002 if actual_owner != 1002 else 1003
    (proc / "status").write_text(f"Uid: 1001 {effective_uid} 1004 1005\n")
    monkeypatch.setattr(linux, "_read_census_stat", lambda directory, pid: ("42", 10, 20, 20, "live"))
    row, kind, ticks = linux._read_census_record(tmp_path, 20, None)
    assert row["uid"] == effective_uid != actual_owner
    assert kind == "live" and ticks == "42"


@requires_linux_procfs_census
def test_proc_record_rejects_uid_change_and_missing_status(monkeypatch, tmp_path):
    proc = tmp_path / "20"
    proc.mkdir()
    monkeypatch.setattr(linux, "_read_census_stat", lambda directory, pid: ("42", 10, 20, 20, "live"))
    with pytest.raises(OSError, match="effective UID observation unavailable"):
        linux._read_census_record(tmp_path, 20, None)
    observations = iter((1002, 1003))
    monkeypatch.setattr(linux, "_read_census_uid", lambda directory: next(observations))
    with pytest.raises(OSError, match="effective UID or topology changed"):
        linux._read_census_record(tmp_path, 20, None)


def _native_nondumpable_self_observation():
    # Do not change the pytest process's dumpability. The disposable child
    # observes its own namespace; a different observer may be denied access.
    script = """
import ctypes
import json
import os
import sys
from pathlib import Path
from runtime_protocol import linux_process_binding as linux
from runtime_protocol import platform
if not __debug__ or sys.platform != 'linux':
    raise RuntimeError('native census observation requires Linux with assertions enabled')
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(4, 0, 0, 0, 0) == 0, ctypes.get_errno()  # PR_SET_DUMPABLE
dumpable = libc.prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
assert dumpable == 0
pid = os.getpid()
root = Path('/proc')
row, kind, _ = linux._read_census_record(root, pid, linux._census_boot(root))
assert kind == 'live'
assert row['uid'] == os.geteuid()
assert row['birth_id'] == platform.process_identity(pid)['birth_id']
proc = root / str(pid)
status_uid = [line.split() for line in (proc / 'status').read_text().splitlines()
              if line.startswith('Uid:')]
assert len(status_uid) == 1 and len(status_uid[0]) == 5
status_euid = int(status_uid[0][2])
assert status_euid == os.geteuid()
print(json.dumps({'effective_uid': os.geteuid(), 'proc_owner': proc.stat().st_uid,
                  'observed_uid': row['uid'], 'status_euid': status_euid,
                  'dumpable': dumpable, 'birth_id': row['birth_id'],
                  'kernel': os.uname().release, 'uid_map': (proc / 'uid_map').read_text(),
                  'pidns': os.readlink(proc / 'ns/pid'),
                  'userns': os.readlink(proc / 'ns/user')}))
"""
    import json
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    result = json.loads(completed.stdout)
    assert result["observed_uid"] == result["effective_uid"] == result["status_euid"]
    assert result["dumpable"] == 0
    return result


@requires_linux_procfs_census
def test_native_nondumpable_self_observes_effective_uid():
    # Ordinary CI proves real nondumpable EUID/birth semantics, not venue
    # capability. Equal owner/EUID here is neither a skip nor strict proof.
    _native_nondumpable_self_observation()


def _require_strict_native_unequal_owner_witness():
    """Mandatory separate native qualification; never satisfied by ordinary CI."""
    if not __debug__ or sys.platform != "linux":
        raise RuntimeError("strict native witness requires Linux with assertions enabled")
    result = _native_nondumpable_self_observation()
    import json
    print(json.dumps(result, sort_keys=True), flush=True)
    assert result["effective_uid"] != 0, "strict witness requires unprivileged EUID"
    assert result["proc_owner"] != result["effective_uid"], "venue did not produce unequal proc owner/EUID"


def test_census_dispatch_refuses_unsupported_os(monkeypatch):
    monkeypatch.setattr(process_binding, "sys", SimpleNamespace(platform="darwin"))
    for call in (process_binding.census, lambda: process_binding.zombie_birth(1),
                 lambda: process_binding.birth_ticks(1)):
        with pytest.raises(NotImplementedError):
            call()

if __name__ == "__main__":
    if sys.argv[1:] != ["--strict-native-witness"]:
        raise SystemExit("usage: python -m tests.test_linux_census --strict-native-witness")
    _require_strict_native_unequal_owner_witness()
