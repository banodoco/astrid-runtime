"""Focused Linux descriptor transport tests; these do not prove P19 admission."""
import array
import fcntl
import multiprocessing
import os
import socket
import stat

import pytest

from runtime_protocol import lifecycle_transfer_transport as transport

pytestmark = pytest.mark.skipif(os.name != "posix" or not os.path.exists("/proc/self/cgroup"), reason="Linux native peer credentials required")
CAP = "a" * 64
DIGEST = "b" * 64


def object_id(fd):
    info = os.fstat(fd)
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IFMT(info.st_mode), "uid": info.st_uid}


def _receiver(path, pipe, objects, capability=CAP):
    try:
        peer = transport.linux_peer_identity(os.getppid())
        with transport.connect(path, peer) as sock:
            pipe.send("connected")
            with transport.receive_aliases(sock, expected_peer=peer, capability=capability,
                                           binding_digest=DIGEST, sequence=1, role="candidate",
                                           expected_objects=objects) as aliases:
                assert all(not os.get_inheritable(fd) for fd in aliases.filenos())
                aliases.close_directory()
                pipe.send("received")
                pipe.recv()
        pipe.send("closed")
    except Exception as exc:
        pipe.send(type(exc).__name__)


def _contends(path):
    fd = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def _pair(tmp_path, *, capability=CAP):
    endpoint = tmp_path / "socket"
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    owner_path = tmp_path / "owner.lock"
    owner_path.touch(mode=0o600)
    owner_fd = os.open(owner_path, os.O_RDWR)
    fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    server = transport.listen(endpoint)
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_receiver, args=(endpoint, child, [object_id(directory_fd), object_id(owner_fd)], capability))
    process.start()
    child.close()
    conn, _ = server.accept()
    assert parent.poll(10) and parent.recv() == "connected"
    return server, conn, parent, process, directory_fd, owner_fd, owner_path


def test_received_alias_keeps_same_lock_after_sender_closes(tmp_path):
    server, conn, pipe, child, directory_fd, owner_fd, path = _pair(tmp_path)
    try:
        transport.send_aliases(conn, expected_peer=transport.linux_peer_identity(child.pid), capability=CAP,
                               binding_digest=DIGEST, sequence=1, role="candidate",
                               directory_fd=directory_fd, owner_fd=owner_fd)
        assert pipe.poll(10) and pipe.recv() == "received"
        assert _contends(path)
        os.close(directory_fd)
        directory_fd = -1
        os.close(owner_fd)
        owner_fd = -1
        assert _contends(path)
        pipe.send("close")
        assert pipe.poll(10) and pipe.recv() == "closed"
        child.join(10)
        assert child.exitcode == 0
        assert not _contends(path)
    finally:
        conn.close()
        server.close()
        pipe.close()
        if directory_fd >= 0:
            os.close(directory_fd)
        if owner_fd >= 0:
            os.close(owner_fd)
        if child.is_alive():
            child.terminate()
            child.join()


def test_rejected_capability_closes_received_aliases(tmp_path):
    server, conn, pipe, child, directory_fd, owner_fd, path = _pair(tmp_path, capability="c" * 64)
    try:
        transport.send_aliases(conn, expected_peer=transport.linux_peer_identity(child.pid), capability=CAP,
                               binding_digest=DIGEST, sequence=1, role="candidate",
                               directory_fd=directory_fd, owner_fd=owner_fd)
        assert pipe.poll(10) and pipe.recv() == "TransferError"
        child.join(10)
        assert child.exitcode == 0
        assert _contends(path)
        os.close(owner_fd)
        owner_fd = -1
        assert not _contends(path)
    finally:
        conn.close()
        server.close()
        pipe.close()
        os.close(directory_fd)
        if owner_fd >= 0:
            os.close(owner_fd)
        if child.is_alive():
            child.terminate()
            child.join()


def test_rejects_insecure_parent(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(transport.TransferError, match="owner-only"):
        transport.listen(tmp_path / "socket")


def test_rejects_wrong_peer_before_delivery(tmp_path):
    server, conn, pipe, child, directory_fd, owner_fd, path = _pair(tmp_path)
    try:
        with pytest.raises(transport.TransferError, match="peer"):
            transport.send_aliases(conn, expected_peer=transport.linux_peer_identity(os.getpid()), capability=CAP,
                                   binding_digest=DIGEST, sequence=1, role="candidate",
                                   directory_fd=directory_fd, owner_fd=owner_fd)
        conn.close()
        assert pipe.poll(10) and pipe.recv() == "TransferError"
        assert _contends(path)
    finally:
        conn.close()
        server.close()
        pipe.close()
        os.close(directory_fd)
        os.close(owner_fd)
        child.join(10)
        if child.is_alive():
            child.terminate()
            child.join()


def test_provisional_original_retains_existing_locks_and_detects_replacement(tmp_path):
    realm = tmp_path / "realm"
    realm.mkdir()
    owner = realm / "owner.lock"
    owner.touch(mode=0o600)
    fence = transport.ProvisionalOriginal.acquire(realm)
    try:
        assert _contends(owner)
        with pytest.raises(transport.TransferError, match="unavailable"):
            transport.ProvisionalOriginal.acquire(realm)
        owner.rename(realm / "old.lock")
        owner.touch(mode=0o600)
        with pytest.raises(transport.TransferError, match="lineage"):
            fence.check()
        assert _contends(realm / "old.lock")
    finally:
        fence.close()
    assert not _contends(realm / "old.lock")


def test_provisional_original_refuses_links_and_missing_owner(tmp_path):
    realm = tmp_path / "realm"
    realm.mkdir()
    with pytest.raises(transport.TransferError):
        transport.ProvisionalOriginal.acquire(realm)
    target = tmp_path / "target"
    target.touch(mode=0o600)
    (realm / "owner.lock").symlink_to(target)
    with pytest.raises(transport.TransferError):
        transport.ProvisionalOriginal.acquire(realm)
    (realm / "owner.lock").unlink()
    os.link(target, realm / "owner.lock")
    with pytest.raises(transport.TransferError, match="invalid original owner"):
        transport.ProvisionalOriginal.acquire(realm)


@pytest.mark.parametrize("count", [3, 24])
def test_extra_or_truncated_rights_are_all_closed(tmp_path, count):
    source = tmp_path / "source"
    source.touch(mode=0o600)
    fd = os.open(source, os.O_RDONLY)
    left, right = socket.socketpair()
    try:
        before = len(os.listdir("/proc/self/fd"))
        left.sendmsg([b"\0\0\0\x02{}"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                             array.array("i", [fd] * count))])
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(transport.TransferError):
            transport.receive_aliases(right, expected_peer=transport.linux_peer_identity(os.getpid()),
                                      capability=CAP, binding_digest=DIGEST, sequence=1,
                                      role="candidate", expected_objects=[])
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        left.close()
        right.close()
        os.close(fd)


@pytest.mark.parametrize("changed", ["parent", "socket", "mode"])
def test_pinned_endpoint_rejects_replacement_without_unlinking_it(tmp_path, changed):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "socket"
    listener = transport.listen(path)
    try:
        if changed == "parent":
            parent.rename(tmp_path / "original")
            parent.mkdir(mode=0o700)
            path.write_text("replacement")
        elif changed == "socket":
            path.rename(parent / "original-socket")
            path.write_text("replacement")
        else:
            path.chmod(0o666)
        with pytest.raises(transport.TransferError):
            listener.check()
    finally:
        listener.close()
    assert path.exists()
    if changed != "mode":
        assert path.read_text() == "replacement"


def test_private_endpoint_refuses_symlink_ancestor(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    (private / "nested").mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(OSError):
        transport.listen(alias / "nested" / "socket")
    assert not (private / "nested" / "socket").exists()
