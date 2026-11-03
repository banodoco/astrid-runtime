"""Native custody across session close and SCM_RIGHTS; not lifecycle admission."""
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys

import pytest

from astrid_runtime import lifecycle_transfer_broker as transport
from astrid_runtime.lifecycle_transfer import begin_transfer
from test_lifecycle_transfer_session import fixture
from test_lifecycle_transfer_transport import CAP, DIGEST, object_id

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux SCM_RIGHTS custody")


def _adopter(endpoint, pipe, objects):
    peer = transport.linux_peer_identity(os.getppid())
    with transport.connect(endpoint, peer) as sock:
        pipe.send(("connected", os.getpid(), os.geteuid()))
        with transport.receive_aliases(sock, expected_peer=peer, capability=CAP,
                                       binding_digest=DIGEST, sequence=1, role="candidate",
                                       expected_objects=objects) as aliases:
            assert [object_id(fd) for fd in aliases.filenos()] == objects
            pipe.send(("adopted", os.getpid(), os.geteuid()))
            assert pipe.recv() == "close"
    pipe.send(("closed", os.getpid(), os.geteuid()))


def _contend(path, directory):
    script = '''import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY if sys.argv[2] == "directory" else os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print(f"pid={os.getpid()} uid={os.getuid()} euid={os.geteuid()} result=blocked", flush=True)
    sys.exit(17)
print(f"pid={os.getpid()} uid={os.getuid()} euid={os.geteuid()} result=acquired", flush=True)
'''
    result = subprocess.run([sys.executable, "-c", script, str(path),
                             "directory" if directory else "owner"],
                            capture_output=True, text=True, timeout=10, check=False)
    print(result.stdout.strip(), flush=True)
    assert not result.stderr, result.stderr
    return result.returncode


def test_session_scm_rights_custody_until_adopter_close(tmp_path, monkeypatch):
    config, root, _, binding = fixture(tmp_path)
    session = begin_transfer(config, binding=binding)
    server = conn = pipe = child = None
    try:
        session.pin_and_acquire_original()
        held = session._custody._realm
        directory_fd, owner_fd = held._directory_fd, held._owner_fd
        objects = [object_id(directory_fd), object_id(owner_fd)]
        print(f"broker pid={os.getpid()} uid={os.getuid()} euid={os.geteuid()} objects={objects}", flush=True)
        for path, directory in ((root, True), (root / "owner.lock", False)):
            assert _contend(path, directory) == 17
            print(f"assertion broker-held {path.name}: blocked", flush=True)

        # A relative socket path avoids Linux's short sockaddr_un pathname limit.
        monkeypatch.chdir(tmp_path)
        endpoint = Path("s")
        server = transport.listen(endpoint)
        ctx = multiprocessing.get_context("spawn")
        pipe, child_pipe = ctx.Pipe()
        child = ctx.Process(target=_adopter, args=(endpoint, child_pipe, objects))
        child.start()
        child_pipe.close()
        conn, _ = server.accept()
        assert pipe.poll(10)
        connected = pipe.recv()
        assert connected == ("connected", child.pid, os.geteuid())
        transport.send_aliases(conn, expected_peer=transport.linux_peer_identity(child.pid),
                               capability=CAP, binding_digest=DIGEST, sequence=1,
                               role="candidate", directory_fd=directory_fd, owner_fd=owner_fd)
        assert pipe.poll(10)
        adopted = pipe.recv()
        assert adopted == ("adopted", child.pid, os.geteuid())
        print(f"assertion SCM_RIGHTS adopted same objects: {adopted}", flush=True)
        session.close()
        print("assertion broker session closed both original aliases", flush=True)
        for path, directory in ((root, True), (root / "owner.lock", False)):
            assert _contend(path, directory) == 17
            print(f"assertion adopter-held {path.name}: blocked", flush=True)
        pipe.send("close")
        assert pipe.poll(10)
        assert pipe.recv() == ("closed", child.pid, os.geteuid())
        child.join(10)
        assert child.exitcode == 0
        for path, directory in ((root, True), (root / "owner.lock", False)):
            assert _contend(path, directory) == 0
            print(f"assertion adopter-closed {path.name}: acquired", flush=True)
    finally:
        session.close()
        if conn is not None:
            conn.close()
        if server is not None:
            server.close()
        if pipe is not None:
            pipe.close()
        if child is not None and child.is_alive():
            child.terminate()
            child.join(10)
