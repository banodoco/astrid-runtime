"""Shared fixture helpers ported from provisional custody tests."""
import subprocess
import sys
from types import SimpleNamespace

def realm(tmp_path):
    root = tmp_path / "realm"
    root.mkdir(mode=0o700)
    (root / "owner.lock").touch(mode=0o600)
    return root


def contender(path):
    script = """import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(17)
"""
    return subprocess.run([sys.executable, "-c", script, str(path)], check=False).returncode


def paths(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    lock = support / "bootstrap.lock"
    lock.touch(mode=0o600)
    return SimpleNamespace(runtime_support=support, bootstrap_lock_path=lock)
