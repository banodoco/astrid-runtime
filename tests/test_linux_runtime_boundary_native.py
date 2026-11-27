"""Exercise Linux Runtime-boundary publication and real native signal custody."""
import json
import os
from pathlib import Path
import signal
import stat
import sys
import errno

import pytest

from astrid_runtime.bootstrap import SourceProfile
from astrid_runtime.custody_broker import (
    ACTIVE_CAPABILITY_NAME,
    CustodyError,
    NATIVE_CAPABILITY_VERSION,
    NativeProcessCustody,
)
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol import platform

from tests.lanes import requires_linux_tree_custody
pytestmark = requires_linux_tree_custody

# Stand-in for the Runtime service only: it publishes its own real process
# identity and serves the health endpoint expected by LocalRuntimeBoundary.
_SERVICE = r'''
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from runtime_protocol import platform

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--support-root', required=True)
args, _ = parser.parse_known_args()
class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'status': 'ok', 'protocol': 'workspace.v1'}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass
server = HTTPServer(('127.0.0.1', 0), Health)
pid = os.getpid()
identity = platform.process_identity(pid)
support = Path(args.support_root)
record = {'pid': pid, 'process_birth_id': identity['birth_id'],
          'endpoint': 'http://127.0.0.1:%s' % server.server_port,
          'runtime_instance_id': 'test-service'}
temp = support / 'discovery.tmp'
temp.write_text(json.dumps(record))
os.replace(temp, support / 'discovery.json')
server.serve_forever()
'''


@pytest.fixture
def started_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("ASTRID_RUNTIME_ADMISSION_TIMEOUT_SECONDS", "5")
    boundary = LocalRuntimeBoundary(wait_seconds=5)
    support = tmp_path / "support"
    profile = SourceProfile(
        profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path),
        runtime_command=(sys.executable, "-c", _SERVICE),
    )
    try:
        result = boundary.start(realm_id="realm", realm_root=tmp_path / "realm",
                                owner_lock=support / "instance.lock", source_profile=profile)
        yield boundary, support, result
    finally:
        process = boundary._process
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            boundary.stop()


@pytest.fixture
def delivered_signals(monkeypatch):
    """Observe at the actual pidfd signal call, forwarding it to the kernel."""
    calls = []
    real_send = platform.pidfd_send_signal

    def observe(fd, signum):
        info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        pid = int(next(line.split()[1] for line in info.splitlines() if line.startswith("Pid:")))
        calls.append((pid, platform.process_identity(pid), signum))
        return real_send(fd, signum)

    monkeypatch.setattr(platform, "pidfd_send_signal", observe)
    return calls


@pytest.mark.needs_real_pidfd
def test_start_publishes_native_custody_and_term_signals_exact_owner(started_owner, delivered_signals):
    boundary, support, result = started_owner
    process = boundary._process
    custody = process._runtime_native_custody
    assert isinstance(custody, NativeProcessCustody)
    assert not hasattr(process, "_runtime_custody_broker")
    path = support / ACTIVE_CAPABILITY_NAME
    assert custody.path == path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.getuid()
    record = json.loads(path.read_text())
    identity = platform.process_identity(process.pid)
    target = {key: identity[key] for key in ("pid", "uid", "birth_id")}
    assert record == {"version": NATIVE_CAPABILITY_VERSION, "role": "runtime_owner",
                      "target": target, "controller": platform.process_identity(os.getpid()),
                      "state": "owned"}
    assert result["pid"] == target["pid"]
    assert result["process_birth_id"] == target["birth_id"]
    custody.signal(platform.TERM)
    assert len(delivered_signals) == 1
    pid, observed, signum = delivered_signals[0]
    assert pid == target["pid"] and signum == platform.TERM
    assert {key: observed[key] for key in target} == target
    assert process.wait(timeout=10) == -signal.SIGTERM


@pytest.mark.needs_real_pidfd
@pytest.mark.parametrize("field", ["birth_id", "uid"])
def test_forged_record_and_stale_incarnation_are_refused(started_owner, delivered_signals, field):
    boundary, support, _ = started_owner
    process = boundary._process
    native = process._runtime_native_custody
    path = support / ACTIVE_CAPABILITY_NAME
    record = json.loads(path.read_text())
    forged = dict(record["target"])
    forged[field] = forged[field] + "-stale" if field == "birth_id" else forged[field] + 1
    # The actual published custody rejects a forged expected target at the record fence.
    imposter = NativeProcessCustody(support, forged, authority=native._authority)
    with pytest.raises(CustodyError, match="differs from the selected owner"):
        imposter.signal(platform.TERM)
    assert delivered_signals == [] and process.poll() is None
    # Even if a stale identity is present in the record too, the real pidfd
    # identity check refuses it before any signal reaches the kernel.
    record["target"] = forged
    path.write_text(json.dumps(record))
    with pytest.raises(CustodyError, match="differs from expected incarnation"):
        imposter.signal(platform.TERM)
    assert delivered_signals == [] and process.poll() is None
    assert platform.process_identity(process.pid)["birth_id"] == native.identity["birth_id"]


@pytest.mark.needs_real_pidfd
def test_reaped_owner_is_refused_without_signal(started_owner, delivered_signals):
    boundary, _, _ = started_owner
    process = boundary._process
    custody = process._runtime_native_custody
    process.kill()
    assert process.wait(timeout=10) == -signal.SIGKILL
    assert platform.process_identity(process.pid) is None
    with pytest.raises(CustodyError):
        custody.signal(platform.TERM)
    assert delivered_signals == []


@pytest.mark.needs_real_pidfd
def test_journal_alone_never_authorizes_even_same_controller(started_owner, delivered_signals):
    boundary, support, _ = started_owner
    process = boundary._process
    target = process._runtime_native_custody.identity
    before = (support / ACTIVE_CAPABILITY_NAME).read_bytes()
    with pytest.raises(CustodyError, match="requires retained authority"):
        NativeProcessCustody(support, target).signal(platform.TERM)
    assert (support / ACTIVE_CAPABILITY_NAME).read_bytes() == before
    assert delivered_signals == [] and process.poll() is None


@pytest.mark.needs_real_pidfd
def test_boundary_stop_uses_owned_child_native_term_and_closes(started_owner, delivered_signals):
    boundary, _, _ = started_owner
    process = boundary._process
    native = process._runtime_native_authority
    boundary.stop()
    assert [(pid, signum) for pid, _, signum in delivered_signals if signum] == [
        (process.pid, platform.TERM)]
    assert process.returncode == -signal.SIGTERM
    from runtime_protocol.linux_process_binding import LinuxBindingError
    with pytest.raises(LinuxBindingError, match="closed"):
        native.verify()


def test_denied_pidfd_publication_is_named_refusal(tmp_path, monkeypatch, request):
    # The configured seccomp job must witness the actual denial; on a normal
    # native lane inject only the syscall failure, not the publication result.
    if request.config.getoption("--process-control") == "sandbox":
        with pytest.raises(OSError) as error:
            platform.pidfd_open(os.getpid())
        assert error.value.errno in (errno.ENOSYS, errno.EPERM, errno.EACCES)
    else:
        def denied(*args, **kwargs):
            raise OSError(errno.ENOSYS, "pidfd denied")
        monkeypatch.setattr(platform, "pidfd_open", denied)
    identity = platform.process_identity(os.getpid())
    assert identity is not None
    with pytest.raises(CustodyError, match="Linux pidfd custody is unavailable"):
        NativeProcessCustody(tmp_path, identity).publish()
    assert not (tmp_path / ACTIVE_CAPABILITY_NAME).exists()
