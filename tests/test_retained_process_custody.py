"""Real wait ownership and cleanup regressions for retained children."""

import os
import signal
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from runtime_protocol.local_execution_supervisor import (
    NativeHostSession, RelayError, RetainedProcess, RetainedWaitTimeout,
)
from runtime_protocol.local_worker_composition import CrossProcessWorkerPreparer


@pytest.mark.parametrize("case,expected", [
    ("natural", 0), ("TERM", -15), ("KILL", -9),
    ("external_waitpid", None), ("external_popen_wait", None),
])
def test_retained_wait_owns_real_child_status(case, expected):
    code = "pass" if case == "natural" else "import time; time.sleep(20)"
    child = subprocess.Popen([sys.executable, "-c", code])
    retained = RetainedProcess(child)
    try:
        if case in ("TERM", "KILL", "external_waitpid", "external_popen_wait"):
            os.kill(child.pid, signal.SIGTERM if case == "TERM" else signal.SIGKILL)
        if case == "external_waitpid":
            os.waitpid(child.pid, 0)
        elif case == "external_popen_wait":
            child.wait(timeout=3)
        if expected is None:
            for _ in range(2):
                with pytest.raises(RelayError):
                    retained.wait(3)
                assert retained.exit_code is None
        else:
            assert retained.wait(3) == expected
            assert retained.poll() == expected
            assert child.returncode == expected
    finally:
        if child.returncode is None:
            try:
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                _, status = os.waitpid(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                child.returncode = -signal.SIGKILL


@pytest.mark.parametrize("consumer", ["host", "relay"])
@pytest.mark.parametrize("reap_during_wait", [False, True])
def test_external_reap_cannot_complete_cleanup_or_escalate(consumer, reap_during_wait):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    retained = RetainedProcess(child)
    control, activation = Mock(), Mock()
    signals = []

    def signal_and_reap(sig, *, expected_pid):
        assert expected_pid == child.pid
        signals.append(sig)
        os.kill(child.pid, signal.SIGKILL)
        os.waitpid(child.pid, 0)

    broker = SimpleNamespace(signal=signal_and_reap)
    if not reap_during_wait:
        os.kill(child.pid, signal.SIGKILL)
        os.waitpid(child.pid, 0)
    try:
        if consumer == "host":
            session = NativeHostSession.__new__(NativeHostSession)
            session.retained, session.broker, session.timeout = retained, broker, 1
            session.control, session.activation = control, activation
            cleanup = session.reap_host
        else:
            preparer = CrossProcessWorkerPreparer.__new__(CrossProcessWorkerPreparer)
            preparer.cleanup_timeout_seconds = 1
            preparer._rpc = Mock(return_value={"host_exit_code": 0, "host_result": {"status": "cleaned"}})
            handle = SimpleNamespace(closed=False, retained=retained, broker=broker,
                                     worker=child, control=control)
            preparer._active = handle
            cleanup = lambda: preparer._relay_abort_locked(handle)
        with pytest.raises(RelayError):
            cleanup()
        assert len(signals) == int(reap_during_wait)
        assert retained.exit_code is None
        control.close.assert_not_called()
        activation.close.assert_not_called()
        if consumer == "relay":
            assert not handle.closed
            assert preparer._active is handle
    finally:
        if child.returncode is None:
            try:
                os.kill(child.pid, signal.SIGKILL)
                os.waitpid(child.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
            child.returncode = -signal.SIGKILL


def test_popen_wait_lock_does_not_block_retained_wait_deadline():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    retained = RetainedProcess(child)
    try:
        with child._waitpid_lock:
            with pytest.raises(RetainedWaitTimeout):
                retained.wait(0)
        assert retained.exit_code is None
    finally:
        os.kill(child.pid, signal.SIGKILL)
        assert retained.wait(3) == -signal.SIGKILL


@pytest.mark.parametrize("consumer", ["host", "relay"])
def test_cleanup_escalates_only_on_retained_wait_timeout(consumer):
    retained = SimpleNamespace(child=SimpleNamespace(pid=123), poll=Mock(return_value=None),
                               wait=Mock(side_effect=[RetainedWaitTimeout("timeout"), -9]))
    broker = SimpleNamespace(signal=Mock())
    control, activation = Mock(), Mock()
    if consumer == "host":
        session = NativeHostSession.__new__(NativeHostSession)
        session.retained, session.broker, session.timeout = retained, broker, 1
        session.control, session.activation = control, activation
        assert session.reap_host() == -9
    else:
        preparer = CrossProcessWorkerPreparer.__new__(CrossProcessWorkerPreparer)
        preparer.cleanup_timeout_seconds = 1
        preparer._rpc = Mock(return_value={"host_exit_code": 0, "host_result": {"status": "cleaned"}})
        handle = SimpleNamespace(closed=False, retained=retained, broker=broker,
                                 worker=retained.child, control=control)
        preparer._active = handle
        preparer._relay_abort_locked(handle)
        assert handle.closed
        assert preparer._active is None
    assert [call.args[0] for call in broker.signal.call_args_list] == [signal.SIGTERM, signal.SIGKILL]
    assert retained.wait.call_count == 2
    control.close.assert_called_once()
