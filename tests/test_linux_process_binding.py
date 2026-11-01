"""Linux process-binding provider: exact identity, refusal before signal, real process."""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from runtime_protocol import linux_process_binding as lpb
from runtime_protocol import platform

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux provider")


def _sleeper():
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_token_round_trips_for_a_live_child_and_refuses_forged_fields():
    child = _sleeper()
    try:
        token = lpb.token(child.pid)
        words = token["words"]
        assert lpb.details(words)["pid"] == child.pid
        assert lpb.details(words)["sha256"] == token["sha256"]
        # Forged start ticks for the same pid: refused as reused.
        forged_ticks = list(words); forged_ticks[4] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb._matches(forged_ticks)
        # Forged uid for the same pid: refused.
        forged_uid = list(words); forged_uid[2] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb._matches(forged_uid)
        # Forged pid: names a different process, whose identity cannot match these ticks.
        time.sleep(0.05)  # start ticks are ~10 ms; separate them so the test is deterministic
        other = _sleeper()
        try:
            forged_pid = list(words); forged_pid[1] = other.pid
            with pytest.raises(lpb.LinuxBindingError):
                lpb._matches(forged_pid)
        finally:
            other.kill(); other.wait()
    finally:
        child.kill(); child.wait()


def test_signal_reaches_the_same_process_and_refusal_signals_nothing():
    child = _sleeper()
    try:
        words = lpb.token(child.pid)["words"]
        forged = list(words); forged[4] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb.signal(forged, platform.TERM)
        assert child.poll() is None  # refusal delivered no signal
        lpb.signal(words, platform.TERM)
        assert child.wait(timeout=10) == -platform.TERM
    finally:
        if child.poll() is None:
            child.kill(); child.wait()


def test_exited_child_is_refused_without_signal():
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    with pytest.raises(lpb.LinuxBindingError):
        lpb.token(child.pid)


def test_namespace_zero_or_missing_is_refused():
    with pytest.raises(lpb.LinuxBindingError):
        lpb._parse_birth("proc-start-ticks:123")
    with pytest.raises(lpb.LinuxBindingError):
        lpb.details([lpb.TOKEN_TAG, os.getpid(), 0, 0, 1, 0, 0, 0])
