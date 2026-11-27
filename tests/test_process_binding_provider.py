"""The portable provider boundary, with real Linux identity/action checks."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from runtime_protocol import platform, process_binding as binding
from runtime_protocol.errors import ConflictError
from tests.lanes import requires_linux_tree_custody


def test_provider_import_does_not_load_application_or_foreign_backend():
    code = """import json, sys
import runtime_protocol.process_binding
blocked = ('runtime_protocol.service', 'runtime_protocol.store',
           'runtime_protocol.daemon', 'astrid_runtime',
           'runtime_protocol.windows_handoff', 'runtime_protocol.darwin_process_binding')
print(json.dumps([name for name in sys.modules
                  if any(name == item or name.startswith(item + '.') for item in blocked)]))
"""
    result = subprocess.run([sys.executable, "-I", "-c", code],
                            cwd=Path(__file__).parents[1], capture_output=True,
                            text=True, timeout=10, check=True)
    assert json.loads(result.stdout) == []


@requires_linux_tree_custody
def test_linux_observation_token_details_and_identity_parity():
    observed = binding.token(os.getpid())
    assert set(observed) == {"pid", "uid", "pidversion", "sha256", "words"}
    assert binding.details(observed["words"]) == {
        key: observed[key] for key in ("pid", "uid", "pidversion", "sha256")}
    expected = platform.process_identity(os.getpid())
    assert binding.identity(os.getpid()) == expected
    assert binding.birth_matches(expected["birth_id"], expected["birth_id"]) is True
    assert observed["pid"] == expected["pid"]
    assert observed["uid"] == expected["uid"]


@pytest.mark.parametrize("selected,expected", [
    ("linux", "linux"), ("linux2", "linux"), ("win32", "windows"),
    ("darwin", "darwin"), ("unavailable-os", "other"),
])
def test_dispatch_reads_platform_at_call_time(monkeypatch, selected, expected):
    monkeypatch.setattr(binding, "_platform", lambda: selected)
    assert binding.backend() == expected


def test_windows_observation_dispatch_preserves_arguments(monkeypatch):
    from runtime_protocol import windows_handoff
    monkeypatch.setattr(binding, "_platform", lambda: "win32")
    seen = []
    monkeypatch.setattr(platform, "handoff_token", lambda pid: seen.append(("token", pid)) or {"pid": pid})
    monkeypatch.setattr(platform, "handoff_token_details", lambda words: seen.append(("details", words)) or {"words": words})
    monkeypatch.setattr(windows_handoff, "peer_token", lambda channel: seen.append(("peer", channel)) or {"peer": True})
    channel = object()
    assert binding.token(123) == {"pid": 123}
    assert binding.details((1, 2)) == {"words": [1, 2]}
    assert binding.peer_token(channel) == {"peer": True}
    assert seen == [("token", 123), ("details", [1, 2]), ("peer", channel)]


@pytest.mark.parametrize("selected", ["darwin", "win32"])
def test_backend_authority_hook_preserves_object_and_expected_identity(monkeypatch, selected):
    monkeypatch.setattr(binding, "_platform", lambda: selected)
    sentinel, channel, child, guard = object(), object(), object(), object()
    expected, words, calls = {"pid": 123, "uid": 456, "birth_id": "native"}, [1] * 8, []
    native = SimpleNamespace(
        retain_peer=lambda connection, **kw: calls.append(("peer", connection, kw)) or sentinel,
        retain_child=lambda process, **kw: calls.append(("child", process, kw)) or sentinel,
        signal=lambda token, signum, **kw: calls.append(("signal", token, signum, kw)),
        resume_once=lambda authority: calls.append(("resume", authority)),
    )
    monkeypatch.setattr(binding, "_native_backend", lambda: native)
    assert binding.retain_peer(channel, expected=expected) is sentinel
    assert binding.retain_child(child, reap_guard=guard, expected=expected) is sentinel
    binding.signal(words, platform.TERM, authority=sentinel)
    assert calls == [
        ("peer", channel, {"expected": expected}),
        ("child", child, {"reap_guard": guard, "expected": expected}),
        ("signal", words, platform.TERM, {"authority": sentinel}),
    ]
    if selected == "darwin":
        binding.resume_once(sentinel)
        assert calls[-1] == ("resume", sentinel)
    else:
        with pytest.raises(binding.ProcessBindingUnavailable, match="one-shot"):
            binding.resume_once(sentinel)


@pytest.mark.parametrize("operation", ["retain_peer", "retain_child", "signal"])
def test_windows_named_native_error_uses_shared_refusal(monkeypatch, operation):
    class WindowsBindingError(ConflictError):
        pass

    refusal = WindowsBindingError("retained Windows reference is unavailable")

    def refuse(*args, **kwargs):
        raise refusal

    native = SimpleNamespace(WindowsBindingError=WindowsBindingError, **{operation: refuse})
    monkeypatch.setattr(binding, "_platform", lambda: "win32")
    monkeypatch.setattr(binding, "_native_backend", lambda: native)
    calls = {
        "retain_peer": lambda: binding.retain_peer(object()),
        "retain_child": lambda: binding.retain_child(object(), reap_guard=object()),
        "signal": lambda: binding.signal([1] * 8, platform.TERM, authority=object()),
    }
    with pytest.raises(binding.ProcessBindingError, match="retained Windows reference") as caught:
        calls[operation]()
    assert caught.value.__cause__ is refusal


def test_windows_dispatch_does_not_hide_unrelated_backend_errors(monkeypatch):
    class WindowsBindingError(ConflictError):
        pass

    def broken(channel, **kwargs):
        raise TypeError("provider implementation error")

    native = SimpleNamespace(WindowsBindingError=WindowsBindingError, retain_peer=broken)
    monkeypatch.setattr(binding, "_platform", lambda: "win32")
    monkeypatch.setattr(binding, "_native_backend", lambda: native)
    with pytest.raises(TypeError, match="provider implementation error"):
        binding.retain_peer(object())


@pytest.mark.parametrize("signum", [0, True, "15", -1, 99999])
def test_denied_signals_never_reach_a_backend(monkeypatch, signum):
    monkeypatch.setattr(binding, "_linux_call", lambda *a, **k: pytest.fail("native backend reached"))
    monkeypatch.setattr(binding, "_native_call", lambda *a, **k: pytest.fail("native backend reached"))
    with pytest.raises(binding.ProcessBindingError, match="admitted"):
        binding.signal([], signum, authority=object())


def test_unknown_backend_has_a_named_refusal(monkeypatch):
    monkeypatch.setattr(binding, "_platform", lambda: "unavailable-os")
    for operation in (
        lambda: binding.token(1), lambda: binding.details([0] * 8),
        lambda: binding.peer_token(object()), lambda: binding.retain_peer(object()),
        lambda: binding.signal([0] * 8, platform.TERM),
        lambda: binding.resume_once(object()),
    ):
        with pytest.raises(binding.ProcessBindingUnavailable):
            operation()


@requires_linux_tree_custody
@pytest.mark.needs_real_pidfd
def test_token_observation_never_opens_signal_authority(monkeypatch):
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
    try:
        token = binding.token(child.pid)
        monkeypatch.setattr(platform, "pidfd_open", lambda *a: pytest.fail("cached PID reopened"))
        with pytest.raises(binding.ProcessBindingError, match="retained native authority"):
            binding.signal(token["words"], platform.TERM)
        assert child.poll() is None
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@requires_linux_tree_custody
@pytest.mark.needs_real_pidfd
def test_owned_child_signal_requires_matching_retained_incarnation(monkeypatch):
    child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
    try:
        with binding.retain_child(child, reap_guard=threading.RLock()) as authority:
            words = authority.token["words"]
            forged = list(words)
            forged[4] ^= 1
            with pytest.raises(binding.ProcessBindingError, match="differs"):
                binding.signal(forged, platform.TERM, authority=authority)
            with pytest.raises(binding.ProcessBindingError, match="admitted"):
                binding.signal(words, signal.SIGHUP, authority=authority)
            assert child.poll() is None
            monkeypatch.setattr(platform, "pidfd_open", lambda *a: pytest.fail("authority reopened"))
            binding.signal(words, platform.TERM, authority=authority)
            assert child.wait(timeout=5) == -platform.TERM
            with pytest.raises(binding.ProcessBindingError, match="exited|absent"):
                binding.signal(words, platform.KILL, authority=authority)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@pytest.mark.parametrize("selected", ["linux", "windows"])
def test_broker_dispatches_through_provider(monkeypatch, selected):
    from astrid_runtime import custody_broker as broker
    monkeypatch.setattr(binding, "backend", lambda: selected)
    calls, channel, authority = [], object(), object()
    monkeypatch.setattr(binding, "token", lambda pid: calls.append(("token", pid)) or {"pid": pid})
    monkeypatch.setattr(binding, "details", lambda words: calls.append(("details", words)) or {})
    monkeypatch.setattr(binding, "peer_token", lambda connection: calls.append(("peer", connection)) or {})
    monkeypatch.setattr(binding, "signal", lambda words, signum, **kw: calls.append(("signal", words, signum, kw)))
    assert broker.current_process_audit_token(123) == {"pid": 123}
    broker.audit_token_details([1] * 8)
    broker._peer_token(channel)
    broker.signal_audit_token([1] * 8, platform.TERM, authority=authority)
    assert calls == [("token", 123), ("details", [1] * 8), ("peer", channel),
                     ("signal", [1] * 8, platform.TERM, {"authority": authority})]
