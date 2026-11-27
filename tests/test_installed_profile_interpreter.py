"""Portable fixture/inspector contracts; native OS observations are doubled here.

The real installed Darwin host/pack test supplies the native qualification.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from runtime_protocol import local_worker_composition as composition
from runtime_protocol import platform as runtime_platform
from runtime_protocol.errors import ConflictError
from tests import test_installed_pack_custody_spawn as installed


def _digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def interpreter_files(tmp_path, monkeypatch):
    launcher = tmp_path / "bin" / "python3"
    image = tmp_path / "Python.app" / "Contents" / "MacOS" / "Python"
    launcher.parent.mkdir(parents=True)
    image.parent.mkdir(parents=True)
    launcher.write_bytes(b"selected framework launcher")
    image.write_bytes(b"independent kernel interpreter image")
    monkeypatch.setattr(installed.sys, "executable", str(launcher))
    return launcher, image


def test_profile_pins_selected_launcher_and_kernel_image_separately(interpreter_files, monkeypatch):
    launcher, image = interpreter_files
    observed = []

    def process_executable(pid):
        observed.append(pid)
        return str(image)

    monkeypatch.setattr(runtime_platform, "process_executable", process_executable)
    identity = installed._selected_interpreter_identity(launcher)

    assert observed == [os.getpid()]
    assert identity == {
        "host_executable": str(launcher),
        "host_artifact_digest": _digest(launcher),
        "host_os_executable": str(image),
        "host_os_artifact_digest": _digest(image),
    }
    assert identity["host_artifact_digest"] != identity["host_os_artifact_digest"]


def test_profile_does_not_observe_current_process_for_another_interpreter(interpreter_files, monkeypatch):
    launcher, image = interpreter_files

    def forbidden(_pid):
        raise AssertionError("foreign selection must fail before native observation")

    monkeypatch.setattr(runtime_platform, "process_executable", forbidden)
    with pytest.raises(AssertionError, match="fixture must select its installed interpreter"):
        installed._selected_interpreter_identity(image)


@pytest.mark.parametrize("failure", ["unavailable", "relative", "missing", "directory"])
def test_profile_never_falls_back_to_launcher_for_invalid_kernel_observation(
    interpreter_files, monkeypatch, failure
):
    launcher, image = interpreter_files

    def process_executable(_pid):
        if failure == "unavailable":
            raise OSError("native observation denied")
        return {
            "relative": "Python.app/Contents/MacOS/Python",
            "missing": str(image.with_name("missing")),
            "directory": str(image.parent),
        }[failure]

    monkeypatch.setattr(runtime_platform, "process_executable", process_executable)
    expected = {
        "unavailable": OSError, "relative": AssertionError,
        "missing": FileNotFoundError, "directory": AssertionError,
    }[failure]
    with pytest.raises(expected):
        installed._selected_interpreter_identity(launcher)


@pytest.mark.parametrize("case", ["matching-image", "wrong-path-same-bytes", "wrong-digest"])
def test_inspector_preserves_exact_kernel_path_and_digest_admission(
    interpreter_files, monkeypatch, case
):
    launcher, image = interpreter_files
    monkeypatch.setattr(runtime_platform, "process_executable", lambda _pid: str(image))
    pinned = installed._selected_interpreter_identity(launcher)
    reported_image = image
    digest = pinned["host_os_artifact_digest"]
    if case == "wrong-path-same-bytes":
        reported_image = image.with_name("other-python")
        reported_image.write_bytes(image.read_bytes())
        assert _digest(reported_image) == digest
    elif case == "wrong-digest":
        digest = pinned["host_artifact_digest"]
    monkeypatch.setattr(composition, "_actual_executable", lambda _pid: reported_image)
    monkeypatch.setattr(runtime_platform, "process_identity", lambda pid: {
        "pid": pid, "birth_id": "original-birth", "parent_pid": 123, "uid": 456,
    })
    monkeypatch.setattr(runtime_platform, "process_group", lambda pid: pid)
    monkeypatch.setattr(runtime_platform, "session_id", lambda pid: pid)
    inspector = composition.OSProcessInspector(SimpleNamespace())

    def observe():
        return inspector._identity(789, "original-birth", Path(pinned["host_os_executable"]),
            digest, parent_pid=123, session_owner=True)

    if case == "matching-image":
        identity = observe()
        assert identity.executable == image
        assert identity.artifact_digest == pinned["host_os_artifact_digest"]
    else:
        message = "executable identity" if case == "wrong-path-same-bytes" else "executable artifact digest"
        with pytest.raises(ConflictError, match=message):
            observe()


def test_installed_capability_reader_visits_later_pages_before_refusal_check():
    calls = []
    granted = {"capability_id": "granted.echo", "status": "ready"}
    ungranted = {"capability_id": "ungranted.echo", "status": "ready"}
    pages = [
        {"items": [granted], "next_cursor": "opaque+/cursor"},
        {"items": [ungranted], "next_cursor": None},
    ]

    def call(method, path):
        calls.append((method, path))
        return 200, pages.pop(0)

    catalog = installed._capability_catalog(call, deadline=time.monotonic() + 5, log_tail=lambda: "")
    assert calls == [
        ("GET", "/v1/capabilities"),
        ("GET", "/v1/capabilities?cursor=opaque%2B%2Fcursor"),
    ]
    assert catalog == {"granted.echo": granted, "ungranted.echo": ungranted}
    assert {name for name in catalog if name.startswith("ungranted.")} == {"ungranted.echo"}


@pytest.mark.parametrize("page", [{"data": []}, {"items": []}])
def test_installed_capability_reader_requires_both_canonical_page_fields(page):
    with pytest.raises(KeyError):
        installed._capability_catalog(lambda *_: (200, page),
            deadline=time.monotonic() + 5, log_tail=lambda: "")


@pytest.mark.parametrize("case", ["http-error", "repeated-cursor", "duplicate-capability"])
def test_installed_capability_reader_refuses_incomplete_or_repeated_catalog(case):
    pages = {
        "http-error": [(409, {"message": "unavailable"})],
        "repeated-cursor": [
            (200, {"items": [], "next_cursor": "again"}),
            (200, {"items": [], "next_cursor": "again"}),
        ],
        "duplicate-capability": [
            (200, {"items": [{"capability_id": "granted.echo"}], "next_cursor": "next"}),
            (200, {"items": [{"capability_id": "granted.echo"}], "next_cursor": None}),
        ],
    }[case]
    with pytest.raises(AssertionError):
        installed._capability_catalog(lambda *_: pages.pop(0),
            deadline=time.monotonic() + 5, log_tail=lambda: "")
