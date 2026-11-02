"""Real replacement must drain maintenance outside the request SQLite lock."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_real_replace_drains_real_reaper_without_store_mutex_deadlock(tmp_path, owned_process_groups):
    home, temp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir()
    temp.mkdir()
    worker = r'''
import json, threading, time, urllib.error, urllib.request
from pathlib import Path
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore

base = Path(__import__("sys").argv[1])
active = base / "active"
support = base / "support"
RealmStore.initialize(active).close()
daemon = RuntimeDaemon(active, support_root=support).start()
verified = threading.Event()
allow_shutdown = threading.Event()
reaper_started = threading.Event()
reaper_done = threading.Event()
original_write = daemon._write_replacement_state
original_reap = daemon.service.reap_task_lifetimes

def write_state(*, state, **kwargs):
    result = original_write(state=state, **kwargs)
    if state == "verified":
        verified.set()
        if not allow_shutdown.wait(8):
            raise RuntimeError("test did not release replacement after observing verified")
    return result

def reap():
    reaper_started.set()
    try:
        return original_reap()
    finally:
        reaper_done.set()

daemon._write_replacement_state = write_state
daemon.service.reap_task_lifetimes = reap
backup = base / "backup"
candidate = base / "candidate"
daemon.service.backup(backup)
daemon.service.restore(backup, candidate)
response = {}

def replace_request():
    request = urllib.request.Request(
        daemon.endpoint + "/v1/replace",
        data=json.dumps({"candidate": str(candidate)}).encode(),
        headers={"Authorization": "Bearer " + daemon.token,
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            response["status"] = reply.status
            response["body"] = json.loads(reply.read())
    except urllib.error.HTTPError as exc:
        response["status"] = exc.code
        response["body"] = exc.read().decode(errors="replace")

# Hold the real scheduling gate so the test can start precisely one real
# service_actions reaper after replacement reached its durable verified state.
daemon.httpd._maintenance_lock.acquire()
request_thread = threading.Thread(target=replace_request, daemon=True)
request_thread.start()
if not verified.wait(6):
    raise RuntimeError("replacement never reached verified state")
daemon.httpd._maintenance_lock.release()
daemon.httpd.service_actions()
if not reaper_started.wait(4):
    raise RuntimeError("real maintenance reaper did not start")
allow_shutdown.set()
request_thread.join(9)
if request_thread.is_alive():
    raise RuntimeError("real /v1/replace request did not finish")
if not reaper_done.wait(1):
    raise RuntimeError("server replacement returned before its admitted reaper drained")
if response.get("status") != 200 or response.get("body", {}).get("state") != "complete":
    raise AssertionError("real replacement failed: " + repr(response))

daemon.stop()
print("real-replacement-and-reaper-complete")
'''
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": str(home),
        "TMPDIR": str(temp),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(ROOT / "packages" / "python"), str(ROOT))),
        "ASTRID_CHECKOUT": str(ROOT.parent / "agent-contract"),
        "ASTRID_RUNTIME_CHECKOUT": str(ROOT),
    }
    process = owned_process_groups.popen(
        [sys.executable, "-c", worker, str(tmp_path)],
        env=env,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        owned_process_groups.terminate_all()
        pytest.fail("child deadlocked in real replacement/reaper shutdown (12 second bound)")
    assert process.returncode == 0, f"child exit={process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    assert "real-replacement-and-reaper-complete" in stdout
