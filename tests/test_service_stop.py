from __future__ import annotations

import subprocess
import sys
import time

import pytest

from tests.lanes import requires_posix_process_groups, requires_windows_job_object
from runtime_protocol import platform


def _wait_for(path, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    pytest.fail(f"did not observe {path.name}")


@pytest.mark.integration
@requires_posix_process_groups
def test_service_stdin_eof_runs_handlers_and_cleans_process_group(tmp_path):
    pid_file = tmp_path / "child.pid"
    child_done = tmp_path / "child.done"
    script = tmp_path / "service.py"
    script.write_text(
        "import os,pathlib,signal,subprocess,sys\n"
        "import time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "if sys.argv[1] == 'child':\n"
        " p=pathlib.Path(sys.argv[2]); t=p.with_suffix('.tmp')\n"
        " t.write_text(str(os.getpid())); t.replace(p)\n"
        " sys.stdin.buffer.read()\n"
        " pathlib.Path(sys.argv[3]).write_text('eof')\n"
        "else:\n"
        " subprocess.Popen([sys.executable, __file__, 'child', sys.argv[2], sys.argv[3]])\n"
        " while not pathlib.Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
        " sys.exit(0)\n",
        encoding="utf-8")
    process = platform.spawn_tree([sys.executable, str(script), "root", str(pid_file), str(child_done)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(pid_file)
        child_pid = int(pid_file.read_text())
        deadline = time.monotonic() + 5
        while not platform.tree_exited(process) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert platform.tree_exited(process), "service root did not exit before stop"
        platform.stop_tree(process, grace=0.15, stop_channel=True)
    finally:
        if process.poll() is None:
            platform.stop_tree(process, grace=0.1, stop_channel=True)
    assert child_done.read_text() == "eof"
    deadline = time.monotonic() + 5
    while platform.process_identity(child_pid) is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert platform.process_identity(child_pid) is None


@pytest.mark.integration
@requires_windows_job_object
def test_windows_service_stdin_eof_runs_handler_before_job_cleanup(tmp_path):
    done = tmp_path / "service.done"
    ready = tmp_path / "service.ready"
    script = tmp_path / "service.py"
    script.write_text(
        "import pathlib,signal,sys\n"
        "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
        f"pathlib.Path({str(ready)!r}).write_text('ready')\n"
        "sys.stdin.buffer.read()\n"
        f"pathlib.Path({str(done)!r}).write_text('eof')\n",
        encoding="utf-8")
    process = platform.spawn_tree([sys.executable, str(script)], hidden=True, stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(ready)
        platform.stop_tree(process, grace=1.0, stop_channel=True)
    finally:
        if process.poll() is None:
            platform.stop_tree(process, grace=0.1, stop_channel=True)
    assert done.read_text() == "eof"
    assert process.returncode == 0


@pytest.mark.integration
@requires_windows_job_object
def test_windows_stop_tree_drains_descendants_after_leader_exits(tmp_path):
    pid_file = tmp_path / "child.pid"
    script = tmp_path / "service.py"
    script.write_text(
        "import pathlib,signal,subprocess,sys,time\n"
        "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
        "if sys.argv[1] == 'child':\n"
        f" pathlib.Path({str(pid_file)!r}).write_text(str(__import__('os').getpid()))\n"
        " while True: time.sleep(1)\n"
        "subprocess.Popen([sys.executable, __file__, 'child'])\n"
        f"deadline=time.monotonic()+5\nwhile not pathlib.Path({str(pid_file)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n"
        "sys.exit(0)\n",
        encoding="utf-8")
    process = platform.spawn_tree([sys.executable, str(script), "root"], hidden=True,
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_for(pid_file)
        child_pid = int(pid_file.read_text())
        deadline = time.monotonic() + 5
        while not platform.tree_exited(process) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert platform.tree_exited(process), "service root did not exit before stop"
        platform.stop_tree(process, grace=0.1, stop_channel=True)
        assert platform.tree_drained(process)
    finally:
        job = getattr(process, "_runtime_job", None)
        if job is not None and job.handle:
            platform.stop_tree(process, grace=0.1, stop_channel=True)
    deadline = time.monotonic() + 5
    while platform.process_identity(child_pid) is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert platform.process_identity(child_pid) is None
