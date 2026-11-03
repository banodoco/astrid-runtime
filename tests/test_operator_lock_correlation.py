from __future__ import annotations

import errno
import json
import select
import subprocess
import sys
import traceback
from types import SimpleNamespace

import pytest

from astrid_runtime.operator_upgrade import OperatorUpgradeError, _installer_mutex
from runtime_protocol import platform
from tests.lanes import requires_linux_installer_lock_diagnostics

pytestmark = requires_linux_installer_lock_diagnostics


def _paths(tmp_path):
    return SimpleNamespace(home=tmp_path / "home", runtime_support=tmp_path)


@pytest.mark.parametrize("stage", ["owner_only", "lock_file"])
@pytest.mark.parametrize(
    ("number", "category"),
    [(errno.EAGAIN, "would_block"), (errno.EACCES, "access_denied"),
     (errno.EPERM, "permission_denied"), (errno.EIO, "other"), (None, "other")],
)
def test_refusal_stage_and_errno_are_bounded_and_traceback_redacted(tmp_path, monkeypatch, stage, number, category):
    calls = []
    secret = "holder-secret /private/path pid=12345 inode=678 device=9"

    def fail(*_args, **_kwargs):
        calls.append(stage)
        raise OSError(number, secret, "/private/filename")

    monkeypatch.setattr(platform, stage, fail)
    if stage == "owner_only":
        monkeypatch.setattr(platform, "lock_file", lambda *_args, **_kwargs: pytest.fail("lock attempted after owner-only refusal"))
    monkeypatch.setattr(platform, "unlock_file", lambda *_args: pytest.fail("unlock after failed acquisition"))
    with pytest.raises(OperatorUpgradeError) as caught:
        with _installer_mutex(_paths(tmp_path)):
            pytest.fail("refusal must not yield")
    assert calls == [stage]
    assert str(caught.value) == (
        "another installer owns the installation lifetime lock "
        f"(stage={stage}, errno_category={category})"
    )
    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert "/private/filename" not in rendered
    assert caught.value.__suppress_context__


def test_cli_json_preserves_safe_child_correlation_fields(tmp_path, monkeypatch, capsys):
    from astrid_runtime import cli, operator_upgrade

    def fail(*_args, **_kwargs):
        raise OSError(errno.EAGAIN, "private-holder-text", "/private/path")

    def invoke_mutex(paths, *_args, **_kwargs):
        with _installer_mutex(paths):
            pytest.fail("refusal must not yield")

    monkeypatch.setattr(platform, "lock_file", fail)
    monkeypatch.setattr(operator_upgrade, "upgrade_workspace", invoke_mutex)
    monkeypatch.setattr(cli, "_paths", lambda _args: _paths(tmp_path))
    assert cli.main(["upgrade", "--data-root", str(tmp_path), "--json"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "ok": False,
        "error": "another installer owns the installation lifetime lock (stage=lock_file, errno_category=would_block)",
    }
    assert "private-holder-text" not in output.out + output.err
    assert "/private/path" not in output.out + output.err


def test_real_held_lock_excludes_until_release_then_reacquires(tmp_path):
    code = """
import sys
from pathlib import Path
from types import SimpleNamespace
from astrid_runtime.operator_upgrade import _installer_mutex
root = Path(sys.argv[1])
paths = SimpleNamespace(home=root / 'home', runtime_support=root)
with _installer_mutex(paths):
    print('held', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert select.select([child.stdout], [], [], 10)[0], "lock holder did not become ready"
        assert child.stdout.readline().strip() == "held"
        for _ in range(2):
            with pytest.raises(OperatorUpgradeError, match=r"stage=lock_file, errno_category=would_block"):
                with _installer_mutex(_paths(tmp_path)):
                    pytest.fail("held lock admitted another process")
        child.stdin.write("release\n")
        child.stdin.flush()
        _, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, stderr
        with _installer_mutex(_paths(tmp_path)):
            pass
        with _installer_mutex(_paths(tmp_path)):
            pass
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
