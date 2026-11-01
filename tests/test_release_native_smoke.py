"""Controls for the bounded release native-provider smoke CLI."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "check-before-push"
NODES = (
    "tests/test_timeline_native_asset_union.py::test_genuine_native_capture_is_retained_with_lossless_union[raw]",
    "tests/test_timeline_native_asset_union.py::test_disjoint_clip_merge_and_guarded_undo_preserve_explicit_scopes[raw-None]",
)


def _checkout(tmp_path: Path) -> Path:
    root = tmp_path / "agent"
    (root / "astrid/core/execution").mkdir(parents=True)
    (root / "astrid/sdk/timeline").mkdir(parents=True)
    (root / "astrid/core/execution/generic_host.py").touch()
    (root / "astrid/sdk/timeline/commit.py").touch()
    return root


def _python_stub(tmp_path: Path) -> Path:
    stub = tmp_path / "python-stub"
    stub.write_text(
        """#!/bin/sh
set -eu
case " $* " in
  *' -c '*) exit "${FAKE_PROVIDER_EXIT:-0}" ;;
  *' --collect-only '*)
    if [ "${FAKE_ZERO_SELECTION:-0}" -eq 0 ]; then
      printf '%s\\n' \
        'tests/test_timeline_native_asset_union.py::test_genuine_native_capture_is_retained_with_lossless_union[raw]' \
        'tests/test_timeline_native_asset_union.py::test_disjoint_clip_merge_and_guarded_undo_preserve_explicit_scopes[raw-None]'
    fi
    exit 0
    ;;
  *' -m pytest '*)
    if [ "${FAKE_SKIP:-0}" -eq 1 ]; then printf '%s\\n' '1 skipped' ; fi
    exit "${FAKE_PYTEST_EXIT:-0}"
    ;;
  *) exit 99 ;;
esac
""",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub


def _run(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"PYTHON_BIN": str(_python_stub(tmp_path)), **overrides})
    return subprocess.run(
        ["bash", str(SCRIPT), "--native-provider-smoke"],
        cwd=SCRIPT.parents[1],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_native_smoke_cli_fails_closed_for_prerequisite_and_execution_failures(tmp_path):
    missing = _run(tmp_path / "missing", ASTRID_CHECKOUT="")
    assert missing.returncode == 2
    assert "requires ASTRID_CHECKOUT" in missing.stderr

    checkout = _checkout(tmp_path)
    provider_failure = _run(
        tmp_path,
        ASTRID_CHECKOUT=str(checkout),
        FAKE_PROVIDER_EXIT="17",
    )
    assert provider_failure.returncode == 17

    nonzero = _run(
        tmp_path,
        ASTRID_CHECKOUT=str(checkout),
        FAKE_PYTEST_EXIT="9",
    )
    assert nonzero.returncode == 9

    zero_selection = _run(
        tmp_path,
        ASTRID_CHECKOUT=str(checkout),
        FAKE_ZERO_SELECTION="1",
    )
    assert zero_selection.returncode == 2
    assert "selected node is missing" in zero_selection.stderr

    skipped = _run(
        tmp_path,
        ASTRID_CHECKOUT=str(checkout),
        FAKE_SKIP="1",
    )
    assert skipped.returncode == 2
    assert "cannot pass with skipped" in skipped.stderr
