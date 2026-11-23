"""A sibling inspection must observe, not take over, a live launcher gap."""
import json

from runtime_protocol.startup_operation import read_operation

from tests.test_startup_attempt import (
    _INSPECT_RECEIPT,
    _observe,
    _process_waiting_after,
    _runtime_args,
    selection,
)


_LAUNCHER_HOLDING_INSPECTION = """
import pathlib, sys
from astrid_runtime.cli import _config, _paths, parser
from astrid_runtime.workspace import begin_startup_attempt
args = parser().parse_args(["startup-status", *sys.argv[2:]])
paths = _paths(args)
with begin_startup_attempt(paths, config=_config(args, paths)):
    pathlib.Path(sys.argv[1]).touch()
    sys.stdin.readline()
"""


def test_unrelated_startup_inspection_observes_launcher_inspecting_workspace(
    selection, tmp_path,
):
    paths, _, _ = selection
    launcher_ready = tmp_path / "launcher-inspecting"
    inspection_receipt = tmp_path / "sibling-inspection.json"

    with _process_waiting_after(
        _LAUNCHER_HOLDING_INSPECTION,
        _runtime_args(selection),
        launcher_ready,
    ) as launcher:
        attempt = _observe(selection)
        assert attempt["state"] == "inspecting_workspace"
        expected = {
            "ok": False,
            "state": "inspecting_workspace",
            "startup_attempt": {
                "attempt_id": attempt["attempt_id"],
                "state": "inspecting_workspace",
            },
        }
        with _process_waiting_after(
            _INSPECT_RECEIPT,
            _runtime_args(selection),
            inspection_receipt,
        ) as sibling:
            envelope = json.loads(inspection_receipt.read_text())
            result = json.loads(envelope["stdout"])
            operation = read_operation(paths.runtime_support)
            discovery_exists = paths.discovery_path.exists()
            launcher_alive = launcher.poll() is None

            assert (
                envelope["returncode"] == 1
                and result == expected
                and operation is None
                and sibling.pid != launcher.pid
                and launcher_alive
                and not discovery_exists
            ), (
                "unrelated inspection took over the launcher's offline verifier: "
                f"result={result!r}, operation="
                f"{None if operation is None else operation.as_observation()!r}, "
                f"operation_owner_pid={None if operation is None else operation.owner_pid!r}, "
                f"sibling_pid={sibling.pid}, launcher_pid={launcher.pid}, "
                f"launcher_alive={launcher_alive}, discovery_exists={discovery_exists}"
            )
        assert sibling.returncode == 0
        assert launcher.poll() is None
        assert not paths.discovery_path.exists()
