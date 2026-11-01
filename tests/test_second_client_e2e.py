from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from runtime_protocol.daemon import WORKER_ACTOR, RuntimeDaemon
from runtime_protocol.store import RealmStore

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "conformance" / "second-client-core-v1.yaml"
CLIENT = ROOT / "packages" / "typescript"
ACTOR = ROOT / "conformance" / "dist" / "conformance" / "fake-second-product.js"
INDEPENDENT_CLIENT_SMOKE = ROOT / "conformance" / "dist" / "conformance" / "typescript" / "smoke.js"


@pytest.fixture()
def daemon(tmp_path: Path):
    RealmStore.initialize(tmp_path / "realm").close()
    instance = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        yield instance
    finally:
        instance.stop()


def _build_actor() -> None:
    """Install and compile the checked-in client, without ambient module paths."""
    subprocess.run(
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=CLIENT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        ["npm", "run", "build"],
        cwd=CLIENT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        [str(CLIENT / "node_modules" / ".bin" / "tsc"), "-p", str(ROOT / "conformance" / "tsconfig.json")],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert ACTOR.is_file(), f"TypeScript actor was not emitted at {ACTOR}"
    assert INDEPENDENT_CLIENT_SMOKE.is_file(), f"independent TypeScript smoke was not emitted at {INDEPENDENT_CLIENT_SMOKE}"


def test_second_client_core_journey_is_executable(daemon: RuntimeDaemon) -> None:
    _build_actor()
    smoke = subprocess.run(["node", str(INDEPENDENT_CLIENT_SMOKE)], cwd=ROOT, check=True, capture_output=True, text=True)
    assert "independent TypeScript conformance client smoke passed" in smoke.stdout
    fixture = yaml.safe_load(FIXTURE.read_text())
    assert fixture["fixture"] == "second-client-core-v1"
    assert fixture["protocol"] == "workspace.v1"
    expected_steps = [step["id"] for step in fixture["steps"]]

    # The actor receives the scoped credential explicitly, as a real client would;
    # no product-specific or ambient token injection is permitted for this journey.
    env = os.environ.copy()
    env.pop("ASTRID_RUNTIME_OWNER_TOKEN", None)
    env.pop("ASTRID_RUNTIME_LOCAL_OWNER_TOKEN", None)
    completed = subprocess.run(
        ["node", str(ACTOR), "--endpoint", daemon.endpoint, "--token", daemon.token, "--worker-token", daemon.worker_token, "--executor-id", WORKER_ACTOR],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["product"] == fixture["actor"]["product_name"]
    assert result["realm_id"]
    assert result["steps"] == expected_steps
    assert result["project_id"] and result["object_id"] and result["task_id"]
