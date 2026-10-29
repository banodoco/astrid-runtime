from __future__ import annotations

import json
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator
from astrid_runtime_client import Health

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from tests.door_helpers import DoorWorld, HOSTED, create_realm, start_door_world


ROOT = Path(__file__).parents[1]
API_RUNTIME = "/api/runtime"


def test_direct_door_and_discovery_publish_one_immutable_owner_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "43")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
    world = start_door_world(tmp_path)
    try:
        expected_identity = {"release": 43, "managed_by": "pinokio"}
        bound_instance_id = world.daemon.startup_identity_instance_id
        assert bound_instance_id == world.daemon.instance_id

        status, direct_bytes = world.owner("GET", "/v1/health")
        direct = json.loads(direct_bytes)
        proxied_reply = world.call(f"{API_RUNTIME}/v1/health")
        proxied = proxied_reply.json()
        discovery = world.daemon.discovery.read()

        assert status == 200
        assert proxied_reply.status == 200
        assert direct["identity"] == proxied["identity"] == discovery["identity"] == expected_identity
        assert direct["runtime_instance_id"] == proxied["runtime_instance_id"] == discovery["runtime_instance_id"] == bound_instance_id
        assert proxied["install"] == {"managed_by": "pinokio"}

        schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
        Draft202012Validator(schema).validate(direct)
        assert Health.from_json(direct).identity == expected_identity

        # Both the installer environment and a caller-owned property result may
        # change while this owner lives. All publication paths keep its snapshot.
        monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "44")
        monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY")
        exposed_copy = world.daemon.startup_identity
        exposed_copy["release"] = 999

        status, later_direct_bytes = world.owner("GET", "/v1/health")
        later_direct = json.loads(later_direct_bytes)
        later_proxied_reply = world.call(f"{API_RUNTIME}/v1/health")
        later_proxied = later_proxied_reply.json()
        later_discovery = world.daemon.discovery.read()

        assert status == 200 and later_proxied_reply.status == 200
        for body in (later_direct, later_proxied, later_discovery):
            assert body["identity"] == expected_identity
            assert body["runtime_instance_id"] == bound_instance_id
        assert later_proxied["install"] == {"managed_by": "pinokio"}
        Draft202012Validator(schema).validate(later_direct)
        assert Health.from_json(later_direct).identity == expected_identity
    finally:
        world.stop()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def _source_checkout(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    (root / "tracked.txt").write_text("initial\n")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-qm", "initial")
    return root


def test_source_owner_http_and_discovery_keep_the_captured_checkout_identity(tmp_path, monkeypatch):
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE", raising=False)
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY", raising=False)
    runtime_checkout = _source_checkout(tmp_path / "runtime-checkout")
    agent_checkout = _source_checkout(tmp_path / "agent-checkout")
    realm_root = tmp_path / "realm"
    create_realm(realm_root)
    credential_file = tmp_path / "astrid.json"
    daemon = RuntimeDaemon(
        realm_root,
        support_root=tmp_path / "support",
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential_file),
        runtime_checkout=runtime_checkout,
        agent_checkout=agent_checkout,
    ).start()
    world = DoorWorld(tmp_path, daemon, credential_file)
    try:
        world.provision()
        expected_identity = daemon.startup_identity
        bound_instance_id = daemon.startup_identity_instance_id
        assert expected_identity["managed_by"] == "source"
        assert expected_identity["dirty"] is False

        schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
        status, direct_bytes = world.owner("GET", "/v1/health")
        direct = json.loads(direct_bytes)
        proxied_reply = world.call(f"{API_RUNTIME}/v1/health")
        proxied = proxied_reply.json()
        discovery = daemon.discovery.read()
        assert status == 200 and proxied_reply.status == 200
        assert direct["identity"] == proxied["identity"] == discovery["identity"] == expected_identity
        assert direct["runtime_instance_id"] == proxied["runtime_instance_id"] == discovery["runtime_instance_id"] == bound_instance_id
        Draft202012Validator(schema).validate(direct)

        (runtime_checkout / "tracked.txt").write_text("changed after startup\n")
        (agent_checkout / "untracked.txt").write_text("also changed after startup\n")

        status, later_direct_bytes = world.owner("GET", "/v1/health")
        later_direct = json.loads(later_direct_bytes)
        later_proxied_reply = world.call(f"{API_RUNTIME}/v1/health")
        later_proxied = later_proxied_reply.json()
        later_discovery = daemon.discovery.read()
        assert status == 200 and later_proxied_reply.status == 200
        for body in (later_direct, later_proxied, later_discovery):
            assert body["identity"] == expected_identity
            assert body["runtime_instance_id"] == bound_instance_id
        Draft202012Validator(schema).validate(later_direct)
        assert Health.from_json(later_direct).identity == expected_identity
    finally:
        world.stop()


def test_health_fixture_carries_the_source_owner_identity():
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
    fixture = json.loads((ROOT / "conformance/fixtures/health.json").read_text())
    Draft202012Validator(schema).validate(fixture)
    assert fixture["identity"]["managed_by"] == "source"
    assert isinstance(fixture["runtime_instance_id"], str)


def test_neutral_identity_is_valid_for_a_raw_runtime_health_response():
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
    fixture = json.loads((ROOT / "conformance/fixtures/health.json").read_text())
    Draft202012Validator(schema).validate({**fixture, "identity": None})
