"""Selected Astrid profile: real Runtime + SDK resident host shutdown."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from astrid_runtime import cli
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.daemon import RuntimeDaemon

pytestmark = pytest.mark.integration


def test_down_waits_for_selected_generic_host_exit(tmp_path, monkeypatch, capsys):
    from astrid.sdk import AstridClient
    from astrid.sdk import host_bootstrap
    import astrid.services

    source = Path(astrid.services.__file__).resolve().parents[1]
    runtime = Path(__file__).resolve().parents[1]
    data = tmp_path / "launcher"
    data.mkdir()
    # Existing Runtime fixture realm; workspace attach below is the supported
    # owner operation. No installer, venv or application workspace is built.
    realm = tmp_path / "realm"
    fixture = RuntimeDaemon(realm, support_root=tmp_path / "fixture-support").start()
    realm_id = fixture.service.realm["id"]
    fixture.stop()
    manifest = data / "source-manifest.json"
    manifest.write_text(json.dumps({"profile": "astrid", "source_checkout": str(source),
        "runtime_checkout": str(runtime), "runtime_environment": sys.prefix}))
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setenv("ASTRID_RUNTIME_DATA_ROOT", str(data))
    monkeypatch.setenv("ASTRID_RUNTIME_SOURCE_MANIFEST", str(manifest))
    monkeypatch.setenv("ASTRID_RUNTIME_CHECKOUT", str(runtime))
    monkeypatch.setenv("ASTRID_PACK_HOST_PYTHON", sys.executable)
    observations = []
    host_states = []

    def command(*words):
        argv = [*words, "--profile", "astrid", "--data-root", str(data),
                "--source-manifest", str(manifest), "--hosted-origin", "off", "--json"]
        result = cli.main(argv)
        output = capsys.readouterr().out
        observations.append({"argv": argv, "exit": result, "stdout": output})
        (tmp_path / "runtime-host-lifecycle.json").write_text(json.dumps(observations, indent=2))
        assert result == 0, output
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == manifest_sha

    command("workspace", "attach", "--realm-root", str(realm), "--realm-id", realm_id,
            "--process-control", "sandbox")
    try:
        prior_instance = None
        for _ in range(2):
            command("up")
            client = AstridClient.open_from_launcher()
            assert client.projects.list().ok
            support = data / "runtime"
            registration = json.loads((support / "generic-host.json").read_text())
            host_states.append(registration)
            ready = json.loads((support / "generic-host.ready.json").read_text())
            owner = json.loads((support / "instance.lock").read_text())
            discovery = json.loads((support / "discovery.json").read_text())
            assert registration["runtime_instance_id"] == owner["runtime_instance_id"] == discovery["runtime_instance_id"]
            assert owner["runtime_instance_id"] != prior_instance
            prior_instance = owner["runtime_instance_id"]
            assert registration["support_root"] == str(support)
            assert owner["realm_root"] == discovery["realm_root"] == str(realm)
            for key in ("pid", "process_birth_id", "runtime_instance_id"):
                assert registration[key] == ready[key]
            assert host_bootstrap._registered_host_status(registration) == "ours"
            assert LocalRuntimeBoundary.process_birth_identity(registration["pid"]) == registration["process_birth_id"]
            observations.append({"before_down": {"manifest_sha256": manifest_sha,
                "registration": registration, "owner": owner, "discovery": discovery}})
            command("down")
            # These are synchronous postconditions of down, with no wait here.
            assert LocalRuntimeBoundary.process_birth_identity(registration["pid"]) != registration["process_birth_id"]
            assert LocalRuntimeBoundary.process_birth_identity(owner["pid"]) != owner["process_birth_id"]
            assert not (support / "generic-host.json").exists()
            assert not (support / "discovery.json").exists()
    finally:
        for state in host_states:
            if host_bootstrap._registered_host_status(state) == "ours":
                host_bootstrap._stop_registered_host(state)
        command("down")
