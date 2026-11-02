"""Selected Astrid profile: real Runtime + SDK resident host shutdown."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import shutil

import pytest

from astrid_runtime import cli
from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore

pytestmark = pytest.mark.integration


def test_down_waits_for_selected_generic_host_exit(tmp_path, monkeypatch, astrid_importable):
    from astrid.sdk import AstridClient
    from astrid.sdk import host_bootstrap
    import astrid.services

    source = astrid_importable
    assert Path(astrid.services.__file__).resolve().is_relative_to(source)
    runtime = Path(__file__).resolve().parents[1]
    data = tmp_path / "launcher"
    data.mkdir()
    # Existing Runtime fixture realm; workspace attach below is the supported
    # owner operation. No installer, venv or application workspace is built.
    realm = tmp_path / "realm"
    RealmStore.initialize(realm, display_name="RunPod CPU shutdown fixture").close()
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

    def command(*words, preload=None, selected_manifest=None, expected_error=None):
        argv = [*words, "--profile", "astrid", "--data-root", str(data),
                "--source-manifest", str(selected_manifest or manifest), "--hosted-origin", "off", "--json"]
        # Select Runtime only; isolated Python still sees the environment's
        # installed Agent. Production CLI must select the manifest's Agent.
        preimport = (f"sys.path.insert(0,{str(preload)!r}); import astrid.services; sys.path.pop(0); "
                     if preload else "")
        launch = [sys.executable, "-I", "-B", "-c",
                  "import runpy,sys; " + preimport + "sys.path.insert(0,sys.argv.pop(1)); "
                  "runpy.run_module('astrid_runtime',run_name='__main__')",
                  str(runtime), *argv]
        environment = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "LANG") if key in os.environ}
        result = subprocess.run(launch, env=environment, capture_output=True, text=True, timeout=90)
        output = result.stdout
        observations.append({"argv": launch, "exit": result.returncode, "stdout": output,
                             "stderr": result.stderr})
        (tmp_path / "runtime-host-lifecycle.json").write_text(json.dumps(observations, indent=2))
        if expected_error is None:
            assert result.returncode == 0, (output, result.stderr)
        else:
            assert result.returncode == 1, (output, result.stderr)
            payload = json.loads(output)
            assert payload["ok"] is False and expected_error in str(payload["error"])
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
            assert host_bootstrap._host_birth_identity(registration["pid"]) == registration["process_birth_id"]
            # Agent's registration uses boot:tick; Runtime's kernel identity
            # additionally includes PID-namespace scope. Retain both encodings
            # and compare each only through its own observation boundary.
            host_kernel_birth = LocalRuntimeBoundary.process_birth_identity(registration["pid"])
            assert host_kernel_birth
            observations.append({"before_down": {"manifest_sha256": manifest_sha,
                "registration": registration, "host_kernel_birth_id": host_kernel_birth,
                "owner": owner, "discovery": discovery}})
            # A real second source was imported before CLI dispatch. Refuse
            # its cached owner even though it has the shutdown helper.
            foreign = tmp_path / "foreign-agent"
            foreign_package = foreign / "astrid"
            foreign_package.mkdir(parents=True, exist_ok=True)
            for name in ("__init__.py", "version.py", "services.py"):
                shutil.copyfile(source / "astrid" / name, foreign_package / name)
            command("down", preload=foreign, expected_error="unselected origin")
            assert LocalRuntimeBoundary.process_birth_identity(owner["pid"]) == owner["process_birth_id"]
            assert json.loads((support / "generic-host.json").read_text()) == registration

            # Declared source paths and registration custody are checked at
            # the same real CLI boundary, before any stop effect.
            invalid = json.loads(manifest.read_text())
            invalid["source_checkout"] = str(tmp_path / "missing-agent")
            bad_manifest = data / "invalid-source.json"
            bad_manifest.write_text(json.dumps(invalid))
            command("down", selected_manifest=bad_manifest, expected_error="Selected Agent checkout")
            replaced = {**registration, "runtime_instance_id": "foreign-incarnation"}
            (support / "generic-host.json").write_text(json.dumps(replaced))
            try:
                command("down", expected_error="differs from the selected Runtime owner")
                assert LocalRuntimeBoundary.process_birth_identity(owner["pid"]) == owner["process_birth_id"]
                assert json.loads((support / "generic-host.json").read_text()) == replaced
            finally:
                (support / "generic-host.json").write_text(json.dumps(registration))
            command("down")
            # These are synchronous postconditions of down, with no wait here.
            after = {"host_pid": registration["pid"], "host_before_birth": host_kernel_birth,
                "host_after_birth": LocalRuntimeBoundary.process_birth_identity(registration["pid"]),
                "runtime_pid": owner["pid"], "runtime_before_birth": owner["process_birth_id"],
                "runtime_after_birth": LocalRuntimeBoundary.process_birth_identity(owner["pid"]),
                "registration_exists": (support / "generic-host.json").exists(),
                "discovery_exists": (support / "discovery.json").exists()}
            observations.append({"after_down": after})
            (tmp_path / "runtime-host-lifecycle.json").write_text(json.dumps(observations, indent=2))
            assert after["host_after_birth"] != host_kernel_birth
            assert after["runtime_after_birth"] != owner["process_birth_id"]
            assert not after["registration_exists"]
            assert not after["discovery_exists"]
    finally:
        for state in host_states:
            if host_bootstrap._registered_host_status(state) == "ours":
                host_bootstrap._stop_registered_host(state)
        # Preserve the production-boundary failure while cleaning its owner.
        assert cli.main(["down", "--profile", "astrid", "--data-root", str(data),
                         "--source-manifest", str(manifest), "--hosted-origin", "off", "--json"]) == 0
