"""Real retained custody spawn of the Agent host with installed packs (B1, darwin lane).

The Runtime is started for real (``runtime_protocol start --worker-profile``), its
local worker start spawns the real Agent generic host under retained custody, and
the installed collection holds one verified pack and one whose definitions record
was edited after install. The evidence is the assertions:

* the verified host argv carries ``--pack-root`` for the installed granted root and
  none for the refused one;
* the granted pack's executor registers and a task on it runs to ``succeeded``;
* the ungranted pack is named in discovery.json with its reason and never registers.

Lane: ``darwin_native`` (run by the ``darwin-native`` CI job, deselected and skipped
elsewhere; tests/lanes.py). The host-only custody spawn is a Darwin path; on a darwin
lane a broken spawn fails this test, it never skips. It needs the Astrid Agent
installed as a distribution in the test interpreter (the release digest is taken
from its RECORD) and ``git`` on PATH; a missing prerequisite is a failure.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
import subprocess
import sys
import sysconfig
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

PACK_YAML = """schema_version: 3
id: {pack}
name: {name}
version: 1.0.0
pack_api: "2.3"
documentation: {{kind: none, reason: Custody spawn fixture.}}
"""


def _executor(pack):
    return json.dumps({"schema_version": 1, "id": f"{pack}.echo", "name": "Echo", "kind": "external", "version": "1.0",
        "command": {"argv": ["{python_exec}", "-c",
            f"from pathlib import Path; Path('{{out}}/answer.txt').write_text('{pack} ran')"]},
        "outputs": [{"name": "answer", "type": "file", "path_template": "{out}/answer.txt", "artifact_type": "text/plain"}],
        "metadata": {"resource_keys": ["cpu"], "estimated_scratch_bytes": 1}})


def _source_repository(root):
    for pack in ("granted", "ungranted"):
        folder = root / "packs" / pack
        (folder / "executors" / "echo").mkdir(parents=True)
        (folder / "pack.yaml").write_text(PACK_YAML.format(pack=pack, name=pack.title()))
        (folder / "executors" / "echo" / "executor.yaml").write_text(_executor(pack))
    git = ["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.test"]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "fixture"], check=True)
    return root


def _installed_record(name, site):
    """RECORD of the installed dist-info; ambient sys.path entries (a checkout's *.egg-info) have none."""
    for dist in metadata.Distribution.discover(name=name, path=[str(site)]):
        record = dist.read_text("RECORD")
        if record is not None:
            return record
    raise AssertionError(f"{name} has no installed RECORD beneath {site}")


def _worker_profile(base, support, python):
    from astrid.core.gateway.dispatch import compose_profile_handoff
    from runtime_protocol.local_worker import _digest
    from runtime_protocol.local_worker_composition import _owner_machine_id
    from runtime_protocol.verified_host_launch import raw_digest, source_checkout_closure

    site = Path(sysconfig.get_paths()["purelib"]).resolve()
    records = {name: hashlib.sha256(_installed_record(name, site).encode()).hexdigest()
        for name in ("astrid", "astrid-runtime")}
    kernel = python.resolve()
    kernel_digest = "sha256:" + hashlib.sha256(kernel.read_bytes()).hexdigest()
    boot = support / "astrid-host" / "boot-manifest.json"
    compose_profile_handoff(boot, support_root=support)
    launch = {"source_checkout": str(site), "pack_root": str(site / "astrid" / "packs"), "boot_manifest_path": str(boot),
        "boot_manifest_hash": "sha256:" + hashlib.sha256(boot.read_bytes()).hexdigest(), "capability_matrix": None,
        "environment": {}, "max_concurrency": 2}
    profile = {"execution_mode": "host_only_cpu", "profile_id": "astrid", "machine_id": _owner_machine_id(),
        "host_executable": str(python), "host_artifact_digest": kernel_digest, "host_os_executable": str(kernel),
        "host_os_artifact_digest": kernel_digest, "session_config_digest": _digest(launch), "profile_revision": "1",
        "profile_digest": "sha256:" + "1" * 64, "release_digest": "sha256:" + raw_digest(records),
        "host_protocol": {"version": "runtime.local-execution-current-roles/v1", "module": "astrid.core.execution.generic_host",
            "source_closure_digest": source_checkout_closure(site)["digest"]},
        **launch, "worker_timeout_seconds": 60}
    path = base / "worker-profile.json"
    path.write_text(json.dumps(profile))
    return path


# Records the exact argv the Runtime's custody build hands the verified launcher (the
# launcher passes it to the host unchanged); nothing else in the Runtime is altered.
RECORDING_RUNTIME = """
import json, runpy, sys
from runtime_protocol import verified_host_launch as gate
record = sys.argv.pop(1)
original = gate.TrustedLocalHostLaunchVerifier.verify
def verify(self, *, host_argv, **kwargs):
    with open(record, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(list(host_argv)) + "\\n")
    return original(self, host_argv=host_argv, **kwargs)
gate.TrustedLocalHostLaunchVerifier.verify = verify
sys.argv[0] = "runtime_protocol"
runpy.run_module("runtime_protocol", run_name="__main__", alter_sys=True)
"""


@pytest.mark.darwin_native
def test_real_custody_spawn_launches_granted_installed_pack_and_refuses_ungranted(tmp_path, owned_process_groups):
    base = tmp_path.resolve()
    home, realm, support = base / "home", base / "realm", base / "support"
    home.mkdir(); support.mkdir(mode=0o700)
    python = Path(os.path.abspath(sys.executable))
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["HOME"] = str(home)
    source = _source_repository(base / "source")
    for pack in ("granted", "ungranted"):
        subprocess.run([str(python), "-c", "import sys; from astrid.core.pack.cli import main; sys.exit(main(sys.argv[1:]))",
            "add", "--pack-id", pack, "--subpath", "packs/" + pack, "--revision", "main", "--yes", str(source)],
            check=True, env=environment, capture_output=True)
    collection = home / "Astrid" / "packs"
    granted, ungranted = collection / "granted", collection / "ungranted"
    record_path = ungranted / ".build" / "definitions.json"
    record = json.loads(record_path.read_text())
    record["definitions"][0]["capability_id"] = "ungranted.forged"
    record_path.write_text(json.dumps(record))
    profile = _worker_profile(base, support, python)

    realm_id = str(uuid.uuid4())
    subprocess.run([str(python), "-m", "runtime_protocol", "create", "--root", str(realm), "--realm-id", realm_id],
        check=True, env=environment)
    argv_record = base / "host-argv.jsonl"
    log_path = base / "runtime.log"
    with log_path.open("w") as log:
        runtime = owned_process_groups.popen([str(python), "-c", RECORDING_RUNTIME, str(argv_record), "start",
            "--root", str(realm), "--support-root", str(support), "--realm-id", realm_id, "--worker-profile", str(profile)],
            env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            cwd=str(base))  # not the checkout: its *.egg-info would shadow the installed dist-info

    def stop_runtime():
        # Graceful first, so the Runtime retires its custody host; the group kill follows.
        if runtime.poll() is None:
            runtime.terminate()
            runtime.wait(30)
    owned_process_groups.add_cleanup(stop_runtime)

    def log_tail():
        return log_path.read_text(errors="replace")[-4000:]

    discovery_path = support / "discovery.json"
    deadline = time.monotonic() + 60
    while not discovery_path.exists():
        assert runtime.poll() is None, "Runtime exited before discovery:\n" + log_tail()
        assert time.monotonic() < deadline, "Runtime published no discovery:\n" + log_tail()
        time.sleep(0.1)
    while True:
        try:
            endpoint = json.loads(discovery_path.read_text())["endpoint"]
            break
        except (ValueError, KeyError):
            assert time.monotonic() < deadline, "Runtime discovery is unreadable:\n" + log_tail()
            time.sleep(0.1)
    token = (support / "credentials" / "owner.token").read_text().strip()

    def call(method, path, body=None, *, key=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        request = urllib.request.Request(endpoint + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors="replace")
        except (urllib.error.URLError, ConnectionError) as error:  # the Runtime dropped the call
            return None, repr(error)

    status, started = call("POST", "/v1/control/local-worker/start",
        {"profile_id": "astrid", "expected_workspace_uuid": realm_id})

    # DIAG (temporary): surface the start response and Runtime log before the argv read.
    (base / "start-response.json").write_text(json.dumps({"status": status, "body": started}, default=str))
    print("DIAG start status:", status, "body:", started)
    print("DIAG runtime.log tail:\n" + log_tail())
    print("DIAG argv_record exists:", argv_record.exists())
    # (1) The verified host argv carries the granted installed root, never the refused one.
    launches = [json.loads(line) for line in argv_record.read_text().splitlines()]
    assert launches, "custody build handed no argv to the verified launcher:\n" + log_tail()
    argv = launches[-1]
    roots = [argv[i + 1] for i, value in enumerate(argv) if value == "--pack-root"]
    assert str(granted) in roots
    assert str(ungranted) not in argv and str(collection) not in roots

    # (2) The ungranted pack is a named refusal in discovery.json.
    named = json.loads((support / "external-pack-sources" / "discovery.json").read_text())
    assert named["installed_pack_root"] == str(collection)
    assert named["refusals"] == [{"pack_id": "ungranted", "root": str(ungranted),
        "reason": "installed pack ungranted is excluded from host discovery: "
                  "installed pack definitions record differs from its admission digest"}]

    # (3) The real spawn succeeded; the granted executor registers (the ungranted one
    # never does) and runs.
    assert status == 200, (started, log_tail())
    deadline = time.monotonic() + 60
    while True:
        status, listing = call("GET", "/v1/capabilities")
        assert status == 200, (listing, log_tail())
        capabilities = {item["capability_id"]: item for item in listing["data"]}
        if capabilities.get("granted.echo", {}).get("status") == "ready":
            break
        assert runtime.poll() is None, "Runtime exited before registration:\n" + log_tail()
        assert time.monotonic() < deadline, (capabilities, log_tail())
        time.sleep(0.25)
    assert not {name for name in capabilities if name.startswith("ungranted.")}
    status, project = call("POST", "/v1/projects", {"slug": "custody-spawn", "name": "Custody spawn", "metadata": {}},
        key="custody-spawn-project")
    assert status in (200, 201), project
    status, task = call("POST", "/v1/tasks", {"project": project["data"]["project_id"], "capability_id": "granted.echo",
        "capability_digest": capabilities["granted.echo"]["definition_digest"], "input_object_ids": [], "spec": {}},
        key="custody-spawn-granted")
    assert status in (200, 201), task
    task_id = task["data"]["task_id"]
    deadline = time.monotonic() + 120
    while True:
        status, current = call("GET", f"/v1/tasks/{task_id}")
        assert status == 200, current
        state = (current.get("data") or current)["state"]
        if state not in ("queued", "claimed", "running", "pending"):
            break
        assert time.monotonic() < deadline, (current, log_tail())
        time.sleep(0.25)
    assert state == "succeeded", (current, log_tail())
