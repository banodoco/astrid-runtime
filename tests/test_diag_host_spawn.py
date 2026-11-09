"""DIAG ONLY (never merge): does a Runtime-managed host-only spawn work, independent of installed packs?

Uses the built-in packs (no `pack add`), so it also runs against R10, whose Agent has no installed-pack CLI.
Reuses the helpers of the custody-spawn test. Passes only if POST /v1/control/local-worker/start returns 200."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from tests.test_installed_pack_custody_spawn import _worker_profile

# Same as the custody-spawn test's recorder, plus: log every control frame the Runtime receives from the host.
RECORDING_RUNTIME = """
import json, runpy, sys
from runtime_protocol import verified_host_launch as gate
from runtime_protocol import local_worker_composition as lwc
record = sys.argv.pop(1)
original = gate.TrustedLocalHostLaunchVerifier.verify
def verify(self, *, host_argv, **kwargs):
    with open(record, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(list(host_argv)) + "\\n")
    return original(self, host_argv=host_argv, **kwargs)
gate.TrustedLocalHostLaunchVerifier.verify = verify
real_receive = lwc._frame_receive
def receive(channel):
    value = real_receive(channel)
    with open(record + ".frames", "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, default=str) + "\\n")
    return value
lwc._frame_receive = receive
sys.argv[0] = "runtime_protocol"
runpy.run_module("runtime_protocol", run_name="__main__", alter_sys=True)
"""


@pytest.mark.darwin_native
def test_diag_host_only_spawn_with_builtin_packs(tmp_path, owned_process_groups):
    base = tmp_path.resolve()
    home, realm, support = base / "home", base / "realm", base / "support"
    home.mkdir(); support.mkdir(mode=0o700)
    python = Path(os.path.abspath(sys.executable))
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["HOME"] = str(home)
    profile = _worker_profile(base, support, python)
    realm_id = str(uuid.uuid4())
    subprocess.run([str(python), "-m", "runtime_protocol", "create", "--root", str(realm), "--realm-id", realm_id],
        check=True, env=environment)
    argv_record = base / "host-argv.jsonl"
    log_path = base / "runtime.log"
    with log_path.open("w") as log:
        runtime = owned_process_groups.popen([str(python), "-c", RECORDING_RUNTIME, str(argv_record), "start",
            "--root", str(realm), "--support-root", str(support), "--realm-id", realm_id, "--worker-profile", str(profile)],
            env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, cwd=str(base))

    def stop_runtime():
        if runtime.poll() is None:
            runtime.terminate()
            runtime.wait(30)
    owned_process_groups.add_cleanup(stop_runtime)
    discovery_path = support / "discovery.json"
    deadline = time.monotonic() + 60
    while not discovery_path.exists():
        assert runtime.poll() is None, "Runtime exited before discovery:\n" + log_path.read_text(errors="replace")[-3000:]
        assert time.monotonic() < deadline
        time.sleep(0.1)
    while True:
        try:
            endpoint = json.loads(discovery_path.read_text())["endpoint"]
            break
        except (ValueError, KeyError):
            time.sleep(0.1)
    token = (support / "credentials" / "owner.token").read_text().strip()
    request = urllib.request.Request(endpoint + "/v1/control/local-worker/start", method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        data=json.dumps({"profile_id": "astrid", "expected_workspace_uuid": realm_id}).encode())
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            status, body = response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read().decode(errors="replace")
    except (urllib.error.URLError, ConnectionError) as error:
        status, body = None, repr(error)
    spawned = argv_record.exists()
    (base / "start-response.json").write_text(json.dumps({"status": status, "body": body, "spawned": spawned}))
    print("DIAG2 spawned:", spawned, "start status:", status, "body:", body[:400])
    frames = Path(str(argv_record) + ".frames")
    print("DIAG2 host control frames:", frames.read_text() if frames.exists() else "<none>")
    print("DIAG2 runtime.log tail:\n" + log_path.read_text(errors="replace")[-3000:])
    assert status == 200, (status, body)
