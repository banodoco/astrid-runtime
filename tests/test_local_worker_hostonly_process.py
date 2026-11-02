"""Installed CPU host, canonical installer stop, and same-root restart.

Build local wheels offline, as test_portable_lifecycle does. Process custody,
host preparation/activation, absence ACK, shutdown and proof are production code.
The full-pack case takes ASTRID_HOST_ONLY_INSTALLED_PYTHON from a stopped CPU
install for read-only dependencies; all selected wheels and mutable roots are private.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import time
import urllib.request

import pytest

from tests.astrid_checkout import astrid_checkout
from tests.lanes import requires_linux_tree_custody

pytestmark = [pytest.mark.integration, requires_linux_tree_custody]
ROOT = Path(__file__).resolve().parents[1]


def _run(argv, **kwargs):
    # -I ignores PYTHONDONTWRITEBYTECODE; keep retained dependency trees read-only.
    result = subprocess.run([str(argv[0]), "-B", *[str(arg) for arg in argv[1:]]], capture_output=True, text=True,
                            timeout=180, **kwargs)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def _copy_cpu_dependencies(purelib):
    # Same small offline dependency closure as Agent's installed CPU canary.
    owners = importlib.metadata.packages_distributions()
    for name in ("PIL", "yaml", "dotenv", "jsonschema", "attrs", "attr", "referencing", "rpds",
                 "jsonschema_specifications", "typing_extensions", "filelock", "jwt"):
        module = importlib.import_module(name)
        path = Path(module.__file__)
        if hasattr(module, "__path__"):
            shutil.copytree(path.parent, purelib / path.parent.name,
                            ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(path, purelib / path.name)
        for owner in owners.get(name, ()):
            distribution = importlib.metadata.distribution(owner)
            for item in distribution.files or ():
                libs = Path(item.parts[0])
                if libs.name.endswith(".libs") and not (purelib / libs.name).exists():
                    shutil.copytree(distribution.locate_file(libs), purelib / libs.name)


@pytest.fixture
def installed_cpu_host(tmp_path, monkeypatch, full_journey):
    agent_source = astrid_checkout()
    installed_python = os.environ.get("ASTRID_HOST_ONLY_INSTALLED_PYTHON")
    if full_journey:
        assert installed_python, "full journey requires ASTRID_HOST_ONLY_INSTALLED_PYTHON from a retained CPU install"
    home = tmp_path / "home"
    home.mkdir()
    for key in tuple(os.environ):
        if key.startswith(("ASTRID_", "VIBECOMFY_")):
            monkeypatch.delenv(key)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    monkeypatch.setenv("ASTRID_RUNTIME_DOOR_PORT", "0")
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "0")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    monkeypatch.setenv("ASTRID_HOST_EXECUTION_PROFILE", "installed")
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    sources = tmp_path / "sources"
    sources.mkdir()
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "tests", "build", "*.egg-info")
    for name, source, packages in (
        ("runtime", ROOT, ("astrid_runtime", "runtime_protocol")),
        ("agent", agent_source, ("astrid",)),
        ("client", ROOT / "packages/python", ("astrid_runtime_client",)),
    ):
        target = sources / name
        target.mkdir()
        for filename in ("pyproject.toml", "setup.py", "LICENSE", "NOTICE", "README.md"):
            if (source / filename).is_file():
                shutil.copy2(source / filename, target / filename)
        for package in packages:
            shutil.copytree(source / package, target / package, ignore=ignore)
        _run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
              "--no-build-isolation", "--wheel-dir", wheelhouse, target], env=env)
    environment = tmp_path / "venv"
    # The verifier inventories the complete interpreter prefix. Use a private
    # copy of this interpreter/stdlib, like an installer's managed Python;
    # Debian's /usr prefix would include unrelated multi-gigabyte system tools.
    base = tmp_path / "python-base"
    (base / "bin").mkdir(parents=True)
    base_python = base / "bin/python3"
    if installed_python:
        installed_paths = json.loads(_run([installed_python, "-I", "-c",
            "import json,sys,sysconfig;print(json.dumps({'executable':sys.executable,"
            "'stdlib':sysconfig.get_path('stdlib'),'purelib':sysconfig.get_path('purelib')}))"], env=env))
        shutil.copy2(Path(installed_paths["executable"]).resolve(), base_python)
        stdlib = Path(installed_paths["stdlib"])
    else:
        shutil.copy2(Path(sys.executable).resolve(), base_python)
        stdlib = Path(sysconfig.get_path("stdlib"))
    shutil.copytree(stdlib, base / "lib" / stdlib.name,
                    ignore=shutil.ignore_patterns("site-packages", "dist-packages", "__pycache__", "*.pyc"))
    assert Path(_run([base_python, "-I", "-c", "import sys;print(sys.base_prefix)"], env=env)) == base
    _run([base_python, "-m", "venv", environment], env=env)
    python = environment / "bin/python"
    _run([python, "-m", "pip", "install", "--no-index", "--no-deps", *wheelhouse.glob("*.whl")], env=env)
    purelib = Path(_run([python, "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"], env=env))
    if installed_python:
        # Copy the actual CPU dependencies, including VibeComfy, without a
        # fallback product root: reviewed metadata forbids duplicate origins.
        products = {"astrid", "astrid_runtime", "runtime_protocol", "astrid_runtime_client",
                    "pip", "setuptools", "pkg_resources", "_distutils_hack", "wheel"}
        for item in Path(installed_paths["purelib"]).iterdir():
            if (item.name in products or item.suffix == ".pth" or item.name == "__pycache__"
                    or any(item.name.startswith(name + "-") and item.name.endswith(".dist-info")
                           for name in products) or (purelib / item.name).exists()):
                continue
            if item.is_dir():
                shutil.copytree(item, purelib / item.name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            elif item.is_file():
                shutil.copy2(item, purelib / item.name)
    else:
        _copy_cpu_dependencies(purelib)
    # The canonical installer also retains source configuration beside its
    # wheels. Keep the real capability census: it makes full serving-slot
    # construction materially slower than the one-pack round 2 fixture.
    shutil.copytree(agent_source / "config", purelib / "config")
    return python, purelib, env


def _wait_ready(data, process, log, *, prior_instance=None, capability="cpu_probe.ping"):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        assert process.poll() is None, log.read_text()
        try:
            discovery = json.loads((data / "runtime/discovery.json").read_text())
            ready = json.loads((data / "runtime/worker-astrid-ready.json").read_text())
            if (ready["runtime_instance_id"] == discovery["runtime_instance_id"]
                    and discovery["runtime_instance_id"] != prior_instance):
                with urllib.request.urlopen(discovery["endpoint"] + "/v1/health", timeout=3) as response:
                    assert json.load(response)["status"] == "ok"
                assert capability in ready["ready_capabilities"]
                return discovery, ready
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.05)
    pytest.fail("Verified CPU host did not become READY: " + log.read_text())


@pytest.mark.parametrize("full_journey", [False, True], ids=["probe", "full-pack-profile-change"])
def test_installed_host_only_canonical_stop_publishes_proof_and_restarts(tmp_path, installed_cpu_host, full_journey):
    python, purelib, env = installed_cpu_host
    data, version = tmp_path / "data", tmp_path / "version"
    version.mkdir()
    # The full journey must serve the ordinary installed pack inventory before
    # adding the inert canary pack. A tiny pack misses full-host exit latency.
    pack = purelib / "cpu_probe"
    (pack / "actions").mkdir(parents=True)
    (pack / "pack.yaml").write_text(json.dumps({
        "schema_version": 3, "id": "cpu_probe", "name": "CPU probe", "version": "1.0.0",
        "actions": {"ping": {"description": "CPU restart probe", "invocation": {
            "kind": "python", "path": "actions/ping.py", "function": "run"},
            "inputs": [], "outputs": {}}},
    }))
    (pack / "actions/ping.py").write_text("def run():\n    return {}\n")
    profile = version / "profile.json"
    _run([python, "-I", "-c", '''
import json, pathlib, sys
from astrid.installer.worker_profile import write_worker_profile
from astrid.services import service_declaration
from runtime_protocol.local_worker import _digest
folder, source, data, pack = map(pathlib.Path, sys.argv[1:5])
full_journey = sys.argv[5] == 'True'
worker_path = write_worker_profile(folder, source, data,
    source / 'config/astrid-beta-capabilities.json' if full_journey else None)
worker = json.loads(worker_path.read_text())
if not full_journey:
    worker['pack_root'] = str(pack)
launch = {key: worker[key] for key in ('source_checkout', 'pack_root', 'boot_manifest_path',
    'boot_manifest_hash', 'capability_matrix', 'environment', 'max_concurrency')}
worker['session_config_digest'] = _digest(launch)
worker['profile_digest'] = _digest({key: value for key, value in worker.items() if key != 'profile_digest'})
worker_path.write_text(json.dumps(worker))
services = service_declaration(source_checkout=source, data_root=data, python=sys.executable, bun=sys.executable)
services['services'] = [row for row in services['services'] if row['name'] == 'pack-host']
services_path = folder / 'services.json'
services_path.write_text(json.dumps(services))
(folder / 'profile.json').write_text(json.dumps({'profile':'astrid', 'runtime_checkout':str(source),
    'source_checkout':str(source), 'runtime_environment':sys.prefix,
    'service_declaration':str(services_path), 'worker_profile':str(worker_path)}))
''', version, purelib, data, pack, full_journey], env=env)
    command = [str(python), "-I", "-B", "-m", "astrid_runtime.cli"]
    options = ["--data-root", str(data), "--source-manifest", str(profile), "--hosted-origin", "off", "--json"]
    _run([*command, "workspace", "create", "--realm-root", data / "realm", "--realm-id", "cpu-restart", *options], env=env)
    stop_script = '''
import pathlib,sys
from astrid.installer.backend import Backend
from astrid.installer.core import Version
folder,data=map(pathlib.Path,sys.argv[1:])
backend=Backend(folder/'program',folder/'installer.log',pathlib.Path(sys.executable),say=lambda _:None)
assert backend.stop(Version(folder,pathlib.Path(sys.executable),folder/'profile.json',{}),data)['status']=='stopped'
'''
    processes = []
    log = tmp_path / "foreground.log"
    try:
        with log.open("w") as output:
            first = subprocess.Popen([*command, "run", *options], env=env, stdout=output, stderr=subprocess.STDOUT)
            processes.append(first)
            discovery, ready = _wait_ready(data, first, log,
                capability="h3_av.prepare" if full_journey else "cpu_probe.ping")
            # Capture only the synthetic generation's nonsecret proof binding.
            binding = json.loads(_run([python, "-I", "-c", '''
import json,pathlib,sys
from runtime_protocol.auth import CredentialStore
from runtime_protocol.local_worker import _credential_commit_generation,_digest
from runtime_protocol.daemon import WORKER_ACTOR
store=CredentialStore(pathlib.Path(sys.argv[1])/'runtime/credentials')
print(json.dumps({'receipt_digest':_digest(store.actor_metadata(WORKER_ACTOR)['local_launch_receipt']),
    'credential_generation':_credential_commit_generation(store,WORKER_ACTOR)}))
''', data], env=env))
            _run([python, "-I", "-c", stop_script, version, data], env=env)
            assert first.wait(timeout=10) == 0, log.read_text()
            proof = json.loads((data / "runtime/host-only-orderly-stop.json").read_text())
            assert proof == {"version": "runtime.host-only-orderly-stop/v1", "state": "complete",
                "actor": "astrid-pack-host", "workspace_uuid": "cpu-restart",
                "realm_root": str(data / "realm"), "support_root": str(data / "runtime"), **binding}
            if full_journey:
                # Frozen installed_canary/journey.py stops first, then copies
                # the pack and rewrites profile/session bindings before start.
                canary = tmp_path / "canary-pack" / "cpu_probe"
                shutil.copytree(pack, canary)
                old_profile = json.loads((version / "worker-profile.json").read_text())
                _run([python, "-I", "-c", '''
import json,pathlib,sys
from runtime_protocol.local_worker import _digest
from runtime_protocol.local_worker_composition import _pack_inventory
path,pack=map(pathlib.Path,sys.argv[1:])
worker=json.loads(path.read_text())
worker['additional_pack_roots']=[{'path':str(pack),'files':_pack_inventory(pack)}]
matrix=json.loads(pathlib.Path(worker['capability_matrix']).read_text())
matrix['capabilities'].append({'id':'cpu_probe.ping','disposition':'optional',
    'evidence_reason':'inert installed restart canary','adapter_family':'cpu','resource_keys':['cpu']})
matrix_path=path.parent/'canary-capabilities.json'
matrix_path.write_text(json.dumps(matrix))
worker['capability_matrix']=str(matrix_path)
launch={key:worker[key] for key in ('source_checkout','pack_root','boot_manifest_path',
    'boot_manifest_hash','capability_matrix','environment','max_concurrency','additional_pack_roots')}
worker['session_config_digest']=_digest(launch)
worker['profile_digest']=_digest({key:value for key,value in worker.items() if key!='profile_digest'})
path.write_text(json.dumps(worker))
''', version / "worker-profile.json", canary], env=env)
                assert json.loads((version / "worker-profile.json").read_text())["profile_digest"] != old_profile["profile_digest"]
            second = subprocess.Popen([*command, "run", *options], env=env, stdout=output, stderr=subprocess.STDOUT)
            processes.append(second)
            next_discovery, next_ready = _wait_ready(data, second, log, prior_instance=discovery["runtime_instance_id"])
            assert next_discovery["active_realm"] == discovery["active_realm"]
            assert next_ready["activation"]["executor_incarnation"] != ready["activation"]["executor_incarnation"]
            if full_journey:
                advertised = _run([python, "-I", "-c", '''
import json,pathlib,sys
from astrid_runtime.cli import _credential
from astrid_runtime.paths import RuntimePaths
from astrid_runtime_client import WorkspaceClient
data=pathlib.Path(sys.argv[1]);discovery=json.loads((data/'runtime/discovery.json').read_text())
client=WorkspaceClient(discovery['endpoint'],_credential(RuntimePaths.current(data_root=data)))
rows=[];cursor=None;seen=set()
while True:
    page,cursor=client.list_capabilities(cursor=cursor,limit=100)
    rows.extend(page)
    if cursor is None:break
    assert cursor not in seen
    seen.add(cursor)
selected={r.capability_id:r for r in rows if r.capability_id in ('cpu_probe.ping','h3_av.prepare')}
assert set(selected)=={'cpu_probe.ping','h3_av.prepare'}
assert all(r.status=='ready' and r.definition_digest for r in selected.values())
print(json.dumps({k:r.definition_digest for k,r in selected.items()}))
''', data], env=env)
                (tmp_path / "canary-capabilities.json").write_text(advertised)
            _run([python, "-I", "-c", stop_script, version, data], env=env)
            assert second.wait(timeout=10) == 0, log.read_text()
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
