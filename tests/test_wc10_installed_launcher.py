"""One installed-host proof for the normal Astrid launcher profile.

This builds a private, non-editable carrier with the approved 54-distribution
dependency closure so normal profile, custody, authentication, and provider-
backed empty-timeline behavior are tested without checkout imports or shared
environment writes.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from packaging.utils import canonicalize_name


AGENT_COMMIT = "6efc81500a0e0688c2bb41e736503f0fc3e04abb"
AGENT_TREE = "2ed2b8a12b5b3391ca221ba6ff05390f71a73556"
AGENT_SOURCE = Path("/home/user/work/wt/agt-pin-6efc8150")
RUNTIME_COMMIT = "8f70a8184aca5bb61b2fcb133c5cedc3c6e0800a"
NORMAL_RUNTIME_COMMIT = "95bd3c5f6d00e9bc8cc8cbe5ef510b68ed660f3c"
NORMAL_RUNTIME_SOURCE = Path("/home/user/work/wt/rt-pin-95bd3c5f")
APPROVED_ENVIRONMENT = Path("/home/user/work/venv-agent")

DECLARED_CLOSURE = (
    "aiofiles",
    "annotated-types",
    "anthropic",
    "anyio",
    "asyncstdlib",
    "attrs",
    "certifi",
    "cffi",
    "charset-normalizer",
    "click",
    "cryptography",
    "distro",
    "docstring-parser",
    "fal-client",
    "filelock",
    "google-auth",
    "google-genai",
    "h11",
    "httpcore",
    "httpcore2",
    "httpx",
    "httpx-sse",
    "httpx2",
    "idna",
    "jiter",
    "jsonschema",
    "jsonschema-specifications",
    "msgpack",
    "numpy",
    "openai",
    "opencv-python-headless",
    "pillow",
    "platformdirs",
    "pyasn1",
    "pyasn1-modules",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "pyjwt",
    "python-dotenv",
    "pyyaml",
    "referencing",
    "requests",
    "rpds-py",
    "scenedetect",
    "sniffio",
    "tenacity",
    "tqdm",
    "truststore",
    "typing-extensions",
    "typing-inspection",
    "urllib3",
    "websockets",
    "xxhash",
)


def _python(environment: Path) -> Path:
    return environment / "bin" / "python"


def _run(argv: list[str | Path], *, env: dict[str, str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(part) for part in argv], env=env, text=True, **kwargs)


def _git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def _copy_source(source: Path, destination: Path, package_dirs: tuple[str, ...]) -> None:
    destination.mkdir()
    shutil.copy2(source / "pyproject.toml", destination / "pyproject.toml")
    for filename in ("setup.py", "LICENSE"):
        if (source / filename).is_file():
            shutil.copy2(source / filename, destination / filename)
    for package in package_dirs:
        shutil.copytree(
            source / package,
            destination / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )


def _build_product_wheels(tmp_path: Path) -> Path:
    """Build all products from private copies, without importing a checkout."""
    runtime_source = tmp_path / "runtime-wheel-source"
    client_source = tmp_path / "normal-client-wheel-source"
    agent_source = tmp_path / "agent-wheel-source"
    root = Path(__file__).resolve().parents[1]
    _copy_source(root, runtime_source, ("astrid_runtime", "runtime_protocol"))
    _copy_source(
        NORMAL_RUNTIME_SOURCE / "packages" / "python",
        client_source,
        ("astrid_runtime_client",),
    )
    _copy_source(AGENT_SOURCE, agent_source, ("astrid", "astrid_runtime_client"))

    wheelhouse = tmp_path / "product-wheelhouse"
    wheelhouse.mkdir()
    build_environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(runtime_source),
            str(client_source),
            str(agent_source),
        ],
        check=True,
        env=build_environment,
    )
    wheels = sorted(wheelhouse.glob("*.whl"))
    assert len(wheels) == 3, wheels
    assert {wheel.name.split("-", 1)[0] for wheel in wheels} == {
        "astrid",
        "astrid_runtime",
        "astrid_runtime_client",
    }
    return wheelhouse


def _approved_distributions() -> dict[str, str]:
    available = {
        canonicalize_name(distribution.metadata["Name"]): distribution.version
        for distribution in importlib.metadata.distributions()
    }
    missing = [name for name in DECLARED_CLOSURE if canonicalize_name(name) not in available]
    assert not missing, f"approved shared inventory is missing {missing}"
    return {name: available[canonicalize_name(name)] for name in DECLARED_CLOSURE}


def _site_packages(environment: Path) -> Path:
    result = subprocess.run(
        [
            _python(environment),
            "-I",
            "-B",
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=environment.parent,
        env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return Path(result.stdout.strip()).resolve()


def _safe_copy(source: Path, source_root: Path, target_root: Path) -> None:
    source = source.absolute()
    if source.is_symlink():
        raise AssertionError(f"shared dependency contains a symlink: {source}")
    resolved = source.resolve(strict=True)
    if not resolved.is_relative_to(source_root):
        raise AssertionError(f"shared dependency escapes its environment: {source}")
    relative = resolved.relative_to(source_root)
    target = target_root / relative
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise AssertionError(f"private dependency target is not a file: {target}")
        if hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(resolved.read_bytes()).digest():
            raise AssertionError(f"dependency collision changed bytes: {target}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resolved, target)


def _install_approved_closure(environment: Path) -> None:
    """Copy the validated shared closure into this private environment by bytes."""
    source_root = APPROVED_ENVIRONMENT.resolve()
    target_root = environment.resolve()
    for name in DECLARED_CLOSURE:
        distribution = importlib.metadata.distribution(name)
        for record in distribution.files or ():
            _safe_copy(distribution.locate_file(record), source_root, target_root)


def _install_products(environment: Path, wheelhouse: Path) -> None:
    pip = environment / "bin" / "pip"
    wheels = {wheel.name.split("-", 1)[0]: wheel for wheel in wheelhouse.glob("*.whl")}
    subprocess.run(
        [
            str(pip),
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheels["astrid_runtime"]),
            str(wheels["astrid"]),
            str(wheels["astrid_runtime_client"]),
        ],
        check=True,
    )


def _make_installed_environment(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    approved = _approved_distributions()
    environment = tmp_path / "installed-runtime"
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    _install_approved_closure(environment)
    wheelhouse = _build_product_wheels(tmp_path)
    _install_products(environment, wheelhouse)
    return environment, approved


def _preflight_installed_environment(environment: Path, approved: dict[str, str]) -> dict[str, str]:
    expected = json.dumps(
        {
            **approved,
            "astrid": "0.1.0",
            "astrid-runtime": "0.1.0",
            "astrid-runtime-client": "0.2.14",
        }
    )
    probe = r'''
import importlib
import importlib.metadata as metadata
import json
from pathlib import Path
import sys
import sysconfig

expected = json.loads(sys.argv[1])
root = Path(sys.prefix).resolve()
site = Path(sysconfig.get_paths()["purelib"]).resolve()


def inside(path, parent):
    return path.is_relative_to(parent)


def no_symlink_component(path):
    current = path
    while True:
        if current.is_symlink():
            return False
        if current == root:
            return True
        if current == current.parent:
            return False
        current = current.parent


for name, version in expected.items():
    distribution = metadata.distribution(name)
    assert distribution.version == version, (name, distribution.version, version)
    records = distribution.files or ()
    for record in records:
        candidate = distribution.locate_file(record)
        resolved = candidate.resolve(strict=True)
        assert inside(resolved, root), (name, record, resolved)
        assert no_symlink_component(candidate), (name, record, candidate)

    top_level = distribution.read_text("top_level.txt") or ""
    modules = {line.strip() for line in top_level.splitlines() if line.strip()}
    if not modules:
        for record in records:
            parts = Path(record).parts
            if len(parts) >= 2 and parts[1] == "__init__.py":
                modules.add(parts[0])
            elif len(parts) == 1 and parts[0].endswith(".py"):
                modules.add(parts[0][:-3])
    modules.update(
        module_name
        for module_name, distributions in metadata.packages_distributions().items()
        if name in distributions
    )
    modules = {
        module_name
        for module_name in modules
        if (
            (site / (module_name + ".py")).exists()
            or (site / module_name).is_dir()
            or any(site.glob(module_name + ".*.so"))
        )
    }
    for module_name in modules:
        module = importlib.import_module(module_name)
        origins = [Path(module.__file__)] if module.__file__ else [Path(item) for item in module.__path__]
        for origin in origins:
            origin = origin.resolve()
            assert inside(origin, site), (name, module_name, origin, site)
            assert no_symlink_component(origin), (name, module_name, origin)

from astrid_runtime_client import contract_metadata
assert contract_metadata.CONTRACT_VERSION == "0.2.14"
assert contract_metadata.SCHEMA_DIGEST == "sha256:7d4afa05962b8cd61643213fc79cdde41e16046c4e2a777bd299b48af0f31816"

print(json.dumps({"site": str(site), "prefix": str(root)}, sort_keys=True))
'''
    result = subprocess.run(
        [_python(environment), "-I", "-B", "-c", probe, expected],
        check=False,
        capture_output=True,
        text=True,
        cwd=environment.parent,
        env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(result.stdout)


@pytest.mark.integration
def test_wc10_installed_normal_launcher_provider_bootstrap(tmp_path):
    """Launch the installed Runtime and create/read one provider-backed empty timeline."""
    root = Path(__file__).resolve().parents[1]
    assert _git(AGENT_SOURCE, "rev-parse", "HEAD") == AGENT_COMMIT
    assert _git(AGENT_SOURCE, "rev-parse", "HEAD^{tree}") == AGENT_TREE
    assert not _git(AGENT_SOURCE, "status", "--porcelain")
    assert _git(NORMAL_RUNTIME_SOURCE, "rev-parse", "HEAD") == NORMAL_RUNTIME_COMMIT
    assert not _git(NORMAL_RUNTIME_SOURCE, "status", "--porcelain")
    runtime_boundary = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--quiet",
            RUNTIME_COMMIT,
            "--",
            "astrid_runtime/runtime_boundary.py",
        ],
        check=False,
    )
    assert runtime_boundary.returncode == 0, "fixture must build the reviewed 8f70 launcher source"

    environment, approved = _make_installed_environment(tmp_path)
    identity = _preflight_installed_environment(environment, approved)
    site_packages = Path(identity["site"])
    assert site_packages == _site_packages(environment)

    support = tmp_path / "support"
    manifest = tmp_path / "astrid-profile.json"
    manifest.write_text(
        json.dumps(
            {
                "profile": "astrid",
                "runtime_checkout": str(site_packages),
                "source_checkout": str(site_packages),
                "runtime_environment": str(environment.resolve()),
            }
        ),
        encoding="utf-8",
    )
    child_env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        environment / "bin" / "astrid-runtime",
        "--profile",
        "astrid",
        "--data-root",
        support,
        "--source-manifest",
        manifest,
        "--hosted-origin",
        "https://hosted.test",
        "--json",
    ]
    created = _run(
        [
            *command[:1],
            "workspace",
            "create",
            "--realm-root",
            support / "runtime" / "realms" / "wc10",
            "--realm-id",
            "wc10",
            *command[1:],
        ],
        env=child_env,
        capture_output=True,
        cwd=tmp_path,
    )
    assert created.returncode == 0, created.stderr + created.stdout
    started = None
    try:
        started = _run(
            [*command[:1], "up", "--wait", "--door-port", "0", *command[1:]],
            env=child_env,
            capture_output=True,
            cwd=tmp_path,
            timeout=90,
        )
        assert started.returncode == 0, started.stderr + started.stdout
        ready = json.loads(started.stdout)
        assert ready["realm_id"] == "wc10"
        assert ready["door_endpoint"].startswith("http://127.0.0.1:")

        status = _run(
            [*command[:1], "status", "--data-root", support, "--json"],
            env=child_env,
            capture_output=True,
            cwd=tmp_path,
        )
        assert status.returncode == 0, status.stderr + status.stdout
        status_json = json.loads(status.stdout)
        assert status_json["support"]["healthy"] is True
        assert status_json["health"]["status"] == "ok"

        operation = """
import json, sys
from pathlib import Path
from astrid.sdk.workspace_client import WorkspaceClient

credential = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert isinstance(credential["token"], str) and credential["token"]
client = WorkspaceClient(sys.argv[1], credential["token"])
health = client.health()
assert health["status"] == "ok"
project_result = client.create_project("WC10", slug="wc10", idempotency_key="wc10-project")
assert set(project_result) == {"data", "receipt"}
project = project_result["data"]
project_receipt = project_result["receipt"]
assert project["name"] == "WC10" and project["slug"] == "wc10"
assert project_receipt["command_kind"] == "project.create"
assert project_receipt["idempotency_key"] == "wc10-project"
assert project_receipt["project_id"] == project["project_id"]
assert project_receipt["receipt_id"]
assert project_receipt["result"]["id"] == project["project_id"]
project_id = project["project_id"]
timeline_result = client.create_timeline(project_id, "empty", idempotency_key="wc10-empty")
assert set(timeline_result) == {"data", "receipt"}
timeline = timeline_result["data"]
timeline_receipt = timeline_result["receipt"]
assert timeline["project_id"] == project_id and timeline["timeline_id"] == "empty"
assert timeline_receipt["command_kind"] == "timeline.create"
assert timeline_receipt["idempotency_key"] == "wc10-empty"
assert timeline_receipt["project_id"] == project_id
assert timeline_receipt["receipt_id"]
assert timeline_receipt["result"] == timeline
assert timeline["head_revision_id"] and timeline["head_publication_id"]
history = client.list_timeline_commits(project_id, "empty", limit=10)
assert history["head"] == {
    "revision_id": timeline["head_revision_id"],
    "publication_id": timeline["head_publication_id"],
}
assert len(history["items"]) == 1
assert history["items"][0]["intent"] == "bootstrap"
assert history["items"][0]["records"] is None
assert "publish_parent_composition" not in json.dumps(history, sort_keys=True)
inspection = client.inspect_timeline(project_id, "empty")
assert inspection["project_id"] == project_id
assert inspection["timeline_id"] == "empty"
print(json.dumps({"project": project, "timeline": timeline, "inspection": inspection}, sort_keys=True))
"""
        credential = json.loads((support / "runtime" / "discovery.json").read_text(encoding="utf-8"))[
            "credential_file"
        ]
        measured = _run(
            [_python(environment), "-I", "-B", "-c", operation, ready["endpoint"], credential],
            env=child_env,
            capture_output=True,
            cwd=tmp_path,
            timeout=60,
        )
        assert measured.returncode == 0, measured.stderr + measured.stdout
        assert json.loads(measured.stdout)["timeline"]["timeline_id"] == "empty"
    finally:
        if started is not None and (support / "runtime" / "discovery.json").is_file():
            stopped = _run(
                [*command[:1], "down", *command[1:]],
                env=child_env,
                capture_output=True,
                cwd=tmp_path,
                timeout=60,
            )
            assert stopped.returncode == 0, stopped.stderr + stopped.stdout
