"""Golden vectors for the shared host source closure definition."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime_protocol import verified_host_launch


ROOT = Path(__file__).resolve().parents[1]
DEFINITION = json.loads(
    (ROOT / "runtime_protocol/schemas/host-source-closure-v1.json").read_text(encoding="utf-8")
)


def _materialize(tree, vector):
    for relative, text in vector["files"].items():
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    for relative, target in vector["symlinks"].items():
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path, target_is_directory=(path.parent / target).is_dir())


@pytest.mark.parametrize("vector", DEFINITION["vectors"], ids=lambda vector: vector["name"])
def test_host_source_closure_vector(tmp_path, vector):
    tree = tmp_path / "checkout"
    _materialize(tree, vector)
    if "expect_refusal" in vector:
        with pytest.raises(verified_host_launch.HostLaunchError, match=vector["expect_refusal"]):
            verified_host_launch.source_checkout_closure(tree)
    else:
        assert verified_host_launch.source_checkout_closure(tree) == {
            "schema_version": 1, **vector["expect"],
        }


def test_definition_pins_nine_source_components():
    assert DEFINITION["schema_version"] == 1
    assert DEFINITION["components"] == {
        "host": "astrid/core/execution/generic_host.py",
        "core": "astrid/core",
        "sdk": "astrid/sdk",
        "launcher": "astrid/omp_agent.py",
        "astrid_entrypoint": "astrid/__init__.py",
        "astrid_version": "astrid/version.py",
        "astrid_main": "astrid/__main__.py",
        "astrid_runtime_cli": "astrid/runtime_cli.py",
        "vendored_workspace_client": "astrid_runtime_client",
    }


@pytest.mark.parametrize("package", ["runtime_protocol", "astrid_runtime"])
@pytest.mark.parametrize("kind", ["file", "dangling_symlink"])
def test_installed_pair_requires_real_directories(tmp_path, package, kind):
    tree = tmp_path / "checkout"
    vector = next(vector for vector in DEFINITION["vectors"] if vector["name"] == "source-checkout")
    _materialize(tree, vector)
    path = tree / package
    if kind == "file":
        path.write_bytes(b"not a package")
    else:
        os.symlink("absent-package", path, target_is_directory=True)
    with pytest.raises(verified_host_launch.HostLaunchError):
        verified_host_launch.source_checkout_closure(tree)


def test_verified_host_launch_import_is_stdlib_only():
    code = """
import sys
before = set(sys.modules)
import runtime_protocol.verified_host_launch
loaded = set(sys.modules) - before
allowed = {
    "runtime_protocol",
    "runtime_protocol.errors",
    "runtime_protocol.verified_host_launch",
}
assert {name for name in sys.modules if name.split(".")[0] == "runtime_protocol"} == allowed
assert not {name for name in sys.modules if name.split(".")[0] in {"astrid", "astrid_runtime"}}
unexpected = {name for name in loaded if name not in allowed and name.split(".")[0] not in sys.stdlib_module_names}
assert not unexpected, unexpected
assert not hasattr(runtime_protocol.verified_host_launch._closure_definition, "_cached")
"""
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True, timeout=30)
