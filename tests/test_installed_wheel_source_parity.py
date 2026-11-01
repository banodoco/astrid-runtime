from __future__ import annotations

import inspect
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def test_installed_runtime_wheel_contains_selected_source(stage1_runtime_environment):
    root = Path(__file__).resolve().parents[1]
    wheelhouse = stage1_runtime_environment.parent / "wheelhouse"
    wheels = list(wheelhouse.glob("astrid_runtime-*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as wheel:
        members = {
            name
            for name in wheel.namelist()
            if name.endswith(".py") and ".dist-info/" not in name
        }
        source_members = {
            path.relative_to(root).as_posix()
            for package in ("astrid_runtime", "runtime_protocol")
            for path in (root / package).rglob("*.py")
        }
        assert members == source_members
        for member in sorted(members):
            assert wheel.read(member) == (root / member).read_bytes(), member

    python = stage1_runtime_environment / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    probe = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import importlib, inspect, pathlib; "
                "bootstrap = importlib.import_module('astrid_runtime.bootstrap'); "
                "daemon = importlib.import_module('runtime_protocol.daemon'); "
                "assert bootstrap.WORKER_SCOPES == daemon.WORKER_SCOPES; "
                "assert 'projects:read' in bootstrap.WORKER_SCOPES; "
                "assert pathlib.Path(inspect.getfile(bootstrap)).is_relative_to("
                "pathlib.Path(__import__('sys').prefix))"
            ),
        ],
        cwd=str(root.parent),
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr


def test_build_replaces_stale_generated_package_files(tmp_path):
    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    source.mkdir()
    builders = [sys.executable, "python3.11", "python3.12", "python3.13", "python3", "python"]
    builder = None
    for candidate in builders:
        try:
            probe = subprocess.run(
                [candidate, "-c", "import setuptools.build_meta"],
                capture_output=True,
                check=False,
            )
        except OSError:
            continue
        if probe.returncode == 0:
            builder = candidate
            break
    if builder is None:
        raise RuntimeError("the stale-build regression needs a setuptools builder")
    for filename in ("pyproject.toml", "setup.py", "LICENSE"):
        shutil.copy2(root / filename, source / filename)
    for package in ("astrid_runtime", "runtime_protocol"):
        shutil.copytree(root / package, source / package)

    stale = source / "build" / "lib" / "astrid_runtime" / "bootstrap.py"
    stale.parent.mkdir(parents=True)
    stale.write_text("# stale generated module must never enter the wheel\n")

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    build_env = os.environ.copy()
    if builder == sys.executable:
        build_env.pop("SETUPTOOLS_USE_DISTUTILS", None)
    else:
        build_env["SETUPTOOLS_USE_DISTUTILS"] = "stdlib"
    subprocess.run(
        [
            builder,
            "-m",
            "pip",
            "wheel",
            "--no-cache-dir",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            str(source),
        ],
        env=build_env,
        check=True,
    )
    wheels = list(wheelhouse.glob("astrid_runtime-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as wheel:
        assert "# stale generated module" not in wheel.read("astrid_runtime/bootstrap.py").decode()
        for package in ("astrid_runtime", "runtime_protocol"):
            for source_file in sorted((source / package).rglob("*.py")):
                member = source_file.relative_to(source).as_posix()
                assert wheel.read(member) == source_file.read_bytes(), member
