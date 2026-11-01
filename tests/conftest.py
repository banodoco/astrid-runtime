from __future__ import annotations

import shutil
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.astrid_checkout import astrid_importable  # noqa: F401  (fixture)
from tests.lanes import pytest_collection_modifyitems, pytest_configure  # noqa: F401  (lanes)
from tests.process_groups import ProcessGroups

def pytest_addoption(parser):
    parser.addoption(
        "--process-control", choices=("strict", "sandbox"), default="strict",
        help="run the suite as an install with this Runtime process-control setting "
             "(CI's seccomp job uses sandbox; see tests/seccomp/README.md)")


@pytest.fixture(scope="session", autouse=True)
def _suite_process_control(request):
    """--process-control=sandbox: every Runtime support root without a setting reads as sandbox."""
    if request.config.getoption("--process-control") != "sandbox":
        yield
        return
    from runtime_protocol import platform, process_control

    original = process_control.configure_from

    def configure_from(support_root):
        mode = process_control.read_setting(support_root)
        if not process_control.setting_path(support_root).exists():
            mode = "sandbox"
        platform.configure_process_control(mode)
        return mode

    platform.configure_process_control("sandbox")
    process_control.configure_from = configure_from
    try:
        yield
    finally:
        process_control.configure_from = original


# A real `astrid-runtime up` in a test opens its browser door on an ephemeral
# port, never the well-known 17340 that this machine's own Runtime, or a
# parallel test, may hold.
os.environ["ASTRID_RUNTIME_DOOR_PORT"] = "0"


@pytest.fixture
def owned_process_groups():
    """Own process groups explicitly launched by this test."""
    owner = ProcessGroups()
    try:
        yield owner
    finally:
        owner.terminate_all()


def pytest_sessionfinish(session, exitstatus):
    """Catch a CLI daemon that outlived its pytest child fixture."""
    _ = exitstatus
    if sys.platform == "win32":
        # Windows has no portable process-table/session inventory equivalent
        # to the POSIX `ps` query below. Test-owned trees are closed by their
        # ProcessGroups Job handles instead.
        return
    try:
        basetemp = Path(session.config._tmp_path_factory.getbasetemp()).resolve()
        listing = subprocess.run(
            ["ps", "-axo", "pid=,pgid=,command="], capture_output=True, text=True, check=True
        ).stdout
    except (AttributeError, OSError, subprocess.CalledProcessError) as exc:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"WARNING: daemon/host session guard could not inspect processes: {exc}")
        return
    leaked: list[tuple[int, int, str]] = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid, pgid = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        command = fields[2]
        is_runtime = "runtime_protocol" in command and "start" in command and "--root" in command
        is_host = "generic_host" in command and "--support-root" in command
        if not (is_runtime or is_host):
            continue
        roots = []
        tokens = command.split()
        for option in ("--root", "--support-root"):
            if option in tokens and tokens.index(option) + 1 < len(tokens):
                roots.append(tokens[tokens.index(option) + 1].strip("'\""))
            roots.extend(token.split("=", 1)[1].strip("'\"") for token in tokens if token.startswith(option + "="))
        if any(_under(root, basetemp) for root in roots):
            leaked.append((pid, pgid, command))
    if not leaked:
        return
    groups = {pgid for _, pgid, _ in leaked if pgid != os.getpgrp()}
    for pgid in groups:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            # PermissionError: seccomp sandboxes (e.g. OpenShell) deny process-group
            # kills; still report the leak below instead of losing the summary.
            pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and any(_group_exists(pgid) for pgid in groups):
        time.sleep(0.02)
    for pgid in groups:
        if _group_exists(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(f"ERROR: killed daemon/host processes left under pytest basetemp: {leaked!r}")
    session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _under(candidate: str, parent: Path) -> bool:
    try:
        return Path(candidate).resolve().is_relative_to(parent)
    except (OSError, ValueError):
        return False


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


@pytest.fixture(scope="session")
def stage1_runtime_environment(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One offline venv containing both installed runtime packages.

    Local wheels are built with the running interpreter (the `test` extra
    pins setuptools>=70.1, which ships bdist_wheel), then installed into the
    clean target venv without consulting a package index.
    """
    root = Path(__file__).resolve().parents[1]
    environment = tmp_path_factory.mktemp("stage1-runtime") / "venv"
    wheelhouse = environment.parent / "wheelhouse"
    source = environment.parent / "source"
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
        raise RuntimeError("Stage 1 tests require an available Python with setuptools.build_meta")
    # setuptools writes build/ and egg-info beside the source tree. Build
    # from a private copy so concurrent pytest sessions cannot delete or
    # replace each other's generated package files in the checkout.
    source.mkdir()
    for filename in ("pyproject.toml", "setup.py", "LICENSE"):
        shutil.copy2(root / filename, source / filename)
    for package in ("astrid_runtime", "runtime_protocol"):
        shutil.copytree(root / package, source / package, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    client_source = source / "packages" / "python"
    client_source.mkdir(parents=True)
    shutil.copy2(root / "packages" / "python" / "pyproject.toml", client_source / "pyproject.toml")
    shutil.copytree(
        root / "packages" / "python" / "astrid_runtime_client",
        client_source / "astrid_runtime_client",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    wheelhouse.mkdir()
    build_env = os.environ.copy()
    if builder == sys.executable:
        build_env.pop("SETUPTOOLS_USE_DISTUTILS", None)
    else:
        build_env["SETUPTOOLS_USE_DISTUTILS"] = "stdlib"
    subprocess.run(
        [builder, "-m", "pip", "wheel", "--no-index", "--no-build-isolation", "--no-deps", "--wheel-dir", str(wheelhouse), str(source), str(client_source)],
        cwd=str(source),
        env=build_env,
        check=True,
    )
    scripts = "Scripts" if os.name == "nt" else "bin"
    pip = environment / scripts / ("pip.exe" if os.name == "nt" else "pip")
    wheels = sorted(wheelhouse.glob("*.whl"))
    if len(wheels) != 2:
        raise RuntimeError(f"expected two local Stage 1 wheels, found {len(wheels)}")
    # The prepared interpreter may carry an editable checkout of this
    # project.  Force-install the exact wheels into the fresh child venv so
    # pip cannot mistake that outer editable metadata for an installed
    # package and silently omit one of the two runtime components.
    subprocess.run(
        [str(pip), "install", "--no-index", "--no-deps", "--force-reinstall", *(str(wheel) for wheel in wheels)],
        check=True,
    )
    return environment
