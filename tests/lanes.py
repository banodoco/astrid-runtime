"""Test lanes (testing plan R-2).

Lanes. The default run deselects tests marked ``integration``, ``darwin_native`` or
``live`` (see ``addopts`` in pyproject.toml). ``integration`` runs in the nightly
job (and in the ``-m ""`` portability jobs), ``darwin_native`` in the ``darwin-native``
job; no test is marked ``live`` yet. A ``darwin_native`` test is skipped off macOS.

Leaked file descriptors (testing plan LEAK.2). The run fails if the pytest process
ends holding more than FD_LEAK_ALLOWANCE descriptors beyond what it held at start.
(Leaked daemon and host process groups are caught by conftest's session guard.)
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

import pytest



class Host(NamedTuple):
    sys_platform: str
    os_name: str


FD_LEAK_ALLOWANCE = 64
LANE_MARKERS = {
    "integration": "needs a long-lived subprocess, Node, ffmpeg, the network, or a second checkout",
    "darwin_native": "needs native macOS APIs; skipped elsewhere",
    "live": "needs real provider credentials",
    "needs_real_pidfd": "exercises the real Linux pidfd syscalls; only the seccomp sandbox-process-control job deselects it",
}

# --- The skip registry ------------------------------------------------------
# Every skip the suite may report is declared here, once, with the exact
# condition, the reason and the CI jobs that run the test where the condition
# is false. Test modules never call pytest's skip APIs (tests/test_skip_policy.py);
# they use the ``requires_*`` marks below. The guard further down fails the run
# on any skip whose reason does not carry a registered ``[declared:NAME]`` tag,
# on any xfail, and prints every skip by test name.
#
# ``skip_when`` is executable: a Python expression over ``sys_platform`` and
# ``os_name`` that is true on the hosts where the test is skipped. The mark is
# built from it, so the condition written here is the condition that runs.
# ``ci`` lists the jobs (ci.yml / nightly.yml) that run the test on a host where
# the condition is false. tests/test_skip_registry.py parses the workflows and
# checks, per entry, that each listed job exists, that its -m expression and test
# paths select a test that uses the entry on a runner OS where it runs, and that
# no unlisted job does. ``blocking=False`` says every job and OS that runs the
# test has ``continue-on-error``, so a failure there cannot fail CI; the run
# summary lists those skips under their own header.
# ``no_ci`` is the one exception to "some CI job runs it": a plain reason, for an
# entry that no CI job runs. The test is skipped wherever CI runs, the checker
# accepts the reason in place of a job (and fails if a job does run it, or if an
# entry has neither), and the run summary prints those skips under
# "NOT RUN BY ANY CI JOB". Keep the list short.

HOSTS = {
    "linux": Host("linux", "posix"),
    "macos": Host("darwin", "posix"),
    "windows": Host("win32", "nt"),
}
CURRENT = Host(sys.platform, os.name)


@dataclass(frozen=True)
class DeclaredSkip:
    name: str
    skip_when: str  # Python expression over ``sys_platform`` and ``os_name``; true = skipped
    reason: str
    ci: tuple[str, ...]  # jobs that run the test on a host where the condition is false
    no_ci: str = ""  # why no CI job runs it (then ``ci`` is empty)
    blocking: bool = True  # False: every (job, OS) that runs it is continue-on-error
    only_error: Callable[[BaseException], bool] | None = None  # runtime entries: the one error that may skip

    @property
    def tag(self) -> str:
        return f"[declared:{self.name}]"

    def applies(self, host: Host) -> bool:
        """True when the skip may fire on ``host``."""
        names = {"sys_platform": host.sys_platform, "os_name": host.os_name}
        return bool(eval(self.skip_when, {"__builtins__": {}}, names))  # noqa: S307 - registry-owned expression

    def runs_on(self) -> frozenset[str]:
        """The HOSTS keys where the condition is false, so the test runs.

        A runtime entry (``only_error``) skips only for one error, so its test runs on every host.
        """
        if self.only_error is not None:
            return frozenset(HOSTS)
        return frozenset(key for key, host in HOSTS.items() if not self.applies(host))

    def mark(self):
        return pytest.mark.skipif(self.applies(CURRENT), reason=f"{self.tag} {self.reason}")


SKIP_REGISTRY: dict[str, DeclaredSkip] = {}
NO_WINDOWS_CI = "Windows is supported as a beta; there is no Windows CI job (CI runs on Linux and macOS)"


def _declare(name: str, skip_when: str, reason: str, ci: tuple[str, ...], **extra) -> DeclaredSkip:
    assert name not in SKIP_REGISTRY, name
    SKIP_REGISTRY[name] = declared = DeclaredSkip(name, skip_when, reason, ci, **extra)
    return declared


requires_windows_security = _declare(
    "windows-security", "sys_platform != 'win32'",
    "native Windows socket exclusivity and file DACL APIs", ("windows-realm-publication",),
).mark()
requires_windows_runtime_venv = _declare(
    "windows-runtime-venv", "sys_platform != 'win32'",
    "native Windows venv redirector and Runtime Job Object custody", ("windows-realm-publication",),
).mark()
requires_linux_tree_custody = _declare(
    "linux-tree-custody", "sys_platform != 'linux'",
    "Linux waitid WNOWAIT process-group custody", ("unit", "portability-lifecycle", "integration"),
).mark()
requires_posix_inherited_descriptors = _declare(
    "posix-inherited-descriptors", "os_name == 'nt'",
    "relay integration requires POSIX inherited descriptors", ("integration",),
).mark()
requires_posix_uid_metadata = _declare(
    "posix-uid-metadata", "os_name == 'nt'",
    "Windows owner-only checks use native DACLs, not POSIX uid metadata", ("unit",),
).mark()
requires_posix_file_modes_native_custody = _declare(
    "posix-file-modes-native-custody", "sys_platform == 'win32'",
    "Windows uses native DACLs instead of POSIX file modes", ("unit", "portability-lifecycle"),
).mark()
requires_posix_private_modes = _declare(
    "posix-private-modes", "sys_platform == 'win32'",
    "Windows uses native DACLs rather than POSIX modes", ("unit", "portability-lifecycle"),
).mark()
requires_windows_token_process_times = _declare(
    "windows-token-process-times", "sys_platform != 'win32'",
    "Windows token and process-time APIs", (), no_ci=NO_WINDOWS_CI,
).mark()
requires_posix_process_groups = _declare(
    "posix-process-groups", "sys_platform == 'win32'",
    "POSIX process group integration", ("unit", "portability-lifecycle", "integration"),
).mark()
requires_windows_job_object = _declare(
    "windows-job-object", "sys_platform != 'win32'",
    "Windows Job Object integration", ("windows-realm-publication",),
).mark()
requires_windows_dirfd_adapter = _declare(
    "windows-dirfd-adapter", "os_name != 'nt'",
    "exercises the native Windows dir-fd adapter", (), no_ci=NO_WINDOWS_CI,
).mark()
requires_windows_reparse_point_rejection = _declare(
    "windows-reparse-point-rejection", "os_name != 'nt'",
    "exercises Windows reparse-point rejection", (), no_ci=NO_WINDOWS_CI,
).mark()
requires_windows_sqlite_backup = _declare(
    "windows-sqlite-backup", "os_name != 'nt'",
    "exercises Windows SQLite backup snapshots", (), no_ci=NO_WINDOWS_CI,
).mark()
requires_windows_process_and_lock_apis = _declare(
    "windows-process-and-lock-apis", "os_name != 'nt'",
    "native Windows process and lock APIs", (), no_ci=NO_WINDOWS_CI,
).mark()
requires_posix_owner_only_permissions = _declare(
    "posix-owner-only-permissions", "os_name == 'nt'",
    "POSIX owner-only permission behavior", ("unit", "portability-lifecycle"),
).mark()
requires_posix_process_group_id_reuse = _declare(
    "posix-process-group-id-reuse", "os_name == 'nt'",
    "this regression checks POSIX process group ID reuse", ("unit",),
).mark()
requires_posix_fork = _declare(
    "posix-fork", "os_name == 'nt'",
    "multiprocessing fork is unavailable on Windows", ("unit",),
).mark()
requires_linux_o_path = _declare(
    "dirfd-o-path", "sys_platform != 'linux'",
    "the ancestor walk uses Linux O_PATH", ("unit",),
).mark()

# Decided while the test runs, so it is a call rather than a mark. The skip can
# only fire on Windows, and only for WinError 1314 (no symlink privilege).
_WINDOWS_SYMLINKS = _declare(
    "windows-symlink-creation", "os_name == 'nt'",
    "symlink creation is unavailable for this Windows account", ("unit",),
    only_error=lambda error: getattr(error, "winerror", None) == 1314,
)
# Applied to every ``darwin_native`` test below; the lane is deselected by default
# and run by the ``darwin-native`` job.
_DARWIN_NATIVE = _declare(
    "darwin-native", "sys_platform != 'darwin'", "needs native macOS APIs",
    ("darwin-native",),
)


def skip_for_declared_error(name: str, error: BaseException) -> None:
    """Skip for a declared runtime condition, or raise ``error`` when it is not that condition."""
    declared = SKIP_REGISTRY[name]
    if declared.applies(CURRENT) and (declared.only_error is None or declared.only_error(error)):
        pytest.skip(f"{declared.tag} {declared.reason}")
    raise error


def _open_fds() -> int | None:
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            return len(os.listdir(directory))
        except OSError:
            continue
    return None


class _FdGuard:
    def __init__(self) -> None:
        self.start = _open_fds()

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        end = _open_fds()
        if self.start is None or end is None or end - self.start <= FD_LEAK_ALLOWANCE:
            return
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"ERROR: the test session leaked {end - self.start} file descriptors ({self.start} -> {end})")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


_DECLARED_TAG = re.compile(r"\[declared:([a-z0-9-]+)\]")


class _SkipGuard:
    """No invisible skips: list every skip by name and fail on any undeclared one.

    A skip is declared when its reason carries ``[declared:NAME]`` for a NAME in
    SKIP_REGISTRY (the ``requires_*`` marks and ``darwin_native`` do this). Any
    other skip (a raw ``pytest.skip``, ``importorskip``, ``skip`` mark), and any
    xfail, fails the run. Works under xdist: reports reach the controller.
    """

    def __init__(self) -> None:
        self.declared: list[tuple[str, str]] = []
        self.undeclared: list[tuple[str, str]] = []

    def _record(self, report) -> None:
        if getattr(report, "wasxfail", None) is not None:
            self.undeclared.append((report.nodeid, "xfail is not allowed: " + str(report.wasxfail)))
            return
        if not report.skipped:
            return
        longrepr = report.longrepr
        reason = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr)
        reason = reason.removeprefix("Skipped: ")
        match = _DECLARED_TAG.search(reason)
        if match and match.group(1) in SKIP_REGISTRY:
            entry = SKIP_REGISTRY[match.group(1)]
            if entry.applies(CURRENT):
                self.declared.append((report.nodeid, reason))
            else:
                # The declared reason does not hold here, so the skip hides a test that should run.
                self.undeclared.append((
                    report.nodeid,
                    f"{entry.tag} used where its condition ({entry.skip_when}) is false on this host: {reason}",
                ))
        else:
            self.undeclared.append((report.nodeid, reason))

    def pytest_runtest_logreport(self, report) -> None:
        # A skipif mark skips in setup, a runtime pytest.skip() in call, a fixture's in teardown.
        self._record(report)

    def pytest_collectreport(self, report) -> None:
        self._record(report)

    def pytest_terminal_summary(self, terminalreporter) -> None:
        write = terminalreporter.write_line
        if self.declared:
            write(f"declared skips ({len(self.declared)}):")
            for nodeid, reason in sorted(self.declared):
                write(f"  SKIP {nodeid}: {reason}")
        non_blocking = [
            (nodeid, reason) for nodeid, reason in sorted(self.declared)
            if not SKIP_REGISTRY[_DECLARED_TAG.search(reason).group(1)].blocking
        ]
        if non_blocking:
            write(f"declared skips whose tests run only in non-blocking CI jobs ({len(non_blocking)}):")
            for nodeid, reason in non_blocking:
                write(f"  NON-BLOCKING {nodeid}: {reason}")
        no_ci = [
            (nodeid, reason) for nodeid, reason in sorted(self.declared)
            if SKIP_REGISTRY[_DECLARED_TAG.search(reason).group(1)].no_ci
        ]
        if no_ci:
            write(f"NOT RUN BY ANY CI JOB ({len(no_ci)}):")
            for nodeid, reason in no_ci:
                entry = SKIP_REGISTRY[_DECLARED_TAG.search(reason).group(1)]
                write(f"  NO CI {nodeid}: {entry.tag} {entry.no_ci}")
        for nodeid, reason in sorted(self.undeclared):
            write(f"UNDECLARED SKIP {nodeid}: {reason}")

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        if self.undeclared:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
            return
        # A run that executed nothing (everything skipped or deselected) is a failure, not a quiet pass.
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if exitstatus != pytest.ExitCode.OK or reporter is None or session.config.option.collectonly:
            return
        if not reporter.stats.get("passed"):
            reporter.write_line("ERROR: no test passed in this run; a run that executes nothing is a failure")
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_configure(config):
    for name, meaning in LANE_MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {meaning}")
    config.pluginmanager.register(_FdGuard(), "fd-leak-guard")
    config.pluginmanager.register(_SkipGuard(), "skip-guard")


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    for item in items:
        if _DARWIN_NATIVE.applies(CURRENT) and item.get_closest_marker("darwin_native"):
            item.add_marker(pytest.mark.skip(reason=f"{_DARWIN_NATIVE.tag} {_DARWIN_NATIVE.reason}"))
