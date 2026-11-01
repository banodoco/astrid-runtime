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
# entry that no CI job runs. The checker accepts the reason in place of a job,
# and the run summary prints those skips under "NOT RUN BY ANY CI JOB".
# Today every entry is blocking: the Windows ``unit`` matrix leg is continue-on-error,
# but each Windows entry is also run by ``portability-lifecycle`` (or
# ``windows-worker-handoff``), which fails CI.

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
        return bool(eval(self.skip_when, {"__builtins__": {}}, names))

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


@dataclass(frozen=True)
class DeclaredXfail:
    """One exact, temporary xfail declaration.

    Xfails are intentionally narrower than skips: a reason is not an
    authority.  The node ids, reason, strictness and exception type all have
    to match the declaration, so copying a known reason to another test
    cannot hide a new failure.
    """

    name: str
    nodeids: tuple[str, ...]
    reason: str
    raises: str
    strict: bool = True


def _xfail_reason(name: str, reason: str) -> str:
    return f"[declared-xfail:{name}] {reason}"


DECLARED_XFAILS = {
    "runtime-domains-publication": DeclaredXfail(
        "runtime-domains-publication",
        ("tests/test_runtime_domains.py::test_generated_python_client_timeline_publication_is_retired_pending_commit_replacement",),
        _xfail_reason("runtime-domains-publication", "RT02/D04 held: legacy timeline publication (update_timeline) is retired (410); restored by the /v1 commit replacement"),
        "tests.test_runtime_domains._RetiredTimelinePublication",
    ),
    "runtime-domains-update": DeclaredXfail(
        "runtime-domains-update",
        ("tests/test_runtime_domains.py::test_generated_direct_timeline_shot_reference_writers_remain_retired",),
        _xfail_reason("runtime-domains-update", "direct timeline update writer remains retired"),
        "tests.test_runtime_domains._RetiredTimelineUpdate",
    ),
    "runtime-exact-idempotency": DeclaredXfail(
        "runtime-exact-idempotency",
        ("tests/test_runtime_exact_idempotency.py::test_timeline_shot_and_reference_creation_are_keyed_durable_and_non_overwriting",),
        _xfail_reason("runtime-exact-idempotency", "RT02 held: direct shot writes are retired (410); the reference half is the KEPT catalog (RK01)"),
        "astrid_runtime_client.generated.ApiError",
    ),
    "second-client-core": DeclaredXfail(
        "second-client-core",
        ("tests/test_second_client_e2e.py::test_second_client_core_journey_is_executable",),
        _xfail_reason("second-client-core", "RT02/D04 held: direct shot writes and legacy timeline publication are retired (410); the actor is ported with their replacements"),
        "subprocess.CalledProcessError",
    ),
    "snapshot-legacy-certification": DeclaredXfail(
        "snapshot-legacy-certification",
        (
            "tests/test_snapshot_legacy_certification.py::test_already_admitted_capture_after_upgrade[genuine-ref]",
            "tests/test_snapshot_legacy_certification.py::test_already_admitted_capture_after_upgrade[genuine-inline]",
        ),
        _xfail_reason("snapshot-legacy-certification", "ledger: no row id yet (PLAN 2026-10-20 capture certification); valid legacy capture is not re-certified until Agent project_capture lands"),
        "tests.test_snapshot_legacy_certification.LegacyGenuineUncertified",
    ),
    "stage1-runtime-contract": DeclaredXfail(
        "stage1-runtime-contract",
        ("tests/test_stage1_runtime_contract_completion.py::test_timeline_update_archive_recover_replay_the_same_committed_receipt",),
        _xfail_reason("stage1-runtime-contract", "ledger D04: direct timeline writes retired; awaiting commit-path replacement"),
        "runtime_protocol.errors.RetiredRouteError",
    ),
    "timeline-clip-replacement": DeclaredXfail(
        "timeline-clip-replacement",
        (
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_is_atomic_cas_and_exactly_replayable",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_cross_project_source",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_malformed_source_without_mutation",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_tampered_cas_without_mutation",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_wrong_stream_without_mutation",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_rejects_too_short_source_without_mutation",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_requires_source_to_reach_authored_end",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_generic_visual_media_requires_video_stream",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_replays_after_intervening_edit_and_reopen",
            "tests/test_timeline_clip_replacement.py::test_replace_timeline_clip_public_http_route",
        ),
        _xfail_reason("timeline-clip-replacement", "ledger D04: direct clip replacement retired; awaiting commit-path replacement"),
        "runtime_protocol.errors.RetiredRouteError",
    ),
    "timeline-public-s2-historical-audio": DeclaredXfail(
        "timeline-public-s2-historical-audio",
        ("tests/test_timeline_public_s2_mixed_cli_journey.py::test_public_cli_stale_trim_rebases_label_lost_ack_restart_retry_and_undo[historical-audio]",),
        _xfail_reason("timeline-public-s2-historical-audio", "M2 historical audio capture: /tmp/claude-0/-home-user-repo/7dc61be1-7066-52e0-a5d0-94f90e61430a/scratchpad/orch/design/runtime-public-s2-literal-journey.md#original-audio-requirement"),
        "tests.test_timeline_public_s2_mixed_cli_journey.HistoricalAudioCaptureGap",
    ),
    "p1-top-level-text-hook": DeclaredXfail(
        "p1-top-level-text-hook",
        ("tests/test_timeline_visual_fields.py::test_supported_top_level_type_on_retains_original_roundtrip_expectations",),
        _xfail_reason("p1-top-level-text-hook", "P1 top-level text-hook restoration requirement"),
        "runtime_protocol.errors.RuntimeErrorBase",
    ),
}


def _exception_name(exception_type) -> str | None:
    if exception_type is None:
        return None
    if isinstance(exception_type, str):
        return exception_type
    return f"{exception_type.__module__}.{exception_type.__qualname__}"


def declared_xfail_reason(name: str) -> str:
    return DECLARED_XFAILS[name].reason


def is_declared_xfail(nodeid: str, reason: str, *, strict: bool, raises) -> bool:
    """Return true only for an exact registered node and marker contract."""
    actual_raises = _exception_name(raises)
    return any(
        nodeid in declaration.nodeids
        and declaration.reason == reason
        and declaration.strict is strict
        and declaration.raises == actual_raises
        for declaration in DECLARED_XFAILS.values()
    )


def _declare(name: str, skip_when: str, reason: str, ci: tuple[str, ...], **extra) -> DeclaredSkip:
    assert name not in SKIP_REGISTRY, name
    SKIP_REGISTRY[name] = declared = DeclaredSkip(name, skip_when, reason, ci, **extra)
    return declared


requires_windows_security = _declare(
    "windows-security", "sys_platform != 'win32'",
    "native Windows socket exclusivity and file DACL APIs", ("unit", "portability-lifecycle", "windows-realm-publication"),
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
    "Windows token and process-time APIs", ("unit", "portability-lifecycle"),
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
    "exercises the native Windows dir-fd adapter", ("unit", "portability-lifecycle"),
).mark()
requires_windows_reparse_point_rejection = _declare(
    "windows-reparse-point-rejection", "os_name != 'nt'",
    "exercises Windows reparse-point rejection", ("unit", "portability-lifecycle"),
).mark()
requires_windows_sqlite_backup = _declare(
    "windows-sqlite-backup", "os_name != 'nt'",
    "exercises Windows SQLite backup snapshots", ("unit", "portability-lifecycle"),
).mark()
requires_windows_process_and_lock_apis = _declare(
    "windows-process-and-lock-apis", "os_name != 'nt'",
    "native Windows process and lock APIs", ("portability-lifecycle", "windows-worker-handoff"),
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
    "symlink creation is unavailable for this Windows account", ("unit", "portability-lifecycle"),
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


def _declared_entry(reason: str) -> DeclaredSkip:
    match = _DECLARED_TAG.search(reason)
    assert match is not None
    return SKIP_REGISTRY[match.group(1)]


class _SkipGuard:
    """No invisible skips: list every skip by name and fail on any undeclared one.

    A skip is declared when its reason carries ``[declared:NAME]`` for a NAME in
    SKIP_REGISTRY (the ``requires_*`` marks and ``darwin_native`` do this). Any
    other skip (a raw ``pytest.skip``, ``importorskip``, ``skip`` mark) fails the
    run. Xfails additionally need an exact node, reason, strictness and
    exception declaration in ``DECLARED_XFAILS``. Works under xdist: reports
    reach the controller.
    """

    def __init__(self) -> None:
        self.declared: list[tuple[str, str]] = []
        self.declared_xfails: list[tuple[str, str]] = []
        self.undeclared: list[tuple[str, str]] = []
        self._reported_xfails: set[tuple[str, str]] = set()
        self._approved_xfails: set[tuple[str, str]] = set()

    @staticmethod
    def _xfail_mark(item, reason: str):
        return next(
            (mark for mark in item.iter_markers("xfail") if mark.kwargs.get("reason") == reason),
            None,
        )

    def _check_xfail(self, item, mark) -> bool:
        reason = mark.kwargs.get("reason")
        valid = isinstance(reason, str) and is_declared_xfail(
            item.nodeid,
            reason,
            strict=mark.kwargs.get("strict", False),
            raises=mark.kwargs.get("raises"),
        )
        if not valid:
            key = (item.nodeid, str(reason))
            if key not in self._reported_xfails:
                self._reported_xfails.add(key)
                self.undeclared.append((item.nodeid, "xfail is not allowed: " + str(reason)))
        else:
            self._approved_xfails.add((item.nodeid, reason))
        return valid

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config, items) -> None:
        for item in items:
            for mark in item.iter_markers("xfail"):
                self._check_xfail(item, mark)

    def _record(self, report) -> None:
        if not report.skipped:
            return
        reason = getattr(report, "wasxfail", None)
        if reason is not None and (report.nodeid, str(reason)) in self._approved_xfails:
            return
        longrepr = report.longrepr
        reason = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr)
        reason = reason.removeprefix("Skipped: ")
        match = _DECLARED_TAG.search(reason)
        if match and match.group(1) in SKIP_REGISTRY:
            declared = SKIP_REGISTRY[match.group(1)]
            if declared.applies(CURRENT):
                self.declared.append((report.nodeid, reason))
            else:
                self.undeclared.append((report.nodeid, f"{declared.tag} used where its condition is false on this host: {reason}"))
        else:
            self.undeclared.append((report.nodeid, reason))

    def pytest_runtest_logreport(self, report) -> None:
        # A skipif mark skips in setup, a runtime pytest.skip() in call, a fixture's in teardown.
        self._record(report)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        reason = getattr(report, "wasxfail", None)
        if reason is None:
            return
        mark = self._xfail_mark(item, str(reason))
        if mark is None or not self._check_xfail(item, mark):
            return
        key = (item.nodeid, str(reason))
        if key not in self._reported_xfails:
            self._reported_xfails.add(key)
            self.declared_xfails.append(key)

    def pytest_collectreport(self, report) -> None:
        self._record(report)

    def pytest_terminal_summary(self, terminalreporter) -> None:
        write = terminalreporter.write_line
        if self.declared:
            write(f"declared skips ({len(self.declared)}):")
            for nodeid, reason in sorted(self.declared):
                write(f"  SKIP {nodeid}: {reason}")
        if self.declared_xfails:
            write(f"declared xfails ({len(self.declared_xfails)}):")
            for nodeid, reason in sorted(self.declared_xfails):
                write(f"  XFAIL {nodeid}: {reason}")
        non_blocking = [
            (nodeid, reason) for nodeid, reason in sorted(self.declared)
            if not _declared_entry(reason).blocking
        ]
        if non_blocking:
            write(f"declared skips whose tests run only in non-blocking CI jobs ({len(non_blocking)}):")
            for nodeid, reason in non_blocking:
                write(f"  NON-BLOCKING {nodeid}: {reason}")
        no_ci = [
            (nodeid, reason) for nodeid, reason in sorted(self.declared)
            if _declared_entry(reason).no_ci
        ]
        if no_ci:
            write(f"NOT RUN BY ANY CI JOB ({len(no_ci)}):")
            for nodeid, reason in no_ci:
                entry = _declared_entry(reason)
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
