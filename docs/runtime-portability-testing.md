# Runtime portability checks

The portability CI job runs the platform boundary, native process custody,
foreground lifecycle, and installed-wheel lifecycle checks on Ubuntu, macOS,
and Windows. The `windows-realm-publication` job runs native Windows realm
publication, console-signal, foreground cleanup, owner identity, and M1 security
checks, including `tests/test_m1_review.py` and
`tests/test_runtime_cli_serve_cleanup.py`. Astrid also runs an exploratory
Windows install and task-host journey. The portability-lifecycle matrix includes
native Windows dir-fd qualification. The selected tests use `-m ""` because pytest's
default configuration excludes integration-marked tests.

`tests/test_windows_runtime_launch.py` also runs in `windows-realm-publication`.
It demonstrates the Windows venv redirector's different PID, then runs the
selected venv's neutral `up --hosted-origin off`, authenticated backup, and
`down` without Pinokio or a prior forced stop. The native case is skipped off
Windows with the registered reason `[declared:windows-runtime-venv] native
Windows venv redirector and Runtime Job Object custody`. Portable launch tests
also check that bypassing the redirector retains the selected environment.

Run the same host-specific subset locally after installing the test and
generated-client packages:

```sh
python -m pip install -e '.[test]'
python -m pip install -e packages/python
python -m pytest -q -m "" \
  tests/test_platform.py \
  tests/test_platform_signaling.py \
  tests/test_platform_windows.py \
  tests/test_platform_filesystem.py \
  tests/test_m1_review.py \
  tests/test_foreground.py \
  tests/test_runtime_cli_serve_cleanup.py \
  tests/test_native_custody.py \
  tests/test_portable_lifecycle.py
```

The broader `tests/test_real_bootstrap.py` cases remain marked
`darwin_native`: they exercise the previous Darwin-specific bootstrap and
restart paths directly. The portable lifecycle module instead validates the
installed command surface on each CI host. Platform-specific Windows and
POSIX process-tree cases in `tests/test_platform.py` retain their own
skip-if-other-host markers.

## OS boundary

`runtime_protocol/platform.py` owns `file_lock` (including owner-only file
creation), `lock_file`/`unlock_file` for retained descriptors,
`spawn_tree`/`stop_tree`, `process_identity`, `owner_only`/`is_owner_only`,
`current_user`, `data_root`, and `log_dir`. Narrow helpers handle isolated
session creation, process observation/signaling, and stop handlers. No new
runtime dependency is required. `RuntimePaths.current` replaces the old
macOS-specific constructor; there is no compatibility alias.

macOS keeps its audit-token owner broker and durable birth-marker spelling.
Linux uses `/proc` birth ticks and identity-checked pidfds for adopted signals;
Linux 5.3+ is required for detached stop/restart. When Python lacks a pidfd
wrapper, the platform module calls libc `syscall()` on verified Linux ABIs.
Unverified ABIs fail closed; signaling still pins a pidfd before checking the
process birth identity, and never falls back to signaling a bare PID.
Retained-descriptor consumers share the public Linux helpers
`platform.pidfd_open(pid, flags=0)` and
`platform.pidfd_send_signal(fd, signum, siginfo=None, flags=0)`. The opener
transfers descriptor ownership to its caller; the sender leaves it open.
Callers must check process identity after opening the pidfd and before
signaling. `signal_process` owns the combined pin, identity-check and signal
sequence. The syscall fallback accepts only `None` for siginfo.

**Sandbox process control.** All of the above is the default, `strict`. An
install made with `--sandbox` writes `process_control: "sandbox"` to
`<data-root>/runtime/process-control.json` (through `astrid_runtime workspace
create|attach --process-control`). Every signalling process reads it at
startup. Sandbox mode is for seccomp sandboxes such as NVIDIA OpenShell, which
deny `pidfd_open` (ENOSYS) and negative-PID `kill` (EPERM), and it relaxes
exactly those two cases on Linux:

- When `pidfd_open` answers ENOSYS, `signal_process` re-reads the start time
  from `/proc`, compares it with the expected birth and only then calls
  `kill(pid)`. It refuses if the start time can't be read or doesn't match.
  Other errors still fail closed.
- When `killpg` answers EPERM, the group is signalled member by member,
  birth-checked, rescanning until no unsignalled member is left, leader last.
  The unreaped leader keeps the group ID from being reused meanwhile.

Each fallback logs once. `platform.process_control_probe()` reports what works
(`astrid-runtime doctor` shows it as `process_signalling`). CI runs the suite in
this mode under `tests/seccomp/openshell-like.json`. macOS and Windows accept the
setting but have nothing to relax yet.
Windows uses process creation FILETIMEs and SID-derived numeric user identity,
identity-checked process handles, and kill-on-close Job Objects. Children start
suspended until assigned to their Job. A detached owner inherits the Job handle
and clears its inheritance before launching descendants.

The existing `dirfd.py` Windows filesystem adapter is **M2 (unqualified)**.
It remains in place for subsequent native qualification; it is not part of
M1's completed portability claims. Its intended design uses retained native
directory handles to reject reparse points and prevent parent renames.
SQLite connections close
across fresh-realm publication on Windows while the owner file lock remains
held. Backup verification copies pinned SQLite bytes to a private immutable
snapshot; it never relies on `/dev/fd` there.

Windows credential and discovery directories and files are created with an
explicit protected DACL granting access only to the token owner and SYSTEM.
Existing credential/discovery files are read through the same handle whose
owner and DACL are validated with `GetSecurityInfo`. Unsafe owners, public or
unprotected/NULL DACLs, unfamiliar ACEs and reparse points fail closed with a
reason; existing shared credential directories are rejected. Stat metadata
alone cannot authorize Windows credentials. This uses ctypes and native APIs,
without new dependencies. See Microsoft's [handle-based security API](https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).

Both Windows listeners disable address reuse and enable exclusive address use
before binding. POSIX socket options are unchanged. Linux tree teardown holds
the Popen wait lock and observes the leader using `waitid(WNOWAIT)` until the
final group signal, then reaps it. Already-reaped or externally-reaped children
cannot authorize group signals. macOS keeps its previous tree teardown path.

Foreground startup scopes cancellation through launcher/admission locks,
snapshot copying, SQLite progress, CAS inspection and readiness polling.
Cancellation exits nonzero with a reason and runs cleanup outside the scope.
Readiness GETs poll with short transport timeouts during this scope, retaining
their original total request budgets. Outside startup their timeouts are unchanged.

Windows directory admission
uses an abandoned-aware named mutex plus an in-process gate; those directory
locks must be released by their acquiring thread. Ordinary file locks use
LockFileEx. Windows sends CTRL_BREAK for cooperative stopping where a console
exists and otherwise terminates through the identity-checked native handle.

## Remaining execution work

The Runtime and browser-door lifecycle has native backends. Windows local
Worker descriptor transfer and independent listener custody still fail closed
with explicit errors: SCM_RIGHTS/Unix peer credentials have no Windows
implementation here. The delegated host/relay audit-token role broker remains
macOS-specific, so those execution profiles also need the agent-port transport
work on Linux. These paths are not required to serve projects, timelines, or
media through the door. Installer/service registration and real GPU/chat
qualification belong to the subsequent installer and agent workstreams.

## Verification in the restricted macOS worktree

Port-binding and process-signaling integration tests are written and collected
but require an unrestricted runner. Exploratory server tests were rejected by
the sandbox before binding; the full macOS suite could not be completed here.
Windows-native APIs cannot be executed on this host. The three-host CI job is
the remaining native validation gate, not a claim that it has already passed.
The safe test selection and final result are recorded below.

Final safe selection: **453 passed, 13 skipped, 9 deselected** on macOS.
Skipped tests need Windows APIs; deselected tests include the process-tree,
installed lifecycle, and Darwin-native lanes, plus the real TCP health test.
Compilation, `git diff --check`, and `scripts/artifact_manifest.py --check`
also passed. The pytest session's pre-existing process guard could not invoke
`ps` under the sandbox and printed a warning.

```sh
.venv/bin/python -m pytest -q \
  tests/test_bootstrap.py tests/test_runtime_boundary.py \
  tests/test_role_custody_authority.py tests/test_data_root.py \
  tests/test_foreground.py tests/test_native_custody.py \
  tests/test_dirfd_publication.py tests/test_platform.py \
  tests/test_platform_windows.py tests/test_platform_filesystem.py \
  tests/test_realm_tiered_admission.py tests/test_workspace_adopt.py \
  tests/test_relocation_plan.py tests/test_local_worker_composition.py \
  tests/test_local_execution_supervisor.py tests/test_verified_host_launch.py \
  tests/test_portable_lifecycle.py -k 'not slow_healthy_runtime'
```

## Files left uncommitted

Review follow-up safe verification: **470 passed, 18 skipped, 15 deselected**
on macOS, using the preceding safe selection plus `tests/test_m1_review.py`.
The 18 skips require native Windows APIs; the deselections cover integration,
Darwin-native, and real TCP health checks. All six new integrations collected
successfully without execution. Compilation, artifact-manifest verification,
and `git diff --check` passed. The existing pytest process inventory guard
could not run `ps` in this sandbox.

The list below describes the original portability branch. The independent
review follow-up changes `.github/workflows/ci.yml`, `tests/lanes.py`,
`tests/test_foreground.py`, and the following runtime files:

- `runtime_protocol/server.py`, `platform.py`, `windows_security.py` (new),
  `cancellation.py` (new), `auth.py`, `catalog.py`, `daemon.py`, `door.py`,
  `store.py`, and the M2 qualification docstring in `dirfd.py`.
- `astrid_runtime/bootstrap.py`, `cli.py`, `paths.py`, `io.py`,
  `runtime_boundary.py`, and `custody_broker.py`.
- New `tests/test_m1_review.py` contains mocked regressions, Windows security
  checks, a Windows rebind integration, a Linux exited-leader integration,
  and SIGTERM/SIGINT startup lock/door integrations.
- This document records the scope and native qualification limits.

Regression tests were added and observed failing before fixes where runnable
on macOS. Windows-native tests are written but cannot execute here. No port
binds, signals, or commits were performed in this follow-up. The safe selection
excludes all integration/Darwin-native/live tests and the existing real TCP
health test. Native Windows security/socket tests, Linux group cleanup, and
SIGTERM/SIGINT startup integrations require their native unrestricted runners.

### Runtime source

- `astrid_runtime/__init__.py`
- `astrid_runtime/bootstrap.py`
- `astrid_runtime/cli.py`
- `astrid_runtime/custody_broker.py`
- `astrid_runtime/io.py`
- `astrid_runtime/operator_upgrade.py`
- `astrid_runtime/paths.py`
- `astrid_runtime/relocation.py`
- `astrid_runtime/runtime_boundary.py`
- `astrid_runtime/workspace_adopt.py`
- `runtime_protocol/auth.py`
- `runtime_protocol/backup.py`
- `runtime_protocol/cas.py`
- `runtime_protocol/catalog.py`
- `runtime_protocol/cli.py`
- `runtime_protocol/daemon.py`
- `runtime_protocol/dirfd.py`
- `runtime_protocol/door.py`
- `runtime_protocol/fsclone.py`
- `runtime_protocol/local_execution_handoff.py`
- `runtime_protocol/local_execution_supervisor.py`
- `runtime_protocol/local_worker.py`
- `runtime_protocol/local_worker_composition.py`
- `runtime_protocol/local_worker_handoff.py`
- `runtime_protocol/platform.py`
- `runtime_protocol/service.py`
- `runtime_protocol/snapshot_refs.py`
- `runtime_protocol/store.py`
- `runtime_protocol/upgrade.py`

### Tests

- `tests/conftest.py`
- `tests/process_groups.py`
- `tests/test_astrid_activation_join.py`
- `tests/test_bootstrap.py`
- `tests/test_data_root.py`
- `tests/test_door_lifecycle.py`
- `tests/test_foreground.py`
- `tests/test_installed_wheel_source_parity.py`
- `tests/test_local_execution_supervisor.py`
- `tests/test_local_worker_composition.py`
- `tests/test_local_worker_placement.py`
- `tests/test_native_custody.py`
- `tests/test_operator_upgrade.py`
- `tests/test_platform.py`
- `tests/test_platform_filesystem.py`
- `tests/test_platform_windows.py`
- `tests/test_portable_lifecycle.py`
- `tests/test_process_group_cleanup.py`
- `tests/test_realm_admission_hardening.py`
- `tests/test_relocation_plan.py`
- `tests/test_relocation_real_e2e.py`
- `tests/test_replay_policy_process.py`
- `tests/test_role_custody_authority.py`
- `tests/test_runtime_boundary.py`
- `tests/test_runtime_e2e.py`
- `tests/test_runtime_upgrade.py`
- `tests/test_t4_replacement_foundation.py`
- `tests/test_workspace_adopt.py`
- `tests/test_workspace_lifecycle.py`

### Documentation and CI

- `.github/workflows/ci.yml`
- `README.md`
- `docs/runtime-portability-testing.md`

