# R14-P39-29 omission evidence

Source: Runtime `97321788fab40400878f9abf1860a7adbf6ddb92`; original CI
`44462380054`, attempt 1, and Nightly `44462380084`, attempt 1. This is an
evidence extraction only. All **51 omissions remain refused** by the unchanged
trusted inventory policy. No test, registry, inventory allowance, evaluator,
failure-ceiling entry or unresolved reconciliation item was changed.

`omission-dispositions.json.gz` retains all 51 exact lane/native/parameter/subtest
identities, their native setup/call/teardown records and stream line numbers,
source declarations and hashes, registry bindings, command text and hashes,
command/stream raw exits, archive and receipt hashes, original dependency tuples,
and each same-ID supported-platform witness. Witness PASS means only that exact
test passed on that original tuple; several containing jobs have raw exit 1.

## Dispositions for Lead

| Group | Original observation | Supported-platform evidence | Disposition requested |
| --- | --- | --- | --- |
| 13 unseeded Windows skips | All setup SKIP in `CI/windows-realm-publication/step-10`; native/command exit 0 | All 13 have native PASS witnesses: 12 pidfd cases each pass Ubuntu unit and Ubuntu portability; service-stop passes Ubuntu portability, macOS portability and Nightly integration | Existing platform declarations are source-bound, but new inventory rows require PASS and cannot grant omissions. Lead may review a separate trusted omission migration for these exact records. This packet keeps them unseeded and refused. |
| One unseeded Darwin XFAIL | Call XFAIL in `CI/darwin-native`; native/command exit 0 | The original macOS invocation matches the strict declared exception. No PASS witness for the exact ID in the required artifacts | Keep existing issue #808 / Plan 38 ownership and the original failure. Any trusted inventory/quarantine migration must retain the exact reason, exception, strictness and expiry. No product correction or Plan 38 test change here. |
| 37 seeded macOS listener skips | All setup SKIP in `CI/unit (macos-latest)`; native/command exit 1 | Every ID passes Ubuntu unit. Sandbox has 35 PASS and two call FAIL, all retained | Existing rows explicitly have `observed_unapproved_omission`, with no allowance. Lead must route source declaration/policy reconciliation; an ordinary append-only packet cannot edit these rows or authorize their omissions. |

## Windows declarations

Twelve cases are in `tests/test_platform_signaling.py` and use
`requires_linux_tree_custody`, declared at `tests/lanes.py:359`:
`sys_platform != 'linux'`, reason `Linux waitid WNOWAIT process-group custody`.
Their native reason is exactly
`Skipped: [declared:linux-tree-custody] Linux waitid WNOWAIT process-group custody`.
All five function bindings are present in `tests/skip-bindings.json`; expanded
parameters are retained individually in the JSON.

| Declaration | Source line | Expanded cases |
| --- | ---: | ---: |
| `test_linux_pidfd_fallback_checks_and_terminates_real_child` | 409 | 1 |
| `test_linux_pidfd_fallback_refuses_changed_or_unknown_identity` | 435 | 5 |
| `test_linux_pidfd_fallback_rejects_invalid_signal_without_terminating_child` | 464 | 2 |
| `test_public_pidfd_helpers_fallback_signals_real_child_and_retains_fd` | 697 | 1 |
| `test_public_pidfd_send_signal_fallback_errors_retain_real_fd` | 726 | 3 |

All twelve are also marked `needs_real_pidfd`; sandbox deselection of that marker
does not supply a witness. Their actual PASS witnesses are Ubuntu unit and Ubuntu
portability from this same original CI run, on Agent
`0e1543e0da2215db9cb3320cfd1083174c3c62a9`. The original Windows invocation used
Agent `ff40f2c684fc7ce22e42a5cacda5c63a0c8800a9`.

The thirteenth case is
`tests/test_service_stop.py::test_service_stdin_eof_runs_handlers_and_cleans_process_group`
at line 24. It has the existing `integration` marker and
`requires_posix_process_groups`, declared at `tests/lanes.py:387` with condition
`sys_platform == 'win32'` and reason `POSIX process group integration`. The exact
function is in `skip-bindings.json`. Both portability jobs and Nightly execute
and pass it on Agent `0e1543e0da2215db9cb3320cfd1083174c3c62a9`.

The Windows archive is `14503649687`, SHA256
`43a213baab8b2e47c7a6256f8721c20844f6991da5fa234f9a45cd6e9a229f8f`.

## Darwin declaration and known product defect

Exact ID:
`tests/test_installed_pack_custody_spawn.py::test_real_custody_spawn_launches_granted_installed_pack_and_refuses_ungranted`.
The source declaration at line 128 has `darwin_native` and
`xfail(strict=True, raises=KnownSourceClosureMismatch,
reason=declared_xfail_reason("installed-pair-source-closure"))`.
`tests/lanes.py` binds the exact ID, reason and exception name, owner `r14-lead`,
issue `https://github.com/banodoco/astrid-dev/issues/808`, and expiry `2026-12-01`.
That expiry is valid on the original receipt date, 19 November 2026.

The native call detail shows the specific product refusal:
`host-only preparation response differs from original launch`, followed by
`tests/test_installed_pack_custody_spawn.py:208: KnownSourceClosureMismatch`.
The conditional immediately before that raise checked a 409 refusal and unequal
Agent/Runtime source-closure digests. The receipt therefore supports the named
existing defect; it is neither a PASS nor an unexplained timeout.

Original Darwin Agent pin:
`4866090edcce7df31d1f0e03cf2354b878e94105`. Archive `14505142580`, SHA256
`27c377bbfd4d280d9d10cf1952058cf4789e3d6e8df93f5de2699506fdafcfaf`.
The registry text cites older run `42602337622` / job `129109610936`; this
extraction does not independently re-verify that older assertion or treat it as
a passing witness.

## macOS listener declaration and retained Linux failures

All 37 identities inherit the direct module-level declaration at
`tests/test_linux_listener.py:22`:

```python
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux retained listener primitive")
```

The native reason is `Skipped: Linux retained listener primitive`. It carries no
`[declared:...]` registry token and the source has no authorized skip binding.
The sealed seed already records this as an unapproved omission. Linux execution
does not grant authority to change that immutable record.

Ubuntu unit passes all 37 identities. Sandbox passes 35 and retains these two
call failures, with setup and teardown PASS in both:

| Exact native ID in `tests/test_linux_listener.py` | Original sandbox failure |
| --- | --- |
| `test_child_exit_during_actual_http_invalidates_buffered_success` | Call at test line 117 to `platform.pidfd_open`; `runtime_protocol/platform.py:1182` raises `OSError: [Errno 38] Function not implemented`. |
| `test_actual_custodian_crash_keeps_engine_but_refuses_replacement` | The `owner-loss` subprocess times out after the existing 15-second limit. Its retained stderr includes `PermissionError: [Errno 1] Operation not permitted` in process-group signaling. The receipt alone does not establish a causal product fix. |

Both native failures remain outside the zero-entry failure ceiling; do not infer
that their unit PASS removes the lane-specific sandbox failure. No reproduction
or source fix was attempted. Their full original failure details and normalized
diagnostics are in the JSON, bound to archive `14505574545`, SHA256
`31d45311cb58884bb24d95d8fac94a2575689c3a70552310d1987cd3bfbac507`.

## Applicable trusted policy

`ci/README.md` requires new identities to have actual PASS and prohibits new
omission allowances. `scripts/ci/failure_ceiling.py:282-304` freezes all existing
inventory rows and permits only exact supported PASS additions;
`:319-329` requires a pre-existing exact omission allowance. These 51 have none.
The source skip/xfail registry is additional evidence, not an independent grant
of inventory authority. Lead decision `6998651356` retains Runtime's zero-entry
failure ceiling and excluded reds/unknowns. No later release tuple is qualified
by these original command-specific pin combinations.
