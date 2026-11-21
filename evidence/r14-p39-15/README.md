# R14-P39-15 / RT1 + RT2: implementation and native evidence

**Draft Runtime [#73](https://github.com/banodoco/astrid-runtime/pull/73). BLOCKED, not Done.**
Local execution of all 366 original distinct IDs yields **309 PASS, 5 call FAIL and 52 setup ERROR**.
The new supported authoring journey and both refusal controls passed. The 57 remaining cases are retained for Lead disposition; candidate hosted qualification is pending.

## Authority and source identity

Sole writer `r14-P39-15-1`, run `r14-dispatch`; topic `p39/rt1-rt2` targets only `release/14/plan-39`.
The destination and starting base were verified as `97321788fab40400878f9abf1860a7adbf6ddb92`.
The task is exactly [R14-P39-15 at dev a12d9e89](https://github.com/banodoco/astrid-dev/blob/a12d9e891d54992fa480515027f464829bdb5e9f/releases/14/packets/R14-P39-15.md), the [RT1/RT2 rows](https://github.com/banodoco/astrid-dev/blob/a12d9e891d54992fa480515027f464829bdb5e9f/plans/39-green-mains/tasks.md), [run authority](https://github.com/banodoco/astrid-dev/blob/a12d9e891d54992fa480515027f464829bdb5e9f/releases/14/run.md), [Lead 7027307796](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-7027307796) and [RS1 6995664680](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-6995664680).

Runtime #56 is already in the base. Installed Agent remains pinned to `0e1543e0da2215db9cb3320cfd1083174c3c62a9`.
Checkpoint parent is `c0cf8bfdd5c28be09621a7886f5d33761c5b806e`.
The frozen source tree before these evidence additions is **`0f476068e04ae01ed2fb60e7005a6e66cc60805c`**.
The two complete candidate executions recorded c0cf8bfd plus explicit worktree changes; every one of their 373 test-source hashes matches this frozen tree.
The final publication adds the evidence directory without further executable changes. Its head/tree are reported in the PR and mailbox to avoid self-referential commit metadata.
This is source-byte binding, not a claim that the earlier local commands executed a clean final commit.

## What changed and why

Archived realm loaders correctly leave v33 verification fenced. Several retained fixtures then mutated that realm before registering a provider, or reopened it without fresh process registration. The shared `tests/migrated_realm.py` helper registers through the real `register_timeline_commit_provider`/`provider_ready` path and checks `require_ready`. The service opener closes a failed registration; the daemon wrapper selects the supported Astrid profile before admission. Existing prepared host-boundary providers remain explicit fixture inputs.

Thirteen original fixture/test files now register before their first supported mutation or when opening a new owner. This includes the process-registration restart and real-Agent restore fixtures. No activation marker is manufactured, no readiness function is patched, and no product admission or verification policy is changed.

`tests/test_migrated_realm_readiness.py` adds four native IDs:

- A pre-ready mutation still refuses with the exact verification-pending error and leaves SQL unchanged; registration then permits the save.
- Both `None` and `neutral` profiles refuse startup on a migrated realm and leave it backfill-complete.
- One real migrated realm starts with the supported authoring provider, verifies its retained baseline, saves a real `track.create` command through the public client, stops, refuses a new neutral owner despite the durable ready marker, then reopens under a fresh supported provider. Realm identity, saved revision, publication receipt, idempotent retry and backup digest are checked.

The seven-case focused receipt (three original failures plus these four new controls) is **7 PASS, exit 0**. Those four new IDs are additional evidence and are not counted among the original 366.

## Exact native census and local results

G2 has **366 distinct IDs** across 17 source files, producing **1,082 observations** across Linux/macOS unit, sandbox and Nightly. The exact 366-ID roster governs this packet; the task row's shorthand of seven fixture files is not used to drop IDs.

| Original group | IDs | Candidate PASS | Call FAIL | Setup ERROR |
| --- | ---: | ---: | ---: | ---: |
| Registration | 128 | 127 | 1 | 0 |
| Verification-pending | 237 | 181 | 4 | 52 |
| Process-registration | 1 | 1 | 0 | 0 |
| **Union** | **366** | **309** | **5** | **52** |

| Local selection | IDs | Base PASS / FAIL / ERROR | Candidate PASS / FAIL / ERROR | Candidate teardown PASS | Raw exit |
| --- | ---: | --- | --- | ---: | ---: |
| Original unit IDs | 358 | 0 / 15 / 343 | 305 / 2 / 51 | 358 | 1 |
| Original Nightly IDs | 8 | 0 / 7 / 1 | 4 / 3 / 1 | 8 | 1 |

No ID is missing, extra, skipped or uncollected in either complete scoped candidate run.
Transitions are **290 ERROR→PASS, 19 FAIL→PASS, 2 ERROR→FAIL, 52 ERROR→ERROR and 3 FAIL→FAIL**. The two ERROR→FAIL transitions remain failures.
All 366 teardowns passed. All original and complete candidate raw exits remain 1; the seven-case focused probe's raw exit is 0.

Local worker uses CPython 3.13.5, Node 22.23.5, TypeScript 5.9.3 and the unchanged pinned Agent. Original hosted workflows use Python 3.11. The exact command, source hashes, selection, incremental events, JUnit and unedited terminal output are included for each full local run. Local unit execution is Linux; the local integration selection is not a hosted Nightly receipt. Local results do not substitute for macOS or seccomp execution.

## Remaining boundaries: 57 original IDs

| Count | Current phase | Native refusal and disposition |
| ---: | --- | --- |
| 51 | Setup ERROR | Deliberately `neutral` inputs in `test_timeline_reference_authority.py` (38) and imported `test_project_reference_catalog.py` cases (13) mutate a migrated realm with no provider. The original verification fence at `v33_lifecycle.py:300` remains. Both source files and their parameters are unchanged. Substituting the Astrid provider would change the input labelled neutral. Lead fixture/oracle disposition requested. The bodies did not execute. |
| 2 | Call FAIL, previously setup ERROR | `test_delegated_verified_final_publication_only_stores_artifacts[http]` and `[service]` now reach final settlement at test line 517. Service raises `VerificationReceiptMissingError` at `service.py:6904`, via `settle_attempt:8888`; HTTP returns 409 / `verification_receipt_missing`. Possible product or fixture-contract issue; no receipt requirement weakened and no cause attribution asserted. |
| 3 | Call FAIL | `test_host_boundary_first_capture_process_death[after-config]`, `[before-config]`, `[pre-config]` now pass initial registration but reach unchanged `_migrate_duplicate_realm` line 79, `assert 33 == 31`; the same original helper later expects target 32. Its crash body has not run. An oracle/setup disposition is required. |
| 1 | Setup ERROR, changed refusal | `test_public_cli_stale_trim_rebases_label_lost_ack_restart_retry_and_undo[historical-audio]` now registers and ingests, then `historical_audio_fixture.py:335` calls `publish_parent_composition`. Runtime `service.py:3640 → 1814 → 452` refuses the retired timeline route and requires `commitTimeline`. Fixture history/publication semantics were not rewritten. The journey body did not run; this is not yet an established supported-user product bug. |

All exact residual native IDs are in [residual-ids.txt](residual-ids.txt). Full per-ID phases and literal traceback detail are in the capsule. Dependent semantic/oracle/product changes stopped at these boundaries, as required by the packet. No failure is counted as fixed merely because an earlier refusal moved.

## Original and exact-destination hosted receipts

The original G2 source is [dev 7290367c / final-report-data.json.gz](https://github.com/banodoco/astrid-dev/blob/7290367c170eb751ae14fd41d7f433f92b0e0e1e/plans/39-green-mains/evidence/release-14-phase1-measurement-20261116/remeasure-g2/final-report-data.json.gz), blob `0975f72507ddd06b2bab84a765c4bc7a6a0a4c7a`, SHA256 `50760681220707845c9bd50e6795a0914fce9f705177359f6300ebc9324be522`. Runtime G2 was `19cd1e35cd247fd394204940b6e7a02929fa3fc6`, with the same Agent pin.

| Lane | G2 native run / job / artifact | Exact 97321788 run / job / artifact |
| --- | --- | --- |
| Ubuntu unit | [44309715979 / 134820394487](https://github.com/banodoco/astrid-runtime/actions/runs/44309715979/job/134820394487) / 14433570144 | [44462380054 / 135352013255](https://github.com/banodoco/astrid-runtime/actions/runs/44462380054/job/135352013255) / 14504120479 |
| macOS unit | [44309715979 / 134905940661](https://github.com/banodoco/astrid-runtime/actions/runs/44309715979/job/134905940661) / 14441948450 | [44462380054 / 135352013303](https://github.com/banodoco/astrid-runtime/actions/runs/44462380054/job/135352013303) / 14504167097 |
| Sandbox | [44309715979 / 134820394531](https://github.com/banodoco/astrid-runtime/actions/runs/44309715979/job/134820394531) / 14432965131 | [44462380054 / 135352013198](https://github.com/banodoco/astrid-runtime/actions/runs/44462380054/job/135352013198) / 14505574545 |
| Nightly | [44309715980 / 134820393924](https://github.com/banodoco/astrid-runtime/actions/runs/44309715980/job/134820393924) / 14429154793 | [44462380084 / 135352012926](https://github.com/banodoco/astrid-runtime/actions/runs/44462380084/job/135352012926) / 14504397024 |

G2's Linux/sandbox attempt-2 envelopes retain the original attempt-1 receipts; macOS is attempt 2 and Nightly attempt 1. The capsule distinguishes envelope IDs 134906035312 / 134906039914 from their actual native job IDs. Destination receipts are attempt 1, terminal failure, raw exit 1. All ZIP and payload digests were verified. Duplicate sandbox snapshots and collection-only events are not counted twice.

Across all 1,082 scoped observations, exact-destination setup/call/teardown outcomes, literal failure lines and first Runtime exception sites match G2. Native histories and complete selected tracebacks are retained. These existing destination runs can be reused; no new baseline dispatch is requested.

Candidate hosted Linux, macOS, sandbox and Nightly remain **pending**, with live run identities maintained in the PR/mailbox after final publication. Checkpoint CI 44656667095 and Failure-ceiling 44656667145 on c0cf8bfd were explicitly nonqualifying implementation runs. No manual cancellation was performed. The final source must stay frozen during qualification. No scheduled release night is claimed.

## Preservation and review limits

Byte/AST comparison across all 371 original Python test files finds 358 byte-identical and 13 changed files. All **13,489 original assertion ASTs**, **2,364 pytest oracle ASTs** and **3,716 total pytest-call ASTs** are retained; one fixture identity assertion was added. Original test signatures and parameter decorators are unchanged. The new helper and journey file add two files. All 373 source hashes match both full candidate invocation snapshots.

This is a preservation check, not independent implementation approval and not evidence that an unreachable oracle executed. There are no product, dependency pin, workflow, inventory, skip registry, global conftest, Plan38/55, destination or board changes. Lead owns review, scope/oracle decisions, integration and task status.

## Capsule and verification

[native-evidence.tar.gz](native-evidence.tar.gz) has SHA256 **`bb820e82b3b8016368f9f51c12de38f8a246db72368510096786ace7b4dda527`**, **754168 bytes**. [artifacts.json](artifacts.json) records the envelope; `payload-manifest.json` inside records every included file's exact bytes and digest.

The capsule includes all six local native receipts (full logs, XML, incremental phases and raw exits; complete command/source snapshots for the four full runs), all 366 G2 identities and 1,082 observations, selected original/destination native events including complete tracebacks, hosted provenance, exact workflow bytes, per-ID comparisons, source diff and assertion audit. Whole upstream suite ZIPs and the canonical G2 compressed report are referenced by immutable identities/digests rather than duplicated. Historical analysis scripts retain their recorded workspace paths as provenance; use the portable verifier below to verify the sealed receipt independently.

```sh
python evidence/r14-p39-15/verify_evidence.py
```

The verifier reads the archive without extracting it, checks every payload digest, recomputes candidate phases/outcomes and original-group counts from the raw events, verifies all 366 original IDs and all teardown outcomes, and compares current test-source bytes with both recorded invocation snapshots. It does not execute tests or turn the retained failures into a passing qualification verdict.
