# R14-P39-29 historical failure preservation

Read-only extraction at Runtime `97321788fab40400878f9abf1860a7adbf6ddb92`. The unchanged trusted job normalizer consumed the original CI `44462380054` and Nightly `44462380084` receipts. No source, test, policy, inventory or destination was changed by this extraction.

## Full failure census

All **1,630 failed lane identities** are retained: **1,133 setup** and **497 call** failures. There are no failed nested subtest identities in these original streams. Every failed identity, parameter, stage, exact normalized comparator diagnostic, original job/run/attempt/tuple, native source hashes and historical matching records is in `historical-failure-map.json.gz`. A lane identity is not a distinct product defect.

All **349 explicit historical exclusions** still fail. Their original rows and reasons are retained exactly:

| Original exclusion reason | Count |
| --- | ---: |
| sensitive case retained outside ceiling pending explicit cause/installed-witness review | 153 |
| G1 diagnostic is missing, too weak or truncated | 18 |
| matching error alone does not resolve custody/persistence/settlement/refusal cause; outside-cut admission not established | 28 |
| failure stage is not bound to the call phase on both measurements | 150 |

The zero-entry failure ceiling stays zero. No message comparison, inherited owner row or aggregate result authorizes a failure addition. The accepted nine-literal-ID reconciliation remains unchanged; no new alias or title-only matching was introduced.

## Relationship to G1/G2

Both archived reports matched the exact sealed hashes. All six G2 native artifact ZIPs also matched the seed archive digests; their original native setup/call/teardown records supply phase evidence. G1 lacks the Nightly integration lane, so its 149 current failures have no G1 lane witness. Absence from a failed-row list is not treated as PASS.

| Native comparison with G2 | All current failures | Outside the 349 exclusions |
| --- | ---: | ---: |
| Exact identity, failed stage, and error text agree after unchanged `core.error_message` processing of both original native details | 1,605 | 1,259 |
| Exact identity and stage agree; native error text differs | 21 | 18 |
| G2 native PASS; current native call FAIL | 4 | 4 |

This auxiliary native-detail comparison preserves values and parameters and does not establish causal equivalence. The original G2 report often contains a setup wrapper, a shortened JUnit message or an entire traceback. A direct comparison of that report field with the current comparator diagnostic agrees for 330 rows and differs for 1,296, with four absent from the G2 failed roster. Both representations and their hashes remain in the JSON; the destination evaluator is unchanged.

For the 1,281 failures outside the explicit exclusion roster, G1 has 954 exact identity/message matches, 174 same-identity message differences, 149 missing-lane cases, and four IDs absent from its failed rows. These are evidence relationships, not failure admission decisions.

## Four changed outcomes requiring preserved routing

The equal total of 1,630 failures at G2 and now hides four changed failed identities. `new-failure-routing.json.gz` retains the original and current native reports, exact artifact/stream/command hashes, raw exits and source tuples.

| Current FAIL | G2 artifact → current artifact | First current frame | Disposition |
| --- | --- | --- | --- |
| `CI/sandbox-process-control` — `tests/test_artifact_manifest.py::test_committed_artifact_manifest_is_current` | 14432965131 → 14505574545 | `tests/test_artifact_manifest.py:18` | Lead routing needed |
| `CI/unit (macos-latest)` — `tests/test_artifact_manifest.py::test_committed_artifact_manifest_is_current` | 14441948450 → 14504167097 | `tests/test_artifact_manifest.py:18` | Lead routing needed |
| `CI/unit (macos-latest)` — `tests/test_prepared_owner_authenticated_cleanup.py::test_authenticated_delayed_cleanup_ack_precedes_original_child_reap` | 14441948450 → 14504167097 | `tests/test_prepared_owner_authenticated_cleanup.py:76` | RT12 |
| `CI/unit (ubuntu-latest)` — `tests/test_artifact_manifest.py::test_committed_artifact_manifest_is_current` | 14433570144 → 14504120479 | `tests/test_artifact_manifest.py:18` | Lead routing needed |

The three manifest failures name `packages/typescript/package.json: changed`. This is a possible manifest/source defect for Lead disposition; no fix or causal attribution was attempted. The macOS cleanup occurrence has the existing RT12 `proc_signal_with_audittoken` signature (`returncode=3, errno=3`), so it is routed to that standing row.

The exact offsetting FAIL→PASS observations are the skip-binding guard `tests/test_skip_registry.py::test_skip_bindings_match_explicit_platform_lane_uses` in Ubuntu unit, macOS unit and sandbox, plus the macOS RT11 watchdog `tests/test_p2_commit_phase_capture.py::test_live_watchdog_uses_real_handler_and_private_faulthandler_output`. Their old failures stay in the evidence; these passes do not qualify the release or prove a causal repair.

The authenticated G2 report already flags 310 of the matched failed lane identities as possible product bugs. That historical flag is retained with its recorded owner; this packet does not investigate or change those products.

## Remaining native error-text differences

All 21 rows retain both exact normalized error texts and raw detail hashes. No cause or new-defect inference is made from a difference.

| Lane | Native ID | Existing G2 owner |
| --- | --- | --- |
| CI/portability-lifecycle (macos-latest) | `tests/test_portable_lifecycle.py::test_real_post_worker_finishes_after_runtime_daemon_process_is_killed` | RT7 |
| CI/portability-lifecycle (ubuntu-latest) | `tests/test_portable_lifecycle.py::test_installed_up_reports_occupied_browser_door_without_claiming_owner` | RT7 |
| CI/portability-lifecycle (ubuntu-latest) | `tests/test_portable_lifecycle.py::test_real_post_worker_finishes_after_runtime_daemon_process_is_killed` | RT7 |
| CI/sandbox-process-control | `tests/test_spec_dedup.py::test_offline_migration_and_compaction_of_duplicate_render_specs` | RT6.25 |
| CI/unit (macos-latest) | `tests/test_spec_dedup.py::test_offline_migration_and_compaction_of_duplicate_render_specs` | RT6.25 |
| CI/unit (ubuntu-latest) | `tests/test_spec_dedup.py::test_offline_migration_and_compaction_of_duplicate_render_specs` | RT6.25 |
| Nightly/integration | `tests/test_capture_candidate_binding.py::test_real_candidate_reaches_verified_host_without_mutating_inputs[child-inline]` | RT6.39 |
| Nightly/integration | `tests/test_capture_candidate_binding.py::test_real_candidate_reaches_verified_host_without_mutating_inputs[child-ref]` | RT6.39 |
| Nightly/integration | `tests/test_capture_candidate_binding.py::test_real_candidate_reaches_verified_host_without_mutating_inputs[parent-inline]` | RT6.39 |
| Nightly/integration | `tests/test_capture_candidate_binding.py::test_real_candidate_reaches_verified_host_without_mutating_inputs[parent-ref]` | RT6.39 |
| Nightly/integration | `tests/test_portable_lifecycle.py::test_installed_up_reports_occupied_browser_door_without_claiming_owner` | RT6.32 |
| Nightly/integration | `tests/test_portable_lifecycle.py::test_real_post_worker_finishes_after_runtime_daemon_process_is_killed` | RT7 |
| Nightly/integration | `tests/test_timeline_absent_head_repair_integration.py::test_repair_exact_bootstrap_retry_restart_and_edit_undo[absent]` | RT6.45 |
| Nightly/integration | `tests/test_timeline_absent_head_repair_integration.py::test_repair_exact_bootstrap_retry_restart_and_edit_undo[null]` | RT6.45 |
| Nightly/integration | `tests/test_timeline_clip_replacement.py::test_native_clip_swap_is_atomic_cas_and_exactly_replayable` | RT6.46 |
| Nightly/integration | `tests/test_timeline_clip_replacement.py::test_native_clip_swap_public_http_route` | RT6.46 |
| Nightly/integration | `tests/test_timeline_commit_input_integration.py::test_move_from_corrupt_local_timing_cache_conflicts_without_writes[config]` | RT6.51 |
| Nightly/integration | `tests/test_timeline_commit_input_integration.py::test_move_from_corrupt_local_timing_cache_conflicts_without_writes[transcript]` | RT6.51 |
| Nightly/integration | `tests/test_timeline_history_assembly.py::test_provider_history_lookup_authenticates_each_graph_node_once[2]` | RT6.56 |
| Nightly/integration | `tests/test_timeline_history_assembly.py::test_provider_history_lookup_authenticates_each_graph_node_once[4]` | RT6.56 |
| Nightly/integration | `tests/test_timeline_history_assembly.py::test_provider_history_lookup_authenticates_each_graph_node_once[8]` | RT6.56 |

## Reproduction and limits

`extractors/build_historical_failure_map.py` and `extractors/build_new_failure_routing.py` in `trusted-replay.tar.gz` only read the immutable source checkout and archived receipts. They assert the 349 exclusions, 1,630 unique failed identities and the four exact offsetting outcome pairs. The scripts use their recorded scratch source paths; those paths locate authenticated bytes and are not additional authority. This is evidence extraction for the Lead, not an independent review or a passing trusted verdict.
