# R14-P39-29: Runtime native PASS inventory reconciliation

This packet proposes **437 append-only PASS identities**, including **180 exact
native subtest contexts**. The inventory grows from 30,871 to 31,308 rows. All
original rows, metadata, source bindings, omission rules, required jobs, dependency
pins, the zero-entry failure ceiling, and the 349 historical exclusions remain
unchanged. The original merge and release comparisons both remain **FAIL**.

Authority: [packet and run at dev ef0544ed](https://github.com/banodoco/astrid-dev/blob/ef0544ed6780352d0a58dba3d4c0e9d500191d2c/releases/14/packets/R14-P39-29.md),
[Lead dispatch](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-7024805843),
[slot handoff](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-7024901171),
and [conservative seed ruling](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-6998651356).
Runtime destination and original execution source:
`97321788fab40400878f9abf1860a7adbf6ddb92`. Topic:
`p39/runtime-native-inventory`, targeting `release/14/plan-39`.

## Verified PASS additions

All ten original archive digests match GitHub metadata. The unchanged destination
normalizer accepted all ten required job envelopes and thirteen native
invocations, with complete commands, exact dependency tuples, no collection
errors and no unexplained failed steps. Every sealed identity appeared in the
31,322-identity release union. Of the 451 unseeded identities, only the 437
observed passes are proposed; the other 14 remain refused.

| Exact lane | PASS rows added | Original command/native exit |
| --- | ---: | ---: |
| `CI/unit (ubuntu-latest)` | 60 subtests | 1 |
| `CI/unit (macos-latest)` | 60 subtests | 1 |
| `CI/sandbox-process-control` | 60 subtests | 1 |
| `CI/windows-realm-publication/step-08` | 8 | 0 |
| `CI/windows-realm-publication/step-09` | 47 | 0 |
| `CI/windows-realm-publication/step-10` | 106 | 0 |
| `CI/windows-realm-publication/step-11` | 11 | 0 |
| `CI/darwin-native` | 20 | 0 |
| `CI/typescript-client` | 64 | 0 |
| `CI/boundary` | 1 | 0 |
| **Total** | **437** | **Unchanged** |

`pass-additions.json` contains the exact proposed rows. The full
`pass-identity-audit.json.gz` records each native report and line, complete
parameter/subtest identity, source declaration and Git blob, original command,
command/stream/archive digests, run/job/attempt, and raw exits. No separate source
field was emitted by these reporters, so no synthetic source field is inserted
in the inventory. The supporting audit maps all 373 pytest identities to their
unchanged declarations and all 64 Node tuples to their exact file, line, column,
nesting and title. Dynamic titles retain their native expansion.

The 180 subtest identities are serialized `SubtestContext` strings, including
nested escaping. They are not flattened, parsed into a different identity,
deduplicated with their parents, or credited as successful commands. Every
subtest has an already-seeded passing parent with no failed child subtest; the
three containing commands still exit 1.

## Two trusted original-record comparisons

The evaluator, adapters and manifests are exported unchanged from `97321788`.
Both sides use the same original native report and original command-specific
pins. The before side uses the destination records; the after side uses the
proposed inventory as data. The replay uses the evaluator's existing `now`
argument at **2026-11-19 06:56:07 UTC**, just after both archived workflows
finished. This is an offline historical comparison, **not execution on the
candidate commit, a current release qualification, or a qualifying night**.

| Trusted receipt | Required jobs / native invocations | Before | After | Exact finding delta |
| --- | --- | --- | --- | --- |
| [Merge comparison](merge-comparison.json) | 9 / 12 | FAIL, exit 1, 937 findings | FAIL, exit 1, 500 findings | 437 supported PASS retention findings removed; none added |
| [Release comparison](release-comparison.json) | 10 / 13 | FAIL, exit 1, 937 findings | FAIL, exit 1, 500 findings | 437 supported PASS retention findings removed; none added |

Both evaluations stop at the same first fatal refusal:

```text
new skip/xfail/deselection:
CI/unit (macos-latest)
tests/test_linux_listener.py::test_real_http_uses_inherited_listener_and_retained_child
parameter=null, subtest=null
```

The 500 retained evaluator findings are 14 unseeded non-PASS identities, 485
uncovered failures reached before that stop, and the fatal omission refusal.
They are **not** the complete failure census. The full retained release census
contains 1,630 failed lane identities: 1,133 setup and 497 call failures. Merge
contains 1,481: 1,105 setup and 376 call failures. All IDs, stages and normalized
diagnostics remain in the original reports and `remaining-native-refusals.json.gz`.
The release union is 29,333 PASS, 1,630 FAIL, 319 SKIP and 40 XFAIL. Different
lanes can observe the same native ID, so 1,630 is not a distinct product-defect
count.

The evaluator never reaches its final unresolved-obligation loop after the
fatal omission. An empty returned `unknown` list therefore does not resolve
`complete-native-inventory`; that field remains explicitly `unknown`. The
accepted nine-literal-ID ruling remains resolved and unchanged. Both comparison
receipts retain these obligations separately and record the first emitted
finding as well as the fatal stopping point.

Original workflows: [CI 44462380054](https://github.com/banodoco/astrid-runtime/actions/runs/44462380054)
and [Nightly 44462380084](https://github.com/banodoco/astrid-runtime/actions/runs/44462380084),
attempt 1, both terminal failure. The complete records and raw evaluator stdout,
stderr and process exits are in `trusted-replay.tar.gz`; no original workflow was
rerun or cancelled for this packet.

## Exact omission dispositions for Lead

The complete declaration, policy, native phase/diagnostic and matching platform
witness for every identity is in `omission-dispositions.json.gz`.

| Group | Source and matching witness | Requested disposition |
| --- | --- | --- |
| 13 unseeded Windows setup skips | Twelve `requires_linux_tree_custody` cases have Ubuntu unit and portability PASS witnesses. One `requires_posix_process_groups` service-stop case passes both portability jobs and Nightly. Registry bindings and reasons match. | Keep all 13 unseeded/refused. Any exact omission migration needs trusted Lead review; an ordinary PASS addition cannot grant it. |
| One Darwin call XFAIL | Exact `KnownSourceClosureMismatch`, `strict=True`, issue #808, owner `r14-lead`, expiry 2026-12-01. Original detail reaches `test_installed_pack_custody_spawn.py:208`: host-only preparation response differs from original launch. No PASS witness exists in the original required artifacts. | Preserve #808 / Plan 38 ownership and the original XFAIL. No product or Plan 38 test change. Any inventory/quarantine migration is separate trusted work. |
| 37 seeded macOS setup skips | Direct, unregistered module `skipif` at `tests/test_linux_listener.py:22`; every row already records `observed_unapproved_omission`. Ubuntu unit passes all 37. Sandbox passes 35 and fails two. | Keep all rows and refusals unchanged. Lead routes source declaration and omission-policy reconciliation. Linux PASS does not grant an allowance. |

The two retained sandbox listener failures are
`test_child_exit_during_actual_http_invalidates_buffered_success` (ENOSYS at
`runtime_protocol/platform.py:1182`) and
`test_actual_custodian_crash_keeps_engine_but_refuses_replacement` (the original
15-second owner-loss timeout, with process-group EPERM in retained stderr).
Their passing setup/teardown and full failing calls remain in the evidence.

## Historical failures and remaining policy obligations

`historical-failure-map.json.gz` maps all 1,630 failed lane identities to
authenticated G1/G2 evidence and the explicit exclusion roster, retaining phase
and diagnostic differences. All 349 historical exclusions remain byte-for-byte
unchanged and still fail: 153 sensitive cases requiring causal/installed
witnesses, 150 without call-phase agreement, 28 with unresolved cause, and 18
with deficient G1 diagnostics. The other 1,281 are not silently classified as
new defects or admitted failures; their exact historical relationships and
limits are retained in the map.

The authenticated native-detail comparison with G2 finds 1,605 same-identity,
same-stage error-text matches, 21 text differences and four verified PASS to
FAIL changes. Outside the 349 exclusions, those counts are 1,259 / 18 / 4.
This auxiliary use of the unchanged `error_message` function is not causal
equivalence and does not replace the retained comparator diagnostics. G1 lacks
the Nightly lane (149 failures), and four other current failing IDs are absent
from its failed-row list; absence is not credited as PASS. Original reports:
[G1](https://github.com/banodoco/astrid-dev/blob/77a95b4b/plans/39-green-mains/evidence/release-14-phase1-measurement-20261116/baseline-g1/final-report-data.json.gz)
and [G2](https://github.com/banodoco/astrid-dev/blob/7290367c/plans/39-green-mains/evidence/release-14-phase1-measurement-20261116/remeasure-g2/final-report-data.json.gz).

`new-failure-routing.json.gz` preserves four current call failures with original
G2 PASS witnesses: `tests/test_artifact_manifest.py::test_committed_artifact_manifest_is_current`
in Ubuntu unit, macOS unit and sandbox (the diagnostic names changed
`packages/typescript/package.json`), and the macOS authenticated delayed cleanup
ACK case with the existing RT12 audit-token signaling signature. The exact
offsetting recoveries are the skip-binding guard in those three lanes and the
macOS RT11 watchdog case. Equal aggregate failure counts did not erase these
changes. Lead owns routing; no product correction or failure admission is made.

The sealed tier lists name only five merge lanes and six release lanes. **257
proposed PASS rows are in seven required streams absent from those lists**:
Windows steps 08/09/10/11, Darwin, TypeScript and boundary. The trusted lost-ID
loop uses those tier lists. Native invocation completeness is a different
check and does not itself retain an old ID that disappears from collection.
`lane-loss-obligations.json` records this static policy gap. The 180 added
subtests are in already-listed lanes. This packet preserves all tier metadata;
Lead must route any expansion of trusted loss enforcement separately.

## Original dependency tuples

Every command includes Runtime `97321788fab40400878f9abf1860a7adbf6ddb92`.

| Commands | Original required Agent revision |
| --- | --- |
| Unit, portability, sandbox, boundary, Nightly | `0e1543e0da2215db9cb3320cfd1083174c3c62a9` |
| Windows realm publication | `ff40f2c684fc7ce22e42a5cacda5c63a0c8800a9` |
| Darwin native | `4866090edcce7df31d1f0e03cf2354b878e94105` |
| TypeScript client | Runtime only; no Agent dependency |

These original tuples do not qualify a later integrated release tuple.

## Reproduction and custody

`SHA256SUMS` binds the complete committed evidence. `trusted-replay.tar.gz`
contains `source/` GitHub metadata, all normalized before/after reports and raw
evaluator output, the original required job manifests and per-command hashes,
the unchanged 27-probe comparator test result, source hashes and the read-only
extraction recipes. Those auxiliary recipes retain their original scratch input
paths as recorded provenance; the portable `reconcile.py` invocation below
reproduces the trusted comparisons. Download the
ten immutable ZIPs identified in `archive-digests.json` into `inputs/raw/<id>.zip`.
The archives themselves remain at their original GitHub artifact URLs.

Export the trusted snapshot and run the offline recipe from the repository root:

```sh
mkdir -p /tmp/p39-runtime-trusted /tmp/p39-runtime-inputs
git archive 97321788fab40400878f9abf1860a7adbf6ddb92 ci scripts/ci | tar -x -C /tmp/p39-runtime-trusted
tar -xzf ci/evidence/p39-native-inventory/trusted-replay.tar.gz -C /tmp/p39-runtime-inputs
python -I ci/evidence/p39-native-inventory/reconcile.py \
  --trusted /tmp/p39-runtime-trusted --candidate . \
  --inputs /tmp/p39-runtime-inputs --output /tmp/p39-runtime-replay
```

The recipe verifies archive digests, uses only the exported destination
normalizer/evaluator, checks the exact supported delta and unchanged originals,
and calls before/after evaluation in separate processes. `--write-inventory` is
an explicit reproduction option from the original inventory; it is not used by
CI. Set iteration may reorder emitted findings between processes; exact sets,
native evidence and the fatal stopping point remain the comparison criteria.

No product source, test assertion, marker, selector, timeout, retry, ceiling
entry, omission allowance, dependency pin, workflow, destination branch, or
release board is changed by this packet. Submitted for Lead review, not Done.
