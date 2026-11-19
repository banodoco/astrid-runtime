# R14-FIX-12: durable logs on first settlement and owner retry

Scope: [banodoco/astrid-dev#926](https://github.com/banodoco/astrid-dev/issues/926)
and [#958](https://github.com/banodoco/astrid-dev/issues/958), under
[R14-FIX-12](https://github.com/banodoco/astrid-dev/blob/4edaf151153084a162fe608ae4439b5de8e9a823/releases/14/packets/R14-FIX-12.md).

## Release baseline

- Runtime: `2537fed24385ec1c24f48a812e09af4bb63fb794`.
- Agent: `aa988878b383fb965b5fc05601baa15a93849d42`.
- VibeComfy: the Agent's unchanged pin, `c27fe76b79d917fd9c08246660bc77211be64146`.
- Ordinary CPU-action probe: **1 failed**, HTTP 409 on the second attempt's
  `job.stdout`; conflicting fields are `attempt_id` and `provenance_json`.
  The action ran twice (`fail`, `success`), on one task with no generation.
- Legacy creative diagnostic: **2 failed**, one for each legacy creative
  effect's first settlement. Both count canonical durable logs as creative outputs.
- Both reproductions retained identical product inputs throughout their runs.

`release-baseline.tar.xz` contains the unchanged probes, command/environment and
source-identity records, complete pytest logs, JUnit, and the ordinary probe's
selected custody observations. `release-baseline.json` records member hashes.
The required ordinary probe SHA-256 remains
`671648e5b9287ead292f2ded239d0af64fd64e6aeaa0e4a541bfcb59192a1e22`.

An initial ordinary run selected P55-12's newer VibeComfy checkout. The existing
dependency guard refused that input before the action ran. Its record is retained
as setup NO-RESULT; the reproduction uses the release pin above.

## Product change and proposed pin

Runtime product commit: `d192c2c3e536770f0766c928eff24539abe7f734`.
Agent proposed pin commit: `e894d7bd248ca35e48edb9ed209a2b06991c2e69`.

The store gives new default durable `logs` associations a
`log-attempt:<actual fenced attempt ID>` group. A pre-fix default association
keeps its identity when the same attempt is replayed. Earlier attempts' rows
and bytes remain intact; non-log collisions still reach the existing immutable
association guard. Explicit producer groups, including P55-12's
`thumbnail-attempt:<ID>` groups, are unchanged.

Both legacy creative validators exclude only canonical durable `job.stdout`
and `job.stderr` objects from the creative-output count. A second creative
output, noncanonical logs, and creative metadata disguised as logs remain
refused. The original immutable-field comparison/refusal block is byte-identical
to the release base: SHA-256
`f59a1db746cb3797e36514051add1bac7ee836a0024f3676ca5fade69e1cec0e`.
No schema, generated-client, existing test, or fixture bytes changed.

Agent PR [#439](https://github.com/banodoco/astrid-agent/pull/439) proposes the
Runtime product commit in a separate commit. Only `source_commit` in the root
and packaged Runtime locks changes. The canonical refresh script and
`vendor_lock.py check runtime.lock.json --producer ../astrid-runtime` passed;
the generated artifacts and producer manifest retain their prior hashes. This
is a pin proposal; the Lead approves pins and integration.

## Focused proof

`focused-proof.tar.xz` and its companion manifest retain the exact commands,
selected environment, source identities before/after, full `-rA` logs, JUnit,
frozen probes, and by-ID comparisons. Every final pytest run records unchanged
inputs during execution.

| Proof | Before | Fixed candidate |
|---|---|---|
| Unchanged real GenericPackHost CPU retry probe | 1 failure, HTTP 409 | 1 pass on Agent `e894d7bd` / Runtime `d192c2c3` / Vibe `c27fe76b` |
| Release focused cases | 80 executed: 4 failed, 76 passed | 80 passed; 4 fixed, 0 regression, 0 missing |
| P55-12 combined Runtime cases | 88 executed: 4 failed, 84 passed | 88 passed; 4 fixed, 0 regression, 0 missing |
| Protected installed thumbnail recovery | Unchanged P55-12 source | Both cases pass |
| Frozen installed preserved-variant journey | Previously blocked by #958 | Pass: both creative first settlements, restart, two ordinary preview tasks, preserved primary and both readable JPEGs |
| Agent pin guards | 16 executed: 1 failed, 15 passed | Same 1 failed, 15 passed; 0 regression, 0 missing |

The 36 new Runtime cases cover identical and different retry log bytes,
owner-only retry, reads of both attempts through the generated HTTP client,
provenance and replay, immutable successful outputs/log bytes, both creative
settlements, rejection of a second creative output, and 14 noncanonical-log
forms per creative effect. The remaining release-focused cases exercise
existing generic publication, managed-output API, generation/variant, and
thumbnail settlement behavior.

The unchanged CPU probe was run with temporary-file retention enabled so its
realm could be reopened. `verify_real_log_reads.py` then restarted that realm
and used only `list_managed_outputs`, `get_managed_output`, and `get_object`
to retrieve stdout and stderr for each attempt. All four reads pass, retaining
the recorded attempt ID, task ID, executor, capability, fence, runtime epoch,
and full provenance. The selected readback contains no credentials or database.

The one inherited Agent pin-test failure is
`tests/test_vendor_lock.py::test_one_root_lock_covers_all_known_runtime_paths`.
It asserts historical Runtime `1e6d899efa77a2d6ec247c38250f9748330bb587` on both
the release base (which pins `2537fed2`) and the candidate. It remains executed
and unchanged; the other 15 refusal/validation cases pass on both sides.

## Combined P55-12 source identity

The installed combined proof uses accepted Agent
`e379565641414bc183cd02edebab1cbf77617931` and its Vibe pin
`1ba0ac3ad4fe69fa0b4966cc41e6852224013f97`. Runtime is the clean, proof-only
detached merge `02f0c7bb00cb7e9c032599e0b2403e531bc1f370`, whose parents are
merged P55-12 `b35c93ad92cfbca2372e01bc1bf9f53e4edbb9f0` and FIX-12
`d192c2c3e536770f0766c928eff24539abe7f734`. It applies the same FIX-12 product
delta; it does not merge a destination or plan branch. The archive contains a
verified thin Git bundle to reconstruct this exact merge from those parents.

All six selected P55-12 Runtime test files and both protected Agent recovery
tests/helpers retain their accepted bytes. The previously untracked installed
variant diagnostic retains SHA-256
`dd98270eb9fbb9e27c438f52f7d18b1bdb97271bbd4bf86e86fafe0e29003a84`.
The Runtime seven-case attempt-selector checks include actual prior-attempt
selector refusal after owner retry; all seven pass unchanged.

The release-pin tuple and the accepted P55-12 tuple are separate evidence
rows. Integrating all Agent main/Plan-55 work is not claimed by this packet.

## Retained diagnostic mismatch and hosted blockers

The original #958 two-case diagnostic remains byte-identical. On fixed product
bytes both first settlements succeed and produce three associations, then its
last assertion fails with `KeyError: 'name'`. Managed-output associations expose
`variant_key` and `filename`; `name` belongs to settlement-output descriptors.
The raw two failures are retained. No fictitious public field was added and
the frozen diagnostic was not edited. The separate packet-owned tests exercise
the supported association read shape. The exact one-field corrected-copy
proposal is [REQUEST 6999723650](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-6999723650).

Full hosted qualification is **BLOCKED**, not green:

- Agent's existing exact-base full CI `44453036237` and Lanes `44453036281`
  already cover the required eight/four shard inventories. They are not
  duplicated. Candidate Agent `e894d7bd` is frozen for Lead dispatch of full
  CI and affected Lanes; this session exposes no new workflow-dispatch tool.
- Runtime exact-base CI `43888599361` / `44280730934` and Nightly `43968523867`
  omit passing IDs and have no JUnit artifacts. An unchanged rerun cannot
  establish a complete per-ID/no-missing comparison. Reporting-only capture
  and base-capture disposition are requested in
  [BLOCKED 6999750539](https://github.com/banodoco/astrid-dev/issues/796#issuecomment-6999750539).
- Initial Runtime checkpoint CI `44458366771` was cancelled by workflow
  concurrency when the product commit advanced. It is unqualified evidence;
  no run was manually cancelled. Runtime product CI `44459143790` is likewise
  diagnostic until the reporting gap is resolved.

No release-completion, full-suite-green, pin-approval, or merge claim is made.
The Lead owns review and integration; no independent review was commissioned.

Routes used: Unknown — direct ChatGPT packet execution has no configured
route-binding record. A bounded helper performed read-only source/evidence
retrieval; implementation and judgment remained with the packet session.
