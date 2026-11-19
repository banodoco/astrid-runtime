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

This is a failing-before checkpoint. Fixed-head, per-attempt read/provenance,
successful-output immutability, combined P55-12 thumbnail checks, installed
preserved-variant journey, and hosted-suite evidence remain to be added.

Routes used: X implementation/judgment; read-only evidence discovery by a bounded
helper. No independent review was commissioned; the Lead owns packet review.
