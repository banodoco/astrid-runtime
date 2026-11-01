# Astrid Runtime

## Running tests

Run locally with `python -m pytest -q -n 2`; avoid `-n auto` on small machines.
Run the full default lane (`python -m pytest -q -n 2`) before pushing.
Run the full nightly lane with `ASTRID_CHECKOUT` set:
`python -m pytest -q -m "integration or darwin_native or live"`. CI runs `integration`
nightly and `darwin_native` in the `darwin-native` job; every skip is declared in
`tests/lanes.py` and the run fails on an undeclared one.
Nightly CI runs the integration subset on Linux with the pinned Astrid checkout
installed into the runner interpreter. For a local integration run, use:
`ASTRID_CHECKOUT=/path/to/astrid-agent .venv/bin/python -m pytest -m integration`.
When the checkout has its own `.venv`, host materialization uses that interpreter
so Astrid's dependencies stay in the agent environment.

Independent neutral runtime and protocol repository for the Astrid Stage 1 beta and later Astrid App integration.

**Windows support is in beta.** Native Windows has been exercised by testers; CI runs on Linux, macOS and Windows. See [portability testing](docs/runtime-portability-testing.md) for coverage and limitations.

The repository contains the first independently runnable neutral-runtime slice. It is dependency-free Python and can be exercised without any product checkout or hosted service. The daemon owns one realm's canonical SQLite database, append-only SHA-256 CAS, task/event ledger, credentials, and loopback HTTP boundary. Realm creation is explicit; startup and doctor never migrate or repair an existing root.

## Custody

- Initial branch: `main`
- Remote: `origin` at `https://github.com/banodoco/astrid-runtime`.
- The Stage 1 oracle worktree is `../astrid-runtime-oracle` on `megado/astrid-stage1-beta`.
- The exact Astrid source baseline and frozen roadmap inputs are recorded in the external Phase 0 custody receipt and in the oracle worktree.

## Development boundary

The runtime owns durable structured state, task/lease semantics, capability registration, append-only CAS accounting, verified backup/restore/replacement, and the language-neutral protocol. Product repositories consume generated clients and never open its database or storage directly.

## Clearing named tasks

`astrid-runtime tasks clear <task-id> [<task-id> ...]` uses the selected live
Runtime's owner credential. It cancels only the exact named tasks through the
canonical task API, then confirms that each is terminal with no remaining
lifecycle blockers. `--json` reports an outcome for each supplied id, including
repeated and unknown ids. It exits zero only when all named tasks are settled
or confirmed already settled, and never starts a Runtime to clear tasks.

Local host-only Worker tasks require the owner's retained process handle and
positive child ACK plus completed wait. Relinquishing a Worker requires naming
all its outstanding tasks; a refusal reports additional required ids. Interrupted
cleanup retries the exact named set and generation using durable stop proof.
Uncertain stop proof, expired initial leases, or unsupported external work
remain explicit failures. `cancel_requested` does not mean cleared. An unnamed
task can still block `down` after a successful clear of other tasks.

When handing this action to someone else, provide both **Copy for your agent**
(inspect the named blockers and clear only the explicitly selected ids) and
**Run it yourself** (`astrid-runtime tasks clear <task-id> ...`). Until the
installer's terminal shim is available, use the selected installation's Python
with `-I -m astrid_runtime tasks clear <task-id> ...`, preserving that
installation's data and support arguments. Pinokio users use its Stop/Update
buttons for the subsequent lifecycle action.

## Client contract releases

`generators/release.json` owns the contract version. Run
`python generators/generate.py` to stamp the Python package, the TypeScript
package and its lockfile, and their public `CONTRACT_VERSION` exports.
`packages/python` (`astrid_runtime_client`) and `packages/typescript`
(`@astrid/runtime-client`) are the two language packages in one release.
The independent TypeScript client under `conformance/typescript` is test
coverage, not a distributable. Shared fixtures and recorded responses live
under `conformance/`.

Before release, run:

```bash
python generators/generate.py --check
node tools/generate_typescript_conformance.mjs \
  --contract contract/openapi/workspace-v1.yaml \
  --schema-manifest contract/manifest.json \
  --component-manifest contract/component-manifest.json \
  --fixture-root conformance/fixtures --check
python scripts/artifact_manifest.py --check
python -m pytest -q -n 2
(cd packages/typescript && npm ci && npm test)
```

The release checklist also requires the real Agent provider native-seed smoke;
the checkout and provider-origin checks are fail-closed, and Runtime-only
fixtures do not qualify. Run it from this checkout with the exact interpreter
used for Runtime:

```bash
ASTRID_CHECKOUT=/absolute/path/to/astrid-agent \
PYTHON_BIN=/absolute/path/to/runtime/.venv/bin/python \
bash scripts/check-before-push --native-provider-smoke
```

This bounded smoke selects the existing genuine D101 native-capture and
history/guarded-Undo nodes, and each probe/test phase has a 45-second limit.
The no-argument form of `scripts/check-before-push` retains the default pytest
run and invokes this smoke automatically when Runtime protocol paths change.

After changing released artifacts, regenerate `contract/artifacts.json` with
`python scripts/artifact_manifest.py`. Its hashes verify the selected bytes;
they are not interoperability admission rules. Release both packages, schemas
and conformance fixtures together from a `contract-v<version>` Git tag
(initially `contract-v0.1.0`). The release coordinator creates the tag after
verification. Consumers resolve it to an immutable commit and record that
commit as the sole dependency selector in `runtime.lock.json`; version, paths
and hashes describe the selected release.

Compatible additions increment the minor version, fixes increment the patch
version, and incompatible wire changes require a protocol major. The release
version is not a handshake admission gate. Response readers accept unknown
fields while validating known fields; request shapes remain unchanged.

## Run it

For an existing configured workspace, `astrid-runtime up --wait` starts or
reconnects Astrid and returns after its browser door is ready. Open
https://astrid.haus. A service manager should execute `astrid-runtime run`:
the daemon and door run in that process until it receives a stop signal, and
startup or listener failure exits non-zero with a reason and log path.

Both commands supervise the optional long-running services declared by the
active source profile. See [profile services](docs/profile-services.md) for the
JSON Schema, interpreter tokens, restart policies, logs and health readback.

Defaults are native per-user paths:

| OS | Data root | Foreground log |
| --- | --- | --- |
| macOS | `~/Library/Application Support/Astrid Runtime` | `~/Library/Logs/Astrid Runtime/runtime.log` |
| Linux | `$XDG_DATA_HOME/astrid-runtime` (default `~/.local/share/astrid-runtime`) | `$XDG_STATE_HOME/astrid-runtime/logs/runtime.log` (default `~/.local/state/astrid-runtime/logs/runtime.log`) |
| Windows | `%LOCALAPPDATA%\Astrid Runtime` | `%LOCALAPPDATA%\Astrid Runtime\logs\runtime.log` |

The established macOS background log remains `runtime/runtime.log` below the
data root. See [portability checks and remaining worker transport work](docs/runtime-portability-testing.md).

The local launcher accepts an absolute `--data-root` support directory on
lifecycle commands, or `ASTRID_RUNTIME_DATA_ROOT`. This directory directly
contains the installation's `runtime/` and `credentials/` trees.
`astrid-runtime relocate --data-root /old/support --destination /new/support --plan`
previews a same-filesystem move of that complete support tree. Execution uses
`--confirm "RELOCATE <realm-id>"`, verifies the owner before stopping it,
cold-starts at the new location, and restores the old tree if cutover fails.
The optional backup path is recorded in the plan; relocation does not perform
a backup/restore or migrate a legacy realm.

Local consumers can resolve a project object through
`get_project_object_location(project_id, object_id)` in Python or
`getProjectObjectLocation(projectId, objectId)` in TypeScript. The authenticated
lookup verifies ownership, size, and SHA-256 bytes before returning the current
CAS path. Paths are valid for the local runtime host at lookup time; task and
managed-output receipts remain portable and do not embed them.

Binary object and project media-import POSTs stream raw bytes with a default
5 GiB limit. Set `RUNTIME_MAX_OBJECT_BYTES` to a positive decimal byte count to
lower that limit (ASCII digits only, no signs, whitespace or separators).
Values above 5,368,709,120 bytes or zero are rejected before opening a realm.
JSON control requests remain limited to 64 MiB. Binary
requests require one Content-Length or chunked Transfer-Encoding; ambiguous
framing, compressed bodies, incomplete transfers and chunk trailers are
rejected. The TypeScript client's `RequestBody` accepts `Uint8Array | Blob`;
pass browser File/Blob bodies directly instead of materializing an ArrayBuffer.

Typed image/video/audio imports require local `ffprobe` and `ffmpeg`. A forced
local demuxer and one decoded frame/sample check the declared media type before
publication. Generic object routes continue accepting arbitrary blobs. Keep the
same Idempotency-Key, bytes and metadata for a full-request retry. An interrupted
prepublication transfer creates no durable operation; a lost response after
commit is recoverable by import-operation lookup or exact receipt replay.
Object GET/HEAD supports single closed, open and suffix byte ranges and 416
responses. Transfers and hash verification run outside SQLite transactions.

```bash
python3 -m runtime_protocol doctor --root .runtime --json
python3 -m runtime_protocol create --root .runtime
python3 -m runtime_protocol start --root .runtime
```

Backups are verified before publication into a new inactive sibling. Replacement
requires support custody outside the movable realm root; the default in-root
`root/support` layout remains valid for ordinary startup but is rejected before
replacement moves. Use one stable sibling support directory for the daemon,
backup authentication key, credentials, epoch floor, and catalog:

```bash
python3 -m runtime_protocol create --root ./runtime-realm
python3 -m runtime_protocol start --root ./runtime-realm --support-root ./runtime-support
# Stop the daemon before using the offline CLI backup command.
python3 -m runtime_protocol backup --root ./runtime-realm \
  --support-root ./runtime-support --destination ./realm-backup
python3 -m runtime_protocol replace --root ./runtime-realm \
  --support-root ./runtime-support --backup ./realm-backup
```

Replacement retains the superseded root for recovery evidence, rotates the
owner credentials, advances the Runtime epoch, and publishes readiness only
after the new owner has passed admission. Old realms and backups are
unsupported and are neither migrated nor salvaged by Runtime; preserve them
for an explicitly owned offline disposition.

`start` prints the loopback endpoint and owner credential path, then keeps the
daemon alive until SIGINT/SIGTERM. The test suite demonstrates the workspace.v1
HTTP boundary, project CRUD, managed object ingest and authenticated byte
reads (`ETag`/`Range`), deterministic worker claim/settlement, restart
reconnect, hash verification, path safety, and sole-owner refusal.

The HTTP binding in this slice is the canonical Stage 1 runtime transport
boundary used by the daemon and product integrations. OpenAPI and generated
product bindings consume this same protocol contract in the
protocol/conformance lane. No runtime module imports a product checkout.

Remote worker preparation currently supports one remote worker credential
generation per Runtime, using the shared `astrid-pack-host` actor. A local
worker must not use that actor concurrently. Configured local profiles leave
the actor available while their launcher is idle, so Runtime can start and
reconcile an exact remote generation without changing profiles. If remote
credential custody is live or unresolved at startup, local launcher creation is
deferred and the credential remains disabled. Explicit local start stays
refused until exact remote drain or revocation cleanup finishes; remote
credential control is refused while the local launcher is preparing or active.
The owner-only
`control_remote_credential(task_id, body)` seam provisions an exact disabled
generation, enables it after Runtime qualification, and reconciles exact
cleanup. Repeating an identical provision never rotates its token; foreign or
unresolved generations must be explicitly reconciled first. On daemon restart,
persisted remote metadata and its token remain retained and disabled. Fresh
Runtime session/epoch and process observations are required before reactivation.

For explicit machine release, pass the exact recorded qualification with
`action: "begin-drain"`, then `action: "finish-drain"` through the same owner
control seam. Begin pins a running parent's attempt, lease, fence and epoch. It
blocks fresh parent claims, retries and checkpoint resumes, while preserving
existing attempt settlement and required child continuations under that exact
parent lineage. Qualification expiry does not strand those pinned
continuations; current session, epoch, binding and incarnation still must
match. Finish computes parent/child terminal state, attempt settlement,
reservations and binding status inside Runtime's serialized transaction. It
returns `pending` while any work is unresolved, otherwise revokes that exact
activation and removes only its credential generation. These responses are
observations, not portable cleanup permits: a machine owner must call Runtime
immediately before its independently verified process/provider cleanup.

After restart, an already-persisted drain can finish only when the same binding
remains authoritative and all work is proven quiescent. A live interrupted
attempt stays unsettled with `provider_state_unknown`; release stays pending.
An old successful finish retry never deletes a replacement generation. The
credential file returned by provision is local to the resident Runtime owner;
a remote SSH preparer must privately deliver the exact token into its owned
restricted target file before acknowledging a grant. Runtime responses and
preparation receipts never carry bearer bytes.

Interrupted credential deletion retains a Runtime cleanup intent containing
only committed credential-file hashes. Owner reconciliation removes surviving
files only if their bytes still match that exact intent; changed or unrelated
bytes remain unresolved. The daemon starts with such an actor disabled so the
owner can reconcile it without replacing its credential generation.
