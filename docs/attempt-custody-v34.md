# Attempt custody in schema v34

Tracked installation remains disabled pending implementation review, protected
acceptance and the separate host stop-proof change. This module supplies Runtime
custody and recovery authority. It does not implement an installation supervisor.

`runtime_protocol.custody.Custody` owns the record and transactions. A task's
immutable admitted `spec.install_binding` contains `realm_id`, `installation_id`,
`executor_incarnation` and the lowercase SHA-256 hex `capability_digest`,
`source_digest` and `definition_digest`. A direct store admission may place that
binding at the top of its spec. Create verifies it against the attempt, live
lease, current epoch, registered source and capability, and captures the exact
reservations. It requires an independent commit boundary and committed readback.
A create replay reads the same retained row, including any later disposition.

The owner enrolls Ed25519 public keys with `enroll_key`; rotation enrolls a new
key ID and revokes the old one atomically. Public key bytes use standard base64.
Key IDs cannot be reused, and supervisor and controller roles cannot share a
signer. Runtime never receives a private key. The registry persists through
backup, restore and restart.

The supervisor adapter must durably deduplicate `dispatch_intent_id`, check permit
expiry, and enforce durable permit revocation. Runtime commits the intent before
calling it and never dispatches a replacement on uncertainty. Query retries use
the exact original intent, at most five retries, full jitter and a shared
30-second deadline. A test double models these protocol obligations only in
acceptance tests; it is not proof of a deployed supervisor's behaviour.

## Recovery

`POST /v1/control/tasks/{task_id}/reconcile` requires an admin-scoped authenticated
actor and `Idempotency-Key`. Its body contains `custody_id`, `mode` (`reconcile`,
`repair`, `lost`), `expected_custody_version`, `old_identity_digest`,
`target_recovery_generation` and `proof`. The contract schema and verifier specify
the exact fields. `recovery_ref` is a public lookup reference and grants no authority.

A proof is `{envelope, signature}`. Sign `signed_bytes(envelope, repair=False)`
for a supervisor stop proof, or `repair=True` for a controller repair/lost proof.
The bytes are the versioned domain prefix followed by UTF-8 JSON with sorted keys,
compact separators, literal Unicode and no non-finite numbers. The signature is
standard base64 Ed25519. The envelope covers the complete old identity, its CAS
version, next recovery generation, evidence inventory, supervisor births,
dispatch intent, permit, nonce and timestamp. Supervisor proofs require complete
child and callback inventories, observed stops and durable revocation/fencing.
Independent controller fencing evidence must already be staged in immutable CAS.
A replacement repair permanently quarantines the old installation. Controller
repair does not claim observed stop. A lost disposition retains reservations and
can exit only through authenticated repair.

Evidence bytes are durable before a CAS transaction pins their digest. Pending
terminal requests retain exact serialized request bytes, including inline output
bytes and idempotency identity. Checkpoint bytes are also pinned as custody
evidence. Released rows preserve terminal publication linkage without inventing
success, manifests, operation IDs or journal history. Final release and its audit,
reservations, attempt settlement, binding and replay receipts commit together.

The realm holds two maximum-sized fencing objects plus two bounded proof
envelopes of recovery budget per new row before dispatch. Ordinary evidence
cannot consume that allowance. Four of the 32 reference slots cover initial
fencing, lost proof, updated fencing and repair proof. Spending a fencing slot
requires owner/admin authority. Exhaustion refuses work. Detail compaction affects only released rows older
than 30 days; nonces, replay receipts, create identities and tombstones remain for
the realm lifetime. Unresolved rows and evidence are never compacted or evicted.

## Migration and recovery sets

The v33 SQL declaration and U33 fingerprint remain frozen. Fresh realms use
`CURRENT_SCHEMA_SQL`; the explicit U33-to-V34 transaction shares the exact v34
DDL and pinned fingerprint. Classification of a detached WAL-aware copy precedes
writes. The `.v34-activation.json` marker binds the activation to a verified full
realm recovery inventory and is separate from the retained round-1b archive.

Finish the old v33 classifier/backfill/provider activation with its owning
coordinator before custody migration. Historical migration functions still produce
that gated U33 intermediate; the new binary cannot serve it as v34. The current
upgrade coordinator refuses inputs older than U33 before journal or owner changes.
For a stopped,
ready U33 realm, use `migrate-canonical --confirm 'MIGRATE CANONICAL <realm-id>'`,
then the explicit `activate-custody` command after verification. Interrupted
intact U33 retries against its recovery set. Committed V34 remains closed until
offline activation. Hybrids refuse without mutation.

The upgrade coordinator verifies the candidate provider before opening requests;
its explicit v34 recovery resumes the candidate and preserves writes. Automatic
rollback of v34 refuses. Generic backup replacement must preserve the entire
custody authority, quarantines, replay state and bound attempts/reservations, or
refuse. A corrupt active authority cannot be guessed empty. A restored snapshot
is reconciled under a new epoch and supplies no stop evidence.

Legacy in-flight attempts without custody are quarantined without synthesizing
custody or stop history. Their attempts and reservations survive restart,
backup/restore and replacement checks. Missing installation attribution closes
realm execution admission, including new work for another installation.
Inventory includes unsettled attempts absent from the task's current projection
and declared installers whose old Runtime projection is already terminal. Old
booleans do not prove stop: terminal flags and previously released reservations
are preserved truthfully, while installation reuse stays blocked. Quarantined
specs and bindings are excluded from terminal-detail retirement.
The authenticated exit is deferred to `A03B-LEGACY-QUARANTINE-REPAIR`.
Migrated-realm relocation is deferred to `A03B-V34-RELOCATION-HANDOFF`:
preflight refuses before mutation and rechecks under launcher exclusion, including
affected secondary realms. A copied or moved root cannot bypass startup binding.

Restart changes an armed row to unresolved without changing its old identity or
permit/dispatch facts. A duplicate create never rearms it.

A stop proof with an uncommitted successful terminal publication currently stages
verified evidence and refuses release. The exact request bytes and linkage remain
pinned. Its typed hold is `custody_pending_success`, with next action
`A03B-PENDING-SUCCESS-RECONCILE`. That separately scoped publication replay and
finalization protocol must finish before tracked installation can be enabled.
Cancellation and authenticated repair cannot replace the retained success with
an invented terminal outcome.
