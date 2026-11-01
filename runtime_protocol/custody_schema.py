"""Schema v34 additions. The v33 declaration and fingerprint remain frozen."""

CUSTODY_SCHEMA_SQL = r"""
CREATE TABLE custody_installations (
    installation_id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm(id),
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0,1)),
    permanent INTEGER NOT NULL DEFAULT 0 CHECK (permanent IN (0,1)),
    replacement_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE custody_keys (
    installation_id TEXT NOT NULL REFERENCES custody_installations(installation_id),
    key_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('supervisor','controller')),
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(installation_id, key_id)
);
CREATE TABLE attempt_custody (
    custody_id TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm(id),
    task_id TEXT NOT NULL REFERENCES tasks(id),
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id),
    lease_id TEXT NOT NULL, fence INTEGER NOT NULL, runtime_epoch INTEGER NOT NULL,
    executor_id TEXT NOT NULL, executor_incarnation TEXT NOT NULL,
    capability_digest TEXT NOT NULL CHECK (length(capability_digest)=64 AND capability_digest NOT GLOB '*[^0-9a-f]*'),
    source_digest TEXT NOT NULL CHECK (length(source_digest)=64 AND source_digest NOT GLOB '*[^0-9a-f]*'),
    definition_digest TEXT NOT NULL CHECK (length(definition_digest)=64 AND definition_digest NOT GLOB '*[^0-9a-f]*'),
    install_binding_digest TEXT NOT NULL CHECK (length(install_binding_digest)=64 AND install_binding_digest NOT GLOB '*[^0-9a-f]*'),
    request_digest TEXT NOT NULL CHECK (length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
    installation_id TEXT NOT NULL REFERENCES custody_installations(installation_id),
    recovery_generation INTEGER NOT NULL DEFAULT 0 CHECK (recovery_generation>=0),
    custody_state TEXT NOT NULL CHECK (custody_state IN ('armed','dispatching','active','unresolved','proof_staged','lost_fenced','released')),
    custody_version INTEGER NOT NULL CHECK (custody_version>=1),
    custody_seq INTEGER NOT NULL CHECK (custody_seq>=1),
    dispatch_intent_id TEXT UNIQUE,
    launch_permit_id TEXT NOT NULL UNIQUE,
    launch_permit_expires_at TEXT NOT NULL,
    permit_revoked INTEGER NOT NULL DEFAULT 0 CHECK (permit_revoked IN (0,1)),
    supervisor_identity_json TEXT NOT NULL CHECK (json_valid(supervisor_identity_json)),
    install_binding_json TEXT NOT NULL CHECK (json_valid(install_binding_json)),
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json) AND length(CAST(metadata_json AS BLOB))<=65536),
    pending_publication_json TEXT CHECK (pending_publication_json IS NULL OR json_valid(pending_publication_json)),
    evidence_seq INTEGER NOT NULL DEFAULT 0,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_refs_json) AND json_array_length(evidence_refs_json)<=32),
    proof_digest TEXT,
    disposition TEXT CHECK (disposition IN ('released_observed_stop','released_completed','lost_fenced')),
    stop_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (stop_confirmed IN (0,1)),
    reservation_refs_json TEXT NOT NULL CHECK (json_valid(reservation_refs_json)),
    recovery_ref TEXT NOT NULL UNIQUE,
    evidence_budget INTEGER NOT NULL CHECK (evidence_budget>=0),
    released_version INTEGER, released_seq INTEGER, disposition_digest TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, released_at TEXT
);
CREATE UNIQUE INDEX idx_custody_installation_live ON attempt_custody(installation_id) WHERE custody_state<>'released';
CREATE INDEX idx_custody_task ON attempt_custody(task_id, custody_state);
CREATE TABLE custody_receipts (
    custody_id TEXT NOT NULL REFERENCES attempt_custody(custody_id),
    operation TEXT NOT NULL, replay_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL CHECK (json_valid(result_json)),
    created_at TEXT NOT NULL,
    PRIMARY KEY(custody_id, operation, replay_key)
);
CREATE TABLE custody_creates (
    realm_id TEXT NOT NULL REFERENCES realm(id), idempotency_key TEXT NOT NULL,
    custody_id TEXT NOT NULL REFERENCES attempt_custody(custody_id),
    request_digest TEXT NOT NULL, result_json TEXT NOT NULL CHECK (json_valid(result_json)),
    PRIMARY KEY(realm_id, idempotency_key)
);
CREATE TABLE custody_evidence (
    digest TEXT PRIMARY KEY REFERENCES objects(digest),
    realm_id TEXT NOT NULL REFERENCES realm(id), size INTEGER NOT NULL CHECK (size>=0 AND size<=8388608),
    refcount INTEGER NOT NULL CHECK (refcount>=0)
);
CREATE TABLE custody_evidence_pins (
    custody_id TEXT NOT NULL REFERENCES attempt_custody(custody_id),
    digest TEXT NOT NULL REFERENCES custody_evidence(digest),
    PRIMARY KEY(custody_id, digest)
);
CREATE TABLE custody_nonces (
    installation_id TEXT NOT NULL REFERENCES custody_installations(installation_id),
    nonce TEXT NOT NULL, request_digest TEXT NOT NULL,
    PRIMARY KEY(installation_id, nonce)
);
"""

CUSTODY_TABLES = frozenset({
    'custody_installations', 'custody_keys', 'attempt_custody', 'custody_receipts',
    'custody_creates', 'custody_evidence', 'custody_evidence_pins', 'custody_nonces',
})
