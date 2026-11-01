"""Durable attempt custody; uncertainty retains authority fences and reservations.

No private signing keys or supervisor implementation live in Runtime. Adapter
calls happen outside transactions. A dispatch ACK is never a stop proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cas import ContentAddressedStore
from .errors import AuthorizationError, ConflictError, LeaseError, NotFoundError, ValidationError
from .util import canonical_json, now

MAX_METADATA = 65536
MAX_REF = 128
MAX_REFS = 32
MAX_ROWS = 1024
MAX_EVIDENCE = 1024 ** 3
MAX_OBJECT = 8 * 1024 ** 2
# Hold independent fencing evidence and a signed envelope for both lost and
# repair before dispatch. Ordinary evidence cannot spend recovery capacity.
PROOF_BUDGET = 2 * MAX_METADATA
RECOVERY_BUDGET = 2 * MAX_OBJECT + PROOF_BUDGET
INVOCATION_SECONDS = 30
AUTOMATIC_RETRIES = 5
PROOF_DOMAIN = b'astrid-runtime/attempt-custody/stop/v1\x00'
REPAIR_DOMAIN = b'astrid-runtime/attempt-custody/repair/v1\x00'
IDENTITY = ('realm_id', 'installation_id', 'custody_id', 'task_id', 'attempt_id',
            'lease_id', 'fence', 'runtime_epoch', 'executor_id', 'executor_incarnation',
            'capability_digest', 'source_digest', 'definition_digest', 'install_binding_digest')


class UnresolvedTimeout(ConflictError):
    code = 'unresolved_timeout'


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def encoded(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValidationError('custody requires canonical finite JSON') from exc


def opaque(value, field='reference'):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_REF:
        raise ValidationError(f'{field} must be a nonempty opaque reference of at most 128 bytes')
    return value


def sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValidationError('custody digests must be lowercase SHA-256 hex')
    return value


def integer(value, field, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValidationError(f'{field} must be an integer >= {minimum}')
    return value


def owner(identity):
    if not isinstance(identity, dict) or not identity.get('actor') or 'admin' not in identity.get('scopes', []):
        raise AuthorizationError('custody recovery and key management require owner/admin authority')


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('missing timezone')
        return parsed
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValidationError('custody timestamp requires an explicit timezone') from exc


@contextmanager
def deadline_lock(lock, started):
    remaining = INVOCATION_SECONDS - (time.monotonic() - started)
    if remaining <= 0 or not lock.acquire(timeout=remaining):
        raise UnresolvedTimeout('reconciliation timed out waiting for Runtime authority; custody retained')
    try:
        yield
    finally:
        lock.release()


def declared_binding(spec):
    return spec.get('install_binding') or (spec.get('spec') or {}).get('install_binding')


def signed_bytes(envelope, *, repair=False):
    return (REPAIR_DOMAIN if repair else PROOF_DOMAIN) + encoded(envelope)


class Custody:
    def __init__(self, store):
        self.store = store

    @property
    def db(self):
        return self.store.conn

    def row(self, custody_id):
        row = self.db.execute('SELECT * FROM attempt_custody WHERE custody_id=?', (custody_id,)).fetchone()
        if row is None:
            raise NotFoundError('custody not found')
        return dict(row)

    def blocking(self, task_id):
        return self.db.execute("SELECT * FROM attempt_custody WHERE task_id=? AND custody_state<>'released'", (str(task_id),)).fetchone()

    def assert_clear(self, task_id=None, installation_id=None):
        if task_id is not None:
            legacy = self.db.execute("SELECT waiting_reason FROM tasks WHERE id=?", (str(task_id),)).fetchone()
            if legacy and legacy['waiting_reason'] == 'legacy_install_custody_unknown':
                raise ConflictError('legacy in-flight work remains quarantined until independent recovery')
        if task_id is not None and self.blocking(task_id):
            raise ConflictError('attempt custody requires independent reconciliation', details={'reason': 'attempt_custody_unresolved'})
        if installation_id is not None:
            installation = self.db.execute('SELECT * FROM custody_installations WHERE installation_id=?', (installation_id,)).fetchone()
            if installation and installation['quarantined']:
                raise ConflictError('installation is quarantined')
            if self.db.execute("SELECT 1 FROM attempt_custody WHERE installation_id=? AND custody_state<>'released'", (installation_id,)).fetchone():
                raise ConflictError('installation has unreleased custody')

    def assert_task_installation_clear(self, task_id):
        self.assert_execution_admitted()
        self.assert_clear(task_id=task_id)
        task = self.db.execute('SELECT * FROM tasks WHERE id=?', (str(task_id),)).fetchone()
        if task:
            binding = declared_binding(self.store._spec(task))
            if binding:
                self.assert_clear(installation_id=binding.get('installation_id'))

    def assert_execution_admitted(self):
        # A legacy observation without attribution cannot exclude any target.
        for task in self.db.execute("SELECT * FROM tasks WHERE waiting_reason='legacy_install_custody_unknown'"):
            binding = declared_binding(self.store._spec(task))
            if not isinstance(binding, dict) or not binding.get('installation_id'):
                raise ConflictError('legacy installation attribution is missing; realm execution admission is closed',
                                    details={'reason': 'legacy_install_custody_unknown',
                                             'next_action': 'A03B-LEGACY-QUARANTINE-REPAIR'})

    def public(self, row):
        pending = json.loads(row['pending_publication_json'] or '{}')
        task = self.db.execute('SELECT status FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
        pending_success = (row['custody_state'] != 'released' and pending.get('kind') == 'completion'
                           and task and task['status'] not in {'completed', 'failed', 'cancelled'})
        return {k: row[k] for k in ('custody_id', 'custody_state', 'custody_version', 'custody_seq',
                'recovery_generation', 'recovery_ref', 'disposition', 'stop_confirmed', 'dispatch_intent_id')} | {
                'stop_confirmed': bool(row['stop_confirmed']),
                'hold_reason': ('custody_pending_success' if pending_success else
                                'attempt_custody_unresolved' if row['custody_state'] != 'released' else None),
                'next_action': ('A03B-PENDING-SUCCESS-RECONCILE' if pending_success else
                                'owner_reconcile_repair_or_lost' if row['custody_state'] != 'released' else None)}

    def integrity_errors(self):
        errors = []
        try:
            realm = self.db.execute('SELECT id FROM realm').fetchone()[0]
            for row in self.db.execute('SELECT * FROM attempt_custody'):
                self._bounded_row(row)
                if row['realm_id'] != realm:
                    raise ConflictError('custody realm differs')
                refs = json.loads(row['evidence_refs_json'])
                if not isinstance(refs, list) or len(refs) > MAX_REFS:
                    raise ValidationError('invalid custody evidence inventory')
                for ref in refs:
                    opaque(ref['ref']); sha(ref['digest'])
                    if not self.db.execute('SELECT 1 FROM custody_evidence_pins WHERE custody_id=? AND digest=?', (row['custody_id'],ref['digest'])).fetchone():
                        raise ConflictError('custody evidence pin missing')
                if row['custody_state'] != 'released':
                    self._validate_binding(row)
                    self._assert_reservations(row)
                elif (row['released_version'] is None or row['released_seq'] is None or not row['disposition_digest']):
                    raise ConflictError('released custody tombstone missing')
                if row['custody_state'] in {'released','lost_fenced'} and not row['permit_revoked']:
                    raise ConflictError('custody disposition without permit revocation')
            for row in self.db.execute('SELECT * FROM custody_evidence'):
                count = self.db.execute('SELECT COUNT(*) FROM custody_evidence_pins WHERE digest=?', (row['digest'],)).fetchone()[0]
                obj = self.db.execute('SELECT size FROM objects WHERE digest=?', (row['digest'],)).fetchone()
                if row['refcount'] != count or obj is None or obj['size'] != row['size']:
                    raise ConflictError('custody evidence refcount or object metadata differs')
        except (ConflictError, ValidationError, ValueError, TypeError, KeyError) as exc:
            errors.append({'table': 'attempt_custody', 'reason': str(exc)})
        return errors

    def _bounded_row(self, row):
        if len(encoded(dict(row))) > MAX_METADATA:
            raise ValidationError('total custody metadata exceeds 64 KiB')

    def _event(self, row, kind, facts=None):
        task = self.db.execute('SELECT run_id FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
        return self.store._append_event(task['run_id'], row['task_id'], kind,
                                       self.public(row) | (facts or {}))

    def enroll_key(self, installation_id, key_id, public_key, *, identity, role='supervisor', revoke_key_id=None):
        owner(identity)
        opaque(installation_id); opaque(key_id)
        if role not in {'supervisor', 'controller'}:
            raise ValidationError('invalid custody signer role')
        try:
            raw = base64.b64decode(public_key, validate=True)
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ValidationError('custody key must be a base64 Ed25519 public key') from exc
        with self.store._mutex, self.store._transaction():
            realm_id = self.db.execute('SELECT id FROM realm').fetchone()[0]
            self.db.execute('INSERT OR IGNORE INTO custody_installations(installation_id, realm_id, created_at) VALUES (?,?,?)', (installation_id, realm_id, now()))
            if self.db.execute('SELECT 1 FROM custody_keys WHERE installation_id=? AND fingerprint=? AND role<>?', (installation_id, hashlib.sha256(raw).hexdigest(), role)).fetchone():
                raise ConflictError('repair controller must use a separate signer from the supervisor')
            prior = self.db.execute('SELECT * FROM custody_keys WHERE installation_id=? AND key_id=?', (installation_id, key_id)).fetchone()
            if prior:
                if prior['public_key'] != public_key or prior['role'] != role or prior['revoked_at']:
                    raise ConflictError('custody key ID cannot be reused')
            else:
                self.db.execute('INSERT INTO custody_keys VALUES (?,?,?,?,?,NULL,?)', (installation_id, key_id, role, public_key, hashlib.sha256(raw).hexdigest(), now()))
            if revoke_key_id is not None:
                if revoke_key_id == key_id:
                    raise ValidationError('rotation requires a different key ID')
                old = self.db.execute('SELECT role FROM custody_keys WHERE installation_id=? AND key_id=?', (installation_id, revoke_key_id)).fetchone()
                if not old or old['role'] != role:
                    raise ConflictError('rotation requires an enrolled key of the same role')
                self.db.execute('UPDATE custody_keys SET revoked_at=COALESCE(revoked_at,?) WHERE installation_id=? AND key_id=?', (now(), installation_id, revoke_key_id))
        return {'installation_id': installation_id, 'key_id': key_id, 'fingerprint': hashlib.sha256(raw).hexdigest(), 'role': role}

    def revoke_key(self, installation_id, key_id, *, identity):
        owner(identity)
        with self.store._mutex, self.store._transaction():
            if not self.db.execute('SELECT 1 FROM custody_keys WHERE installation_id=? AND key_id=?', (installation_id, key_id)).fetchone():
                raise NotFoundError('custody key not found')
            self.db.execute('UPDATE custody_keys SET revoked_at=COALESCE(revoked_at,?) WHERE installation_id=? AND key_id=?', (now(), installation_id, key_id))

    def _receipt(self, row, operation, key, request_digest):
        prior = self.db.execute('SELECT * FROM custody_receipts WHERE custody_id=? AND operation=? AND replay_key=?', (row['custody_id'], operation, str(key))).fetchone()
        if prior:
            if prior['request_digest'] != request_digest:
                raise ConflictError('conflicting custody replay')
            return json.loads(prior['result_json'])

    def _record(self, row, operation, key, request_digest):
        result = self.public(row)
        self.db.execute('INSERT INTO custody_receipts VALUES (?,?,?,?,?,?)', (row['custody_id'], operation, str(key), request_digest, canonical_json(result), now()))
        return result

    def _validate_binding(self, row, *, live=False):
        task = self.db.execute('SELECT * FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
        attempt = self.db.execute('SELECT * FROM attempts WHERE id=?', (row['attempt_id'],)).fetchone()
        binding = json.loads(row['install_binding_json'])
        if (not task or not attempt or attempt['task_id'] != row['task_id']
                or any(attempt[k] != row[k] for k in ('fence', 'runtime_epoch', 'executor_id', 'lease_id'))
                or declared_binding(self.store._spec(task)) != binding
                or digest(binding) != row['install_binding_digest']
                or any(binding.get(k) != row[k] for k in ('realm_id','installation_id','capability_digest','source_digest','definition_digest','executor_incarnation'))):
            raise ConflictError('custody full install binding changed')
        execution = self.store.execution_binding(row['task_id'])
        if execution and execution.get('executor_incarnation') and execution['executor_incarnation'] != row['executor_incarnation']:
            raise ConflictError('Runtime execution incarnation differs from custody')
        if live:
            self.assert_execution_admitted()
            executor = self.db.execute('SELECT * FROM executors WHERE id=?', (row['executor_id'],)).fetchone()
            if not executor or str(executor['source_digest']).removeprefix('sha256:') != row['source_digest']:
                raise ConflictError('live custody source identity changed')
            if (task['status'] != 'running' or task['attempt_id'] != row['attempt_id']
                    or task['lease_token'] != row['lease_id'] or task['lease_fence'] != row['fence']
                    or row['runtime_epoch'] != self.store._current_runtime_epoch()
                    or timestamp(attempt['lease_expires_at']) <= datetime.now(timezone.utc)
                    or attempt['settled']):
                raise LeaseError('custody requires the current live lease and epoch')
        return task

    def create(self, request, *, idempotency_key):
        opaque(idempotency_key, 'idempotency_key')
        if not isinstance(request, dict) or len(encoded(request)) > MAX_METADATA:
            raise ValidationError('custody metadata exceeds 64 KiB')
        required = {'realm_id', 'task_id', 'attempt_id', 'lease_id', 'fence', 'runtime_epoch',
                    'executor_id', 'executor_incarnation', 'capability_digest', 'source_digest',
                    'definition_digest', 'installation_id', 'install_binding', 'supervisor_identity',
                    'launch_permit_expires_at'}
        if set(request) != required:
            raise ValidationError('custody create requires the complete identity and binding')
        for k in required - {'fence','runtime_epoch','install_binding','supervisor_identity','launch_permit_expires_at'}:
            (sha if k.endswith('_digest') else opaque)(request[k])
        integer(request['fence'], 'fence', 1); integer(request['runtime_epoch'], 'runtime_epoch', 1)
        expiry = timestamp(request['launch_permit_expires_at'])
        if expiry <= datetime.now(timezone.utc):
            raise ConflictError('launch permit has expired')
        supervisor = request['supervisor_identity']
        if not isinstance(supervisor, dict) or set(supervisor) != {'boot_id','pid_start_time','launch_token_digest'}:
            raise ValidationError('complete supervisor birth identity required')
        opaque(supervisor['boot_id']); opaque(supervisor['pid_start_time']); sha(supervisor['launch_token_digest'])
        binding = request['install_binding']
        if not isinstance(binding, dict) or any(binding.get(k) != request[k] for k in ('realm_id','installation_id','capability_digest','source_digest','definition_digest','executor_incarnation')):
            raise ConflictError('incomplete install binding')
        request_digest = digest(request)
        if self.db.in_transaction:
            raise ConflictError('custody create requires its own durable commit boundary')
        with self.store._mutex, self.store._transaction():
            prior = self.db.execute('SELECT * FROM custody_creates WHERE realm_id=? AND idempotency_key=?', (request['realm_id'], idempotency_key)).fetchone()
            if prior:
                if prior['request_digest'] != request_digest:
                    raise ConflictError('custody create idempotency conflict')
                return self.public(self.row(prior['custody_id']))
            if self.db.execute('SELECT id FROM realm').fetchone()[0] != request['realm_id']:
                raise ConflictError('custody realm differs')
            self.assert_execution_admitted()
            self.assert_clear(installation_id=request['installation_id'])
            self.assert_clear(task_id=request['task_id'])
            if not self.db.execute("SELECT 1 FROM custody_keys WHERE installation_id=? AND role='supervisor' AND revoked_at IS NULL", (request['installation_id'],)).fetchone():
                raise ConflictError('installation has no enrolled supervisor')
            count = self.db.execute("SELECT COUNT(*) FROM attempt_custody WHERE realm_id=? AND custody_state<>'released'", (request['realm_id'],)).fetchone()[0]
            if count >= MAX_ROWS or self._capacity() + RECOVERY_BUDGET > MAX_EVIDENCE:
                raise ConflictError('custody quota full; new work refused before dispatch')
            row = {k: v for k,v in request.items() if k not in {'install_binding','supervisor_identity'}}
            row.update(custody_id=uuid.uuid4().hex, request_digest=request_digest,
                       install_binding_digest=digest(binding), install_binding_json=canonical_json(binding),
                       supervisor_identity_json=canonical_json(supervisor), metadata_json='{}',
                       recovery_generation=0, custody_state='armed', custody_version=1, custody_seq=1,
                       launch_permit_id=uuid.uuid4().hex, recovery_ref=uuid.uuid4().hex,
                       evidence_budget=RECOVERY_BUDGET, created_at=now(), updated_at=now())
            task = self._validate_binding(row, live=True)
            executor = self.db.execute('SELECT * FROM executors WHERE id=?', (request['executor_id'],)).fetchone()
            capability = self.db.execute('SELECT * FROM capabilities WHERE id=?', (task['capability'],)).fetchone()
            if (not executor or str(executor['source_digest']).removeprefix('sha256:') != request['source_digest'] or not capability
                    or str(capability['definition_digest']).removeprefix('sha256:') != request['definition_digest']
                    or str(task['capability_digest']).removeprefix('sha256:') != request['capability_digest']):
                raise ConflictError('custody capability/source/definition differs from admission')
            reservations = [dict(r) for r in self.db.execute('SELECT * FROM reservations WHERE task_id=? AND released_at IS NULL ORDER BY resource_key', (request['task_id'],))]
            if any(r['lease_token'] != request['lease_id'] or any(r[k] != request[k] for k in ('fence','runtime_epoch','executor_id')) for r in reservations):
                raise ConflictError('custody reservation identity differs')
            row['reservation_refs_json'] = canonical_json(reservations)
            try:
                self.db.execute(f"INSERT INTO attempt_custody({','.join(row)}) VALUES ({','.join('?' for _ in row)})", tuple(row.values()))
            except sqlite3.IntegrityError as exc:
                raise ConflictError('attempt or installation already has custody') from exc
            row = self.row(row['custody_id'])
            self._bounded_row(row)
            result = self.public(row)
            self.db.execute('INSERT INTO custody_creates VALUES (?,?,?,?,?)', (row['realm_id'], idempotency_key, row['custody_id'], request_digest, canonical_json(result)))
            self._event(row, 'task.custody_armed')
            self._boundary('before_create_commit')
        self._boundary('create_committed')
        # The readback happens after the only authorizing commit.
        return self.public(self.row(row['custody_id']))

    def _capacity(self):
        return self.db.execute('SELECT COALESCE(SUM(size),0) FROM custody_evidence WHERE refcount>0').fetchone()[0] + self.db.execute("SELECT COALESCE(SUM(evidence_budget),0) FROM attempt_custody WHERE custody_state<>'released'").fetchone()[0]

    def hold(self, task_id, reason, *, pending=None):
        """Caller owns the transaction; never erase lineage or pending bytes."""
        row = self.blocking(task_id)
        if not row:
            return False
        if pending is not None and row['pending_publication_json'] is not None:
            previous = json.loads(row['pending_publication_json'])
            if previous != pending:
                if previous.get('kind') == pending.get('kind'):
                    raise ConflictError('conflicting pending publication identity or bytes')
                pending = previous
        if pending is not None and len(encoded(pending)) > MAX_METADATA:
            raise ValidationError('pending custody metadata exceeds 64 KiB; stage evidence first')
        if row['custody_state'] not in {'unresolved', 'lost_fenced'} or pending is not None:
            self.db.execute("UPDATE attempt_custody SET custody_state=CASE WHEN custody_state='lost_fenced' THEN custody_state ELSE 'unresolved' END, custody_version=custody_version+1, custody_seq=custody_seq+1, pending_publication_json=COALESCE(?,pending_publication_json), updated_at=? WHERE custody_id=?", (canonical_json(pending) if pending is not None else None, now(), row['custody_id']))
            self._bounded_row(self.row(row['custody_id']))
            self._event(self.row(row['custody_id']), 'task.custody_unresolved', {'reason': reason, 'stop_confirmed': False})
        self.db.execute("UPDATE tasks SET waiting_reason='attempt_custody_unresolved', lease_expires_at=NULL, updated_at=? WHERE id=?", (now(), task_id))
        self.store.release_execution_attempt(task_id, status='stale')
        return True

    def update(self, custody_id, *, expected_version, custody_seq, state, binding_digest, metadata=None, dispatch_intent_id=None, pending_publication=None):
        integer(expected_version, 'expected_version', 1); integer(custody_seq, 'custody_seq', 2)
        sha(binding_digest)
        request = dict(expected_version=expected_version, custody_seq=custody_seq, state=state,
                       binding_digest=binding_digest, metadata=metadata, dispatch_intent_id=dispatch_intent_id,
                       pending_publication=pending_publication)
        if len(encoded(request)) > MAX_METADATA:
            raise ValidationError('custody metadata exceeds 64 KiB')
        rd = digest(request)
        with self.store._mutex, self.store._transaction():
            row = self.row(custody_id)
            replay = self._receipt(row, 'update', custody_seq, rd)
            if replay is not None:
                return replay
            if row['custody_state'] == 'released' or row['custody_version'] != expected_version or custody_seq <= row['custody_seq']:
                raise ConflictError('stale custody CAS or sequence')
            if row['install_binding_digest'] != binding_digest:
                raise ConflictError('custody install binding differs')
            self._validate_binding(row, live=True)
            allowed = {'armed': {'dispatching','unresolved'}, 'dispatching': {'active','unresolved'},
                       'active': {'active','unresolved'}, 'unresolved': {'unresolved'}}
            if state not in allowed.get(row['custody_state'], set()):
                raise ConflictError('custody transition requires reconciliation')
            if state in {'dispatching','active'}:
                if row['permit_revoked'] or timestamp(row['launch_permit_expires_at']) <= datetime.now(timezone.utc):
                    raise ConflictError('launch permit expired or revoked')
                opaque(dispatch_intent_id, 'dispatch_intent_id')
                if row['dispatch_intent_id'] not in {None, dispatch_intent_id}:
                    raise ConflictError('dispatch ACK differs from exact intent')
            if len(encoded(json.loads(row['install_binding_json']))) + len(encoded(request)) > MAX_METADATA:
                raise ValidationError('total custody metadata exceeds 64 KiB')
            self.db.execute('UPDATE attempt_custody SET custody_state=?, custody_version=custody_version+1, custody_seq=?, metadata_json=?, pending_publication_json=COALESCE(?,pending_publication_json), dispatch_intent_id=COALESCE(dispatch_intent_id,?), updated_at=? WHERE custody_id=? AND custody_version=?', (state, custody_seq, canonical_json(metadata or {}), canonical_json(pending_publication) if pending_publication is not None else None, dispatch_intent_id, now(), custody_id, expected_version))
            row = self.row(custody_id)
            self._bounded_row(row)
            self._event(row, 'task.custody_updated')
            return self._record(row, 'update', custody_seq, rd)

    def stage_evidence(self, custody_id, data, *, expected_version, custody_seq, ref, recovery=False, identity=None):
        opaque(ref); integer(expected_version, 'expected_version', 1); integer(custody_seq, 'custody_seq', 2)
        if recovery:
            owner(identity)
        if not isinstance(data, bytes) or len(data) > MAX_OBJECT:
            raise ValidationError('custody evidence object exceeds 8 MiB')
        object_digest = hashlib.sha256(data).hexdigest()
        rd = digest({'digest': object_digest, 'ref': ref, 'expected_version': expected_version, 'custody_seq': custody_seq})
        with self.store._mutex:
            row = self.row(custody_id)
            replay = self._receipt(row, 'evidence', custody_seq, rd)
            if replay is not None:
                return replay
            if row['custody_state'] == 'released' or (row['custody_state'] == 'lost_fenced' and not recovery) or row['custody_version'] != expected_version or custody_seq <= row['custody_seq']:
                raise ConflictError('stale evidence CAS')
            self._validate_binding(row, live=not recovery)
            refs = json.loads(row['evidence_refs_json'])
            lost = row['disposition'] == 'lost_fenced'
            # Four slots: initial fence, lost proof, replacement fence, repair
            # proof. An owner can spend each reserved fencing slot in order.
            limit = MAX_REFS - (1 if lost else 3) if recovery else MAX_REFS - 4
            if len(refs) >= max(1, limit) or any(e['ref'] == ref for e in refs):
                raise ConflictError('custody evidence reference bound exhausted or reused')
            existing = self.db.execute('SELECT size FROM custody_evidence WHERE digest=?', (object_digest,)).fetchone()
            needed = 0 if existing else len(data)
            floor = MAX_METADATA if lost else MAX_OBJECT + PROOF_BUDGET
            budget = (max(min(floor, row['evidence_budget']), row['evidence_budget'] - needed)
                      if recovery else row['evidence_budget'])
            if self._capacity() + needed - (row['evidence_budget'] - budget) > MAX_EVIDENCE:
                raise ConflictError('custody evidence quota full')
            # Durable immutable bytes precede any database reference.
            if self.db.in_transaction:
                raise ConflictError('evidence staging requires its own commit boundary')
            cas = ContentAddressedStore(self.store.cas_root)
            with cas.stage((data,), self.store.staging_root, max_bytes=MAX_OBJECT) as staged:
                cas.publish(staged, existing_identity=cas.existing_identity(staged.digest, staged.size))
            with self.store._transaction():
                row = self.row(custody_id)
                if row['custody_version'] != expected_version:
                    raise ConflictError('custody changed while staging evidence')
                self.db.execute('INSERT OR IGNORE INTO objects(digest,size,media_type,created_at) VALUES (?,?,?,?)', (object_digest, len(data), 'application/octet-stream', now()))
                self.db.execute('INSERT OR IGNORE INTO custody_evidence VALUES (?,?,?,0)', (object_digest, row['realm_id'], len(data)))
                added = self.db.execute('INSERT OR IGNORE INTO custody_evidence_pins VALUES (?,?)', (custody_id, object_digest)).rowcount
                if added:
                    self.db.execute('UPDATE custody_evidence SET refcount=refcount+1 WHERE digest=?', (object_digest,))
                refs.append({'ref': ref, 'digest': object_digest})
                self.db.execute('UPDATE attempt_custody SET custody_version=custody_version+1, custody_seq=?, evidence_seq=evidence_seq+1, evidence_refs_json=?, evidence_budget=?, updated_at=? WHERE custody_id=?', (custody_seq, canonical_json(refs), budget, now(), custody_id))
                row = self.row(custody_id)
                self._bounded_row(row)
                self._event(row, 'task.custody_evidence_staged', {'digest': object_digest})
                return self._record(row, 'evidence', custody_seq, rd)

    def _verify_envelope(self, row, proof, *, mode, expected_version, target_generation):
        repair = mode in {'repair', 'lost'}
        if not isinstance(proof, dict) or set(proof) != {'envelope','signature'} or len(encoded(proof)) > MAX_METADATA:
            raise ValidationError('bounded signed custody envelope required')
        e = proof['envelope']
        if not isinstance(e, dict):
            raise ValidationError('custody envelope must be an object')
        version_field = 'repair_version' if repair else 'proof_version'
        common = set(IDENTITY) | {version_field, 'key_id','dispatch_intent_id','launch_permit_id',
                'expected_custody_version','target_recovery_generation','nonce','evidence_digests',
                'supervisor_identity','launch_permit_revocation','callback_fence','timestamp','mode'}
        extra = {'fencing_evidence'} if repair else {'child_births','observed_stops','pending_callbacks','callbacks_revoked','complete_child_inventory','complete_callback_inventory'}
        if set(e) != common | extra or type(e[version_field]) is not int or e[version_field] != 1 or e['mode'] != mode:
            raise ValidationError('unsupported or incomplete custody proof envelope')
        if any(e[k] != row[k] or type(e[k]) is not type(row[k]) for k in IDENTITY):
            raise ConflictError('proof old realm/installation/attempt identity differs')
        integer(e['expected_custody_version'], 'proof expected version', 1)
        integer(e['target_recovery_generation'], 'proof target generation', 1)
        if (e['dispatch_intent_id'] != row['dispatch_intent_id'] or e['launch_permit_id'] != row['launch_permit_id']
                or e['expected_custody_version'] != expected_version
                or e['target_recovery_generation'] != target_generation
                or e['supervisor_identity'] != json.loads(row['supervisor_identity_json'])):
            raise ConflictError('proof dispatch, supervisor, version or generation differs')
        opaque(e['key_id']); opaque(e['nonce']); timestamp(e['timestamp'])
        refs = [r for r in json.loads(row['evidence_refs_json']) if r['digest'] != digest(proof)]
        if not isinstance(e['evidence_digests'], list) or e['evidence_digests'] != sorted({r['digest'] for r in refs}):
            raise ConflictError('proof evidence inventory differs')
        for value in e['evidence_digests']:
            sha(value)
        revocation = e['launch_permit_revocation']
        if (not isinstance(revocation, dict) or set(revocation) != {'permit_id','revoked','durable_fence_digest'}
                or revocation['permit_id'] != row['launch_permit_id'] or revocation['revoked'] is not True):
            raise ConflictError('proof requires durable launch permit revocation')
        sha(revocation['durable_fence_digest'])
        channel = e['callback_fence']
        if not isinstance(channel, dict) or set(channel) != {'fenced','durable_fence_digest'} or channel['fenced'] is not True:
            raise ConflictError('proof requires durable callback fencing')
        sha(channel['durable_fence_digest'])
        if repair:
            evidence = e['fencing_evidence']
            if not isinstance(evidence, dict) or evidence.get('kind') not in {'external_absence','isolated_replacement'}:
                raise ConflictError('repair requires independent fencing evidence')
            sha(evidence.get('evidence_digest'))
            if evidence['evidence_digest'] not in e['evidence_digests']:
                raise ConflictError('independent repair fencing evidence must be durably staged')
            if evidence['kind'] == 'isolated_replacement':
                if set(evidence) != {'kind','evidence_digest','replacement_installation_id'}:
                    raise ValidationError('incomplete replacement fencing evidence')
                opaque(evidence['replacement_installation_id'])
                if evidence['replacement_installation_id'] == row['installation_id']:
                    raise ConflictError('replacement must be an isolated different installation')
            elif set(evidence) != {'kind','evidence_digest'}:
                raise ValidationError('invalid external absence evidence')
        else:
            if e['complete_child_inventory'] is not True or e['complete_callback_inventory'] is not True:
                raise ConflictError('proof must cover every child and pending callback')
            for field in ('child_births','observed_stops','pending_callbacks','callbacks_revoked'):
                if not isinstance(e[field], list):
                    raise ValidationError('proof process/callback inventories must be arrays')
                if len({digest(v) for v in e[field]}) != len(e[field]):
                    raise ValidationError('proof inventory contains duplicates')
            births = e['child_births']
            if any(not isinstance(b, dict) or set(b) != {'boot_id','pid','pid_start_time'}
                   or type(b['pid']) is not int or b['pid'] <= 0
                   or not isinstance(b['boot_id'], str) or not b['boot_id']
                   or not isinstance(b['pid_start_time'], str) or not b['pid_start_time'] for b in births):
                raise ValidationError('proof child births require exact process identities')
            for callback in e['pending_callbacks']:
                opaque(callback, 'pending_callback')
            if e['observed_stops'] != births or e['callbacks_revoked'] != e['pending_callbacks']:
                raise ConflictError('proof does not establish stop and revocation of the full inventory')
        key = self.db.execute('SELECT * FROM custody_keys WHERE installation_id=? AND key_id=?', (row['installation_id'], e['key_id'])).fetchone()
        if not key or key['revoked_at'] or key['role'] != ('controller' if repair else 'supervisor'):
            raise AuthorizationError('custody signer is absent, revoked, or has the wrong role')
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key['public_key'], validate=True)).verify(
                base64.b64decode(proof['signature'], validate=True), signed_bytes(e, repair=repair))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise AuthorizationError('invalid custody Ed25519 signature') from exc
        return e, dict(key)

    def reconcile(self, task_id, body, *, identity, idempotency_key):
        owner(identity); opaque(idempotency_key, 'idempotency_key')
        started = time.monotonic()
        if not isinstance(body, dict) or set(body) != {'custody_id','mode','expected_custody_version','old_identity_digest','target_recovery_generation','proof'}:
            raise ValidationError('reconcile requires mode, version, old identity, target generation and proof')
        if len(encoded(body)) > MAX_METADATA or body['mode'] not in {'reconcile','repair','lost'}:
            raise ValidationError('invalid reconcile mode or metadata bound')
        expected = integer(body['expected_custody_version'], 'expected_custody_version', 1)
        target = integer(body['target_recovery_generation'], 'target_recovery_generation', 1)
        sha(body['old_identity_digest']); opaque(body['custody_id'])
        rd = digest(body)
        with deadline_lock(self.store._mutex, started):
            if self.db.in_transaction:
                raise ConflictError('reconcile requires its own durable transaction boundaries')
            row = self.row(body['custody_id'])
            if row['task_id'] != str(task_id):
                raise ConflictError('reconcile task differs')
            replay = self._receipt(row, 'reconcile', idempotency_key, rd)
            if replay is not None:
                return replay
            stage = self._receipt(row, 'reconcile_stage', idempotency_key, rd)
            if row['disposition'] == 'lost_fenced' and body['mode'] != 'repair':
                raise ConflictError('lost custody exits only through authenticated repair')
            if row['custody_state'] == 'released' or target != row['recovery_generation'] + 1:
                raise ConflictError('stale reconciliation generation')
            if stage is None and row['custody_version'] != expected:
                raise ConflictError('stale reconciliation custody version')
            if digest({k: row[k] for k in IDENTITY}) != body['old_identity_digest']:
                raise ConflictError('old custody identity digest differs')
            self._validate_binding(row)
            envelope, key = self._verify_envelope(row, body['proof'], mode=body['mode'], expected_version=expected, target_generation=target)
            proof_bytes = encoded(body['proof'])
            proof_digest = hashlib.sha256(proof_bytes).hexdigest()
            # All potentially expensive object IO precedes the release transaction.
            cas = ContentAddressedStore(self.store.cas_root)
            for ref in json.loads(row['evidence_refs_json']):
                cas.verify(ref['digest'])
            if time.monotonic() - started >= INVOCATION_SECONDS:
                raise UnresolvedTimeout('reconciliation timed out; custody remains unresolved')
            if stage is None:
                if len(json.loads(row['evidence_refs_json'])) >= MAX_REFS:
                    raise ConflictError('proof needs a retained evidence reference')
                needed = 0 if self.db.execute('SELECT 1 FROM custody_evidence WHERE digest=?', (proof_digest,)).fetchone() else len(proof_bytes)
                remaining_budget = max(0, row['evidence_budget'] - needed)
                if self._capacity() + needed - (row['evidence_budget'] - remaining_budget) > MAX_EVIDENCE:
                    raise ConflictError('recovery evidence budget exhausted')
                with cas.stage((proof_bytes,), self.store.staging_root, max_bytes=MAX_OBJECT) as staged:
                    cas.publish(staged, existing_identity=cas.existing_identity(staged.digest, staged.size))
                with self.store._transaction():
                    current = self.row(row['custody_id'])
                    if current['custody_version'] != expected or current['recovery_generation'] + 1 != target:
                        raise ConflictError('custody changed during proof verification')
                    # Recheck enrolled authority after all external work/IO.
                    self._key_unchanged(key)
                    nonce = self.db.execute('SELECT request_digest FROM custody_nonces WHERE installation_id=? AND nonce=?', (row['installation_id'], envelope['nonce'])).fetchone()
                    if nonce and nonce[0] != rd:
                        raise ConflictError('custody proof nonce already consumed')
                    self.db.execute('INSERT OR IGNORE INTO custody_nonces VALUES (?,?,?)', (row['installation_id'], envelope['nonce'], rd))
                    self.db.execute('INSERT OR IGNORE INTO objects(digest,size,media_type,created_at) VALUES (?,?,?,?)', (proof_digest, len(proof_bytes), 'application/json', now()))
                    self.db.execute('INSERT OR IGNORE INTO custody_evidence VALUES (?,?,?,0)', (proof_digest, row['realm_id'], len(proof_bytes)))
                    if self.db.execute('INSERT OR IGNORE INTO custody_evidence_pins VALUES (?,?)', (row['custody_id'], proof_digest)).rowcount:
                        self.db.execute('UPDATE custody_evidence SET refcount=refcount+1 WHERE digest=?', (proof_digest,))
                    refs = json.loads(row['evidence_refs_json']) + [{'ref': 'proof:' + proof_digest, 'digest': proof_digest}]
                    self.db.execute("UPDATE attempt_custody SET custody_state='proof_staged', custody_version=custody_version+1, custody_seq=custody_seq+1, proof_digest=?, evidence_refs_json=?, evidence_seq=evidence_seq+1, evidence_budget=?, updated_at=? WHERE custody_id=?", (proof_digest, canonical_json(refs), remaining_budget, now(), row['custody_id']))
                    self._record(self.row(row['custody_id']), 'reconcile_stage', idempotency_key, rd)
                self._boundary('proof_staged')
            row = self.row(row['custody_id'])
            if row['proof_digest'] != proof_digest:
                raise ConflictError('a different proof superseded this recovery')
            if time.monotonic() - started >= INVOCATION_SECONDS:
                raise UnresolvedTimeout('reconciliation timed out; staged proof releases nothing')
            with self.store._transaction():
                self._key_unchanged(key)
                current = self.row(row['custody_id'])
                if current['custody_version'] != row['custody_version'] or current['recovery_generation'] + 1 != target:
                    raise ConflictError('concurrent custody recovery')
                self._validate_binding(current)
                self._assert_reservations(current)
                mode = body['mode']
                disposition = 'released_observed_stop' if mode == 'reconcile' else 'lost_fenced'
                state = 'lost_fenced' if mode == 'lost' else 'released'
                task = self.db.execute('SELECT * FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
                pending = json.loads(current['pending_publication_json'] or '{}')
                if (state == 'released' and pending.get('kind') == 'completion'
                        and task['status'] not in {'completed','failed','cancelled'}):
                    # A stop proof cannot manufacture or discard a successful
                    # pending publication or its journal linkage. Keep custody
                    # until that exact publication has an authorized outcome.
                    raise ConflictError('pending publication needs independent reconciliation before custody release',
                                        details={'reason': 'custody_pending_success',
                                                 'next_action': 'A03B-PENDING-SUCCESS-RECONCILE'})
                stop = mode == 'reconcile'
                if mode in {'lost','repair'}:
                    evidence = envelope['fencing_evidence']
                    replacement = evidence.get('replacement_installation_id')
                    permanent = evidence['kind'] == 'isolated_replacement'
                    old = self.db.execute('SELECT permanent FROM custody_installations WHERE installation_id=?', (row['installation_id'],)).fetchone()
                    self.db.execute('UPDATE custody_installations SET quarantined=?, permanent=MAX(permanent,?), replacement_id=COALESCE(?,replacement_id) WHERE installation_id=?', (int(mode == 'lost' or permanent or bool(old['permanent'])), int(permanent), replacement, row['installation_id']))
                dd = digest({'request_digest': rd, 'disposition': disposition, 'stop_confirmed': stop, 'generation': target})
                released = now() if state == 'released' else None
                self.db.execute('UPDATE attempt_custody SET custody_state=?, custody_version=custody_version+1, custody_seq=custody_seq+1, recovery_generation=?, disposition=?, stop_confirmed=?, permit_revoked=1, disposition_digest=?, released_version=CASE WHEN ? IS NOT NULL THEN custody_version+1 ELSE NULL END, released_seq=CASE WHEN ? IS NOT NULL THEN custody_seq+1 ELSE NULL END, released_at=?, evidence_budget=CASE WHEN ? IS NOT NULL THEN 0 ELSE evidence_budget END, updated_at=? WHERE custody_id=?', (state, target, disposition, int(stop), dd, released, released, released, released, now(), row['custody_id']))
                result_row = self.row(row['custody_id'])
                if state == 'released':
                    # Only this verified transaction may cross the reservation gate.
                    self.db.execute('UPDATE reservations SET released_at=? WHERE task_id=? AND lease_token=? AND released_at IS NULL', (now(), row['task_id'], row['lease_id']))
                    self.db.execute('UPDATE attempts SET settled=1 WHERE id=?', (row['attempt_id'],))
                    task = self.db.execute('SELECT * FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
                    # Preserve any real terminal publication. Stop evidence alone
                    # cannot invent an install success or a journal link.
                    terminal = task['status'] if task['status'] in {'completed','failed','cancelled'} else 'cancelled'
                    self.db.execute('UPDATE tasks SET status=?, waiting_reason=NULL, lease_expires_at=NULL, updated_at=? WHERE id=?', (terminal, now(), row['task_id']))
                    self.db.execute('UPDATE runs SET status=?, updated_at=? WHERE id=?', (terminal, now(), task['run_id']))
                    self.store.release_execution_attempt(row['task_id'])
                self._event(result_row, 'task.custody_' + state, {'proof_digest': proof_digest, 'reservation_disposition': disposition if state == 'released' else 'retained'})
                result = self._record(result_row, 'reconcile', idempotency_key, rd)
                self._record(result_row, 'generation', target, rd)
                if time.monotonic() - started >= INVOCATION_SECONDS:
                    raise UnresolvedTimeout('reconciliation timed out before release commit; custody retained')
                self._boundary('before_release_commit')
            self._boundary('release_committed')
            return result

    def _key_unchanged(self, key):
        current = self.db.execute('SELECT * FROM custody_keys WHERE installation_id=? AND key_id=?', (key['installation_id'], key['key_id'])).fetchone()
        if not current or dict(current) != key or current['revoked_at']:
            raise AuthorizationError('custody signer changed during verification')

    def _assert_reservations(self, row):
        saved = json.loads(row['reservation_refs_json'])
        current = [dict(r) for r in self.db.execute('SELECT * FROM reservations WHERE task_id=? AND released_at IS NULL ORDER BY resource_key', (row['task_id'],))]
        # Lease extension does not change the authority bound to custody.
        ignored = {'lease_expires_at'}
        if [{k:v for k,v in r.items() if k not in ignored} for r in saved] != [{k:v for k,v in r.items() if k not in ignored} for r in current]:
            raise ConflictError('bound custody reservations changed')

    def compact(self, *, before=None):
        cutoff = timestamp(before) if before else datetime.now(timezone.utc) - timedelta(days=30)
        cutoff = min(cutoff, datetime.now(timezone.utc) - timedelta(days=30))
        with self.store._mutex, self.store._transaction():
            rows = list(self.db.execute("SELECT * FROM attempt_custody WHERE custody_state='released' AND released_at<? AND (metadata_json<>'{}' OR pending_publication_json IS NOT NULL OR evidence_refs_json<>'[]')", (cutoff.isoformat(),)))
            for row in rows:
                for pin in self.db.execute('SELECT digest FROM custody_evidence_pins WHERE custody_id=?', (row['custody_id'],)).fetchall():
                    self.db.execute('UPDATE custody_evidence SET refcount=refcount-1 WHERE digest=?', (pin['digest'],))
                self.db.execute('DELETE FROM custody_evidence_pins WHERE custody_id=?', (row['custody_id'],))
                self.db.execute("UPDATE attempt_custody SET metadata_json='{}', pending_publication_json=NULL, evidence_refs_json='[]', custody_version=custody_version+1, custody_seq=custody_seq+1 WHERE custody_id=?", (row['custody_id'],))
                current = self.row(row["custody_id"])
                self._record(current, "compact", current["custody_seq"], digest({"released_version": row["released_version"]}))
            # Replay receipts, nonces, create identities and tombstones live for
            # the realm lifetime. Unresolved detail is never compacted.
            return len(rows)

    def _boundary(self, name):
        """Fault injection seam; production performs no action here."""

    def dispatch(self, custody_id, supervisor):
        """Adapter must durably deduplicate intent and enforce permit fences.

        This is a protocol client, not evidence that an external supervisor
        implements the required durable deduplication.
        """
        with self.store._mutex:
            if self.db.in_transaction:
                raise ConflictError('dispatch requires committed readback')
            row = self.row(custody_id)
            if row['custody_state'] != 'armed':
                raise ConflictError('dispatch uncertainty requires query of the same intent')
            self._boundary('before_dispatch_intent')
            intent = uuid.uuid4().hex
            self.update(custody_id, expected_version=row['custody_version'], custody_seq=row['custody_seq']+1,
                        state='dispatching', binding_digest=row['install_binding_digest'], dispatch_intent_id=intent)
            row = self.row(custody_id)
        self._boundary('dispatch_intent_committed')
        # A bounded adapter call cannot commit custody from its worker thread.
        reply = bounded_call(lambda: supervisor.dispatch(self.dispatch_command(row)), INVOCATION_SECONDS)
        self._boundary('dispatch_returned')
        if not isinstance(reply, dict) or reply.get('dispatch_intent_id') != intent:
            raise ConflictError('missing exact dispatch ACK; query the retained intent')
        return self.update(custody_id, expected_version=row['custody_version'], custody_seq=row['custody_seq']+1,
                           state='active', binding_digest=row['install_binding_digest'], dispatch_intent_id=intent)

    def dispatch_command(self, row):
        return {k: row[k] for k in IDENTITY} | {k: row[k] for k in ('dispatch_intent_id','launch_permit_id','launch_permit_expires_at','recovery_generation')}

    def query_dispatch(self, custody_id, supervisor, *, sleep=time.sleep, uniform=random.uniform):
        started = time.monotonic()
        row = self.row(custody_id)
        if not row['dispatch_intent_id']:
            raise ConflictError('no durable dispatch intent; non-dispatch still requires proof')
        for attempt in range(AUTOMATIC_RETRIES + 1):
            remaining = INVOCATION_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                raise UnresolvedTimeout('dispatch query timed out; custody retained')
            try:
                reply = bounded_call(lambda: supervisor.query(row['dispatch_intent_id']), remaining)
                if not isinstance(reply, dict) or reply.get('dispatch_intent_id') != row['dispatch_intent_id']:
                    raise OSError('dispatch query remains uncertain')
                return reply
            except (OSError, UnresolvedTimeout):
                if attempt == AUTOMATIC_RETRIES:
                    raise UnresolvedTimeout('dispatch query retry bound exhausted; custody retained')
                delay = uniform(1, min(30, 2 ** (attempt + 1)))
                if time.monotonic() - started + delay >= INVOCATION_SECONDS:
                    raise UnresolvedTimeout('dispatch query timeout; custody retained')
                sleep(delay)


def bounded_call(call, seconds):
    """Return on timeout even when a supervisor transport never responds."""
    import queue
    import threading
    outcome = queue.Queue(maxsize=1)
    def invoke():
        try:
            outcome.put((True, call()))
        except BaseException as exc:
            outcome.put((False, exc))
    threading.Thread(target=invoke, daemon=True).start()
    try:
        success, result = outcome.get(timeout=max(0, seconds))
    except queue.Empty as exc:
        raise UnresolvedTimeout('supervisor invocation timed out; never stop proof') from exc
    if success:
        return result
    raise result
