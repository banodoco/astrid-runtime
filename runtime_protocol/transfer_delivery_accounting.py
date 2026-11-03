"""Conservative in-process accounting for a possible descriptor delivery.

This is not a broker, an authorization decision, a durable ledger, or native
close evidence.  It cannot clear a delivery or authorize a writer.  A caller
must persist intent and validate the native launch before using a transport;
this object only prevents a live holder from repeating an uncertain send.
After a holder dies, external recovery must treat its state as unknown.
"""
from __future__ import annotations

import json
import re
import threading


class AccountingError(RuntimeError):
    pass


_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = frozenset({"offline-backup", "migration", "candidate", "rollback-r1"})
_FIELDS = frozenset({"operation_id", "generation", "request_id", "expected_phase",
                     "binding_digest", "sequence", "role"})


class DeliveryAccounting:
    """Record one possible transfer before any send; resolution is unavailable."""

    def __init__(self, *, operation_id: str, generation: str, binding_digest: str):
        if not (_valid_id(operation_id) and _valid_id(generation)
                and isinstance(binding_digest, str) and _DIGEST.fullmatch(binding_digest)):
            raise AccountingError("binding_changed")
        self._binding = (operation_id, generation, binding_digest)
        self._lock = threading.Lock()
        self._record = None

    def mark_before_send(self, request: dict) -> str:
        """Return 'recorded' once, or 'replay' without authorizing another send.

        This must be called before even attempting sendmsg: any failure after
        that point is delivery-uncertain.  No method accepts caller claims as
        close proof or makes a second writer available.
        """
        if type(request) is not dict:
            raise AccountingError("binding_changed")
        request = request.copy()
        if set(request) != _FIELDS:
            raise AccountingError("binding_changed")
        if (not _valid_id(request['operation_id']) or not _valid_id(request['generation'])
                or not _valid_id(request['request_id'])
                or request['expected_phase'] != 'prepared'
                or not isinstance(request['binding_digest'], str)
                or not _DIGEST.fullmatch(request['binding_digest'])
                or type(request['sequence']) is not int or request['sequence'] != 1
                or not isinstance(request['role'], str) or request['role'] not in _ROLES):
            raise AccountingError("binding_changed")
        # Copy validated primitive fields so later caller mutation cannot change
        # the recorded request or its replay comparison.
        encoded = json.dumps(request, sort_keys=True, separators=(',', ':'))
        with self._lock:
            if self._record is not None:
                previous_id, previous = self._record
                if request['request_id'] == previous_id:
                    if encoded != previous:
                        raise AccountingError("binding_changed")
                    return 'replay'
                raise AccountingError("lease_uncertain")
            if (request['operation_id'], request['generation'], request['binding_digest']) != self._binding:
                raise AccountingError("binding_changed")
            self._record = (request['request_id'], encoded)
            return 'recorded'

    def status(self) -> str:
        with self._lock:
            return 'lease_uncertain' if self._record is not None else 'no_delivery_recorded'


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None
