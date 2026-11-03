"""Process-local timeline editing leases, serialized with commit acceptance."""
from __future__ import annotations

import math
import time

from .errors import ValidationError


class TimelineEditingLeases:
    MAX_TTL_SECONDS = 10

    def __init__(self, mutex, *, clock=time.monotonic):
        self._mutex = mutex
        self._clock = clock
        # Retain sequence fences after release/expiry for this Runtime session.
        self._leases = {}

    def update(self, project, timeline, actor, body, *, release=False):
        required = {"tab_session_id", "sequence"}
        allowed = required if release else required | {"ttl_seconds"}
        if not isinstance(body, dict) or not required <= body.keys() or body.keys() - allowed:
            raise ValidationError("editing requires tab_session_id and sequence")
        tab, sequence = body["tab_session_id"], body["sequence"]
        if not isinstance(tab, str) or not 1 <= len(tab) <= 128:
            raise ValidationError("tab_session_id must contain 1 to 128 characters")
        if type(sequence) is not int or not 1 <= sequence <= 9007199254740991:
            raise ValidationError("sequence must be a positive safe integer")
        ttl = body.get("ttl_seconds", self.MAX_TTL_SECONDS)
        if type(ttl) not in (int, float) or (type(ttl) is float and not math.isfinite(ttl)) or ttl <= 0:
            raise ValidationError("ttl_seconds must be finite and positive")
        ttl = min(ttl, self.MAX_TTL_SECONDS)
        key = (project, timeline, actor, tab)
        with self._mutex:
            now = self._clock()
            previous_sequence, expiry = self._leases.get(key, (0, 0))
            if sequence > previous_sequence:
                previous_sequence, expiry = sequence, 0 if release else now + ttl
                self._leases[key] = previous_sequence, expiry
            remaining = max(0, expiry - now)
            return {"tab_session_id": tab, "sequence": previous_sequence,
                    "active": remaining > 0, "expires_in_seconds": remaining}

    def live(self, project, timeline):
        with self._mutex:
            now = self._clock()
            return any(key[:2] == (project, timeline) and expiry > now
                       for key, (_, expiry) in self._leases.items())

    def owns_live(self, project, timeline, actor, tab_session_id):
        """Possession of a live tab credential, never source attribution.

        The App creates an opaque random tab id. Shared product credentials
        can still deliberately acquire their own lease; this is cooperative
        authority, not authentication of a particular client application.
        """
        if not isinstance(tab_session_id, str) or not tab_session_id:
            return False
        with self._mutex:
            _, expiry = self._leases.get((project, timeline, actor, tab_session_id), (0, 0))
            return expiry > self._clock()
