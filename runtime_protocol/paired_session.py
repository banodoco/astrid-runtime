"""Volatile paired-session bindings at the authenticated local request boundary.

Only CredentialStore's host-provisioned connector metadata can assert a pair.
No handshake ID, request-body actor/project, or ordinary product scope is used.
There is no new route, persistent session store, or credential handoff here.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import threading
import time

from .errors import ForbiddenError, NotFoundError

PAIRED_SESSION_HEADER = "X-Reigh-Paired-Session"
_FIELDS = {"pair_id", "connector_id", "generation", "realm_id", "expires_at"}


def deny(code):
    raise ForbiddenError("paired session refused", details={
        "decision": {"status": "deny", "allowed": False, "code": code}})


@dataclass(frozen=True)
class SessionGrant:
    pair_id: str
    connector_id: str
    generation: int
    realm_id: str
    session_expiry: float
    actor: str
    credential_binding: str
    project_id: str
    expiry: float
    authority: object
    handle: str


class PairedSessionAuthority:
    def __init__(self, *, clock=time.time):
        self.clock = clock
        self._sessions: dict[str, SessionGrant] = {}
        self._generations: dict[str, int] = {}
        self._lock = threading.RLock()

    def authenticate(self, identity, raw, runtime):
        provision = identity.get("connector_assertion")
        if (not isinstance(provision, dict) or set(provision) != {"connector_id", "realm_id"}
                or not identity.get("_credential_binding")):
            deny("paired_connector_assertion_required")
        try:
            if len(raw) > 2048:
                deny("paired_session_invalid")
            def unique(items):
                value = dict(items)
                if len(value) != len(items):
                    raise ValueError("duplicate context key")
                return value
            context = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, TypeError):
            deny("paired_session_invalid")
        if (not isinstance(context, dict) or set(context) != _FIELDS
                or not all(isinstance(context[k], str) and context[k].strip() == context[k] and context[k]
                           for k in ("pair_id", "connector_id", "realm_id"))
                or type(context["generation"]) is not int or context["generation"] <= 0
                or type(context["expires_at"]) is not int or not 0 < context["expires_at"] <= 2**53 - 1):
            deny("paired_session_invalid")
        if context["connector_id"] != provision["connector_id"]:
            deny("paired_connector_mismatch")
        # Realm authority is this authenticated Runtime, corroborated by host
        # credential provisioning. The relay's realm is only an assertion.
        realm = runtime.realm["id"]
        if context["realm_id"] != realm or provision["realm_id"] != realm:
            deny("paired_realm_mismatch")
        now = self.clock()
        session_expiry = context["expires_at"] / 1000
        credential_expiry = identity.get("expires_at")
        if type(credential_expiry) not in (int, float) or not math.isfinite(credential_expiry) or credential_expiry <= now:
            deny("paired_credential_expired")
        if session_expiry <= now:
            deny("paired_session_expired")
        with self._lock:
            connector = context["connector_id"]
            generation = context["generation"]
            if generation < self._generations.get(connector, generation):
                deny("paired_generation_stale")
            old = self._sessions.get(context["pair_id"])
            if old:
                if old.actor != identity["actor"]:
                    deny("project_grant_actor_mismatch")
                if old.credential_binding != identity["_credential_binding"]:
                    deny("paired_credential_mismatch")
                if old.connector_id != connector or old.generation != generation or old.session_expiry != session_expiry:
                    deny("paired_session_binding_changed")
                if now >= old.expiry:
                    deny("project_grant_expired")
                self._generations[connector] = generation
                return old
            try:
                from astrid.core.execution.provider_route_grant import ProjectGrantAuthority, SELECTED_PROJECT_OPERATIONS
            except ImportError:
                deny("paired_grant_authority_unavailable")
            try:
                selected = runtime.current_project(identity["actor"])["project"]["project_id"]
            except NotFoundError:
                deny("project_grant_selected_project_required")
            expiry = min(now + 300, session_expiry, credential_expiry)
            authority = ProjectGrantAuthority(realm=realm, browser_session=context["pair_id"],
                actor_id=identity["actor"], selected_project=selected, clock=lambda: self.clock(),
                session_expiry=session_expiry, credential_expiry=credential_expiry)
            handle = authority.issue({"realm": realm, "browser_session": context["pair_id"],
                "projects": [selected], "operations": sorted(SELECTED_PROJECT_OPERATIONS), "expiry": expiry})
            grant = SessionGrant(context["pair_id"], connector, generation, realm, session_expiry,
                identity["actor"], identity["_credential_binding"], selected, expiry, authority, handle)
            self._generations[connector] = generation
            self._sessions[grant.pair_id] = grant
            return grant

    def decision(self, grant, *, project_id, operation, presented_grant=None):
        with self._lock:
            if grant.generation != self._generations.get(grant.connector_id):
                deny("paired_generation_stale")
            result = grant.authority.decide(grant.handle if presented_grant is None else presented_grant,
                realm=grant.realm_id, browser_session=grant.pair_id, actor_id=grant.actor,
                project_id=project_id, operation=operation)
        if not result["allowed"]:
            raise ForbiddenError("project grant refused", details={"decision": result})
        return result

    def summary(self, grant):
        # A policy decision, not a claim that an executor ran. Handles stay local.
        decision = self.decision(grant, project_id=grant.project_id, operation="rendering.timeline_visualize")
        return {"actor_id": grant.actor, "realm_id": grant.realm_id, "project_id": grant.project_id,
                "expiry": grant.expiry, "decision": decision}
