"""Private, typed admission references. Never a bearer or caller task spec."""
from dataclasses import asdict, dataclass, field, replace
import math

from .errors import ForbiddenError, ValidationError

RESERVED_AUTHORITY_FIELDS = frozenset({
    "authority_binding", "authority_binding_json", "claim_authority", "authority_instance_id",
    "paired_session", "_paired_session", "authenticated_session", "project_grant",
    "_host_owned", "confinement_policy", "authenticated_claim", "_authority_binding",
})


def deny_authority(code):
    raise ForbiddenError("task authority refused", details={
        "decision": {"status": "deny", "allowed": False, "code": code}})


def reject_authority_fields(value):
    if isinstance(value, dict):
        if RESERVED_AUTHORITY_FIELDS.intersection(value):
            raise ValidationError("caller-supplied authority fields are reserved")
        for item in value.values():
            reject_authority_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_authority_fields(item)


@dataclass(frozen=True)
class TaskAuthorityBinding:
    version: int
    kind: str
    authority_instance_id: str
    realm_id: str
    actor_id: str
    credential_binding: str | None = field(repr=False)
    project_id: str | None
    operation: str
    expiry: float | None
    pair_id: str | None = None
    connector_id: str | None = None
    generation: int | None = None
    parent_task_id: str | None = None
    parent_attempt_id: str | None = None

    def record(self):
        if (type(self.version) is not int or self.version != 1 or self.kind not in {"paired_session", "credential", "host_owned"}
                or not all(isinstance(v, str) and v for v in
                           (self.authority_instance_id, self.realm_id, self.actor_id, self.operation))
                or self.expiry is not None and (type(self.expiry) not in (int, float) or not math.isfinite(self.expiry))):
            raise ValidationError("invalid trusted task authority binding")
        if self.kind == "paired_session" and (
                not all(isinstance(v, str) and v for v in
                        (self.credential_binding, self.pair_id, self.connector_id, self.project_id))
                or type(self.generation) is not int or self.generation < 1 or self.expiry is None):
            raise ValidationError("invalid paired task authority binding")
        if self.kind == "credential" and not self.credential_binding:
            raise ValidationError("credential binding required")
        return asdict(self)

    @classmethod
    def from_record(cls, record):
        try:
            binding = cls(**record)
            binding.record()
            return binding
        except (TypeError, ValueError, ValidationError):
            deny_authority("task_authority_invalid")

    def for_operation(self, operation):
        return replace(self, operation=operation)

    def child(self, *, operation, parent_task_id, parent_attempt_id):
        return replace(self, operation=operation, parent_task_id=parent_task_id,
                       parent_attempt_id=parent_attempt_id)
