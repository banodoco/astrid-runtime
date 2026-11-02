"""Opt-in, value-free observations of the stop owner validation path."""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import os

_SWITCH = "ASTRID_RUNTIME_OWNER_DIAGNOSTICS"
_FIELDS = (
    "owner_validator_callable", "pid_alive", "lock_io", "lock_readable", "lock_regular",
    "lock_json", "lock_object", "lock_pid", "lock_instance", "lock_realm",
    "lock_root_readable", "lock_root", "birth_present", "birth_observed",
    "health_present", "health_instance", "birth_legacy", "birth_direct",
    "birth_legacy_bridge", "birth_selected", "owner_valid",
    "birth_direct_pidns", "birth_direct_boot", "birth_direct_tick",
    "birth_bridge_tick", "birth_bridge_fresh_birth", "birth_bridge_boot_valid",
    "birth_bridge_pidns_ascii", "birth_bridge_pidns_numeric",
    "birth_bridge_boot", "birth_bridge_pidns",
    "birth_direct_inputs", "birth_direct_parsed", "birth_direct_scope",
    "birth_bridge_legacy", "birth_bridge_pid_valid", "birth_bridge_actual_string",
    "birth_bridge_parsed", "birth_bridge_native_readable", "birth_bridge_fresh_present",
    "birth_bridge_fresh_pid", "birth_bridge_boot_parseable",
    "liveness_realm_root", "liveness_realm_lock", "liveness_pid_alive",
    "liveness_observer_callable", "liveness_birth_expected",
    "liveness_birth_observed", "liveness_birth_compatible",
    "metadata_callable", "metadata_health", "credential_readable",
    "credential_regular", "credential_present", "realm_response",
    "realm_instance", "endpoint_metadata", "endpoint_instance", "endpoint_realm",
)
_current = ContextVar("owner_validation_diagnostics", default=None)


def outcome(name, value):
    """Record only a predicate result; None means unknown or not observed."""
    record = _current.get()
    if record is not None:
        record[name] = "unobserved" if value is None else "matched" if value else "false"
    return value


@contextmanager
def capture():
    if _current.get() is not None or os.environ.get(_SWITCH) != "1":
        yield
        return
    record = dict.fromkeys(_FIELDS, "unobserved")
    token = _current.set(record)
    try:
        yield
    finally:
        _current.reset(token)
        try:
            # One bounded write keeps each record atomic when stderr is a pipe.
            payload = "ASTRID_OWNER_DIAGNOSTICS " + json.dumps(
                {"schema": 1, "predicates": record}, separators=(",", ":")
            ) + "\n"
            os.write(2, payload.encode("ascii"))
        except Exception:
            pass  # Diagnostics must never alter validation or its exceptions.


def instrument(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with capture():
            return function(*args, **kwargs)
    return wrapped
