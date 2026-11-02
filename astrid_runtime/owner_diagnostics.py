"""Opt-in, redacted observations of owner validation decisions."""

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
    "birth_bridge_fresh_pid", "birth_bridge_boot_parseable", "birth_bridge_boot_read",
    "birth_bridge_pidns_read", "birth_bridge_identity_read",
    "liveness_realm_root", "liveness_realm_lock", "liveness_pid_alive",
    "liveness_observer_callable", "liveness_birth_expected",
    "liveness_birth_observed", "liveness_birth_compatible",
    "metadata_callable", "metadata_health", "credential_readable",
    "credential_regular", "credential_present", "realm_response",
    "realm_instance", "endpoint_metadata", "endpoint_instance", "endpoint_realm",
    "recorded_identity_readable", "recorded_pid_positive", "recorded_birth_present",
    "recorded_instance_present", "recorded_realm_matches", "recorded_root_matches",
    "owner_record_present", "owner_record_root_readable", "owner_record_pid",
    "owner_record_instance", "owner_record_birth", "owner_record_realm", "owner_record_root",
    "published_marker_state", "published_marker_present", "published_marker_realm",
    "published_marker_matches", "published_pid_alive", "published_absence_observed",
    "signal_discovery_pid", "signal_discovery_endpoint", "signal_discovery_instance",
    "signal_discovery_birth", "signal_discovery_realm", "signal_discovery_root",
    "signal_lock_pid", "signal_lock_instance", "signal_lock_birth", "signal_lock_realm",
    "signal_lock_root", "signal_pid_alive", "signal_birth", "signal_health_instance",
    "signal_endpoint_instance", "signal_endpoint_realm", "signal_health",
)
_V1_FIELDS = _FIELDS + (
    "discovery_realm_present", "discovery_owner_alive", "discovery_endpoint_present",
    "discovery_instance_present", "discovery_owner_valid", "discovery_root_present",
    "discovery_root_matches", "discovery_birth_present", "discovery_lock_matches",
    "discovery_health", "discovery_selected_realm", "recovery_marker_unchanged",
    "recovery_discovery_absent", "connect_realm_present", "connect_discovery_present",
    "connect_pid_alive", "connect_owner_valid", "connect_health", "connect_selected_realm",
    "reclaim_records_present", "reclaim_no_live_owner", "reclaim_snapshots_unchanged",
    "stop_discovery_unchanged", "stop_marker_unchanged",
    "compatibility", "startup_identity", "completed_stop_marker", "stopping_marker",
    "binding_fields", "owner_absent_pid", "owner_absent_birth", "recovery_lock_matches",
    "recovery_owner_valid", "recovery_health", "recovery_reattest_publications_absent",
    "recovery_reattest_binding", "stop_cleanup_discovery_matches", "stop_cleanup_marker_matches",
)
_V1_SWITCH = "ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS"
_phase = ContextVar("owner_validation_phase", default="owner_validation")
_current = ContextVar("owner_validation_diagnostics", default=None)


def _v1_enabled():
    return os.environ.get(_V1_SWITCH, "").strip().lower() in {"1", "true", "yes", "on"}


def _emit_v1(name, status, *, depends_on=None):
    if not _v1_enabled() or name not in _V1_FIELDS:
        return
    try:
        item = {"format": "astrid-installer-all-predicates/v1", "phase": _phase.get(),
                "predicate": name, "expected": True,
                "observed": True if status == "pass" else False if status == "fail" else None,
                "provenance": _provenance(name), "result": status}
        if depends_on is not None:
            item["depends_on"] = depends_on
        payload = "[astrid installer all-predicates v1] " + json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
        os.write(2, payload.encode("ascii"))
    except Exception:
        pass


def outcome(name, value, *, error=False):
    """Record an already evaluated predicate, without retaining its inputs."""
    status = ("unknown" if error or value is None else "pass" if value else "fail")
    _emit_v1(name, status)
    record = _current.get()
    if record is not None and name in _FIELDS:
        record[name] = ("error" if error else status)
    return value


def unavailable(name, *, depends_on):
    """Record a predicate skipped because a named prerequisite failed."""
    if depends_on in _V1_FIELDS:
        _emit_v1(name, "unavailable", depends_on=depends_on)


def skipped(name, *, depends_on=None):
    """Mark a known predicate as not evaluated on this authority path."""
    if depends_on is not None:
        unavailable(name, depends_on=depends_on)
    record = _current.get()
    if record is not None and name in _FIELDS and name not in record:
        record[name] = "skipped"


def _provenance(name):
    # Labels describe the existing authority input, never the input itself.
    if name.startswith("birth_bridge_"):
        return "legacy_birth_bridge"
    if name.startswith("birth_direct_"):
        return "birth_comparison"
    if name.startswith("signal_discovery_") or name.startswith("recorded_"):
        return "discovery_record"
    if name.startswith("signal_lock_") or name.startswith("lock_") or name.startswith("owner_record_") or name.startswith("published_marker_"):
        return "owner_lock_or_record"
    if name.startswith("endpoint_") or name.startswith("realm_") or name.startswith("health_"):
        return "endpoint_observation"
    return "authority_check"


@contextmanager
def capture():
    version = os.environ.get(_SWITCH)
    if _current.get() is not None or version not in ("1", "2"):
        yield
        return
    record = {}
    token = _current.set(record)
    try:
        yield
    finally:
        _current.reset(token)
        try:
            if version == "1":
                legacy = {key: {"pass": "matched", "fail": "false", "error": "false"}.get(
                    record.get(key), "unobserved") for key in _FIELDS}
                document = {"schema": 1, "predicates": legacy}
            else:
                document = {"schema": 2, "predicates": [
                    {"name": name, "expected": True,
                     "observed": True if status == "pass" else False if status == "fail" else None,
                     "provenance": _provenance(name), "status": status,
                     "unavailable_due_to": ("not_evaluated" if status == "skipped" else
                                             "indeterminate" if status == "unknown" else
                                             "observation_error" if status == "error" else None)}
                    for name, status in record.items()]}
            payload = "ASTRID_OWNER_DIAGNOSTICS " + json.dumps(document, separators=(",", ":")) + "\n"
            os.write(2, payload.encode("ascii"))
        except Exception:
            pass  # Diagnostics must never alter validation or its exceptions.


def instrument(function):
    return _instrument(function, legacy_capture=True)


def phase_instrument(function):
    return _instrument(function, legacy_capture=False)


def _instrument(function, *, legacy_capture):
    phases = {
        "_bootstrap_locked": "discovery", "connect": "admission",
        "_reclaim_stale_owner_locked": "recovery", "_fenced_stop_and_manager": "stop",
        "_validate_published_stop_owner": "stop", "stop_owner": "stop",
        "_interrupt_owner_locked": "stop", "_reattest_aborted_launch_stop": "recovery",
    }
    @wraps(function)
    def wrapped(*args, **kwargs):
        phase = phases.get(function.__name__)
        token = _phase.set(phase) if phase else None
        try:
            if legacy_capture:
                with capture():
                    return function(*args, **kwargs)
            return function(*args, **kwargs)
        finally:
            if token is not None:
                _phase.reset(token)
    return wrapped
