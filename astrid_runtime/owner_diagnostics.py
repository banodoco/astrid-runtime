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
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
# Only fixed code labels are serializable; inputs cannot register names.
_V1_FIELDS = _FIELDS + (
    "admission_catalog_read",
    "admission_realm_read",
    "admission_source_read",
    "admission_upgrade_journal_read",
    "binding__selected_profile_parse",
    "binding__version_profile_parse",
    "binding_candidate_environment_parse",
    "binding_candidate_pinokio",
    "binding_candidate_version_root_parse",
    "binding_catalog_parse",
    "binding_current_raw_parse",
    "binding_current_version_format",
    "binding_data_root_string",
    "binding_declaration_parse",
    "binding_declaration_raw_parse",
    "binding_environment_parse",
    "binding_environment_pinokio",
    "binding_environment_present",
    "binding_expected_root_parse",
    "binding_fields",
    "binding_install_data",
    "binding_install_managed",
    "binding_install_marker_sha256_digest",
    "binding_install_marker_sha256_string",
    "binding_install_owner",
    "binding_marker_raw_install_marker_parse",
    "binding_owner_identity_sha256_digest",
    "binding_owner_identity_sha256_string",
    "binding_owner_release_integer",
    "binding_owner_release_nonnegative",
    "binding_owner_version_name_string",
    "binding_owner_version_parent",
    "binding_owner_version_raw_owner_version_probe_parse",
    "binding_owner_version_readable",
    "binding_owner_version_root_parse",
    "binding_owner_version_root_string",
    "binding_owner_version_sha256_digest",
    "binding_owner_version_sha256_string",
    "binding_probe_identity_object",
    "binding_probe_management",
    "binding_profile_path_parse",
    "binding_profile_present",
    "binding_profile_raw_profile_parse",
    "binding_profile_readable",
    "binding_profile_sha256_digest",
    "binding_profile_sha256_string",
    "binding_program_root_parse",
    "binding_program_root_string",
    "binding_python_absolute",
    "binding_python_environment",
    "binding_python_file",
    "binding_python_parent_no_symlink",
    "binding_raw_profile_object",
    "binding_realm_id_string",
    "binding_realm_root_string",
    "binding_runtime_checkout_parse",
    "binding_runtime_checkout_string",
    "binding_runtime_environment_string",
    "binding_selected_environment_directory",
    "binding_selected_identity",
    "binding_selected_profile_environment",
    "binding_selected_python_absolute",
    "binding_selected_python_file",
    "binding_selected_python_no_symlink",
    "binding_selected_version_root_parse",
    "binding_selection_data",
    "binding_selection_managed",
    "binding_selection_matches_data",
    "binding_selection_object",
    "binding_selection_owner",
    "binding_selection_present",
    "binding_selection_program",
    "binding_selection_raw_selected_parse",
    "binding_selection_readable",
    "binding_selection_realm",
    "binding_selection_root",
    "binding_service_declaration_sha256_digest",
    "binding_service_declaration_sha256_string",
    "binding_service_declaration_string",
    "binding_service_present",
    "binding_source_checkout_parse",
    "binding_source_checkout_string",
    "binding_source_profile_sha256_digest",
    "binding_source_profile_sha256_string",
    "binding_version_identity_object",
    "binding_version_management",
    "binding_version_profile",
    "binding_version_profile_field",
    "binding_version_profile_runtime_checkout",
    "binding_version_profile_runtime_environment",
    "binding_version_profile_service_declaration",
    "binding_version_profile_source_checkout",
    "binding_version_raw_version_parse",
    "binding_version_release_integer",
    "binding_version_release_nonnegative",
    "binding_version_root",
    "binding_version_source_digest",
    "catalog_one_realm",
    "catalog_profile_supported",
    "catalog_profiles_object",
    "catalog_realm_id_present",
    "catalog_realm_id_safe",
    "catalog_realm_id_unique",
    "catalog_realm_named",
    "catalog_realm_object",
    "catalog_realms_list",
    "catalog_root_absolute",
    "catalog_root_directory",
    "catalog_root_leaf_no_symlink",
    "catalog_root_no_symlink",
    "catalog_selection_matches",
    "catalog_version",
    "cleanup_broker_registered",
    "cleanup_child_exited",
    "cleanup_complete",
    "cleanup_kill",
    "cleanup_native_stop",
    "cleanup_sole_reaper",
    "cleanup_term",
    "cleanup_wait",
    "compatibility",
    "compatibility_capability",
    "compatibility_protocol",
    "compatibility_schema",
    "compatibility_source_protocol",
    "compatibility_source_schema",
    "completed_binding_keys",
    "completed_binding_matches",
    "completed_binding_object",
    "completed_binding_present",
    "completed_binding_selected",
    "completed_birth_absent",
    "completed_birth_present",
    "completed_birth_string",
    "completed_data_matches",
    "completed_data_parse",
    "completed_data_string",
    "completed_instance_present",
    "completed_instance_string",
    "completed_marker_fields",
    "completed_marker_unchanged",
    "completed_owner_matches",
    "completed_owner_strings",
    "completed_pid_absent",
    "completed_pid_integer",
    "completed_pid_positive",
    "completed_realm_matches",
    "completed_realm_root_parse",
    "completed_realm_string",
    "completed_receipt_fields",
    "completed_receipt_object",
    "completed_root_matches",
    "completed_root_parse",
    "completed_root_string",
    "completed_stop_marker",
    "completed_version_integer",
    "completed_version_supported",
    "connect_discovery_present",
    "connect_discovery_unchanged",
    "connect_endpoint_parse",
    "connect_final_discovery",
    "connect_health",
    "connect_instance_parse",
    "connect_owner_valid",
    "connect_pid_alive",
    "connect_pid_parse",
    "connect_realm_present",
    "connect_selected_realm",
    "discovery_birth_present",
    "discovery_endpoint_present",
    "discovery_health",
    "discovery_instance_present",
    "discovery_legacy_absent",
    "discovery_lock_matches",
    "discovery_owner_alive",
    "discovery_owner_read",
    "discovery_owner_valid",
    "discovery_profile_supported",
    "discovery_realm_present",
    "discovery_root_matches",
    "discovery_root_present",
    "discovery_selected_realm",
    "escalation_birth_matches",
    "escalation_endpoint_owner",
    "escalation_group_leader",
    "escalation_health_owner",
    "escalation_identity_present",
    "escalation_identity_read",
    "escalation_metadata_active_realm",
    "escalation_metadata_endpoint",
    "escalation_metadata_identity",
    "escalation_metadata_object",
    "escalation_metadata_pid",
    "escalation_metadata_process_birth_id",
    "escalation_metadata_read",
    "escalation_metadata_realm_id",
    "escalation_metadata_root",
    "escalation_metadata_runtime_instance_id",
    "escalation_pid_matches",
    "escalation_uid_matches",
    "handoff_file_owned",
    "handoff_file_present",
    "handoff_file_regular",
    "handoff_json_object",
    "handoff_json_parse",
    "handoff_leaf_no_symlink",
    "handoff_path_absolute",
    "handoff_path_no_symlink",
    "handoff_value_absolute",
    "handoff_value_canonical",
    "handoff_value_directory",
    "handoff_value_leaf_no_symlink",
    "handoff_value_no_symlink",
    "handoff_value_present",
    "handoff_value_regular",
    "handoff_value_string",
    "identity_agent_head",
    "identity_dirty_boolean",
    "identity_dirty_hash",
    "identity_dirty_hash_hex",
    "identity_dirty_hash_length",
    "identity_dirty_hash_string",
    "identity_fields",
    "identity_head_hex",
    "identity_head_length",
    "identity_head_string",
    "identity_health_instance",
    "identity_health_object",
    "identity_instance_present",
    "identity_management",
    "identity_object",
    "identity_release_integer",
    "identity_release_valid",
    "identity_runtime_head",
    "identity_wire_present",
    "launch_final_publications",
    "launch_marker_completed",
    "launch_marker_live",
    "launch_marker_present",
    "launch_marker_stopping",
    "launch_publication_unchanged",
    "launch_realm_owner_absent",
    "launch_record_owner_absent",
    "liveness_birth_read",
    "liveness_pid_read",
    "lock_match_birth",
    "lock_match_instance",
    "lock_match_pid",
    "lock_match_present",
    "lock_match_read",
    "lock_match_realm",
    "lock_match_root",
    "loopback_host",
    "loopback_no_fragment",
    "loopback_no_password",
    "loopback_no_query",
    "loopback_no_username",
    "loopback_parse",
    "loopback_path",
    "loopback_port_present",
    "loopback_port_range",
    "loopback_scheme",
    "manager_stale_birth_absent",
    "manager_stale_pid_absent",
    "owner_absent_birth",
    "owner_absent_birth_read",
    "owner_absent_pid",
    "realm_leaf_no_symlink",
    "realm_path_absolute",
    "realm_path_available",
    "realm_path_canonical",
    "realm_path_no_symlink",
    "reattest_binding_matches",
    "reattest_binding_parse",
    "reattest_binding_present",
    "reattest_binding_unchanged",
    "reattest_catalog_parse",
    "reattest_current_binding_parse",
    "reattest_discovery_absent",
    "reattest_fence_safe",
    "reattest_final_discovery_absent",
    "reattest_final_marker_absent",
    "reattest_marker_absent",
    "reattest_marker_binding_matches",
    "reattest_realm_directory",
    "reattest_realm_no_symlink",
    "reattest_realm_parse",
    "reattest_realm_root",
    "reattest_realm_selected",
    "reclaim_fresh_absence",
    "reclaim_fresh_snapshots",
    "reclaim_no_live_owner",
    "reclaim_records_present",
    "reclaim_snapshots_unchanged",
    "reconnect_discovery_unchanged",
    "reconnect_final_discovery",
    "reconnect_final_marker",
    "reconnect_health",
    "reconnect_lock_matches",
    "reconnect_owner_alive",
    "reconnect_owner_valid",
    "reconnect_realm_matches",
    "reconnect_realm_present",
    "recorded_birth_parse",
    "recorded_endpoint_parse",
    "recorded_instance_parse",
    "recorded_observed_realm_parse",
    "recorded_observed_root_parse",
    "recorded_pid_parse",
    "recovery_discovery_absent",
    "recovery_health",
    "recovery_lock_matches",
    "recovery_marker_unchanged",
    "recovery_owner_valid",
    "recovery_reattest_binding",
    "recovery_reattest_publications_absent",
    "requested_identity_capture",
    "restore_backup_catalog_bytes_backup_catalog_value_parse",
    "restore_backup_catalog_path_parse",
    "restore_backup_directory",
    "restore_backup_kind",
    "restore_backup_object",
    "restore_backup_parent",
    "restore_backup_root_parse",
    "restore_binding_data",
    "restore_binding_program",
    "restore_binding_realm",
    "restore_binding_root",
    "restore_data_root",
    "restore_data_root_parse",
    "restore_discovery_absent",
    "restore_expected_backups_parse",
    "restore_expected_marker_present",
    "restore_file_regular",
    "restore_install_directory",
    "restore_journal_bytes_journal_parse",
    "restore_journal_data_parse",
    "restore_journal_format",
    "restore_journal_kind",
    "restore_journal_name",
    "restore_journal_path_parse",
    "restore_journal_realm_object",
    "restore_journal_realm_root_parse",
    "restore_journal_realm_string",
    "restore_journal_step",
    "restore_json_object",
    "restore_json_parse",
    "restore_leaf_no_symlink",
    "restore_live_catalog_bytes_live_catalog_parse",
    "restore_live_marker_unchanged",
    "restore_live_realm_matches",
    "restore_live_realm_parse",
    "restore_live_realm_present",
    "restore_live_realm_string",
    "restore_live_root_matches",
    "restore_live_selection_matches",
    "restore_live_selection_string",
    "restore_marker_absent",
    "restore_marker_completed",
    "restore_marker_data",
    "restore_marker_present",
    "restore_marker_realm",
    "restore_marker_root",
    "restore_marker_unchanged",
    "restore_operation_format",
    "restore_operation_string",
    "restore_parent_directory",
    "restore_parsed_live_parse",
    "restore_path_absolute",
    "restore_path_canonical",
    "restore_path_no_symlink",
    "restore_program_root",
    "restore_program_root_parse",
    "restore_realm_absence_read",
    "restore_realm_absent",
    "restore_realm_id",
    "restore_realm_nonempty",
    "restore_realm_root",
    "restore_realm_root_parse",
    "restore_realm_safe",
    "restore_realm_schema",
    "restore_realm_still_absent",
    "restore_retained_parse",
    "restore_retained_realm_matches",
    "restore_retained_realm_parse",
    "restore_retained_realm_present",
    "restore_retained_realm_string",
    "restore_retained_root_matches",
    "restore_retained_selection_matches",
    "restore_retained_selection_string",
    "restore_root_directory",
    "restore_root_no_symlink",
    "restore_selection_bytes_selected_parse",
    "restore_selection_owner",
    "restore_selection_path_parse",
    "restore_selection_realm_string",
    "restore_snapshot_backup_catalog_bytes",
    "restore_snapshot_journal_bytes",
    "restore_snapshot_live_catalog_bytes",
    "restore_snapshot_program_root",
    "restore_snapshot_realm_absent",
    "restore_snapshot_realm_id",
    "restore_snapshot_realm_root",
    "restore_snapshot_selection_bytes",
    "retire_marker_unchanged",
    "reused_birth_different",
    "reused_birth_observed",
    "reused_discovery_unchanged",
    "reused_marker_unchanged",
    "reused_pid_alive",
    "rollback_candidate_matches",
    "rollback_publication_unchanged",
    "rollback_realm_owner_absent",
    "selected_id_present",
    "selected_one_realm",
    "selected_realm_matches",
    "selected_realms_present",
    "signal_adopted_pid",
    "signal_birth_present",
    "signal_capability_load",
    "signal_custody_claim",
    "signal_delivery",
    "signal_endpoint_present",
    "signal_group_leader",
    "signal_handle_pid",
    "signal_handle_present",
    "signal_instance_present",
    "signal_kill",
    "signal_not_operator_pid",
    "signal_pid_positive",
    "signal_publications_read",
    "signal_roots_parse",
    "signal_selected_birth_matches",
    "signal_selected_identity_present",
    "signal_selected_identity_read",
    "signal_selected_owner_absent",
    "signal_selected_pid_matches",
    "signal_selected_uid_matches",
    "signal_target_alive",
    "signal_term",
    "source_checkout_absolute",
    "source_checkout_no_symlink",
    "source_profile_name",
    "source_profile_type",
    "source_protocol",
    "source_runtime_absolute",
    "source_runtime_command_absent",
    "source_runtime_no_symlink",
    "source_runtime_present",
    "source_schema",
    "source_worker_absolute",
    "source_worker_file",
    "source_worker_leaf_no_symlink",
    "source_worker_no_symlink",
    "stale_discovery_unchanged",
    "stale_final_discovery_unchanged",
    "stale_final_marker_unchanged",
    "stale_lock_owner_absent",
    "stale_marker_unchanged",
    "stale_owner_absent",
    "startup_advertised_pid_matches",
    "startup_advertised_pid_parse",
    "startup_advertised_pid_present",
    "startup_birth_matches",
    "startup_child_running",
    "startup_endpoint_health",
    "startup_endpoint_parse",
    "startup_endpoint_present",
    "startup_health",
    "startup_health_read",
    "startup_identity",
    "startup_identity_matches",
    "startup_identity_read",
    "startup_instance_parse",
    "startup_native_birth_matches",
    "startup_native_identity_present",
    "startup_native_identity_read",
    "startup_owner_identity_parse",
    "startup_owner_valid",
    "startup_pid_alive",
    "startup_pid_parse",
    "startup_prior_child_exited",
    "startup_publication_matches",
    "startup_realm_matches",
    "startup_realm_present",
    "startup_requested_identity_parse",
    "startup_root_matches",
    "stop_actual_birth_read",
    "stop_alive_read",
    "stop_binding_unchanged",
    "stop_cleanup_binding_matches",
    "stop_cleanup_discovery_matches",
    "stop_cleanup_discovery_unchanged",
    "stop_cleanup_marker_matches",
    "stop_cleanup_marker_unchanged",
    "stop_completed_marker_present",
    "stop_discovery_unchanged",
    "stop_downstream",
    "stop_intent_discovery_unchanged",
    "stop_intent_marker_unchanged",
    "stop_manager_publication_matches",
    "stop_marker_unchanged",
    "stop_observed_birth_read",
    "stop_observed_read",
    "stop_owner_callable",
    "stop_realm_owner_absent",
    "stop_retained_marker_unchanged",
    "stop_stale_birth_absent",
    "stop_stale_pid_absent",
    "stopping_binding_keys",
    "stopping_binding_matches",
    "stopping_binding_object",
    "stopping_binding_present",
    "stopping_data_matches",
    "stopping_data_root_string",
    "stopping_discovery_object",
    "stopping_intent_fields",
    "stopping_intent_object",
    "stopping_marker",
    "stopping_marker_fields",
    "stopping_marker_state",
    "stopping_owner_strings",
    "stopping_pid_integer",
    "stopping_pid_positive",
    "stopping_process_birth_id_string",
    "stopping_realm_id_string",
    "stopping_realm_matches",
    "stopping_realm_root_string",
    "stopping_root_matches",
    "stopping_root_parse",
    "stopping_runtime_instance_id_string",
    "stopping_version_integer",
    "stopping_version_supported",
    "support_component_safe",
    "support_directory_no_symlink",
    "support_directory_present",
    "support_directory_regular",
    "support_file_no_symlink",
    "support_file_present",
    "support_file_regular",
    "support_json_decode",
    "support_json_object",
    "support_json_open",
    "support_json_parse",
    "support_json_present",
    "support_json_read",
    "support_json_regular",
    "support_path_absolute",
    "support_path_no_symlink",
    "upgrade_journal_operation",
    "upgrade_journal_operator_matches",
    "upgrade_journal_present",
    "upgrade_journal_terminal",
    "worker_actor_matches",
    "worker_credential_nonempty",
    "worker_credential_present",
    "worker_credential_string",
    "worker_file_available",
    "worker_file_owner_only",
    "worker_handoff_object",
    "worker_leaf_no_symlink",
    "worker_path_absolute",
    "worker_path_no_symlink",
    "worker_scopes_match",
)
_V1_SWITCH = "ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS"
_phase = ContextVar("owner_validation_phase", default="owner_validation")
_current = ContextVar("owner_validation_diagnostics", default=None)
_chains = ContextVar("owner_predicate_chains", default=())


@contextmanager
def owner_phase(name):
    token = _phase.set(name)
    try:
        yield
    finally:
        _phase.reset(token)


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


def outcome(name, value, *, error=False, blocked=()):
    """Record an already evaluated predicate, without retaining its inputs."""
    status = ("unknown" if error or value is None else "pass" if value else "fail")
    _emit_v1(name, status)
    for chain in _chains.get():
        if name in chain["names"]:
            chain["seen"].add(name)
            if status != "pass" and chain["failed"] is None:
                chain["failed"] = name
    record = _current.get()
    if record is not None and name in _FIELDS:
        record[name] = ("error" if error else status)
    if status != "pass":
        for dependent in blocked:
            unavailable(dependent, depends_on=name)
    return value


def unavailable(name, *, depends_on):
    """Record a predicate skipped because a named prerequisite failed."""
    if depends_on in _V1_FIELDS:
        _emit_v1(name, "unavailable", depends_on=depends_on)
        for chain in _chains.get():
            if name in chain["names"]:
                chain["seen"].add(name)


@contextmanager
def observation(name, *, malformed=()):
    """Observe an existing read/parse block; never execute an observation itself."""
    try:
        yield
    except Exception as exc:
        outcome(name, False if isinstance(exc, malformed) else None)
        raise
    else:
        outcome(name, True)


def predicate_chain(*names):
    """Name the failed prerequisite when a validator short-circuits.

    Only explicitly declared predicates participate. Optional branches are not
    reported as failures merely because the authority path did not take them.
    No inputs or decisions escape the validator through this observer.
    """

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            chain = {"names": names, "seen": set(), "failed": None}
            token = _chains.set((*_chains.get(), chain))
            try:
                return function(*args, **kwargs)
            except Exception:
                if chain["failed"] is None:
                    pending = next((name for name in names if name not in chain["seen"]), None)
                    if pending is not None:
                        outcome(pending, None)
                raise
            finally:
                _chains.reset(token)
                if chain["failed"] is not None:
                    for name in names[names.index(chain["failed"]) + 1 :]:
                        if name not in chain["seen"]:
                            unavailable(name, depends_on=chain["failed"])

        return wrapped

    return decorate


def skipped(name, *, depends_on=None):
    """Mark a known predicate as not evaluated on this authority path."""
    if depends_on is not None:
        unavailable(name, depends_on=depends_on)
    record = _current.get()
    if record is not None and name in _FIELDS and name not in record:
        record[name] = "skipped"


def _provenance(name):
    # Labels describe the existing authority input, never the input itself.
    if name.startswith(("realm_path_", "realm_leaf_")):
        return "realm_root"
    if name.startswith(("identity_", "startup_identity", "startup_owner_identity", "startup_requested_identity")):
        return "startup_identity"
    if name.startswith(("binding_", "handoff_")):
        return "installation_binding"
    if name.startswith("restore_"):
        return "restore_selection"
    if name.startswith("cleanup_"):
        return "retained_child_custody"
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
        "bootstrap": "discovery",
        "_bootstrap_locked": "discovery",
        "connect": "admission",
        "_reclaim_stale_owner_locked": "recovery",
        "_fenced_stop_and_manager": "stop",
        "_validate_published_stop_owner": "stop",
        "stop_owner": "stop",
        "restart": "stop",
        "start": "startup",
        "_interrupt_owner_locked": "stop",
        "_reattest_aborted_launch_stop": "recovery",
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
