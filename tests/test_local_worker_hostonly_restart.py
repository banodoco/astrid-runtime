"""Host-only restart uses completed owner cleanup, never PID-based adoption.

The process boundary is fake; daemon, HTTP, receipt and durable proof paths
are real. Native custody and the verified launch suites cover the adapters.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json

import pytest

from runtime_protocol.daemon import WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker import LocalWorkerLauncher, _credential_commit_generation, _digest
from tests.lanes import requires_posix_private_modes
from tests.test_local_worker_handover import (
    HostOnlyInspector, HostOnlyStopPreparer, _daemon, _launch,
)


def _replacement_launcher(daemon, proxy):
    original = daemon.local_worker_launcher
    observation = daemon.local_worker_preparer.observation
    preparer = HostOnlyStopPreparer(proxy, observation)
    launcher = LocalWorkerLauncher(
        credentials=daemon.credentials, profiles=original.profiles,
        preparer=preparer, inspector=HostOnlyInspector(proxy, observation),
        workspace_uuid=original.workspace_uuid, realm_root=original.realm_root,
        support_root=original.support_root, runtime_pid=original.runtime_pid + 1,
        actor=WORKER_ACTOR, scopes=WORKER_SCOPES,
    )
    return launcher, preparer


def _assert_departed_fence(launcher, preparer, *, reason="host-only departed owner recovery is unsupported"):
    profile = next(iter(launcher.profiles.values()))
    with pytest.raises(ConflictError, match="local Worker graph cleanup is uncertain"):
        launcher.start(profile.profile_id, profile.workspace_uuid)
    marker = json.loads((launcher.support_root / "orderly-handoff-cleanup-uncertain.json").read_text())
    assert marker["reason"] == reason
    assert preparer.events == []


@pytest.mark.parametrize("retained_revoke", [False, True])
def test_orderly_host_only_daemon_stop_then_restart_is_active(tmp_path, monkeypatch, retained_revoke):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    launch = _launch(daemon, workspace_uuid)
    metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
    proof_path = daemon.support_root / "host-only-orderly-stop.json"
    assert not proof_path.exists()
    original_abort = preparer.abort

    def abort(handle):
        # Stop fences authentication before cleanup and cannot claim completed
        # cleanup before the retained adapter returns.
        assert WORKER_ACTOR in daemon.credentials._disabled_actors
        assert not proof_path.exists()
        original_abort(handle)

    monkeypatch.setattr(preparer, "abort", abort)
    revoke = daemon.credentials.revoke

    def interrupted_revoke(actor):
        if actor == WORKER_ACTOR:
            raise OSError("injected durable revoke interruption")
        return revoke(actor)

    if retained_revoke:
        monkeypatch.setattr(daemon.credentials, "revoke", interrupted_revoke)
    try:
        daemon.stop()
    finally:
        monkeypatch.setattr(preparer, "abort", original_abort)
        monkeypatch.setattr(daemon.credentials, "revoke", revoke)
        if daemon.service is not None:
            daemon.stop()
    assert preparer.events.count("abort") == 1
    assert daemon.credentials.actor_metadata(WORKER_ACTOR) == (metadata if retained_revoke else None)
    assert not (daemon.support_root / "orderly-handoff-cleanup-uncertain.json").exists()

    restarted, next_preparer, _, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        # Each real preparation gets a fresh custody scope and owner epoch.
        observation = next_preparer.observation
        capabilities = copy.deepcopy(observation.custody_capabilities)
        scope = str(tmp_path / "next-scope")
        capabilities["host"]["scope_root"] = scope
        observation = replace(observation, custody_scope=scope,
                              custody_capabilities=capabilities, owner_epoch="next-owner")
        next_preparer.observation = observation
        restarted.local_worker_inspector.observation = observation
        result = _launch(restarted, workspace_uuid)
        assert result["state"] == "active"
        assert result["executor_incarnation"] != launch["executor_incarnation"]
        assert WORKER_ACTOR not in restarted.credentials._disabled_actors
        assert restarted.local_worker_launcher.check_liveness()
        assert restarted.service.health()["status"] == "ok"
        proof = json.loads(proof_path.read_text())
        assert proof["state"] == "complete"
        assert proof["receipt_digest"] == _digest(metadata["local_launch_receipt"])
    finally:
        restarted.stop()


@pytest.mark.parametrize("shutdown_started", [False, True])
def test_host_only_departed_owner_without_completed_stop_stays_fenced(tmp_path, shutdown_started):
    daemon, _, proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        if shutdown_started:
            handles = daemon.local_worker_launcher.begin_shutdown()
            assert handles
            assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        launcher, preparer = _replacement_launcher(daemon, proxy)
        _assert_departed_fence(launcher, preparer)
    finally:
        daemon.stop()


@pytest.mark.parametrize("forgery", [
    "receipt_digest", "credential_generation", "workspace_uuid", "realm_root",
    "support_root", "actor", "state", "version", "extra",
    pytest.param("public", marks=requires_posix_private_modes), "symlink",
    "malformed", "rotated_generation", "prior_uncertainty",
])
def test_host_only_forged_or_mismatched_completion_is_refused(tmp_path, forgery):
    daemon, _, proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    try:
        _launch(daemon, workspace_uuid)
        launcher = daemon.local_worker_launcher
        metadata = daemon.credentials.actor_metadata(WORKER_ACTOR)
        generation = _credential_commit_generation(daemon.credentials, WORKER_ACTOR)
        proof = {
            "version": "runtime.host-only-orderly-stop/v1", "state": "complete",
            "actor": WORKER_ACTOR, "workspace_uuid": workspace_uuid,
            "realm_root": str(daemon.root), "support_root": str(daemon.support_root),
            "receipt_digest": _digest(metadata["local_launch_receipt"]),
            "credential_generation": generation,
        }
        path = daemon.support_root / "host-only-orderly-stop.json"
        if forgery in proof:
            proof[forgery] = "forged"
        if forgery == "extra":
            proof["unbound"] = True
        if forgery == "symlink":
            target = tmp_path / "untrusted-completion.json"
            target.write_text(json.dumps(proof))
            target.chmod(0o600)
            path.symlink_to(target)
        else:
            path.write_text("{" if forgery == "malformed" else json.dumps(proof))
            path.chmod(0o644 if forgery == "public" else 0o600)
        if forgery == "rotated_generation":
            daemon.credentials.provision(WORKER_ACTOR, metadata["scopes"],
                metadata={k: v for k, v in metadata.items() if k not in {"actor", "scopes"}},
                rotate=True, enabled=False)
        if forgery == "prior_uncertainty":
            launcher._latch_cleanup_uncertain("unresolved graph")
        replacement, preparer = _replacement_launcher(daemon, proxy)
        reason = ("retained cleanup uncertainty requires capability recovery"
                  if forgery == "prior_uncertainty" else "host-only departed owner recovery is unsupported")
        _assert_departed_fence(replacement, preparer, reason=reason)
    finally:
        # Do not let the original stop publish over our deliberately bad proof.
        daemon.local_worker_launcher._latch_cleanup_uncertain("test departed owner remains fenced")
        daemon.stop()


def test_host_only_failed_cleanup_never_records_completion(tmp_path, monkeypatch):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path, host_only=True)
    _launch(daemon, workspace_uuid)
    original_abort = preparer.abort

    def failed_abort(handle):
        raise ConflictError("host-only child cleanup acknowledgement unresolved")

    monkeypatch.setattr(preparer, "abort", failed_abort)
    try:
        with pytest.raises(ConflictError, match="local Worker graph cleanup is uncertain"):
            daemon.stop()
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        assert not (daemon.support_root / "host-only-orderly-stop.json").exists()
        replacement, next_preparer = _replacement_launcher(daemon, proxy)
        profile = next(iter(replacement.profiles.values()))
        with pytest.raises(ConflictError, match="local Worker graph cleanup is uncertain"):
            replacement.start(profile.profile_id, profile.workspace_uuid)
        assert next_preparer.events == []
    finally:
        monkeypatch.setattr(preparer, "abort", original_abort)
        daemon.stop()
