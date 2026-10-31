from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runtime_protocol.errors import NotFoundError
from runtime_protocol import platform
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, IDEMPOTENCY_RESULT_MARKER, IdempotencyWindowExpired, command_result, SCHEMA_VERSION
from runtime_protocol.snapshot_refs import restore_spec_snapshots
from runtime_protocol.upgrade import migrate_canonical_to_current, compact_idempotency_ledger
from runtime_protocol.util import canonical_json, now


def _digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _materialize_with_astrid(spec, attempt, checkout, service):
    """Run the checked-out host with its own interpreter when that env exists."""
    checkout = Path(checkout)
    candidate = platform.venv_python(checkout / ".venv")
    interpreter = candidate if candidate.is_file() else Path(sys.executable)
    objects = {}
    for digest in spec.get("input_object_ids", []):
        encoded = base64.b64encode(service.object(digest)[1]).decode("ascii")
        objects[digest] = encoded
        objects[digest.removeprefix("sha256:")] = encoded
    input_file = attempt.parent / "host-input.json"
    input_file.write_text(json.dumps({"spec": spec, "objects": objects}))
    script = r'''
import base64, json, sys
from pathlib import Path
from astrid.core.execution.generic_host import GenericPackHost
payload = json.loads(Path(sys.argv[1]).read_text())
class Client:
    def get_object(self, digest):
        return base64.b64decode(payload["objects"][digest])
host = GenericPackHost(pack_roots=[], client=Client())
values = host._materialize_inputs(payload["spec"], Path(sys.argv[2]))
print(json.dumps(values))
'''
    runtime_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(checkout), str(runtime_root), env.get("PYTHONPATH", "")) if part
    )
    completed = subprocess.run(
        [str(interpreter), "-c", script, str(input_file), str(attempt)],
        cwd=runtime_root, env=env, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, (
        f"Astrid host materialization failed under {interpreter}:\n{completed.stderr}"
    )
    return json.loads(completed.stdout)


@pytest.mark.integration
def test_visualize_task_hydrates_exact_saved_revision_and_refuses_missing_source(tmp_path, astrid_importable):
    # This crosses task admission, CAS custody, task readback, and Astrid's
    # actual host materializer. The child receives bytes read from the real
    # Runtime service, so admission, custody, and hydration stay real.
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "snapshots", "name": "Snapshots"}, idempotency_key="project")
        project_id = project["id"]
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        service.register_capability({"capability_id": "rendering.timeline_visualize", "definition_digest": _digest("visualize")})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.timeline_visualize"]})
        parent = {"config": {"clips": []}, "registry": {"assets": {}}, "clips": [], "occurrences": []}
        with service.store._transaction():
            service.store.conn.execute(
                "INSERT INTO parent_composition_revisions(id,project_id,timeline_id,payload_json,content_digest,created_at) "
                "VALUES (?,?,?,?,?,?)",
                ("revision-1", project_id, "main", canonical_json(parent), _digest(parent), now()),
            )
        snapshot = {"config": {"clips": [{"id": "old", "at": 0, "hold": 1}]}, "registry": {"assets": {}}}
        context = {"mode": "composed_capture", "project_id": project_id, "timeline_id": "main",
                   "revision_id": "revision-1", "capture_snapshot": snapshot}
        task = service.create_task({
            "project": project_id, "capability_id": "rendering.timeline_visualize",
            "capability_digest": _digest("visualize"), "input_object_ids": [],
            "idempotency_key": "capture", "spec": {
                "inputs": {"filmstrip_authority": canonical_json(context)},
                "authority_context": context,
            },
        })["task"]
        spec = task["spec"]
        inner = spec["spec"]
        assert "capture_snapshot" not in inner["authority_context"]
        assert "capture_snapshot" not in json.loads(inner["inputs"]["filmstrip_authority"])
        ref = inner["authority_context"]["capture_snapshot_ref"]
        assert ref["revision_id"] == "revision-1"
        assert ref["revision_digest"] == _digest(parent)
        assert ref["digest"] in spec["input_object_ids"]

        attempt = tmp_path / "attempt"
        attempt.mkdir()
        values = _materialize_with_astrid(spec, attempt, astrid_importable, service)
        assert json.loads((attempt / "inputs" / "timeline.json").read_text()) == snapshot["config"]
        assert json.loads(values["filmstrip_authority"])["capture_snapshot"] == snapshot

        with service.store._transaction():
            service.store.conn.execute("DELETE FROM parent_composition_revisions WHERE id='revision-1'")
        with pytest.raises(NotFoundError, match="parent revision is missing"):
            service.claim_next({"executor_id": "worker", "capability_ids": ["rendering.timeline_visualize"],
                                "runtime_epoch": service.health()["runtime_epoch"]})
    finally:
        service.close()


@pytest.mark.integration
def test_render_hydration_reads_named_revision_after_head_moves(tmp_path, astrid_importable):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "render-ref", "name": "Render"}, idempotency_key="project")
        project_id = project["id"]
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        service.register_capability({"capability_id": "synthetic.render", "definition_digest": _digest("synthetic.render")})
        service.register_executor({"executor_id": "worker", "capabilities": ["synthetic.render"]})
        parent1 = {"config": {"clips": []}, "registry": {}, "clips": [], "occurrences": []}
        parent2 = {"config": {"clips": [{"id": "new"}]}, "registry": {}, "clips": [], "occurrences": []}
        with service.store._transaction():
            for revision_id, payload in (("old", parent1), ("new", parent2)):
                service.store.conn.execute(
                    "INSERT INTO parent_composition_revisions(id,project_id,timeline_id,payload_json,content_digest,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (revision_id, project_id, "main", canonical_json(payload), _digest(payload), now()),
                )
            service.store.conn.execute(
                "INSERT INTO parent_composition_heads(timeline_id,project_id,revision_id,updated_at) VALUES (?,?,?,?)",
                ("main", project_id, "new", now()),
            )
        snapshot = {"config": {"clips": [{"id": "old"}]}, "registry": {"assets": {}}}
        task = service.create_task({
            "project": project_id, "capability_id": "synthetic.render",
            "capability_digest": _digest("synthetic.render"), "input_object_ids": [],
            "idempotency_key": "render", "spec": {
                "timeline_snapshot": snapshot,
                "inputs": {"timeline_authority": {"project_id": project_id, "timeline_id": "main",
                    "parent_revision_id": "old", "parent_content_digest": _digest(parent1)}},
            },
        })["task"]
        attempt = tmp_path / "attempt"
        attempt.mkdir()
        _materialize_with_astrid(task["spec"], attempt, astrid_importable, service)
        assert task["spec"]["spec"]["timeline_snapshot_ref"]["revision_id"] == "old"
        assert json.loads((attempt / "inputs" / "timeline.json").read_text()) == snapshot["config"]
        with service.store._transaction():
            service.store.conn.execute("DELETE FROM parent_composition_revisions WHERE id='old'")
        with pytest.raises(NotFoundError, match="parent revision is missing"):
            service.claim_next({"executor_id": "worker", "capability_ids": ["synthetic.render"],
                                "runtime_epoch": service.health()["runtime_epoch"]})
    finally:
        service.close()


def test_working_copy_uses_cas_and_requires_its_saved_base_at_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "preview", "name": "Preview"}, idempotency_key="project")
        project_id = project["id"]
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        service.register_capability({"capability_id": "rendering.timeline_visualize", "definition_digest": _digest("visualize")})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.timeline_visualize"]})
        base = {"config": {"clips": []}, "registry": {}, "clips": [], "occurrences": []}
        def insert_base():
            with service.store._transaction():
                service.store.conn.execute(
                    "INSERT INTO parent_composition_revisions(id,project_id,timeline_id,payload_json,content_digest,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    ("base", project_id, "main", canonical_json(base), _digest(base), now()),
                )
        insert_base()
        snapshot = {"config": {"clips": [{"id": "preview"}]}, "registry": {"assets": {}},
                    "metadata": {"working_copy": {
                        "candidate_parent_revision_id": "candidate", "candidate_digest": "sha256:" + "b" * 64,
                        "publication_digest": "sha256:" + "c" * 64,
                        "base_parent": {"revision_id": "base", "content_digest": _digest(base)},
                    }}}
        context = {"mode": "composed_capture", "project_id": project_id, "timeline_id": "main",
                   "revision_id": "candidate", "capture_snapshot": snapshot}
        task = service.create_task({
            "project": project_id, "capability_id": "rendering.timeline_visualize",
            "capability_digest": _digest("visualize"), "input_object_ids": [],
            "idempotency_key": "preview", "spec": {"inputs": {"filmstrip_authority": canonical_json(context)},
                                                 "authority_context": context},
        })["task"]
        ref = task["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
        assert ref["source_kind"] == "working_copy"
        assert ref["revision_id"] == "candidate"
        assert service.object(ref["digest"])[1] == canonical_json(snapshot).encode()
        with service.store._transaction():
            service.store.conn.execute("DELETE FROM parent_composition_revisions WHERE id='base'")
        claim = {"executor_id": "worker", "capability_ids": ["rendering.timeline_visualize"],
                 "runtime_epoch": service.health()["runtime_epoch"]}
        with pytest.raises(NotFoundError, match="base parent revision"):
            service.claim_next(claim)
        insert_base()
        assert service.claim_next(claim)["task_id"] == task["id"]
    finally:
        service.close()


def test_v28_inline_spec_migrates_with_exact_replay_and_compacts(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "migration", "name": "Migration"}, idempotency_key="project")
        project_id = project["id"]
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        parent = {"config": {"clips": []}, "registry": {"assets": {}}, "clips": [], "occurrences": []}
        with service.store._transaction():
            service.store.conn.execute(
                "INSERT INTO parent_composition_revisions(id,project_id,timeline_id,payload_json,content_digest,created_at) "
                "VALUES (?,?,?,?,?,?)",
                ("revision-1", project_id, "main", canonical_json(parent), _digest(parent), now()),
            )
        snapshot = {"config": {"clips": [{"id": "saved", "hold": 2}]}, "registry": {"assets": {}}}
        admitted = service.create_task({
            "project": project_id, "capability_id": "synthetic.render",
            "capability_digest": _digest("synthetic.render"), "input_object_ids": [],
            "idempotency_key": "render", "spec": {
                "timeline_snapshot": snapshot,
                "inputs": {"timeline_authority": {"project_id": project_id,
                    "timeline_id": "main", "parent_revision_id": "revision-1",
                    "parent_content_digest": _digest(parent)}},
            },
        })
        spec = admitted["task"]["spec"]
        ref = spec["spec"]["timeline_snapshot_ref"]
        legacy = restore_spec_snapshots(spec, lambda item: json.loads(service.object(item["digest"])[1]))
        legacy["input_object_ids"].remove(ref["digest"])
        body = canonical_json(legacy)
        legacy_digest = hashlib.sha256(body.encode()).hexdigest()
        with service.store._transaction():
            service.store.conn.execute(
                "INSERT INTO task_specs(digest,body_json,created_at) VALUES (?,?,?)",
                (legacy_digest, body, now()),
            )
            for table in ("runs", "tasks"):
                service.store.conn.execute(f"UPDATE {table} SET spec_digest=?", (legacy_digest,))
            service.store.conn.execute("DELETE FROM task_specs WHERE digest!=?", (legacy_digest,))
            service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (ref["digest"].removeprefix("sha256:"),))
            service.store.conn.execute("DELETE FROM objects WHERE digest=?", (ref["digest"].removeprefix("sha256:"),))
            service.store.conn.execute("ALTER TABLE timelines DROP COLUMN name")
            service.store.conn.execute("DROP TABLE user_app_state")
            service.store.conn.execute("DROP INDEX idx_generations_gen")
            service.store.conn.execute("UPDATE runtime_schema SET version=28 WHERE id=1")
        service.cas.path_for(ref["digest"].removeprefix("sha256:")).unlink()
        realm_id = service.realm["id"]
    finally:
        service.close()

    migrated = migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {realm_id}")
    assert migrated["steps"][-1]["target_schema_version"] == SCHEMA_VERSION
    reference_step = next(step for step in migrated["steps"] if step["source_schema_version"] == 28)
    assert reference_step["referenced_pairs"] == 1
    reopened = RuntimeService(root)
    try:
        task = reopened.task(admitted["task"]["id"])["task"]
        migrated_ref = task["spec"]["spec"]["timeline_snapshot_ref"]
        assert migrated_ref["revision_id"] == "revision-1"
        assert migrated_ref["digest"] == ref["digest"]
        assert json.loads(reopened.object(migrated_ref["digest"])[1]) == snapshot
        assert reopened.store.integrity_report()["ok"] is True
    finally:
        reopened.close()
    compacted = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert compacted["after_bytes"] <= compacted["before_bytes"]


def test_expired_parent_publish_body_keeps_bounded_receipt_facts(tmp_path):
    from datetime import datetime, timedelta, timezone

    root = tmp_path / "realm"
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    result = {"project_id": "project", "timeline_id": "main", "parent_revision_id": "revision",
              "content_digest": "sha256:" + "a" * 64, "event_id": "event-1",
              "dependency_manifest": {"shots": [], "internal_timelines": [], "media": []},
              "payload": {"config": {"clips": ["x" * 1_000_000]}}}
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds")
    with store._transaction():
        store.conn.execute(
            "INSERT INTO command_idempotency(command_kind,aggregate_id,idempotency_key,request_hash,result_json,created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("parent_composition.publish", "main", "publish", "request-hash", canonical_json(result), old),
        )
    store.close()
    compacted = compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    assert compacted["after_bytes"] < compacted["before_bytes"]
    reopened = RealmStore(root)
    try:
        body = reopened.conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='parent_composition.publish'"
        ).fetchone()[0]
        receipt = json.loads(body)
        assert len(body) < 1000
        assert receipt["parent_revision_id"] == "revision"
        assert receipt["event_id"] == "event-1"
        assert IDEMPOTENCY_RESULT_MARKER in receipt
        with pytest.raises(IdempotencyWindowExpired):
            command_result(body)
    finally:
        reopened.close()


def test_parent_receipt_compaction_preserves_publication_integrity(tmp_path):
    from datetime import datetime, timedelta, timezone

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "publication", "name": "Publication"}, idempotency_key="project")
        project_id = project["id"]
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        publication = {
            "project_id": project_id, "timeline_id": "main", "expected_head": None,
            "parent_revision_id": "parent-1",
            "parent_composition": {"config": {"clips": [], "tracks": []},
                                   "registry": {"assets": {}}, "clips": [], "occurrences": []},
            "shot_revisions": [], "internal_timeline_revisions": [],
            "dependency_manifest": {"shots": [], "internal_timelines": [], "media": []},
        }
        original = service.publish_parent_composition(project_id, "main", publication, idempotency_key="publish")
        with service.store._transaction():
            service.store.conn.execute(
                "UPDATE command_idempotency SET created_at=? WHERE command_kind='parent_composition.publish'",
                ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="milliseconds"),),
            )
            service.store.conn.execute(
                "UPDATE parent_composition_revisions SET created_at=? WHERE id='parent-1'",
                ((datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="milliseconds"),),
            )
        assert service.store.integrity_report()["ok"] is True
        realm_id = service.realm["id"]
    finally:
        service.close()
    compact_idempotency_ledger(root, confirmation=f"COMPACT IDEMPOTENCY {realm_id}")
    reopened = RuntimeService(root)
    try:
        assert reopened.store.integrity_report()["ok"] is True
        replay = reopened.publish_parent_composition(project_id, "main", publication, idempotency_key="publish")
        assert replay["data"] == original["data"]
        assert replay["receipt"]["result"] == original["receipt"]["result"]
        assert reopened.committed_receipt("parent_composition.publish", "main", "publish", project_id=project_id)["result"] == original["data"]
    finally:
        reopened.close()


@pytest.mark.integration
@pytest.mark.parametrize("failure", [None, "missing_parent_digest", "changed_parent_digest", "wrong_ingest_digest"])
def test_sdk_render_producer_ingest_reference_reaches_real_runtime_admission(tmp_path, failure, astrid_importable):
    """Exercise the production SDK publisher and Runtime reference validator together.

    The transport adapter delegates to the real in-process service and preserves
    its ingestion envelope. No task is executed and no renderer/browser starts.
    """
    from types import SimpleNamespace
    from astrid.packs.rendering.actions.render.managed_timeline import ManagedRenderSnapshot
    from astrid.sdk.invocation import _kernel_invoke
    from astrid.sdk.exceptions import CapabilityInvocationError
    from astrid.core.execution.executor import load_default_registry
    from astrid.core.foundation.hash import executor_definition_digest

    root = tmp_path / "producer-realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "producer", "name": "Producer"}, idempotency_key="project")["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        capability = load_default_registry().get("rendering.render")
        capability_digest = "sha256:" + executor_definition_digest(capability)
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability_digest})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        config = {"clips": [{"id": "saved", "at": 0, "hold": 1}]}
        registry = {"assets": {}}
        parent = {"config": config, "registry": registry, "clips": config["clips"], "occurrences": []}
        parent_digest = _digest(parent)
        with service.store._transaction():
            service.store.conn.execute(
                "INSERT INTO parent_composition_revisions(id,project_id,timeline_id,payload_json,content_digest,created_at) VALUES (?,?,?,?,?,?)",
                ("saved-parent", project, "main", canonical_json(parent), parent_digest, now()),
            )
        produced = ManagedRenderSnapshot(
            project_id=project, project_slug="producer", timeline_id="main", timeline_ulid="main", timeline_slug="main",
            config_version=1, head_event_id="saved-parent", head_hash=parent_digest.removeprefix("sha256:"),
            config=config, registry=registry, config_hash=_digest(config), registry_hash=_digest(registry),
            materialized_registry_hash=_digest(registry),
        )
        authority = produced.authority()
        # This is the actual producer field the SDK serializes, not a hand-built digest witness.
        assert authority["parent_content_digest"] == parent_digest
        if failure == "missing_parent_digest":
            authority.pop("parent_content_digest")
        elif failure == "changed_parent_digest":
            authority["parent_content_digest"] = "sha256:" + "0" * 64
        observations = {}

        class Transport:
            def ingest_project_object(self, project_id, data, *, filename, **kwargs):
                response = service.ingest(project_id, data, original_name=filename, **kwargs)
                assert isinstance(response["data"], dict) and response["data"]["digest"]
                observations["ingest_envelope"] = response
                if failure == "wrong_ingest_digest":
                    response = {**response, "data": {**response["data"], "digest": "sha256:" + "0" * 64}}
                return response

        class Tasks:
            def create(self, *, project_id, capability, spec, input_manifest, idempotency_key, storage_estimate=None):
                observations["outgoing_spec"] = spec
                admitted = service.create_task({
                    "project": project_id, "capability_id": capability, "capability_digest": capability_digest, "spec": spec,
                    "input_object_ids": input_manifest, "idempotency_key": idempotency_key,
                })["task"]
                observations["task"] = admitted
                return SimpleNamespace(ok=True, data={"run_id": admitted["run_id"], "task_id": admitted["id"]})

        client = SimpleNamespace(_transport=Transport(), tasks=Tasks())
        def invoke():
            return _kernel_invoke(capability, kind="executor", project=project,
                inputs={"timeline_ref": "main", "timeline_snapshot": {"config": config, "registry": registry}, "timeline_authority": authority},
                outputs={}, idempotency_key="producer-admission", _client=client)

        if failure is not None:
            expected = CapabilityInvocationError if failure == "wrong_ingest_digest" else NotFoundError
            message = "differs from prepared snapshot" if failure == "wrong_ingest_digest" else "parent revision is missing or changed"
            with pytest.raises(expected, match=message):
                invoke()
            assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
            assert service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
            return
        result = invoke()
        assert result[4]["ok"] is True
        task = observations["task"]
        ref = task["spec"]["spec"]["inputs"]["timeline_snapshot_ref"]
        snapshot = {"config": config, "registry": registry}
        assert ref["revision_id"] == "saved-parent" and ref["revision_digest"] == parent_digest
        assert ref["digest"] == _digest(snapshot)
        assert json.loads(service.object(ref["digest"])[1]) == snapshot
        assert "timeline_snapshot" not in observations["outgoing_spec"]["inputs"]
        assert service.claim_next({"executor_id": "worker", "capability_ids": ["rendering.render"],
                                   "runtime_epoch": service.health()["runtime_epoch"]})["task_id"] == task["id"]
    finally:
        service.close()
