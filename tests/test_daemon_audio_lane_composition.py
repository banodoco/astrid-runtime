"""Actual daemon startup and HTTP inspect with the admitted installed SDK.

RUNTIME_AUDIO_LANE_ASTRID_SOURCE is a test-only source checkout import. Product
composition always imports the fixed installed module, without a source option.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest

import runtime_protocol.daemon as daemon_module
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json
from test_timeline_audio_lane_inspection import OPTIONS, database_state, publication


@pytest.fixture
def installed_astrid(monkeypatch):
    source = os.environ.get("RUNTIME_AUDIO_LANE_ASTRID_SOURCE")
    if not source:
        pytest.skip("requires the explicitly admitted Astrid source checkout")
    monkeypatch.syspath_prepend(source)
    from astrid.sdk import authoring_bundle

    assert Path(authoring_bundle.__file__).resolve().is_relative_to(Path(source).resolve())
    return authoring_bundle


def start_fixture(tmp_path, *, adopted=True):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        project = daemon.service.create_project(
            {"slug": "synthetic-audio", "name": "Synthetic audio"}, idempotency_key="project",
        )["id"]
        daemon.service.create_timeline(project, "main", idempotency_key="timeline")
        daemon.service.publish_parent_composition(
            project, "main", publication(project, adopted=adopted), idempotency_key="publish",
        )
        reader, _ = daemon.credentials.provision("reader", ["projects:read"])
        return daemon, project, reader
    except BaseException:
        daemon.stop()
        raise


def request(daemon, project, reader, options):
    req = urllib.request.Request(
        f"{daemon.endpoint}/v1/projects/{project}/timelines/main/inspect",
        data=json.dumps(options).encode(), method="POST",
        headers={"Authorization": f"Bearer {reader}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def evidence(name, before, after, **details):
    # Optional durable synthetic evidence, never a product source/data input.
    destination = os.environ.get("RUNTIME_AUDIO_LANE_EVIDENCE_DIR")
    if destination:
        root = Path(destination)
        root.mkdir(parents=True, exist_ok=True)
        for suffix, state in (("before", before), ("after", after)):
            (root / f"{name}-{suffix}.sql").write_text("\n".join(state) + "\n")
        (root / f"{name}.json").write_text(json.dumps({
            "unchanged": before == after,
            "store_sha256": hashlib.sha256("\n".join(before).encode()).hexdigest(),
            **details,
        }, indent=2, sort_keys=True) + "\n")


@pytest.mark.parametrize("adopted", [True, False])
def test_daemon_startup_actual_adapter_http_pinned_closure_and_no_mutation(
    tmp_path, monkeypatch, installed_astrid, adopted,
):
    sdk = installed_astrid
    real_open = sdk.open_authoring_bundle
    real_adapter = sdk.project_audio_lane_for_authoring_bundle
    opened, projected = [], []

    def observe_open(parent, *, shot_revisions, internal_timeline_revisions):
        bundle = real_open(parent, shot_revisions=shot_revisions,
                           internal_timeline_revisions=internal_timeline_revisions)
        opened.append((copy.deepcopy((parent, shot_revisions, internal_timeline_revisions)), bundle))
        return bundle

    def observe_adapter(bundle, *, capabilities):
        assert bundle is opened[-1][1]  # Complete, unedited result of real open.
        pristine = copy.deepcopy(bundle)
        result = real_adapter(bundle, capabilities=capabilities)
        assert bundle == pristine
        projected.append((pristine, copy.deepcopy(capabilities), copy.deepcopy(result)))
        return result

    monkeypatch.setattr(sdk, "open_authoring_bundle", observe_open)
    monkeypatch.setattr(sdk, "project_audio_lane_for_authoring_bundle", observe_adapter)
    daemon, project, reader = start_fixture(tmp_path, adopted=adopted)
    try:
        service = daemon.service
        assert service._timeline_audio_lane_provider is sdk.project_audio_lane_for_runtime_inspection
        assert not getattr(service, "_timeline_inspect_started", False)
        with pytest.raises(ConflictError, match="fixed"):
            service.register_timeline_audio_lane_provider(lambda **kw: None)
        before = database_state(service)
        code, result = request(daemon, project, reader, OPTIONS)
        after = database_state(service)
        assert code == 200, result
        assert after == before  # Every table: heads, documents, revisions, OpCalls/journal.
        assert len(opened) == len(projected) == 1
        bundle, capabilities, lane = projected[0]
        assert capabilities == OPTIONS["supported_capabilities"] == ["adopted-music-bed"]
        assert result["presentation"]["audio_lane"] == lane == real_adapter(bundle, capabilities=capabilities)
        assert (lane is not None) == adopted
        parent, shots, internals = opened[0][0]
        def revision_bytes(record):
            return {key: value for key, value in record.items() if key != "created_at"}

        assert parent == revision_bytes(service.get_project_parent_composition_revision(project, "main", "lane-1"))
        assert len(shots) == len(internals) == 2
        for row in shots:
            assert row == revision_bytes(service.get_project_shot_revision(project, row["shot_id"], row["revision_id"]))
        for row in internals:
            assert row == revision_bytes(service.get_project_timeline_revision(project, row["timeline_id"], row["revision_id"]))
        assert result["revision_id"] == parent["revision_id"] == bundle["base_parent"]["revision_id"]
        assert result["parent_content_digest"] == bundle["base_parent"]["content_digest"]
        expected_digest = "sha256:" + hashlib.sha256(canonical_json({
            "schema": result["schema"], "parent": parent["content_digest"],
            "children": [row["occurrence"] for row in result["selected"]],
        }).encode()).hexdigest()
        assert result["snapshot_digest"] == expected_digest
        evidence(f"installed-{'bed' if adopted else 'no-bed'}", before, after,
                 response=result, parent=parent, shots=shots, internals=internals,
                 authoring_bundle=bundle, caller_capabilities=capabilities)

        # A new head must not alter a subsequent explicitly pinned presentation.
        service.publish_parent_composition(project, "main", publication(
            project, adopted=not adopted, revision="lane-2", expected_head="lane-1",
        ), idempotency_key="new-head")
        before = database_state(service)
        code, pinned = request(daemon, project, reader, {**OPTIONS, "revision_id": "lane-1"})
        assert code == 200, pinned
        assert pinned["revision_id"] == "lane-1" and pinned["head_revision_id"] == "lane-2"
        assert pinned["snapshot_digest"] == result["snapshot_digest"]
        assert pinned["presentation"] == result["presentation"]
        assert opened[1][0] == opened[0][0]
        assert projected[1] == projected[0]
        assert database_state(service) == before

        for unsupported in ([], ["projects:read"], ["unknown"]):
            code, refusal = request(daemon, project, reader, {
                **OPTIONS, "supported_capabilities": unsupported,
            })
            assert code == 409 and refusal["code"] == "unavailable"
        assert len(opened) == 2  # Unsupported callers never reach the producer.
        assert database_state(service) == before
    finally:
        daemon.stop()
        assert daemon.httpd is None and daemon.thread is None


@pytest.mark.parametrize("installation", ["absent", "older-sdk"])
def test_daemon_without_installed_adapter_refuses_presentation(tmp_path, monkeypatch, installation):
    real_import = daemon_module.import_module

    def missing_adapter(name):
        assert name == "astrid.sdk.authoring_bundle"
        if installation == "absent":
            raise ModuleNotFoundError("No module named astrid", name="astrid")
        return SimpleNamespace()  # Installed older SDK has no optional export.

    monkeypatch.setattr(daemon_module, "import_module", missing_adapter)
    daemon, project, reader = start_fixture(tmp_path)
    try:
        assert getattr(daemon.service, "_timeline_audio_lane_provider", None) is None
        before = database_state(daemon.service)
        code, result = request(daemon, project, reader, OPTIONS)
        assert code == 409 and result["code"] == "unavailable"
        assert "not installed" in result["message"]
        assert request(daemon, project, reader, {})[0] == 200
        # Installing later cannot change a service's already-fixed unavailable binding.
        monkeypatch.setattr(daemon_module, "import_module", real_import)
        assert request(daemon, project, reader, OPTIONS)[0] == 409
        with pytest.raises(ConflictError, match="fixed"):
            daemon.service.register_timeline_audio_lane_provider(lambda **kw: None)
        after = database_state(daemon.service)
        assert before == after
        evidence(f"unavailable-{installation}", before, after, refusal=result)
    finally:
        daemon.stop()
