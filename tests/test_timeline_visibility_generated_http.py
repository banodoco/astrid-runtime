"""Generated-client coverage for catalog-only timeline visibility."""
from __future__ import annotations

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from test_timeline_authority_door import _snapshot, realm


def test_generated_client_preserves_restored_timeline_film_across_visibility_lifecycle(realm):
    daemon = realm.daemon
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project, timeline = realm.project, realm.timeline

    before = client.get_project_timeline(project, timeline)
    assert before["archived"] is False
    document_before = client.get_project_parent_composition_revision(
        project, timeline, before["head_revision_id"]
    )
    closure_before, closure_cursor = client.list_project_parent_composition_revisions(
        project, timeline
    )
    film_history_before, film_history_cursor = client.list_timeline_history(timeline)

    readonly_token, _ = daemon.credentials.provision("timeline-reader", ["projects:read"])
    readonly = WorkspaceClient(daemon.endpoint, readonly_token)
    unchanged = _snapshot(daemon.service)
    with pytest.raises(ApiError) as denied:
        readonly.archive_timeline(
            timeline, expected_version=before["version"], idempotency_key="visibility-readonly"
        )
    assert denied.value.status == 401
    assert _snapshot(daemon.service) == unchanged

    archived = client.archive_timeline(
        timeline, expected_version=before["version"], idempotency_key="visibility-archive"
    )
    assert archived["archived"] is True
    assert archived["version"] == before["version"] + 1
    assert {key: archived[key] for key in ("shots", "references")} == {
        key: before[key] for key in ("shots", "references")
    }

    recovered = client.recover_timeline(
        timeline,
        expected_version=archived["version"],
        version=archived["version"],
        idempotency_key="visibility-recover",
    )
    assert recovered["archived"] is False
    assert recovered["version"] == archived["version"] + 1
    assert {key: recovered[key] for key in ("shots", "references")} == {
        key: before[key] for key in ("shots", "references")
    }

    assert client.archive_timeline(
        timeline, expected_version=before["version"], idempotency_key="visibility-archive"
    ) == archived
    assert client.recover_timeline(
        timeline,
        expected_version=archived["version"],
        version=archived["version"],
        idempotency_key="visibility-recover",
    ) == recovered

    after = client.get_project_timeline(project, timeline)
    assert {
        key: after[key]
        for key in ("head_revision_id", "head_publication_id", "shots", "references")
    } == {
        key: before[key]
        for key in ("head_revision_id", "head_publication_id", "shots", "references")
    }
    assert client.get_project_parent_composition_revision(
        project, timeline, before["head_revision_id"]
    ) == document_before
    closure_after, closure_cursor_after = client.list_project_parent_composition_revisions(
        project, timeline
    )
    assert closure_after == closure_before
    assert closure_cursor_after == closure_cursor
    film_history_after, film_history_cursor_after = client.list_timeline_history(timeline)
    assert film_history_after == film_history_before
    assert film_history_cursor_after == film_history_cursor
