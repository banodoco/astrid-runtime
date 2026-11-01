from __future__ import annotations

import copy

import pytest

from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.util import canonical_json
from test_shot_composition_runtime import (
    _publication, _service, _validation_baseline, _validation_candidate, _validation_no_writes,
)


@pytest.mark.parametrize("location", ["root", "clip"])
@pytest.mark.parametrize("field,value", [
    ("occurrences", []), ("occurrence_records", []), ("parent_composition", {}),
    ("nested_composition", {}), ("occurrence_id", "nested-occurrence"),
    ("shot_revision_id", "nested-shot"), ("parent_revision_id", "nested-parent"),
    ("composition_revision_id", "nested-composition"),
])
def test_internal_nested_structure_refuses_before_any_write(tmp_path, location, field, value):
    service, project = _service(tmp_path)
    try:
        commits = _validation_baseline(service, project)
        body = _publication(project)
        payload = body["internal_timeline_revisions"][0]["payload"]
        target = payload if location == "root" else payload["clips"][0]
        target[field] = value
        pair = _validation_candidate(service, commits, body, "nested")
        commits.validate_prepared(pair[1])
        with _validation_no_writes(service):
            with pytest.raises(CommitRejected, match="nested") as caught:
                commits.accept(*pair, authorize=lambda: None)
            assert caught.value.failure["http_status"] == 422
            assert caught.value.failure["details"]["reason"] == "invalid_closure"
    finally:
        service.close()


def test_internal_opaque_graph_names_roundtrip_after_restart_and_retry(tmp_path):
    service, project = _service(tmp_path)
    root = service.store.root
    try:
        commits = _validation_baseline(service, project)
        body = _publication(project)
        payload = body["internal_timeline_revisions"][0]["payload"]
        opaque = {"occurrences": [], "occurrence_records": [], "parent_composition": {},
                  "nested_composition": {"shot_revision_id": "opaque-shot"},
                  "occurrence_id": "opaque-occurrence", "parent_revision_id": None,
                  "composition_revision_id": "opaque-composition"}
        for target in (payload, payload["clips"][0]):
            target["params"] = copy.deepcopy(opaque)
            target["provenance"] = {"history": [copy.deepcopy(opaque)]}
        payload["future_extension"] = {"clips": [copy.deepcopy(opaque)]}
        pair = _validation_candidate(service, commits, body, "opaque")
        expected = copy.deepcopy(pair[1]["canonical_document"])
        encoded = canonical_json(payload)
        accepted = commits.accept(*pair, authorize=lambda: None)
        revision = accepted["data"]["accepted_revision_id"]
        assert commits.revision_closure(project, "main", revision) == expected
        stored = service.store.conn.execute(
            "SELECT payload_json FROM internal_timeline_revisions WHERE id='timeline-rev-1'",
        ).fetchone()[0]
        assert stored == encoded
        service.close()
        service = RuntimeService(root)
        commits, _ = service._timeline_commits()
        assert commits.revision_closure(project, "main", revision) == expected
        with _validation_no_writes(service):
            assert commits.accept(*pair, authorize=lambda: None) == accepted
    finally:
        service.close()
