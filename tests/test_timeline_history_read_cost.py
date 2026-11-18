"""Reading a timeline's history costs one pass over its media, not one per revision.

A film's accepted closure pins every media object it uses.  History reads
authenticate each entry by replaying it against that closure, and the
physical CAS bytes of every consumed object are re-checked because CAS lives
outside SQLite's change boundary.  Those re-checks used to run at every nested
verification boundary: listing ten revisions of an imported film re-read and
re-hashed its whole media archive (230 MB) about sixty times and timed out.
This test pins the physical read count of a cold history read to a small
constant per distinct object, independent of the number of revisions.
"""
from __future__ import annotations

import copy
from collections import Counter

import pytest
import test_timeline_commit_integration as real
from test_timeline_commit_authentication import candidate
from test_timeline_commit_port import PreparedProvider

from runtime_protocol import cas as cas_module
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_validation import validate_commit_value

film = real.film

# A cold read touches each object when it is first consumed and once more in
# the final check before anything leaves the request.  Allow a little slack
# for the head check, but nothing that grows with the revision count.
_READS_PER_OBJECT = 3


def _body(service, project, timeline, note, before):
    head = service.get_project_timeline(project, timeline)
    change = {"op": "set", "ref": "parent", "path": ["meta"], "before": before,
              "value": {"org.example.timeline": {"note": note}}}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    return {"api_version": 1, "project_id": project, "timeline_id": timeline,
            "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
            "commands": [command], "label": "Annotate film", "merge": "fields", "reads": [],
            "steps": [{"id": "note", "label": "Opening note", "intent": "Annotate", "tags": [],
                       "command_ordinals": [0], "patch": [change]}]}, change


def _edit(service, project, timeline, count):
    def execute(context, port):
        value = candidate(context, port)
        validate_commit_value(value, "PreparedCommit")
        return port.accept(value)

    service.register_timeline_commit_provider(PreparedProvider(execute))
    service.list_timeline_commits(project, timeline, authorize=lambda: None)
    before = {"state": "absent"}
    for index in range(count):
        body, change = _body(service, project, timeline, f"note {index}", before)
        service.commit_timeline(project, timeline, body, idempotency_key=f"note-{index}",
                                publisher="history-cost", invocation_path=route_path(project, timeline),
                                authorize=lambda: None)
        before = {"state": "present", "value": copy.deepcopy(change["value"])}


def _cold_reads(service, monkeypatch, read):
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    counts = Counter()
    original = cas_module.ContentAddressedStore.read

    def counted(self, digest, **kwargs):
        counts[digest] += 1
        return original(self, digest, **kwargs)

    monkeypatch.setattr(cas_module.ContentAddressedStore, "read", counted)
    try:
        result = read()
    finally:
        monkeypatch.setattr(cas_module.ContentAddressedStore, "read", original)
    return result, counts


@pytest.mark.parametrize("revisions", [2, 8])
def test_cold_history_and_head_reads_check_media_a_bounded_number_of_times(film, monkeypatch, revisions):
    project, timeline = film.fixture.project_id, film.fixture.timeline_id
    service = RuntimeService(film.fixture.duplicate_root)
    try:
        _edit(service, project, timeline, revisions)
        page, counts = _cold_reads(service, monkeypatch, lambda: service.list_timeline_commits(
            project, timeline, limit=50, authorize=lambda: None))
        recorded = [entry for entry in page["items"] if entry["intent"] == "recorded"]
        assert len(recorded) == revisions
        assert counts, "history read must still check physical CAS bytes"
        assert max(counts.values()) <= _READS_PER_OBJECT, counts

        # Opening the head (limit 1) is no dearer than listing everything.
        _, head_counts = _cold_reads(service, monkeypatch, lambda: service.list_timeline_commits(
            project, timeline, limit=1, authorize=lambda: None))
        assert max(head_counts.values()) <= _READS_PER_OBJECT, head_counts
    finally:
        service.close()


def test_bounded_history_read_still_refuses_changed_media_bytes(film, monkeypatch):
    project, timeline = film.fixture.project_id, film.fixture.timeline_id
    service = RuntimeService(film.fixture.duplicate_root)
    try:
        _edit(service, project, timeline, 3)
        commits, _ = service._timeline_commits()
        service.list_timeline_commits(project, timeline, limit=50, authorize=lambda: None)
        media = next(iter(commits._history_state["objects"]))
        path = service.cas.path_for(media)
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with pytest.raises(RuntimeErrorBase):
            service.list_timeline_commits(project, timeline, limit=50, authorize=lambda: None)
        assert not any(commits._history_state.values())
    finally:
        service.close()
