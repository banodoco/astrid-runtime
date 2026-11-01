"""An exact head pair cannot invalidate verification of other mutable rows."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
import test_timeline_recorder_abi_authority as recorder_tests

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_port import RequestCommitPort
from runtime_protocol.util import canonical_json

recorder = recorder_tests.recorder


@pytest.mark.parametrize("mutation", [
    "unchanged", "metadata", "abi", "event", "receipt", "source", "owner", "physical_pin", "range", "aba",
])
def test_same_head_mutation_after_native_preflight_requires_fresh_authority(recorder, monkeypatch, mutation):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document

    runtime, project, fork, publish = recorder
    commits, _ = runtime._timeline_commits()
    submitted = fork(True)
    publish(submitted, "fork")
    expected = commits.head(project, "film")
    source = commits.revision_closure(project, "film", expected["revision_id"])
    submitted.update(base_revision_id=expected["revision_id"], base_publication_id=expected["publication_id"],
                     commands=[capture_track_create(bundle_from_document(source), "parent",
                                                    {"id": "next-track", "kind": "visual"})])
    original_accept = RequestCommitPort.accept
    reached = []

    def mutate():
        # A different handler can acquire this mutex after an outside check.
        # No delayed lock holder or sleep is needed to exhibit the interleaving.
        with runtime.store._mutex:
            conn = runtime.store.conn
            publication = expected["publication_id"]
            if mutation == "unchanged":
                return
            if mutation in {"metadata", "abi", "aba"}:
                row = conn.execute("SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?",
                                   (publication,)).fetchone()
                metadata = json.loads(row[0])
                metadata["recorder_abi" if mutation == "abi" else "label"] = "tampered"
                conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?",
                             (canonical_json(metadata), publication))
                if mutation == "aba":
                    previous = conn.execute(
                        "SELECT previous_revision_id, previous_publication_id FROM timeline_commit_history "
                        "WHERE publication_id=?", (publication,)).fetchone()
                    conn.execute("UPDATE parent_composition_heads SET revision_id=?, publication_id=? "
                                 "WHERE project_id=? AND timeline_id='film'", (*previous, project))
                    conn.execute("UPDATE parent_composition_heads SET revision_id=?, publication_id=? "
                                 "WHERE project_id=? AND timeline_id='film'",
                                 (expected["revision_id"], publication, project))
            elif mutation == "event":
                conn.execute("UPDATE timeline_events SET event_hash='tampered' WHERE timeline_id='film' "
                             "AND id=(SELECT MAX(id) FROM timeline_events WHERE timeline_id='film')")
            elif mutation == "receipt":
                conn.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
            elif mutation == "source":
                row = conn.execute("SELECT previous_revision_id FROM timeline_commit_history WHERE publication_id=?",
                                   (publication,)).fetchone()
                conn.execute("UPDATE parent_composition_revisions SET content_digest='tampered' WHERE id=?", (row[0],))
            else:
                row = conn.execute("SELECT records_json FROM timeline_commit_history WHERE publication_id=?",
                                   (publication,)).fetchone()
                records = json.loads(row[0])
                binding = next(binding for binding in records["commands"][0]["bindings"] if "physical_ref" in binding)
                if mutation == "owner":
                    binding["physical_ref"] = "internal-revision:foreign"
                elif mutation == "physical_pin":
                    binding["revision_id"] = "foreign-revision"
                else:
                    binding["write_range"] = [0, 999]
                conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                             (canonical_json(records), publication))

    def accept_after_mutation(port, prepared):
        assert prepared["expected_head"] == expected
        # This authenticates the exact genuine history before the outside /
        # inside boundary under consideration. Retaining this result across
        # that boundary would require more invalidation than the head pair.
        assert commits.head(project, "film") == expected
        assert not runtime.store._mutex._is_owned()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(mutate).result(timeout=10)
        with runtime.store._mutex:
            actual = runtime.store.conn.execute(
                "SELECT revision_id, publication_id FROM parent_composition_heads "
                "WHERE project_id=? AND timeline_id='film'", (project,)).fetchone()
            assert dict(actual) == expected  # A pair-only CAS would pass.
            before = tuple(runtime.store.conn.iterdump())
        reached.append(mutation)
        if mutation == "unchanged":
            return original_accept(port, prepared)
        with pytest.raises(RuntimeErrorBase) as error:
            original_accept(port, prepared)
        assert tuple(runtime.store.conn.iterdump()) == before
        raise error.value

    monkeypatch.setattr(RequestCommitPort, "accept", accept_after_mutation)
    if mutation == "unchanged":
        result = publish(submitted, "fork-after-outside-verification")
        assert result["data"]["status"] == "accepted"
        assert publish(submitted, "fork-after-outside-verification") == result
    else:
        with pytest.raises(RuntimeErrorBase):
            publish(submitted, "fork-after-outside-verification")
    assert reached == [mutation]
