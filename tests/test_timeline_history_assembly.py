"""Fresh history authentication walks a dependency graph, not recursive paths."""
from __future__ import annotations

import json
from collections import Counter

import pytest
import test_timeline_commit_input_integration as inputs
import test_timeline_commit_integration as real

import runtime_protocol.timeline_commit_inputs as input_store
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import RequestCommitPort
from runtime_protocol.util import canonical_json

film = real.film
agent = real.agent
editing = real.editing
retained = inputs.retained
pytestmark = pytest.mark.integration


def inverse_chain(editing, count):
    change = {"op": "set", "ref": "parent", "path": ["meta"],
              "before": {"state": "absent"}, "value": {"org.example.note": {"text": "Note"}}}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    accepted = []
    for ordinal in range(count):
        if accepted:
            command = real.inverse(accepted[-1]["receipt"]["receipt_id"])
        body = editing.body([command])
        if not accepted:
            body["steps"][0]["patch"] = [change]
        accepted.append(editing.commit(body, f"assembly-{ordinal}"))
    return accepted


def note_curve(editing, count):
    change = {"op": "set", "ref": "parent", "path": ["meta"],
              "before": {"state": "absent"}, "value": {"org.example.note": {}}}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    body = editing.body([command])
    body["steps"][0]["patch"] = [change]
    seed = editing.commit(body, "notes-seed")
    base = {"revision_id": seed["data"]["accepted_revision_id"],
            "publication_id": seed["receipt"]["receipt_id"]}
    accepted = []
    for ordinal in range(count):
        change = {"op": "set", "ref": "parent", "path": ["meta", "org.example.note", f"note-{ordinal}"],
                  "before": {"state": "absent"}, "value": f"Note {ordinal}"}
        command = {**command, "args": {"changes": [change]}}
        body = editing.body([command], base=base)
        body["steps"][0]["patch"] = [change]
        accepted.append(editing.commit(body, f"note-{ordinal}"))
    return accepted


@pytest.mark.parametrize("count", [2, 4, 8])
def test_provider_history_lookup_authenticates_each_graph_node_once(editing, monkeypatch, count):
    accepted = note_curve(editing, count)
    commits, _ = editing.service._timeline_commits()
    calls = Counter()
    verify = commits._verify_accepted_record

    def counted(row, edge, **kwargs):
        calls[edge["publication_id"]] += 1
        return verify(row, edge, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted_record", counted)
    target = accepted[-1]["receipt"]["receipt_id"]
    # Exercise the supported provider port inside real commit execution. Stop
    # before acceptance so only the history read contributes to the bound.
    observed = []
    provider_type = type(editing.service._timeline_commit_provider)

    class ReadComplete(RuntimeErrorBase):
        pass

    def read_only(self, context, port):
        assert isinstance(port, RequestCommitPort)
        calls.clear()
        entry = port.history_entry(target)
        observed.append(entry)
        assert set(calls) == {value["receipt"]["receipt_id"] for value in accepted}
        assert max(calls.values()) == 1
        raise ReadComplete("history read complete")

    monkeypatch.setattr(provider_type, "commit", read_only)
    with pytest.raises(ReadComplete):
        editing.commit(editing.body([real.inverse(target)]), "assembly-read")
    assert observed[0]["receipt"] == accepted[-1]["receipt"]


@pytest.mark.parametrize("mutation", ["ancestor", "parent", "event", "metadata", "file", "rewind", "fork", "aba"])
def test_dependency_graph_is_fresh_between_provider_lookups(editing, monkeypatch, mutation):
    accepted = inverse_chain(editing, 4)
    commits, _ = editing.service._timeline_commits()
    conn = editing.service.store.conn
    target = accepted[-1]["receipt"]["receipt_id"]
    project, timeline = editing.project, editing.timeline
    provider_type = type(editing.service._timeline_commit_provider)
    reached = []

    def read_then_mutate(self, context, port):
        assert port.history_entry(target)["receipt"] == accepted[-1]["receipt"]
        publication = accepted[0]["receipt"]["receipt_id"]
        if mutation in {"ancestor", "parent"}:
            column = "revision_id" if mutation == "ancestor" else "previous_revision_id"
            conn.execute(f"UPDATE timeline_commit_history SET {column}=? WHERE publication_id=?",
                         (accepted[-1 if mutation == "ancestor" else 0]["data"]["accepted_revision_id"], publication))
        elif mutation == "event":
            conn.execute("UPDATE timeline_events SET payload_json='{}' WHERE id=?",
                         (accepted[0]["receipt"]["event_ids"][-1],))
        elif mutation in {"metadata", "aba"}:
            head = commits.head(project, timeline)
            conn.execute("UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?",
                         (publication,))
            if mutation == "aba":
                conn.execute("UPDATE parent_composition_heads SET publication_id=? WHERE project_id=? AND timeline_id=?",
                             (publication, project, timeline))
                conn.execute("UPDATE parent_composition_heads SET publication_id=? WHERE project_id=? AND timeline_id=?",
                             (head["publication_id"], project, timeline))
        elif mutation == "file":
            media = accepted[0]["data"]["canonical_document"]["dependency_manifest"]["media"][0]["media_id"]
            path = editing.service.cas.path_for(media.removeprefix("sha256:"))
            path.write_bytes(b"corrupt physical media")
        else:
            conn.execute("UPDATE timeline_commit_history SET previous_publication_id=? WHERE publication_id=?",
                         (publication if mutation == "rewind" else target, target))
        before = real.rows(editing.service)
        with pytest.raises(RuntimeErrorBase):
            port.history_entry(target)
        assert real.rows(editing.service) == before
        reached.append(True)
        raise ReadComplete("history read complete")

    class ReadComplete(RuntimeErrorBase):
        pass

    monkeypatch.setattr(provider_type, "commit", read_then_mutate)
    with pytest.raises(ReadComplete):
        editing.commit(editing.body([real.inverse(target)]), "mutated-read")
    assert reached == [True]
    with pytest.raises(RuntimeErrorBase):
        commits.history_entry(project, timeline, target)


@pytest.mark.parametrize("attack", ["queued-row", "indirect-cycle"])
def test_unverified_dependencies_cannot_escape_the_graph(editing, monkeypatch, attack):
    accepted = inverse_chain(editing, 2)
    commits, _ = editing.service._timeline_commits()
    target = accepted[-1]["receipt"]["receipt_id"]
    seed = accepted[0]["receipt"]["receipt_id"]
    original = commits._inverse_stage_history

    def attacked(project, timeline, records, **kwargs):
        history = original(project, timeline, records, **kwargs)
        if history and attack == "queued-row":
            # The dependency has been read but not yet authenticated. Its live
            # row must still match when the worklist reaches it.
            editing.service.store.conn.execute(
                "UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?", (seed,))
        elif not history and attack == "indirect-cycle":
            commits.history_entry(project, timeline, target)
        return history

    monkeypatch.setattr(commits, "_inverse_stage_history", attacked)
    with commits.verification_scope():
        with pytest.raises(RuntimeErrorBase):
            commits.history_entry(editing.project, editing.timeline, target)
        assert commits._verification.current["traversal"] is None
        assert not commits._verification.current["active"]
        assert not commits._verification.current["verified"]


def test_reopened_runtime_rechecks_ancestors_before_exact_retry(editing, monkeypatch):
    accepted = inverse_chain(editing, 2)
    seed, undone = accepted
    base = {"revision_id": seed["data"]["accepted_revision_id"],
            "publication_id": seed["receipt"]["receipt_id"]}
    body = editing.body([real.inverse(seed["receipt"]["receipt_id"])], base=base)
    root = editing.service.store.root
    editing.service.close()
    runtime = RuntimeService(root)
    try:
        runtime.register_timeline_commit_provider(editing.agent.provider())
        reopened = real.Editing(runtime, editing.film, editing.agent)

        def forbidden(*args):
            raise AssertionError("exact retry executed provider")

        monkeypatch.setattr(type(runtime._timeline_commit_provider), "commit", forbidden)
        assert reopened.commit(body, "assembly-1") == undone
        conn = runtime.store.conn
        assert conn is not None
        conn.execute("UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?",
                     (seed["receipt"]["receipt_id"],))
        before = real.rows(runtime)
        with pytest.raises(RuntimeErrorBase):
            reopened.commit(body, "assembly-1")
        assert real.rows(runtime) == before
    finally:
        runtime.close()


@pytest.mark.parametrize("boundary", ["collection", "replay", "pins"])
@pytest.mark.parametrize("mutation", [
    "metadata", "parent", "event", "file", "abi", "ledger", "records",
    "source", "closure", "owner", "realm", "sequence", "pin", "queued-cycle", "deleted-row",
])
def test_provider_refuses_inputs_changed_after_ancestor_check(editing, monkeypatch, boundary, mutation):
    accepted = inverse_chain(editing, 4)
    commits, _ = editing.service._timeline_commits()
    conn = editing.service.store.conn
    target = accepted[-1]["receipt"]["receipt_id"]
    seed = accepted[0]["receipt"]["receipt_id"]
    if mutation == "owner":
        editing.service.create_timeline(editing.project, "forged", idempotency_key="foreign-owner")
    elif mutation == "realm":
        conn.execute("INSERT INTO realm SELECT 'forged', display_name, created_at, updated_at FROM realm LIMIT 1")
    edge = conn.execute("SELECT * FROM timeline_commit_history WHERE publication_id=?", (seed,)).fetchone()
    original = getattr(commits, "_verify_accepted_record" if boundary == "collection" else "_verify_accepted_replay")
    mutated, refused = [], []

    def mutate():
        if mutated:
            return
        if mutation in {"metadata", "abi", "records"}:
            column = "records_json" if mutation == "records" else "metadata_json"
            value = json.loads(edge[column])
            if mutation == "metadata":
                value = {}
            elif mutation == "abi":
                value["recorder_abi"] = 1
            else:
                value["steps"][0]["patch"] = []
            conn.execute(f"UPDATE timeline_commit_history SET {column}=? WHERE publication_id=?",
                         (canonical_json(value), seed))
        elif mutation in {"parent", "queued-cycle"}:
            conn.execute("UPDATE timeline_commit_history SET previous_publication_id=? WHERE publication_id=?",
                         (target, seed))
        elif mutation == "event":
            conn.execute("UPDATE timeline_events SET payload_json='{}' WHERE id=?",
                         (accepted[0]["receipt"]["event_ids"][-1],))
        elif mutation == "file":
            media = accepted[0]["data"]["canonical_document"]["dependency_manifest"]["media"][0]["media_id"]
            editing.service.cas.path_for(media.removeprefix("sha256:")).write_bytes(b"changed after check")
        elif mutation == "ledger":
            conn.execute("UPDATE command_idempotency SET request_hash='forged' WHERE txn_id=?", (seed,))
        elif mutation == "source":
            conn.execute("UPDATE parent_composition_revisions SET payload_json='{}' WHERE id=?",
                         (edge["previous_revision_id"],))
        elif mutation == "closure":
            conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json='{}' WHERE id=?",
                         (edge["revision_id"],))
        elif mutation == "owner":
            conn.execute("UPDATE parent_composition_revisions SET timeline_id='forged' WHERE id=?",
                         (edge["previous_revision_id"],))
        elif mutation == "realm":
            conn.execute("UPDATE projects SET realm_id='forged' WHERE id=?", (editing.project,))
        elif mutation == "sequence":
            conn.execute("UPDATE project_sequences SET next_seq=1 WHERE project_id=?", (editing.project,))
        elif mutation == "pin":
            conn.execute("UPDATE composition_revision_dependencies SET content_digest='forged' WHERE parent_revision_id=?",
                         (edge["previous_revision_id"],))
        else:
            conn.execute("DELETE FROM command_idempotency WHERE txn_id=?", (seed,))
        mutated.append(seed)

    def after_ancestor(row, history, *args, **kwargs):
        result = original(row, history, *args, **kwargs)
        if history["publication_id"] == seed:
            mutate()
        return result

    pin_read = input_store.reachable_document_input_pins

    def after_pins(*args, **kwargs):
        result = pin_read(*args, **kwargs)
        mutate()
        return result

    class ReadComplete(RuntimeErrorBase):
        pass

    def read_only(self, context, port):
        assert isinstance(port, RequestCommitPort)
        if boundary == "pins":
            monkeypatch.setattr(input_store, "reachable_document_input_pins", after_pins)
        else:
            monkeypatch.setattr(commits, "_verify_accepted_record" if boundary == "collection" else "_verify_accepted_replay",
                                after_ancestor)
        if boundary == "replay":
            # Exercise the existing mid-replay mutation on a cold D88b memo.
            # Collection and pin cases still exercise the warm read path.
            commits.clear_replay_memo()
        with pytest.raises(RuntimeErrorBase):
            port.history_entry(target)
        assert mutated == [seed]
        assert commits._verification.current["traversal"] is None
        assert commits._verification.current["inputs"] is None
        assert not commits._verification.current["active"]
        refused.append(True)
        raise ReadComplete("history refused")

    monkeypatch.setattr(type(editing.service._timeline_commit_provider), "commit", read_only)
    with pytest.raises(RuntimeErrorBase):
        editing.commit(editing.body([real.inverse(target)]), "callback-attack")
    assert refused == [True]


@pytest.mark.parametrize("boundary", ["collection", "replay", "pins"])
@pytest.mark.parametrize("mutation", ["content", "binding", "link"])
def test_provider_refuses_retained_inputs_changed_after_check(retained, monkeypatch, boundary, mutation):
    case = retained
    request = inputs.body(case.film, inputs.head(case.service, case.film), [inputs.captured_move(case)])
    request.update(label="Retained input freshness", steps=[{
        "id": "move", "label": "Move", "intent": "Move with retained inputs", "tags": [],
        "command_ordinals": [0], "patch": [], "reads": [],
    }])
    moved = inputs.commit(case.service, case.film, request, "fresh-input-move")
    target = moved["receipt"]["receipt_id"]
    request.update(base_revision_id=moved["data"]["accepted_revision_id"], base_publication_id=target)
    commits, _ = case.service._timeline_commits()
    method = "_verify_accepted_record" if boundary == "collection" else "_verify_accepted_replay"
    owner = input_store if boundary == "pins" else commits
    if boundary == "pins":
        method = "reachable_document_input_pins"
    original = getattr(owner, method)
    mutated, refused = [], []

    def after_check(*args, **kwargs):
        result = original(*args, **kwargs)
        if not mutated:
            conn = case.service.store.conn
            if mutation == "content":
                changed = conn.execute("UPDATE timeline_document_input_contents SET content_json='{}' WHERE content_digest=?",
                                       (case.pin["content_digest"],))
            elif mutation == "binding":
                changed = conn.execute("UPDATE timeline_document_input_bindings SET kind='forged' WHERE content_digest=?",
                                       (case.pin["content_digest"],))
            else:
                changed = conn.execute("DELETE FROM timeline_document_input_links WHERE content_digest=?",
                                       (case.pin["content_digest"],))
            assert changed.rowcount > 0
            mutated.append(True)
        return result

    class ReadComplete(RuntimeErrorBase):
        pass

    def read_only(self, context, port):
        monkeypatch.setattr(owner, method, after_check)
        if boundary == "replay":
            commits.clear_replay_memo()
        with pytest.raises(RuntimeErrorBase):
            port.history_entry(target)
        assert mutated == [True]
        refused.append(True)
        raise ReadComplete("retained inputs refused")

    monkeypatch.setattr(type(case.service._timeline_commit_provider), "commit", read_only)
    with pytest.raises(ReadComplete):
        inputs.commit(case.service, case.film, request, "changed-retained-input")
    assert refused == [True]


@pytest.mark.parametrize("boundary", ["history", "closure", "head"])
def test_provider_refuses_mutation_after_dependent_history_reads(editing, monkeypatch, boundary):
    import runtime_protocol.timeline_catalog as catalog

    accepted = inverse_chain(editing, 2)
    commits, _ = editing.service._timeline_commits()
    seed = accepted[0]["receipt"]["receipt_id"]
    through = {"publication_id": accepted[-1]["receipt"]["receipt_id"],
               "revision_id": accepted[-1]["data"]["accepted_revision_id"]}
    owner = catalog if boundary == "head" else commits
    method = {"history": "_history_page", "closure": "revision_closure", "head": "verify_catalog_tail"}[boundary]
    original = getattr(owner, method)
    mutated = []

    def after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        if commits._verification.current["traversal"] is None and not mutated:
            editing.service.store.conn.execute(
                "UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?", (seed,))
            mutated.append(seed)
        return result

    class ReadComplete(RuntimeErrorBase):
        pass

    def read_only(self, context, port):
        monkeypatch.setattr(owner, method, after_read)
        with pytest.raises(RuntimeErrorBase):
            if boundary == "history":
                port.history(through)
            elif boundary == "closure":
                port.revision_closure(through["revision_id"])
            else:
                port.head()
        assert mutated == [seed]
        assert commits._verification.current["inputs"] is None
        raise ReadComplete("dependent history read refused")

    monkeypatch.setattr(type(editing.service._timeline_commit_provider), "commit", read_only)
    with pytest.raises(ReadComplete):
        editing.commit(editing.body([real.inverse(through["publication_id"])]), "late-dependent-read")


def test_provider_read_freshness_isolated_after_refusal_and_between_requests(editing, monkeypatch):
    accepted = inverse_chain(editing, 2)
    commits, _ = editing.service._timeline_commits()
    target = accepted[-1]["receipt"]["receipt_id"]
    seed = accepted[0]["receipt"]["receipt_id"]
    conn = editing.service.store.conn
    metadata = conn.execute("SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?", (seed,)).fetchone()[0]
    original = input_store.reachable_document_input_pins
    scopes = []

    class ReadComplete(RuntimeErrorBase):
        pass

    def read_only(self, context, port):
        def after_pins(*args, **kwargs):
            result = original(*args, **kwargs)
            scopes.append(commits._verification.current["inputs"])
            conn.execute("UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?", (seed,))
            return result

        with monkeypatch.context() as attack:
            attack.setattr(input_store, "reachable_document_input_pins", after_pins)
            with pytest.raises(RuntimeErrorBase):
                port.history_entry(target)
        assert commits._verification.current["inputs"] is None
        conn.execute("UPDATE timeline_commit_history SET metadata_json=? WHERE publication_id=?", (metadata, seed))
        assert port.history_entry(target)["receipt"] == accepted[-1]["receipt"]
        assert commits._verification.current["inputs"] is None
        raise ReadComplete("fresh read after refusal")

    monkeypatch.setattr(type(editing.service._timeline_commit_provider), "commit", read_only)
    for ordinal in range(2):
        with pytest.raises(ReadComplete):
            editing.commit(editing.body([real.inverse(target)]), f"isolated-fresh-read-{ordinal}")
        assert getattr(commits._verification, "current", None) is None
    assert len(scopes) == 2 and scopes[0] is not scopes[1]
