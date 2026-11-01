"""Reuse only the fully authenticated bound within one locked history read."""
from __future__ import annotations

import base64
import copy
import json
from collections import Counter

import pytest
import test_timeline_commit_port as port_tests
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, prepared, request, rows

from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.util import canonical_json

service = port_tests.service


def listed(service, **kwargs):
    return service.list_timeline_commits(service.test_project, "main", authorize=lambda: None, **kwargs)


def test_production_history_authenticates_bound_once_and_preserves_exact_reply(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    commits, _ = service._timeline_commits()
    head = commits.head(service.test_project, "main")
    publications = service.store.conn.execute(
        "SELECT publication_id FROM timeline_commit_history ORDER BY project_seq").fetchall()
    expected = {"head": head, "next_cursor": None, "items": [
        commits.history_entry(service.test_project, "main", row[0]) for row in publications]}
    calls = Counter()
    original = commits._verify_accepted

    def verify(row, edge, **kwargs):
        assert service.store._mutex._is_owned()
        calls[edge["publication_id"]] += 1
        return original(row, edge, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted", verify)
    before = rows(service)
    actual = listed(service, limit=50)
    assert canonical_json(actual) == canonical_json(expected)
    assert actual["items"][-1]["receipt"] == accepted["receipt"]
    assert actual["items"][-1]["receipt"]["result"]["canonical_document"] == accepted["data"]["canonical_document"]
    assert calls == {accepted["receipt"]["receipt_id"]: 1}
    assert rows(service) == before

    # Returned objects and successful proofs never become authority for a later request.
    actual["items"][-1]["records"]["steps"].clear()
    assert listed(service, limit=50) == expected
    assert calls == {accepted["receipt"]["receipt_id"]: 2}


def test_pagination_and_later_mutation_keep_fixed_head_and_reverify(service, monkeypatch):
    provider(service)
    first = commit(service, body(service))
    expected = listed(service, limit=50)
    page = listed(service, limit=1)
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    change["value"] = {"org.example.timeline": {"note": "later"}}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    later = commit(service, next_body, key="later")
    commits, _ = service._timeline_commits()
    calls = Counter()
    original = commits._verify_accepted

    def verify(row, edge, **kwargs):
        calls[edge["publication_id"]] += 1
        return original(row, edge, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted", verify)
    tail = listed(service, cursor=page["next_cursor"], limit=1)
    assert {"head": tail["head"], "next_cursor": tail["next_cursor"],
            "items": page["items"] + tail["items"]} == expected
    assert calls == {first["receipt"]["receipt_id"]: 1}
    calls.clear()
    assert listed(service)["head"]["publication_id"] == later["receipt"]["receipt_id"]
    assert calls == {first["receipt"]["receipt_id"]: 1, later["receipt"]["receipt_id"]: 1}


def test_equal_revision_publications_are_each_authenticated(service, monkeypatch):
    service.test_provider.action = lambda context, port: port.accept(prepared(context, port, same=True))
    accepted = [commit(service, request(service, label=str(i)), key=f"same-{i}") for i in range(3)]
    commits, _ = service._timeline_commits()
    calls = Counter()
    original = commits._verify_accepted

    def verify(row, edge, **kwargs):
        calls[edge["publication_id"]] += 1
        return original(row, edge, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted", verify)
    page = listed(service)
    assert len(page["items"]) == 4
    assert len({entry["revision_id"] for entry in page["items"]}) == 1
    assert calls == {result["receipt"]["receipt_id"]: 1 for result in accepted}
    calls.clear()
    assert commits.history(service.test_project, "main", page["head"]) == page
    assert calls == {result["receipt"]["receipt_id"]: 1 for result in accepted}


@pytest.mark.parametrize("corruption", [
    "receipt", "event", "source", "binding", "dependency", "effect", "head", "cycle", "scope",
])
def test_later_request_rechecks_all_authority_and_never_writes(service, corruption):
    provider(service)
    accepted = commit(service, body(service))
    page = listed(service, limit=50)
    publication = accepted["receipt"]["receipt_id"]
    conn = service.store.conn
    if corruption == "receipt":
        conn.execute("UPDATE command_idempotency SET request_hash='tampered' WHERE txn_id=?", (publication,))
        # This fixture has no sequential capture, so its event-id authority is the receipt guard.
        conn.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
    elif corruption == "event":
        conn.execute("UPDATE timeline_events SET event_hash='tampered' WHERE id=?",
                     (accepted["receipt"]["event_ids"][-1],))
    elif corruption == "source":
        conn.execute("UPDATE parent_composition_revisions SET content_digest='tampered' WHERE id=?",
                     (accepted["data"]["previous_revision_id"],))
    elif corruption in {"binding", "dependency", "effect"}:
        row = conn.execute("SELECT records_json FROM timeline_commit_history WHERE publication_id=?",
                           (publication,)).fetchone()
        records = json.loads(row[0])
        command = records["commands"][0]
        if corruption == "binding":
            command["bindings"][0]["boundary"]["evaluated_head"]["publication_id"] = "foreign"
        elif corruption == "dependency":
            records["steps"][0]["dependencies"] = [{"kind": "field", "ref": "parent", "path": ["meta"],
                                                     "state": {"state": "present", "value": "forged"}}]
        else:
            command["writes"][0]["after"] = {"state": "present", "value": "forged"}
        conn.execute("UPDATE timeline_commit_history SET records_json=? WHERE publication_id=?",
                     (canonical_json(records), publication))
    elif corruption == "head":
        conn.execute("UPDATE parent_composition_heads SET revision_id=? WHERE timeline_id='main'",
                     (accepted["data"]["previous_revision_id"],))
    elif corruption == "cycle":
        baseline = page["items"][0]
        conn.execute("UPDATE timeline_commit_history SET previous_publication_id=?, previous_revision_id=? "
                     "WHERE publication_id=?", (baseline["publication_id"], baseline["revision_id"],
                                                baseline["publication_id"]))
    else:
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
        conn.execute("UPDATE timeline_commit_history SET project_id=? WHERE publication_id=?", (foreign, publication))
    before = rows(service)
    for _ in range(2):
        with pytest.raises(RuntimeErrorBase):
            listed(service, limit=50)
        assert rows(service) == before


@pytest.mark.parametrize("field", ["scope", "head"])
def test_cursor_scope_and_head_are_checked_again_without_writes(service, field):
    provider(service)
    commit(service, body(service))
    first = listed(service, limit=1)
    decoded = json.loads(base64.urlsafe_b64decode(first["next_cursor"]))
    if field == "scope":
        decoded["scope"][1] = "foreign"
    else:
        decoded["scope"][2]["revision_id"] = "foreign"
    cursor = base64.urlsafe_b64encode(canonical_json(decoded).encode()).decode()
    before = rows(service)
    with pytest.raises(RuntimeErrorBase):
        listed(service, cursor=cursor)
    assert rows(service) == before


def test_authorization_still_precedes_authenticated_history(service, monkeypatch):
    provider(service)
    commit(service, body(service))
    listed(service)
    commits, _ = service._timeline_commits()

    def forbidden():
        raise AuthorizationError("refused")

    def unreachable(*args, **kwargs):
        pytest.fail("history read before authorization")

    monkeypatch.setattr(commits, "_read_history", unreachable)
    before = rows(service)
    with pytest.raises(AuthorizationError):
        service.list_timeline_commits(service.test_project, "main", authorize=forbidden)
    assert rows(service) == before
