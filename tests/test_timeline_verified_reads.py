"""Exercise public timeline head and history through the Runtime request dispatcher."""
import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.door import classify
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import digest
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, service
from test_timeline_commit_routes import make_handler


def handler(runtime, route, *, project=None, timeline="main"):
    if project is None:
        project = runtime.test_project
    path = f"/v1/projects/{quote(project, safe='')}/timelines/{quote(timeline, safe='')}/{route}"
    return make_handler(runtime, b"", path=path, command="GET")


def test_verified_head_route_returns_exact_accepted_closure_without_history(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    project = service.test_project
    head = {"revision_id": accepted["data"]["accepted_revision_id"],
            "publication_id": accepted["receipt"]["receipt_id"]}
    commits, _ = service._timeline_commits()
    document = commits.revision_closure(project, "main", head["revision_id"])
    monkeypatch.setattr(service, "list_timeline_commits", lambda *args, **kwargs: pytest.fail("listed history"))

    request = handler(service, "verified-head")
    request._dispatch()
    assert request.reply == (200, {
        "project_id": project, "timeline_id": "main", "head": head,
        "canonical_document": document,
    })
    assert request.scopes_seen and set(request.scopes_seen) == {"projects:read"}
    parent = document["parent_revision"]
    assert parent["revision_id"] == head["revision_id"]
    assert parent["content_digest"] == digest(parent["payload"])
    assert classify("/api/runtime" + request.path, "GET") is not None


def test_handshake_advertises_verified_head_with_existing_core_digest(service):
    handshake = service.handshake({
        "authenticated_actor": "editor", "authenticated_scopes": ["projects:read"],
        "requested_scopes": ["projects:read"],
    })
    assert "timeline.verified_head.v1" in handshake["capabilities"]
    assert handshake["schema_digest"] == SCHEMA_DIGEST


def test_verified_head_denies_authority_and_other_timeline_scope(service):
    def refuse():
        raise AuthorizationError("read revoked")

    with pytest.raises(AuthorizationError, match="read revoked"):
        service.get_timeline_verified_head(service.test_project, "main", authorize=refuse)
    with pytest.raises(RuntimeErrorBase, match="timeline not found"):
        service.get_timeline_verified_head(service.test_project, "elsewhere", authorize=lambda: None)


def next_request(runtime):
    request = body(runtime)
    change = request["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    change["value"] = {"org.example.timeline": {"note": "second"}}
    request["steps"][0]["patch"] = [copy.deepcopy(change)]
    return request


@pytest.mark.parametrize("route", ["commits?limit=1", "verified-head"])
def test_cold_replay_does_not_block_commit_or_publish_a_stale_current_head(service, monkeypatch, route):
    provider(service)
    first = commit(service, body(service))
    first_publication = first["receipt"]["receipt_id"]
    request = next_request(service)
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    reading = threading.Event()
    resume = threading.Event()
    verify = TimelineCommitStore._verify_accepted_record

    def blocked(self, row, edge, **kwargs):
        if threading.current_thread().name.startswith("history-reader") and not reading.is_set():
            assert edge["publication_id"] == first_publication
            reading.set()
            assert resume.wait(15), "reader barrier was never released"
        return verify(self, row, edge, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_record", blocked)
    public = handler(service, route)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="history-reader") as reader, \
            ThreadPoolExecutor(max_workers=1) as writer:
        read = reader.submit(public._dispatch)
        try:
            assert reading.wait(5), f"cold replay did not reach barrier: {getattr(public, 'reply', None)}"
            written = writer.submit(commit, service, request, key="second")
            accepted = written.result(timeout=5)
            assert accepted["data"]["status"] == "accepted"
        finally:
            resume.set()
        read.result(timeout=5)

    assert public.reply[0] in (200, 409, 503), public.reply
    if public.reply[0] == 200:
        assert public.reply[1]["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
