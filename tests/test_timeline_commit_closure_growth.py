"""Historical closure reads reuse only the live request's proven ancestry."""
from __future__ import annotations

import copy

import pytest
import test_timeline_commit_authentication as auth
from test_timeline_commit_port import commit

from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase

service = auth.service


@pytest.mark.parametrize("length", [4, 8])
def test_historical_closures_have_linear_ancestry_cost(service, monkeypatch, length):
    auth.provider(service)
    publications, revisions = [], []
    for number in range(length):
        submitted = auth.body(service)
        change = submitted["commands"][0]["args"]["changes"][0]
        if number:
            change["before"] = {"state": "present", "value": {"org.example.timeline": {"note": str(number - 1)}}}
        change["value"] = {"org.example.timeline": {"note": str(number)}}
        submitted["steps"][0]["patch"] = [copy.deepcopy(change)]
        accepted = commit(service, submitted, key=f"closure-{number}")
        publications.append(accepted["receipt"]["receipt_id"])
        revisions.append(accepted["data"]["accepted_revision_id"])

    commits, _ = service._timeline_commits()
    original = commits._history_entry_view
    calls, ports, revoked = [], [], []

    def counted(*args, **kwargs):
        calls.append(args[2])
        return original(*args, **kwargs)

    def authorize():
        if revoked:
            raise AuthorizationError("revoked")

    monkeypatch.setattr(commits, "_history_entry_view", counted)

    def execute(context, port):
        ports.append(port)
        calls.clear()
        port.history_entry(publications[0])
        assert len(calls) >= length, "another request retained ancestry authority"
        calls.clear()
        expected = []
        for revision in revisions:
            document = port.revision_closure(revision)
            expected.append(copy.deepcopy(document))
            document["parent_revision"]["payload"].clear()
        assert len(calls) <= 2 * length, "historical closures walked proven ancestry again"
        for revision, document in zip(revisions, expected):
            assert port.revision_closure(revision) == document
        revoked.append(True)
        with pytest.raises(AuthorizationError, match="revoked"):
            port.revision_closure(revisions[0])
        revoked.clear()
        # Revocation discards reachability. A changed history must also be
        # authenticated afresh before an uncaptured revision can be returned.
        port.history_entry(publications[0])
        service.store.conn.execute("SAVEPOINT closure_tamper")
        service.store.conn.execute(
            "UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (publications[1],))
        with pytest.raises(RuntimeErrorBase):
            port.history_entry(publications[0])
        service.store.conn.execute("ROLLBACK TO closure_tamper")
        service.store.conn.execute("RELEASE closure_tamper")
        raise AuthorizationError("end closure control")

    service.test_provider.action = execute
    for number in range(2):
        with pytest.raises(AuthorizationError, match="end closure control"):
            commit(service, auth.body(service), key=f"closure-read-{number}", authorize=authorize)
        with pytest.raises(AuthorizationError, match="closed"):
            ports[-1].revision_closure(revisions[0])
