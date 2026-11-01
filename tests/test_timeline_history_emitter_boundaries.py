"""Exercise private history tags at their real guards and public callers."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_timeline_commit_acceptance import context, counts, prepared
from test_timeline_commit_port import prepared as port_prepared
from test_timeline_commit_redacted_diagnostics import Provider, _diagnostic

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_port import digest
from runtime_protocol.util import canonical_json

pytest_plugins = ["test_timeline_commit_acceptance"]


def _commit(service, project, request):
    return service.commit_timeline(
        project, "main", copy.deepcopy(request["request"]),
        idempotency_key=request["idempotency_key"], publisher=request["publisher"],
        invocation_path=request["invocation"]["path"], authorize=lambda: None,
    )


def _public_history(call, capsys, tag, message="history_unavailable", *, status=409, body=None,
                    idempotency_key=None):
    with pytest.raises(RuntimeErrorBase) as caught:
        call()
    assert caught.value.status == status
    assert caught.value.as_dict() == (body if body is not None else {
        "code": "conflict", "message": message,
        "details": {"status": "refused", "reason": "history_unavailable",
                    "base": None, "current": None, "conflicts": []},
    })
    stderr = capsys.readouterr().err
    assert "private-sentinel" not in stderr
    value = _diagnostic(stderr)
    assert len(stderr.encode()) <= 4096
    if idempotency_key is None:
        assert set(value) == {"event", "request_id", "reason", "exception_class_chain", "frames"}
    else:
        assert set(value) == {"event", "request_id", "reason", "exception_class_chain", "frames",
                              "idempotency_key_sha256"}
        assert value["idempotency_key_sha256"] == hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        assert idempotency_key not in stderr
    assert value["event"] == "timeline_commit_error"
    assert re.fullmatch("[a-f0-9]{32}", value["request_id"])
    assert value["exception_class_chain"] == []
    assert value["frames"] == []
    assert value["reason"] == tag
    return value


STORE_CASES = [
    "membership_missing", "head_missing", "head_revision_mismatch",
    "head_canonical_mismatch", "head_catalog_corrupt", "archived_scope_missing",
    "history_entry_missing", "history_ledger_mismatch", "history_bound_revision_mismatch",
    "history_bound_order_invalid", "history_chain_break", "history_through_mismatch",
    "revision_scope_missing", "revision_missing", "revision_dependency_missing",
    "occurrence_rows_mismatch", "occurrence_row_mismatch", "dependency_rows_mismatch",
    "shot_revision_scope_missing", "history_ancestry_cycle", "history_base_outside_ancestry",
    "inverse_stage_targets_unavailable", "request_base_mismatch", "adopt_existing_head",
    "adopt_nonempty_scope", "adopt_existing_parent", "adopt_legacy_shell_mismatch",
    "adopt_prior_publication", "bootstrap_unpublished_head",
]


@pytest.mark.parametrize("case", STORE_CASES)
def test_store_emitter_public_boundary(realm, monkeypatch, capsys, case):
    service, commits, project, head, _ = realm
    conn = service.store.conn
    document = commits.revision_closure(project, "main", head["revision_id"])
    entry = commits.history_entry(project, "main", head["publication_id"])
    message = "history_unavailable"
    call = lambda: commits.head(project, "main")
    if case == "membership_missing":
        call = lambda: commits.head(project, "absent")
    elif case == "head_missing":
        conn.execute("UPDATE parent_composition_heads SET publication_id=NULL")
    elif case == "head_revision_mismatch":
        # A non-null, retained but different revision reaches the pair guard.
        value = copy.deepcopy(document)
        value["parent_revision"]["revision_id"] = "other-parent"
        commits._persist_closure(value)
        conn.execute("UPDATE parent_composition_heads SET revision_id='other-parent'")
    elif case == "head_canonical_mismatch":
        ctx = context(service, project, head)
        accepted = commits.accept(ctx, prepared(commits, ctx), authorize=lambda: None)
        version = service._timeline_resource("main")["version"]
        service.archive_timeline("main", {"expected_version": version}, idempotency_key="archive")
        service.recover_timeline("main", {"expected_version": version + 1}, idempotency_key="recover")
        original = commits.revision_closure

        def changed(*args, **kwargs):
            value = original(*args, **kwargs)
            value["parent_revision"]["payload"]["private-sentinel"] = "private-sentinel"
            return value

        monkeypatch.setattr(commits, "revision_closure", changed)
        assert accepted["receipt"]
        message = "canonical film differs from accepted publication"
    elif case == "head_catalog_corrupt":
        version = service._timeline_resource("main")["version"]
        service.archive_timeline("main", {"expected_version": version}, idempotency_key="archive")
        service.recover_timeline("main", {"expected_version": version + 1}, idempotency_key="recover")
        conn.execute("UPDATE timeline_revisions SET shots_json=?", ('{"x":1,"x":2}',))
        message = "timeline catalog facts are corrupt"
    elif case == "archived_scope_missing":
        call = lambda: commits.history_entry(project, "absent", head["publication_id"], allow_archived=True)
    elif case == "history_entry_missing":
        call = lambda: commits.history_entry(project, "main", "absent")
    elif case == "history_ledger_mismatch":
        conn.execute("UPDATE timeline_commit_history SET project_seq=project_seq+1")
    elif case.startswith("history_bound_") or case in {"history_chain_break", "history_through_mismatch"}:
        through, bound = copy.deepcopy(head), copy.deepcopy(entry)
        after = None
        if case == "history_bound_revision_mismatch":
            through["revision_id"] = "other"
        elif case == "history_bound_order_invalid":
            bound["receipt"]["project_seq"][0] = 0
            after = head["publication_id"]
        elif case == "history_chain_break":
            bound["previous"] = head
        else:
            through["publication_id"] = "different-publication"
        call = lambda: commits._history_page(project, "main", through, bound, after_publication_id=after, limit=100)
    elif case == "revision_scope_missing":
        call = lambda: commits.revision_closure(project, "absent", head["revision_id"], allow_archived=True)
    elif case == "revision_missing":
        call = lambda: commits.revision_closure(project, "main", "absent")
    elif case == "revision_dependency_missing":
        manifest = copy.deepcopy(document["dependency_manifest"])
        manifest["shots"] = [{"revision_id": "absent"}]
        conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json=?", (canonical_json(manifest),))
        call = lambda: commits.revision_closure(project, "main", head["revision_id"])
    elif case in {"occurrence_rows_mismatch", "occurrence_row_mismatch", "dependency_rows_mismatch"}:
        if case == "occurrence_rows_mismatch":
            document["parent_revision"]["payload"]["occurrences"] = [{"occurrence_id": "absent"}]
        elif case == "occurrence_row_mismatch":
            document = _child_document(document)
            commits._persist_closure(document)
            conn.execute("UPDATE composition_revision_occurrences SET duration_ms=duration_ms+1")
        else:
            document["dependency_manifest"]["media"] = [{"media_id": "absent", "content_digest": "absent"}]
        call = lambda: commits._verify_parent_rows(document)
    elif case == "shot_revision_scope_missing":
        document["timeline_id"] = "absent"
        call = lambda: commits._validate_closure(document, allow_archived=True)
    elif case in {"history_ancestry_cycle", "history_base_outside_ancestry"}:
        if case == "history_ancestry_cycle":
            conn.execute("UPDATE timeline_commit_history SET previous_revision_id=?, previous_publication_id=?",
                         (head["revision_id"], head["publication_id"]))
            message = "history ancestry contains a cycle"
        else:
            message = "base is outside evaluated head ancestry"
        call = lambda: commits._binding_continuations(project, "main", "absent", head)
    elif case == "inverse_stage_targets_unavailable":
        message = "inverse stage history targets are unavailable"
        call = lambda: commits._inverse_stage_history(project, "main", {"commands": [{"bindings": [{"key": "inverse.stage"}]}]})
    elif case == "request_base_mismatch":
        bad_head = {**head, "revision_id": "different"}
        call = lambda: commits._check_context(context(service, project, bad_head))
    elif case.startswith("adopt_"):
        if case != "adopt_existing_head":
            conn.execute("UPDATE parent_composition_heads SET publication_id=NULL")
            # Use an independent empty shell so retained bootstrap rows do not
            # mask the later adoption guards.
            service.create_timeline(project, "shell", name="Shell", idempotency_key="shell")
            call = lambda: commits.adopt_empty_shell(project, "shell", authorize=lambda: None)
            if case == "adopt_nonempty_scope":
                conn.execute("UPDATE timeline_revisions SET shots_json='[{}]' WHERE timeline_id='shell'")
            elif case == "adopt_existing_parent":
                other = copy.deepcopy(document)
                other["timeline_id"] = "shell"
                other["parent_revision"]["revision_id"] = "shell-parent"
                commits._persist_closure(other)
            elif case == "adopt_legacy_shell_mismatch":
                conn.execute("UPDATE internal_timeline_revisions SET payload_json='{}' WHERE timeline_id='shell'")
            elif case == "adopt_prior_publication":
                conn.execute("UPDATE command_idempotency SET command_kind='parent_composition.publish', aggregate_id='shell' WHERE txn_id=?", (head["publication_id"],))
        else:
            call = lambda: commits.adopt_empty_shell(project, "main", authorize=lambda: None)
    elif case == "bootstrap_unpublished_head":
        conn.execute("UPDATE parent_composition_heads SET publication_id=NULL")
        call = lambda: commits.bootstrap(project, "main", authorize=lambda: None)
    commits.clear_replay_memo()
    before = counts(service)
    _public_history(lambda: service._verified_read(project, lambda: None, call), capsys, "store_" + case, message)
    assert counts(service) == before


def _child_document(document):
    document = copy.deepcopy(document)
    internal_payload = {"clips": [], "tracks": []}
    internal = {"timeline_id": "shot:child", "revision_id": "internal-child", "payload": internal_payload,
                "content_digest": digest(internal_payload)}
    payload = {"internal_timeline_revision_id": internal["revision_id"], "items": []}
    shot = {"shot_id": "child", "revision_id": "revision-child", "payload": payload,
            "internal_timeline_revision_id": internal["revision_id"], "content_digest": digest(payload)}
    parent = document["parent_revision"]
    parent["revision_id"] = "parent-child"
    parent["payload"]["occurrences"] = [{"occurrence_id": "occ-child", "shot_id": "child",
        "shot_revision_id": "revision-child", "placement": {"start_ms": 0}, "duration_ms": 1000,
        "source_offset": 0, "speed": 1, "track": "picture", "transform": {}, "gain": 1,
        "muted": False, "provenance": {}}]
    parent["content_digest"] = digest(parent["payload"])
    document["shot_revisions"] = [shot]
    document["internal_timeline_revisions"] = [internal]
    document["dependency_manifest"]["shots"] = [{k: shot[k] for k in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}]
    document["dependency_manifest"]["internal_timelines"] = [{k: internal[k] for k in ("timeline_id", "revision_id", "content_digest")}]
    return document


@pytest.mark.parametrize("case,message", [
    ("ancestor_pin_mismatch", "publication/revision pins disagree"),
    ("ancestor_outside_request", "publication is outside request ancestry"),
    ("history_bounds_mismatch", "history bounds disagree"),
    ("revision_outside_ancestry", "revision is outside request ancestry or declared source"),
    ("base_pins_mismatch", "base pins disagree"),
    ("candidate_head_unobserved", "candidate head was not observed through this port"),
])
def test_port_emitter_public_boundary(realm, capsys, case, message):
    service, _, project, head, _ = realm
    base = {**head, "revision_id": "different"} if case in {"ancestor_pin_mismatch", "base_pins_mismatch"} else head
    ctx = context(service, project, base, "port-" + case)

    def action(bound, port):
        if case == "ancestor_pin_mismatch":
            return port.history_entry(head["publication_id"])
        if case == "ancestor_outside_request":
            return port.history_entry("absent")
        if case == "history_bounds_mismatch":
            return port.history({**head, "revision_id": "different"})
        if case == "revision_outside_ancestry":
            return port.revision_closure("absent")
        if case == "base_pins_mismatch":
            port.head()
            return port.revision_closure(bound["request"]["base_revision_id"])
        candidate = port_prepared(bound, port)
        candidate["expected_head"] = {**head, "publication_id": "unobserved"}
        return port.accept(candidate)

    service.register_timeline_commit_provider(Provider(action))
    before = counts(service)
    _public_history(lambda: _commit(service, project, ctx), capsys, "port_" + case, message,
                    idempotency_key=ctx["idempotency_key"])
    assert counts(service) == before


@pytest.mark.parametrize("case", ["ambiguous", "parent_missing"])
def test_shot_emitter_public_boundary(realm, monkeypatch, capsys, case):
    service, commits, project, head, _ = realm
    document = _child_document(commits.revision_closure(project, "main", head["revision_id"]))
    commits._persist_closure(document)
    if case == "ambiguous":
        # Retain the shot while making its sole owner's input manifest absent.
        service.store.conn.execute("UPDATE parent_composition_revisions SET commit_manifest_json=NULL WHERE id='parent-child'")
        tag, message = "store_shot_input_closure_ambiguous", "shot input closure is unavailable or ambiguous"
    else:
        # Fault at the SQL boundary between the two owner queries: the first
        # authenticates one manifest, the second observes an absent owner.
        original = service.store.conn

        class MissingOwner:
            def __getattr__(self, name):
                return getattr(original, name)

            def execute(self, query, parameters=()):
                if query.startswith("SELECT p.timeline_id, p.id FROM parent_composition_revisions p "):
                    return original.execute(query.replace("ORDER BY p.id LIMIT 1", "AND 0 ORDER BY p.id LIMIT 1"), parameters)
                return original.execute(query, parameters)

        monkeypatch.setattr(service.store, "conn", MissingOwner())
        tag, message = "store_shot_parent_missing", "history_unavailable"
    _public_history(lambda: service._verified_read(project, lambda: None,
        lambda: commits.shot_closure(project, "child", "revision-child")), capsys, tag, message)


def test_reference_prepare_real_guard_public_boundary(realm, monkeypatch, capsys):
    service, _, project, head, _ = realm
    request = context(service, project, head, "projection-prepare")
    import runtime_protocol.timeline_commit_reference_projection as projection

    original = projection.prepare_reference_projection

    def changed_scope(connection, document, previous_document, **kwargs):
        previous_document = {**previous_document, "timeline_id": "different"}
        return original(connection, document, previous_document, **kwargs)

    monkeypatch.setattr(projection, "prepare_reference_projection", changed_scope)
    service.register_timeline_commit_provider(Provider(lambda bound, port: port.accept(port_prepared(bound, port))))
    before = counts(service)
    _public_history(lambda: _commit(service, project, request), capsys, "store_reference_projection_prepare_history",
                    idempotency_key=request["idempotency_key"])
    assert counts(service) == before


@pytest.mark.parametrize("case", ["publication_dependency", "corrupt_publication_facts", "source_publication_missing", "unretained_document_dependency", "other_guard"])
def test_baseline_real_guards_public_boundary(tmp_path, monkeypatch, capsys, case):
    from baseline_fixture import load_baseline_fixture
    from test_shot_composition_runtime import _rehash_timeline_events

    from runtime_protocol.errors import NotFoundError
    from runtime_protocol.timeline_commit_baseline import (
        verify_baseline,
        verify_revision_source,
    )

    service, project, (accepted,) = load_baseline_fixture(tmp_path, variant="explicit-media" if case == "publication_dependency" else "single")
    try:
        conn = service.store.conn
        assert conn is not None
        read_object = service.cas.read
        integrity = "source_publication_missing"
        call = lambda: verify_baseline(conn, project, "main", read_object=read_object)
        if case == "publication_dependency":
            def unavailable(_):
                raise NotFoundError("private-sentinel")
            read_object = unavailable
            integrity = "publication_dependency_unavailable:not_found"
        elif case == "corrupt_publication_facts":
            conn.execute('UPDATE parent_composition_revisions SET payload_json=?', ('{"x":1,"x":2}',))
            integrity = "missing_or_corrupt_publication_facts:ValueError"
        elif case == "source_publication_missing":
            call = lambda: verify_revision_source(conn, project, "main", "absent", read_object=read_object)
        elif case == "unretained_document_dependency":
            event_id = int(accepted["data"]["event_id"])
            payload = json.loads(conn.execute("SELECT payload_json FROM timeline_events WHERE id=?", (event_id,)).fetchone()[0])
            payload["dependency_manifest"]["documents"] = [{"document_id": "private-sentinel", "version": 1, "content_digest": "sha256:" + "1" * 64}]
            result = copy.deepcopy(accepted["data"])
            result["dependency_manifest"] = payload["dependency_manifest"]
            conn.execute("UPDATE command_idempotency SET result_json=? WHERE txn_id=?", (canonical_json(result), accepted["receipt"]["receipt_id"]))
            _rehash_timeline_events(service, "main", replacements={event_id: payload})
            integrity = "unretained_document_dependency"
        else:
            conn.execute("UPDATE parent_composition_revisions SET content_digest=?", ("sha256:" + "0" * 64,))
            integrity = "revision_digest_mismatch"
        before = conn.total_changes
        with pytest.raises(RuntimeErrorBase) as caught:
            service._verified_read(project, lambda: None, call)
        assert caught.value.status == 409
        assert caught.value.as_dict() == {
            "code": "conflict", "message": "timeline publication history is unavailable",
            "details": {"status": "refused", "reason": "history_unavailable", "integrity_reason": integrity},
        }
        stderr = capsys.readouterr().err
        assert "private-sentinel" not in stderr
        value = _diagnostic(stderr)
        tag = "history_provider_or_store_guard" if case == "other_guard" else "history_baseline_" + case
        assert value["reason"] == tag
        assert value["exception_class_chain"] == value["frames"] == []
        assert len(stderr.encode()) <= 4096
        assert conn.total_changes == before
    finally:
        service.close()


@pytest.mark.parametrize("caller", ["list", "verified_read", "commit", "create"])
def test_service_history_callers_keep_exact_public_failure(realm, capsys, caller):
    service, _, project, head, _ = realm
    commits, _ = service._timeline_commits()
    if caller == "create":
        service.register_timeline_commit_provider(Provider(lambda *_: None))
        call = lambda: service.create_timeline(project, "main", name="Main", idempotency_key="new-create")
        expected = {"code": "conflict", "message": "timeline already exists", "details": {"timeline_id": "main"}}
        tag = "store_adopt_existing_head"
    else:
        service.store.conn.execute("UPDATE timeline_commit_history SET project_seq=project_seq+1")
        if caller == "list":
            call = lambda: service.list_timeline_commits(project, "main", authorize=lambda: None)
        elif caller == "verified_read":
            call = lambda: service._verified_read(project, lambda: None, lambda: commits.head(project, "main"))
        else:
            service.register_timeline_commit_provider(Provider(lambda bound, port: port.head()))
            call = lambda: _commit(service, project, context(service, project, head, "caller"))
        expected = {"code": "conflict", "message": "history_unavailable", "details": {
            "status": "refused", "reason": "history_unavailable", "base": None, "current": None, "conflicts": []}}
        tag = "store_history_ledger_mismatch"
    with pytest.raises(RuntimeErrorBase) as caught:
        call()
    assert caught.value.status == 409
    assert caught.value.as_dict() == expected
    assert _diagnostic(capsys.readouterr().err)["reason"] == tag


def test_history_diagnostic_sink_failure_keeps_public_envelope(realm, monkeypatch):
    service, _, project, head, _ = realm
    request = context(service, project, head, "sink-disabled")
    service.register_timeline_commit_provider(Provider(lambda _, port: port.history_entry("absent")))

    def disabled(_):
        raise OSError("private-sentinel")

    monkeypatch.setattr("runtime_protocol.timeline_commit_execution.sys.stderr.write", disabled)
    with pytest.raises(RuntimeErrorBase) as caught:
        _commit(service, project, request)
    assert caught.value.status == 409
    assert caught.value.as_dict() == {"code": "conflict", "message": "publication is outside request ancestry", "details": {
        "status": "refused", "reason": "history_unavailable", "base": None, "current": None, "conflicts": []}}


def test_concurrent_history_refusals_have_private_distinct_request_ids(realm, capsys):
    service, _, project, head, _ = realm
    service.register_timeline_commit_provider(Provider(lambda _, port: port.history_entry("absent")))

    def invoke(index):
        request = context(service, project, head, f"private-sentinel-{index}")
        with pytest.raises(RuntimeErrorBase) as caught:
            _commit(service, project, request)
        assert caught.value.status == 409
        assert caught.value.as_dict() == {"code": "conflict", "message": "publication is outside request ancestry", "details": {
            "status": "refused", "reason": "history_unavailable", "base": None, "current": None, "conflicts": []}}

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(invoke, range(8)))
    stderr = capsys.readouterr().err
    assert "private-sentinel" not in stderr
    lines = stderr.splitlines()
    assert len(lines) == 8
    values = [_diagnostic(line) for line in lines]
    assert len({value["request_id"] for value in values}) == 8
    assert all(value["reason"] == "port_ancestor_outside_request" for value in values)


def test_reference_apply_real_guard_public_boundary(realm, monkeypatch, capsys):
    import runtime_protocol.timeline_commit_reference_projection as projection

    service, _, project, head, _ = realm
    request = context(service, project, head, "projection-apply", op="fixture.inspect")
    media = service.ingest(project, b"private-sentinel", idempotency_key="projection-media")["data"]["object_id"]
    pin = {"media_id": media, "content_digest": media}
    request["request"]["commands"][0]["args"] = {"media_pin": pin}

    def action(bound, port):
        candidate = port_prepared(bound, port)
        document = candidate["canonical_document"]
        document["dependency_manifest"]["media"] = [pin]
        parent = document["parent_revision"]
        parent["payload"]["config"]["app"] = {"astrid": {"timeline_references": {
            "reference": {"version": 1, "reference_id": "reference", "role": "source", "media": pin}}}}
        parent["content_digest"] = digest(parent["payload"])
        candidate["document_digest"] = digest(document)
        port.raw_media_info(pin)
        return port.accept(candidate)

    original = projection.prepare_reference_projection

    def changed_version(*args, **kwargs):
        value = original(*args, **kwargs)
        service.store.conn.execute("UPDATE timelines SET version=version+1 WHERE id='main'")
        return value

    monkeypatch.setattr(projection, "prepare_reference_projection", changed_version)
    service.register_timeline_commit_provider(Provider(action))
    before = counts(service)
    _public_history(
        lambda: _commit(service, project, request), capsys, "store_reference_projection_apply_history",
        status=503, body={"code": "not_ready",
                          "message": "Timeline commit outcome unavailable; retry the exact request",
                          "details": {"reason": "runtime_unavailable"}},
        idempotency_key=request["idempotency_key"],
    )
    assert counts(service) == before
