"""Retained inputs through the installed Agent, not a semantic test double.

Only the initial input pin uses prepared-provider acceptance: M1 has no first
source-authoring command. This seed proves Runtime retention, not end-to-end
authoring. All measured moves, inverse, replay and compilation use real Agent.
"""
from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from precut_realm_fixture import load_precut_realm_fixture
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import RequestCommitPort, digest, route_path
from timeline_commit_film_fixture import FilmFixture

pytestmark = pytest.mark.integration


def head(service, film):
    value = service.get_project_timeline(film.project_id, film.timeline_id)
    return {"revision_id": value["head_revision_id"],
            "publication_id": value["head_publication_id"]}


def body(film, base, commands):
    return {"api_version": 1, "project_id": film.project_id, "timeline_id": film.timeline_id,
            "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"],
            "commands": copy.deepcopy(commands), "source": {"via": "python"}}


def commit(service, film, request, key, authorize=lambda: None):
    return service.commit_timeline(
        film.project_id, film.timeline_id, request, idempotency_key=key,
        publisher="retained-input-editor", invocation_path=route_path(film.project_id, film.timeline_id),
        authorize=authorize,
    )


def document(service, film):
    return service._timeline_commits()[0].revision_closure(
        film.project_id, film.timeline_id, head(service, film)["revision_id"],
    )


def history(service, film):
    return service.list_timeline_commits(film.project_id, film.timeline_id, authorize=lambda: None)["items"]


def snapshot(service):
    return tuple(service.store.conn.iterdump())


@pytest.fixture(params=["transcript", "config"])
def retained(request, tmp_path, astrid_importable, monkeypatch):
    # Import Agent only inside this explicitly selected integration fixture.
    from astrid.sdk.timeline import commands as core
    from astrid.sdk.timeline import commit as agent
    from astrid.sdk.timeline.capture import capture_move, capture_track_create
    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    assert Path(agent.__file__).resolve().is_relative_to(astrid_importable)
    captured = load_precut_realm_fixture(tmp_path, variant="anchor")
    pins = captured.pins
    film = FilmFixture(
        source_root=captured.copy_roots[0],
        duplicate_root=captured.copy_roots[1],
        project_id=pins["project_id"],
        timeline_id=pins["timeline_id"],
        parent_revision_id=pins["parent_revision_id"],
        media_ids=pins["media_ids"],
        transcript_document_id=pins["transcript_document_id"],
        text_binding_id=pins["text_binding_id"],
    )
    service = RuntimeService(film.duplicate_root)
    try:
        transcript = service.get_document(film.project_id, film.transcript_document_id)
        config = service.get_document(film.project_id, "film.config")
        sources = [config, transcript]
        captures = [{"pin": {"document_id": source["document_id"], "version": source["version"],
                              "content_digest": digest(source["content"])}, "document": source}
                    for source in sources]
        selected = captures[1 if request.param == "transcript" else 0]
        source, pin = selected["document"], selected["pin"]
        class InitialInputAcceptance:
            provider_id = "astrid-v1"
            interface_version = 1
            contract_digest = SCHEMA_DIGEST

            def commit(self, context, port):
                base = port.head()
                candidate = port.revision_closure(base["revision_id"])
                dependencies = []
                for capture in captures:
                    transcript_input = capture["document"]["kind"] == "media.transcript"
                    read = port.transcript_source if transcript_input else port.config_source
                    assert read(capture["pin"]) == capture
                    dependencies.append({"key": "fixture.initial-input:" + capture["pin"]["document_id"],
                                         "kind": "transcript" if transcript_input else "source",
                                         "pin": capture["pin"], "policy": "exact"})
                candidate["parent_revision"]["revision_id"] = "input-retained-v1"
                candidate["dependency_manifest"]["documents"] = [capture["pin"] for capture in captures]
                record = {"ordinal": 0, "command": context["request"]["commands"][0],
                          "writes": [], "reads": [], "selections": [], "bindings": [], "created": [],
                          "derived_writes": [], "dependencies": dependencies}
                return port.accept({
                    "expected_head": base, "canonical_document": candidate, "document_digest": digest(candidate),
                    "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
                    "id_map": {}, "semantic_events": [],
                    "provider_version": "initial-input-fixture", "compiler_version": "initial-input-fixture",
                })

        dependency_kind = "transcript" if request.param == "transcript" else "source"
        service.register_timeline_commit_provider(InitialInputAcceptance())
        seed_body = body(film, head(service, film), [{
            "schema_version": 1, "op": "fixture.retain-input", "version": "1", "select": None,
            "args": {"inputs": [capture["pin"] for capture in captures]}, "created": [],
        }])
        seed = commit(service, film, seed_body, "initial-input-v1")
        original = seed["data"]["canonical_document"]
        changed = copy.deepcopy(source["content"])
        if request.param == "transcript":
            changed["segments"][0].update(text="producer v2", start=2, end=3)
            changed["segments"][0]["words"] = [{"id": "replacement-word", "text": "v2", "start": 2, "end": 3}]
        else:
            changed.update(enabled=False, opaque=["producer v2"], time_map={"source_offset": 10, "speed": 2})
        current = service.update_document(
            film.project_id, source["document_id"], {"expected_version": 1, "content": changed},
            idempotency_key="producer-v2",
        )["data"]
        assert current["version"] == 2
    finally:
        service.close()

    observed = SimpleNamespace(reads=[], core=[], compiled=[], providers=[])

    def watch_read(method):
        def read(port, value):
            result = method(port, value)
            observed.reads.append(copy.deepcopy(result))
            return result
        return read

    for name in ("transcript_source", "config_source"):
        monkeypatch.setattr(RequestCommitPort, name, watch_read(getattr(RequestCommitPort, name)))
    execute = core.execute
    compile_candidate = agent.compile_authoring_candidate
    provider_type = type(load_timeline_commit_provider("astrid"))
    provider_commit = provider_type.commit

    def observe_execute(bundle, *args, **kwargs):
        observed.core.append(copy.deepcopy(bundle))
        return execute(bundle, *args, **kwargs)

    def observe_compile(bundle):
        result = compile_candidate(bundle)
        observed.compiled.append(copy.deepcopy(bundle))
        return result

    def observe_provider(provider, context, port):
        observed.providers.append(context["idempotency_key"])
        return provider_commit(provider, context, port)

    monkeypatch.setattr(core, "execute", observe_execute)
    monkeypatch.setattr(agent, "compile_authoring_candidate", observe_compile)
    monkeypatch.setattr(provider_type, "commit", observe_provider)
    value = SimpleNamespace(film=film, agent=agent, move=capture_move, track=capture_track_create,
                            source=source, pin=pin, captures=captures,
                            current=current, seed=seed, seed_body=seed_body, original=original,
                            dependency_kind=dependency_kind, observed=observed)

    def restart():
        if getattr(value, "service", None):
            value.service.close()
        value.service = RuntimeService(film.duplicate_root)
        value.service.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))

    value.restart = restart
    restart()
    try:
        yield value
    finally:
        value.service.close()


def captured_move(case, on=1):
    return case.move(case.agent.bundle_from_document(document(case.service, case.film)),
                     "parent/clip:music-bed", on)


def assert_retained(case, accepted):
    result = accepted["data"]["canonical_document"]
    assert result["dependency_manifest"] == case.original["dependency_manifest"]
    assert result["shot_revisions"] == case.original["shot_revisions"]
    assert result["internal_timeline_revisions"] == case.original["internal_timeline_revisions"]
    original_parent = case.original["parent_revision"]["payload"]
    assert result["parent_revision"]["payload"]["occurrences"] == original_parent["occurrences"]
    entry = next(item for item in history(case.service, case.film)
                 if item["publication_id"] == accepted["receipt"]["receipt_id"])
    assert entry["receipt"] == accepted["receipt"]
    records = entry["records"]["commands"]
    assert len(records) == 1
    assert records[0]["command"] == accepted["data"]["commands"][0]
    if records[0]["command"]["op"] == "clip.move":
        assert [dep for dep in records[0]["dependencies"] if dep["kind"] == "time-map"] == [{
            "key": "move.quantization", "kind": "time-map", "policy": "exact",
            "pin": {"numerator": 24, "denominator": 1, "rounding": "half-toward-positive-infinity"},
        }]
    assert [{"kind": dep["kind"], "pin": dep["pin"], "policy": dep["policy"]}
            for dep in records[0]["dependencies"] if dep["kind"] in {"transcript", "source"}] == [
        {"kind": "transcript" if capture["document"]["kind"] == "media.transcript" else "source",
         "pin": capture["pin"], "policy": "exact"} for capture in case.captures
    ]
    links = case.service.store.conn.execute(
        "SELECT document_id, document_version, content_digest, dependency_kind FROM timeline_document_input_links "
        "WHERE publication_id=? AND revision_id=? ORDER BY ordinal",
        (entry["publication_id"], entry["revision_id"]),
    ).fetchall()
    assert [tuple(row) for row in links] == [
        (capture["pin"]["document_id"], capture["pin"]["version"], capture["pin"]["content_digest"],
         "transcript" if capture["document"]["kind"] == "media.transcript" else "source")
        for capture in case.captures
    ]


def assert_retry(case, request, key, accepted):
    before = snapshot(case.service)
    calls = copy.deepcopy(vars(case.observed))
    assert commit(case.service, case.film, request, key) == accepted
    assert snapshot(case.service) == before
    assert vars(case.observed) == calls  # No provider, source read, core or compiler on exact retry.


def moved_and_undone(case):
    request = body(case.film, head(case.service, case.film), [captured_move(case)])
    moved = commit(case.service, case.film, request, "real-move")
    assert_retained(case, moved)
    assert_retry(case, request, "real-move", moved)
    case.restart()
    assert_retry(case, request, "real-move", moved)
    undo = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
            "args": {"publications": [moved["receipt"]["receipt_id"]]}}
    undone = commit(case.service, case.film,
                    body(case.film, head(case.service, case.film), [undo]), "real-inverse")
    assert_retained(case, undone)
    restored_parent = undone["data"]["canonical_document"]["parent_revision"]["payload"]
    assert restored_parent == case.original["parent_revision"]["payload"]
    return request, moved, undone


def test_retained_input_real_move_inverse_replay_after_restart(retained):
    case = retained
    assert_retry(case, case.seed_body, "initial-input-v1", case.seed)
    request, moved, undone = moved_and_undone(case)
    base = head(case.service, case.film)
    request = body(case.film, base, [captured_move(case)])
    track = case.track(case.agent.bundle_from_document(document(case.service, case.film)),
                       "parent", {"id": "disjoint-track", "kind": "audio"})
    independent = commit(case.service, case.film, body(case.film, base, [track]), "disjoint-track")
    assert_retained(case, independent)
    # Replay the original captured move over an actual disjoint acceptance.
    rebased = commit(case.service, case.film, request, "real-replay")
    assert rebased["data"]["status"] == "rebased"
    assert_retained(case, rebased)
    replayed_parent = rebased["data"]["canonical_document"]["parent_revision"]["payload"]
    assert replayed_parent["clips"] == moved["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
    assert replayed_parent["config"]["tracks"][-1] == {"id": "disjoint-track", "kind": "audio"}
    assert_retry(case, request, "real-replay", rebased)
    assert case.observed.reads and all(value in case.captures for value in case.observed.reads)
    assert all(capture in case.observed.reads for capture in case.captures)
    hydrated = [bundle for bundle in case.observed.core if bundle["source_mapping"].get("pinned_documents")]
    assert hydrated and case.observed.compiled
    for bundle in [*hydrated, *case.observed.compiled]:
        assert bundle["source_mapping"]["pinned_documents"] == case.captures
    items = history(case.service, case.film)
    assert len(items) == 7  # Two legacy edges, seed, move, inverse, track, replay.
    assert len({item["publication_id"] for item in items}) == len(items)
    assert head(case.service, case.film)["publication_id"] == rebased["receipt"]["receipt_id"]
    assert case.service.store.conn.execute(
        "SELECT COUNT(*) FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
        (case.film.project_id, case.film.timeline_id),
    ).fetchone()[0] == 1
    assert case.service.get_document(case.film.project_id, case.source["document_id"]) == case.current


def test_move_from_corrupt_local_timing_cache_conflicts_without_writes(retained):
    case = retained
    before = snapshot(case.service)
    base = head(case.service, case.film)
    assert document(case.service, case.film) == case.original
    local = case.agent.bundle_from_document(case.original)
    original_clip = copy.deepcopy(local["parent"]["clips"][0])
    assert original_clip["at"] == 0.25
    assert original_clip["app"]["on"] == original_clip["app"]["astrid"]["on"] == "word:word-1"
    # M1 guards the observed cache; word-follow timing evaluation belongs to M2.
    local["parent"]["clips"][0]["at"] = 99
    local["parent"]["config"]["clips"][0]["at"] = 99
    command = case.move(local, "parent/clip:music-bed", 1)
    assert command["expect"]["parent/clip:music-bed::at"] == {"state": "present", "value": 99}
    for path in ("app.on", "app.astrid.on"):
        assert command["expect"]["parent/clip:music-bed::" + path] == {
            "state": "present", "value": "word:word-1",
        }
    assert command["bindings"]["move.target"] == "parent/clip:music-bed"
    assert command["bindings"]["move.track"] == "parent/track:" + original_clip["track"]
    request = body(case.film, base, [command])
    with pytest.raises(RuntimeErrorBase, match="original authored guard changed") as error:
        commit(case.service, case.film, request, "corrupt-local-cache")
    assert error.value.status == 409
    assert error.value.details == {
        "status": "conflict", "reason": "dependency_changed", "base": base, "current": base,
        "conflicts": [{"kind": "dependency_changed", "ref": "parent/clip:music-bed", "path": ["at"],
                       "base": {"state": "present", "value": 99},
                       "theirs": {"state": "present", "value": 0.25},
                       "ours": {"state": "absent"}, "choices": []}],
    }
    assert case.observed.providers == ["corrupt-local-cache"]
    assert all(capture in case.observed.reads for capture in case.captures)
    assert snapshot(case.service) == before
    assert head(case.service, case.film) == base
    assert document(case.service, case.film) == case.original
    assert case.service.get_document(case.film.project_id, case.source["document_id"]) == case.current
    assert_retry(case, case.seed_body, "initial-input-v1", case.seed)


@pytest.mark.parametrize("damage", ["revoked-source", "foreign-source", "missing-snapshot"])
def test_semantic_read_refuses_damaged_retained_source_but_exact_retry_uses_ledger(retained, damage):
    case = retained
    request = body(case.film, head(case.service, case.film), [captured_move(case)])
    conn = case.service.store.conn
    # Isolated negative cases deliberately corrupt Runtime rows, never provenance
    # used by the positive producer/restart/move/inverse path.
    if damage == "revoked-source":
        if case.dependency_kind == "transcript":
            conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                         (case.film.project_id, case.source["content"]["media_id"].removeprefix("sha256:")))
        else:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("UPDATE timeline_document_input_bindings SET project_id='foreign-project' WHERE document_id=?",
                         (case.pin["document_id"],))
            conn.execute("PRAGMA foreign_keys=ON")
    elif damage == "foreign-source":
        foreign = case.service.create_project({"name": "Foreign source", "slug": "foreign-source"})["id"]
        media = case.service.ingest(foreign, b"foreign source", media_type="video/mp4",
                                    idempotency_key="foreign-source-media")["data"]["object_id"]
        conn.execute("UPDATE timeline_document_input_bindings SET source_media_id=? WHERE document_id=?",
                     (media, case.pin["document_id"]))
    else:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DELETE FROM timeline_document_input_contents WHERE content_digest=?",
                     (case.pin["content_digest"],))
        conn.execute("PRAGMA foreign_keys=ON")
    assert_retry(case, case.seed_body, "initial-input-v1", case.seed)
    before = snapshot(case.service)
    with pytest.raises(RuntimeErrorBase, match="source|retained|dependency_unavailable") as error:
        commit(case.service, case.film, request, "damaged-source-move")
    assert error.value.status == 409
    assert snapshot(case.service) == before

    def denied():
        raise AuthorizationError("current caller authority revoked")

    with pytest.raises(AuthorizationError, match="current caller"):
        commit(case.service, case.film, case.seed_body, "initial-input-v1", authorize=denied)
    assert snapshot(case.service) == before
