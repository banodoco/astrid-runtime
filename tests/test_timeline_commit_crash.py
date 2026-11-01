"""SIGKILL at the real acceptance transaction boundary, through the browser door.

The barrier wraps only private test-process methods. It never replaces provider
execution or SQLite COMMIT, and cannot unwind until the parent kills the owner.
"""
from __future__ import annotations

import copy
import hashlib
import http.client
import json
import multiprocessing
import signal
import sqlite3
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.store import SCHEMA_VERSION, RealmStore
from runtime_protocol.timeline_commit_port import RequestCommitPort, digest
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.upgrade import (
    compact_idempotency_ledger,
    inspect_canonical_schema,
    migrate_canonical_to_current,
)
from runtime_protocol.util import canonical_json
from tests.door_helpers import HOSTED, PRODUCT_ACTOR, DoorWorld, door_call
from tests.lanes import requires_posix_process_groups
from test_timeline_commit_input_integration import body, document, head, retained
from timeline_commit_film_fixture import build_film_fixture

pytestmark = [pytest.mark.integration, requires_posix_process_groups]

_TABLES = (
    "parent_composition_revisions", "shot_revisions", "internal_timeline_revisions",
    "composition_revision_occurrences", "composition_revision_dependencies",
    "parent_composition_heads", "shot_revision_heads", "project_shots", "shot_items",
    "timelines", "timeline_commit_history", "timeline_events", "command_idempotency",
    "project_sequences", "project_documents", "timeline_document_input_contents",
    "timeline_document_input_bindings", "timeline_document_input_links",
)


def _rows(connection):
    return {table: sorted([list(row) for row in connection.execute(f"SELECT * FROM {table}")], key=repr)
            for table in _TABLES}


def _disk_rows(film):
    connection = sqlite3.connect(f"file:{film.duplicate_root / 'realm.sqlite3'}?mode=ro", uri=True)
    try:
        return _rows(connection)
    finally:
        connection.close()


def _objects(film):
    root = film.duplicate_root / "cas" / "sha256"
    return sorted(path.relative_to(root) for path in root.rglob("*") if path.is_file())


def _unavailable(*args, **kwargs):
    raise AssertionError("save/retry reached renderer or forbidden semantic work")


def _migrate_duplicate_realm(film):
    """Bring only the mutable duplicate from captured v31 data to current v32."""
    identity = inspect_canonical_schema(film.duplicate_root)
    assert identity["version"] == 31
    realm_id = identity["realm_id"]
    assert isinstance(realm_id, str)
    result = migrate_canonical_to_current(
        film.duplicate_root,
        confirmation=f"MIGRATE CANONICAL {realm_id}",
        expected_realm_id=realm_id,
    )
    assert result["source_schema_version"] == 31
    assert result["target_schema_version"] == SCHEMA_VERSION == 32
    assert result["changed"] is True
    assert inspect_canonical_schema(
        film.duplicate_root, expected_realm_id=realm_id
    )["version"] == SCHEMA_VERSION


class _FirstCaptureProvider:
    """HOST-BOUNDARY only: first capture, with no Agent semantic claim."""
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def commit(self, context, port):
        base = port.head()
        candidate = port.revision_closure(base["revision_id"])
        pin = context["request"]["commands"][0]["args"]["pin"]
        reader = port.config_source if pin["document_id"] == "film.config" else port.transcript_source
        reader(pin)
        candidate["parent_revision"]["revision_id"] = "host-first-capture"
        candidate["dependency_manifest"]["documents"] = [pin]
        dependency_kind = "source" if pin["document_id"] == "film.config" else "transcript"
        record = {"ordinal": 0, "command": context["request"]["commands"][0],
                  "writes": [], "reads": [], "selections": [], "bindings": [], "created": [],
                  "derived_writes": [], "dependencies": [
                      {"key": "host.input", "kind": dependency_kind, "pin": pin, "policy": "exact"}]}
        return port.accept({
            "expected_head": base, "canonical_document": candidate, "document_digest": digest(candidate),
            "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
            "id_map": {}, "semantic_events": [], "provider_version": "host-fixture", "compiler_version": "host-fixture",
        })


def _runtime_child(pipe, film, tmp, first_capture):
    """One fresh interpreter/owner; all measured mutations arrive over HTTP."""
    daemon = None
    try:
        import runtime_protocol.service as service_module
        import runtime_protocol.visual_seam as visual_seam

        class RendererUnavailable:
            def find_spec(self, fullname, path=None, target=None):
                if fullname.startswith(("astrid.packs.rendering", "astrid.core.rendering",
                                        "astrid.sdk.authoring_render_preview",
                                        "astrid.core.timeline.compatibility", "composition", "remotion")):
                    raise AssertionError("save imported renderer: " + fullname)

        sys.meta_path.insert(0, RendererUnavailable())
        service_module.evaluate_closure = visual_seam.evaluate_closure = _unavailable
        credential = tmp / "product.json"
        daemon = RuntimeDaemon(
            film.duplicate_root, support_root=tmp / "support", authoring_profile="astrid",
            door=DoorConfig(origin=HOSTED, port=0, credential_file=credential),
        )
        if first_capture:
            daemon._load_installed_timeline_commit_provider = _FirstCaptureProvider
        daemon.start()
        world = DoorWorld(tmp, daemon, credential)
        if not credential.exists():
            world.provision()
        handshake = world.call("/api/runtime/v1/handshake", "POST", body=b"{}",
                               headers={"Content-Type": "application/json"})
        assert handshake.status == 200, handshake.body
        service = daemon.service
        commits = service._timeline_commits()[0]
        local, armed, calls = threading.local(), {}, []
        reads, compiled = [], []
        from astrid.sdk.timeline import commit as agent

        def watch_read(method):
            def read(port, pin):
                result = method(port, pin)
                reads.append(copy.deepcopy(result))
                return result
            return read

        for name in ("transcript_source", "config_source"):
            setattr(RequestCommitPort, name, watch_read(getattr(RequestCommitPort, name)))
        compile_candidate = agent.compile_authoring_candidate

        def observe_compile(bundle):
            compiled.append(copy.deepcopy(bundle["source_mapping"].get("pinned_documents", [])))
            return compile_candidate(bundle)

        agent.compile_authoring_candidate = observe_compile
        transaction, accept = RealmStore._transaction, TimelineCommitStore.accept
        provider_type = type(service._timeline_commit_provider)
        provider_commit = provider_type.commit

        def observe_provider(provider, context, port):
            calls.append(context["idempotency_key"])
            return provider_commit(provider, context, port)

        provider_type.commit = observe_provider

        def pause(store, stage):
            context = local.context
            assert store is service.store
            assert store.conn.in_transaction == (stage == "before")
            barrier = {"barrier": stage, "in_transaction": store.conn.in_transaction,
                       "context": context, "rows": _rows(store.conn),
                       "head": head(service, film), "calls": list(calls),
                       "reads": list(reads), "compiled": list(compiled)}
            if stage != "pre":
                envelope = commits._lookup(context)
                assert envelope is not None
                barrier["envelope"] = envelope
            pipe.send(barrier)
            # No release path: the only successful continuation is SIGKILL.
            threading.Event().wait(120)
            raise AssertionError("parent failed to kill paused Runtime")

        @contextmanager
        def barrier_transaction(store):
            active = getattr(local, "context", None) is not None
            with transaction(store):
                yield
                if active and armed.get("stage") == "before":
                    pause(store, "before")
            if active and armed.get("stage") == "after":
                pause(store, "after")

        def observed_accept(store, context, prepared, **kwargs):
            local.context = context
            try:
                if armed.get("stage") == "pre":
                    pause(store.store, "pre")
                return accept(store, context, prepared, **kwargs)
            finally:
                local.context = None

        RealmStore._transaction = barrier_transaction
        TimelineCommitStore.accept = observed_accept
        pipe.send({"port": world.port, "instance": daemon.instance_id, "handshake": handshake.json()})
        while True:
            command, value = pipe.recv()
            if command == "stop":
                break
            if command == "arm":
                armed["stage"] = value
                pipe.send({"armed": value})
            elif command == "tripwire":
                provider_type.commit = _unavailable
                RealmStore.integrity_report = _unavailable
                RequestCommitPort.transcript_source = RequestCommitPort.config_source = _unavailable
                agent.compile_authoring_candidate = _unavailable
                pipe.send({"tripwire": True})
            elif command == "inspect":
                with service.store._mutex:
                    pipe.send({"rows": _rows(service.store.conn), "head": head(service, film),
                               "document": document(service, film), "calls": list(calls),
                               "reads": list(reads), "compiled": list(compiled)})
            else:
                raise AssertionError(command)
    except BaseException:
        pipe.send({"error": traceback.format_exc()})
    finally:
        if daemon is not None:
            daemon.stop()
        pipe.close()


class _Runtime:
    def __init__(self, film, tmp, first_capture=False):
        context = multiprocessing.get_context("spawn")
        self.pipe, child = context.Pipe()
        self.process = context.Process(target=_runtime_child, args=(child, film, tmp, first_capture))
        self.process.start()
        child.close()
        try:
            self.ready = self.receive()
        except BaseException:
            self.close()
            raise

    def receive(self):
        assert self.pipe.poll(40), "Runtime child did not reach the expected barrier/control reply"
        result = self.pipe.recv()
        assert "error" not in result, result.get("error")
        return result

    def control(self, command, value=None):
        self.pipe.send((command, value))
        return self.receive()

    def post(self, path, encoded, key):
        return door_call(self.ready["port"], "/api/runtime" + path, "POST", body=encoded,
                         headers={"Content-Type": "application/json", "Idempotency-Key": key})

    def kill(self):
        assert self.process.is_alive()
        self.process.kill()
        self.process.join(10)
        assert self.process.exitcode == -signal.SIGKILL

    def close(self):
        try:
            if self.process.is_alive():
                self.pipe.send(("stop", None))
                self.process.join(10)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(10)
            assert not self.process.is_alive(), "Runtime child leaked"
        finally:
            self.pipe.close()
            self.process.close()


def _move(film, state, on):
    from astrid.sdk.timeline.capture import capture_move
    from astrid.sdk.timeline.commit import bundle_from_document

    command = capture_move(bundle_from_document(state["document"]), "parent/clip:music-bed", on)
    return body(film, state["head"], [command])


def _accepted(runtime, path, request, key):
    response = runtime.post(path, json.dumps(request).encode(), key)
    assert response.status == 200, response.body
    return response.json()


def _assert_one_acceptance(before, after, accepted, captures=(), first_capture=False):
    receipt = accepted["receipt"]
    assert accepted["data"] == receipt["result"]
    assert len(after["timeline_commit_history"]) == len(before["timeline_commit_history"]) + 1
    assert len(after["command_idempotency"]) == len(before["command_idempotency"]) + 1
    assert len(after["timeline_events"]) == len(before["timeline_events"]) + len(receipt["event_ids"])
    assert sum(row[0] == receipt["receipt_id"] for row in after["timeline_commit_history"]) == 1
    assert set(receipt["event_ids"]) == {str(row[0]) for row in after["timeline_events"]} - {
        str(row[0]) for row in before["timeline_events"]}
    for table in ("shot_revisions", "internal_timeline_revisions", "project_documents"):
        assert after[table] == before[table]
    candidate = accepted["data"]["canonical_document"]
    assert candidate["dependency_manifest"]["documents"] == [capture["pin"] for capture in captures]
    if first_capture:
        history = next(row for row in after["timeline_commit_history"] if row[0] == receipt["receipt_id"])
        records = json.loads(history[7])
        capture = captures[0]
        assert records["commands"][0]["dependencies"] == [{
            "key": "host.input",
            "kind": "source" if capture["document"]["kind"].endswith(".config") else "transcript",
            "pin": capture["pin"],
            "policy": "exact",
        }]
    contents, bindings = [], []
    for capture in captures:
        pin, source = capture["pin"], capture["document"]
        encoded = canonical_json(source["content"])
        contents.append([pin["content_digest"], encoded, len(encoded.encode())])
        transcript = source["kind"] == "media.transcript"
        bindings.append([source["project_id"], source["document_id"], source["version"],
                         pin["content_digest"], source["kind"], source["created_at"], source["updated_at"],
                         source["content"]["media_id"] if transcript else None,
                         source["content"]["source_id"] if transcript else None])
    for table, expected in (("timeline_document_input_contents", contents),
                            ("timeline_document_input_bindings", bindings)):
        assert [row[:-1] for row in after[table]] == sorted(expected, key=repr)
        if first_capture:
            assert before[table] == []
        else:
            assert after[table] == before[table]
    table = "timeline_document_input_links"
    if not captures or first_capture:
        assert before[table] == []
    else:
        assert before[table]
        for identity in {tuple(row[:4]) for row in before[table]}:
            assert [row[4:9] for row in sorted(before[table], key=lambda row: row[4])
                    if tuple(row[:4]) == identity] == [
                [ordinal, "transcript" if capture["document"]["kind"] == "media.transcript" else "source",
                 capture["pin"]["document_id"], capture["pin"]["version"], capture["pin"]["content_digest"]]
                for ordinal, capture in enumerate(captures)
            ]
    added = [row for row in after[table] if row not in before[table]]
    assert after[table] == sorted(before[table] + added, key=repr)
    assert [row[:-1] for row in sorted(added, key=lambda row: row[4])] == [
        [candidate["project_id"], candidate["timeline_id"], receipt["receipt_id"],
         candidate["parent_revision"]["revision_id"], ordinal,
         "transcript" if capture["document"]["kind"] == "media.transcript" else "source",
         capture["pin"]["document_id"], capture["pin"]["version"], capture["pin"]["content_digest"]]
        for ordinal, capture in enumerate(captures)
    ]


@pytest.mark.parametrize("operation", ["commit", "restore"])
@pytest.mark.parametrize("stage", ["pre", "before", "after"])
def test_real_process_death_at_acceptance_boundary(tmp_path, astrid_importable, monkeypatch, operation, stage):
    _crash_boundary(tmp_path, monkeypatch, build_film_fixture(tmp_path), operation, stage)


@pytest.mark.parametrize("operation", ["commit", "restore"])
@pytest.mark.parametrize("stage", ["pre", "before", "after"])
def test_retained_inputs_process_death(retained, tmp_path, monkeypatch, operation, stage):
    case = retained
    assert case.current["version"] == 2
    assert case.service.get_document(case.film.project_id, case.source["document_id"]) == case.current
    assert all(capture["pin"]["version"] == 1 for capture in case.captures)
    case.service.close()  # The spawned daemon must be the sole live owner.
    _crash_boundary(tmp_path, monkeypatch, case.film, operation, stage, case.captures)


@pytest.mark.parametrize("source_kind", ["transcript", "config"])
@pytest.mark.parametrize("stage", ["pre", "before", "after"])
def test_host_boundary_first_capture_process_death(tmp_path, astrid_importable, monkeypatch, source_kind, stage):
    # HOST-BOUNDARY: proves input blob/header/link atomicity, not Agent semantics.
    from runtime_protocol.service import RuntimeService

    film = build_film_fixture(tmp_path)
    with closing(RuntimeService(film.duplicate_root)) as service:
        if source_kind == "config":
            source = service.create_document(film.project_id, {
                "document_id": "film.config", "kind": "film.config",
                "content": {"schema": "film.config/v1", "enabled": True},
            }, idempotency_key="first-config")["data"]
        else:
            source = service.get_document(film.project_id, film.transcript_document_id)
    capture = {"pin": {"document_id": source["document_id"], "version": source["version"],
                       "content_digest": digest(source["content"])}, "document": source}
    _crash_boundary(tmp_path, monkeypatch, film, "commit", stage, [capture], first_capture=True)


def _crash_boundary(tmp_path, monkeypatch, film, operation, stage, captures=(), first_capture=False):
    # Spawn imports this module afresh; Agent also has a top-level tests package.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    source_files = {path.relative_to(film.source_root): path.read_bytes()
                    for path in film.source_root.rglob("*") if path.is_file()}
    # The authenticated v31 source/archive stays immutable; only this duplicate
    # is upgraded before the first Runtime owner opens it.
    _migrate_duplicate_realm(film)
    commit_path = f"/v1/projects/{film.project_id}/timelines/{film.timeline_id}/commit"
    runtime = _Runtime(film, tmp_path, first_capture)
    try:
        original_ready = runtime.ready
        initial = runtime.control("inspect")
        source_revision = initial["head"]["revision_id"]
        if operation == "restore":
            _accepted(runtime, commit_path, _move(film, initial, 1), "prepare-restore")
        before = runtime.control("inspect")
        objects = _objects(film)
        if operation == "restore":
            path = commit_path.removesuffix("commit") + f"composition-revisions/{source_revision}/restore"
            request = {"expected_head": before["head"]["revision_id"],
                       "expected_publication_id": before["head"]["publication_id"]}
        else:
            path, request = commit_path, _move(film, before, 1)
            if first_capture:
                request = body(film, before["head"], [{
                    "schema_version": 1, "op": "fixture.host-first-capture", "version": "1", "select": None,
                    "args": {"pin": captures[0]["pin"]}, "created": [],
                }])
        encoded, key = json.dumps(request).encode(), "crash-exact-flight"
        assert runtime.control("arm", stage) == {"armed": stage}
        with ThreadPoolExecutor(max_workers=1) as pool:
            response = pool.submit(runtime.post, path, encoded, key)
            staged = None
            try:
                barrier = runtime.receive()
                assert barrier["barrier"] == stage
                assert barrier["in_transaction"] == (stage == "before")
                assert not response.done(), "HTTP response escaped before death"
                context = barrier["context"]
                assert context["invocation"] == {
                    "operation": "commitTimeline" if operation == "commit" else "restoreProjectParentCompositionRevision",
                    "path": path, "body": request,
                }
                assert context["publisher"] == PRODUCT_ACTOR
                assert context["idempotency_key"] == key
                assert barrier["calls"] == before["calls"] + [key]
                expected_hash = hashlib.sha256(canonical_json({
                    "operation": context["invocation"]["operation"], "path": path,
                    "publisher": PRODUCT_ACTOR, "request": request,
                }).encode()).hexdigest()
                assert context["request_hash"] == expected_hash
                if stage == "pre":
                    assert barrier["rows"] == before["rows"]
                    assert barrier["head"] == before["head"]
                    assert "envelope" not in barrier
                else:
                    staged = barrier["envelope"]
                    assert staged["receipt"]["request_hash"] == context["request_hash"]
                    _assert_one_acceptance(before["rows"], barrier["rows"], staged, captures, first_capture)
                consumed = barrier["reads"][len(before["reads"]):]
                assert all(capture in captures for capture in consumed)
                assert all(capture in consumed for capture in captures)
                if captures and not first_capture:
                    compilations = barrier["compiled"][len(before["compiled"]):]
                    # Restore also compiles intermediate images to record its writes.
                    assert compilations and compilations[-1] == captures
                    assert all(pins == captures for pins in compilations if pins)
                if stage != "pre":
                    assert staged is not None
                    if operation == "restore":
                        assert staged["data"]["canonical_document"]["parent_revision"]["payload"] == (
                            initial["document"]["parent_revision"]["payload"])
                    elif not first_capture:
                        parent = staged["data"]["canonical_document"]["parent_revision"]["payload"]
                        assert parent["clips"][0]["at"] == 1
                        assert parent["clips"][0]["app"]["astrid"]["fixed_start"] is True
                        assert parent["occurrences"] == initial["document"]["parent_revision"]["payload"]["occurrences"]
                visible = before["rows"] if stage in ("pre", "before") else barrier["rows"]
                assert _disk_rows(film) == visible
                # Commit writes no content-addressed object; a killed flight leaves no orphan either.
                assert _objects(film) == objects
            finally:
                if runtime.process.is_alive():
                    runtime.kill()
            with pytest.raises((OSError, http.client.HTTPException)):
                response.result(timeout=10)
        runtime.close()
        runtime = None
        assert _disk_rows(film) == visible

        runtime = _Runtime(film, tmp_path, first_capture)
        assert runtime.ready["instance"] != original_ready["instance"]
        for field in ("realm_id", "actor_id"):
            assert runtime.ready["handshake"][field] == original_ready["handshake"][field]
        assert runtime.ready["handshake"]["actor_id"] == PRODUCT_ACTOR
        recovered = runtime.control("inspect")
        assert recovered["rows"] == visible
        if stage in ("pre", "before"):
            assert recovered["head"] == before["head"]
            accepted = _accepted(runtime, path, request, key)
            _assert_one_acceptance(before["rows"], runtime.control("inspect")["rows"], accepted,
                                   captures, first_capture)
            if stage == "pre" and not first_capture:
                candidate = accepted["data"]["canonical_document"]["parent_revision"]["payload"]
                if operation == "restore":
                    assert candidate == initial["document"]["parent_revision"]["payload"]
                else:
                    assert candidate["clips"][0]["at"] == 1
                    assert candidate["clips"][0]["app"]["astrid"]["fixed_start"] is True
                    assert candidate["occurrences"] == initial["document"]["parent_revision"]["payload"]["occurrences"]
        else:
            assert staged is not None
            accepted = staged
            assert recovered["head"]["publication_id"] == staged["receipt"]["receipt_id"]

        if operation == "restore" and stage == "after":
            newer = _accepted(runtime, commit_path, _move(film, recovered, 2), "newer-after-restore")
            runtime.close()
            runtime = None
            compact_idempotency_ledger(
                film.duplicate_root,
                confirmation=f"COMPACT IDEMPOTENCY {original_ready['handshake']['realm_id']}",
            )
            runtime = _Runtime(film, tmp_path)
            assert runtime.control("inspect")["head"]["publication_id"] == newer["receipt"]["receipt_id"]

        runtime.control("tripwire")
        settled = runtime.control("inspect")
        replay = runtime.post(path, encoded, key)
        assert replay.status == 200, replay.body
        assert replay.json() == accepted
        assert runtime.control("inspect") == settled
        changed = copy.deepcopy(request)
        changed["expected_publication_id" if operation == "restore" else "rationale"] = "changed-flight"
        refused = runtime.post(path, json.dumps(changed).encode(), key)
        assert refused.status == 409, refused.body
        assert refused.json()["details"]["reason"] == "idempotency_mismatch"
        assert runtime.control("inspect") == settled
        assert {path.relative_to(film.source_root): path.read_bytes()
                for path in film.source_root.rglob("*") if path.is_file()} == source_files
    finally:
        if runtime is not None:
            runtime.close()
