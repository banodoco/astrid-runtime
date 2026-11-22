"""Clean restart replay checkpoint proofs through the ordinary Runtime service."""
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest
import test_timeline_commit_port as port_tests
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, rows

from runtime_protocol import platform, timeline_commit_store
from runtime_protocol.errors import AuthorizationError, RealmAdmissionError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_store import TimelineCommitStore

service = port_tests.service


@pytest.fixture(autouse=True)
def _synthetic_checkpoint_installation(request, monkeypatch):
    """Supply the installation premise for source-only storage/fence controls."""
    if "service" not in request.fixturenames:
        return
    # These controls instrument verifier methods and run from a checkout. The
    # independent installed cases below exercise the real custody/code checks.
    import hashlib

    from runtime_protocol.contract_metadata import SCHEMA_DIGEST
    from runtime_protocol.timeline_commit_validation import digest

    def fingerprint():
        root = Path(timeline_commit_store.__file__).parent
        paths = sorted(root.rglob("*.py")) + [root / "schemas" / "timeline-commit-bundle.json"]
        schemas = ("attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py")
        return digest([timeline_commit_store._REPLAY_CHECKPOINT_FORMAT, SCHEMA_DIGEST,
                       list(sys.version_info), {name: timeline_commit_store.version(name) for name in schemas},
                       {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in paths}])

    timeline_commit_store.replay_checkpoint_version.cache_clear()
    monkeypatch.setattr(timeline_commit_store, "_installed_replay_checkpoint_version", fingerprint)
    request.addfinalizer(timeline_commit_store.replay_checkpoint_version.cache_clear)

_CHECKPOINT = "timeline_replay_checkpoint"


def _history(service, project):
    return service.list_timeline_commits(project, "main", limit=1, authorize=lambda: None)


def _next(service, *, prior="opening", note="second"):
    change_body = body(service)
    change = change_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": {"org.example.timeline": {"note": prior}}}
    change["value"] = {"org.example.timeline": {"note": note}}
    change_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    return change_body


def _seed(service):
    provider(service)
    first = commit(service, body(service))
    last = commit(service, _next(service), key="edit-2")
    project = service.test_project
    expected = _history(service, project)
    root = service.store.root
    service.close()
    return root, project, first["receipt"]["receipt_id"], last["receipt"]["receipt_id"], expected


def _replays(monkeypatch):
    original = TimelineCommitStore._verify_accepted_replay
    calls = []

    def verify(commits, row, edge, *args):
        calls.append((commits.store.db_path, edge["publication_id"]))
        return original(commits, row, edge, *args)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", verify)
    return calls


def _state(root):
    return root / "admission-state.json"


def _uncheckpoint(root):
    path = _state(root)
    state = json.loads(path.read_text())
    state.pop(_CHECKPOINT, None)
    path.write_text(json.dumps(state))


def test_clean_restart_rederives_live_history_without_semantic_replay(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)
    admitted = []
    verify = TimelineCommitStore._verify_accepted_record

    def checked(commits, row, edge, **kwargs):
        admitted.append((commits.store.db_path, edge["publication_id"]))
        return verify(commits, row, edge, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_record", checked)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert any(path != root / "realm.sqlite3" and published == head for path, published in admitted)
    assert (root / "realm.sqlite3", head) in admitted
    assert calls == []


@pytest.mark.parametrize("change", ["version", "realm", "truncated", "stale", "unprotected", "missing"])
def test_invalid_checkpoint_replays_healthy_history(service, monkeypatch, change):
    root, project, first, head, expected = _seed(service)
    path = _state(root)
    state = json.loads(path.read_text())
    checkpoint = state[_CHECKPOINT]
    if change == "version":
        checkpoint["version"] = "unknown"
    elif change == "realm":
        checkpoint["realm_id"] = "another-realm"
    elif change == "stale":
        # Keep the old proof intact while advancing the real SQLite generation.
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE projects SET updated_at='changed' WHERE id=?", (project,))
    elif change == "unprotected":
        if sys.platform == "win32":
            pytest.skip("this case changes POSIX permission bits")
        path.chmod(0o644)
    elif change == "missing":
        del state[_CHECKPOINT]
    path.write_text(json.dumps(state) if change != "truncated" else '{"timeline_replay_checkpoint":')
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert {published for path, published in calls if path != root / "realm.sqlite3"} == {first, head}


def test_full_admission_can_publish_next_checkpoint_without_a_history_request(service, monkeypatch):
    root, project, first, head, expected = _seed(service)
    _uncheckpoint(root)
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)):
        assert {published for _, published in calls} == {first, head}
    calls.clear()
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert calls == []


@pytest.mark.parametrize("change", ["modified", "deleted", "reordered"])
def test_changed_history_has_same_startup_refusal_as_full_replay(service, monkeypatch, change):
    root, _, first, head, _ = _seed(service)
    with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
        if change == "modified":
            conn.execute("UPDATE timeline_commit_history SET metadata_json='{}' WHERE publication_id=?", (head,))
        elif change == "deleted":
            conn.execute("DELETE FROM timeline_commit_history WHERE publication_id=?", (head,))
        else:
            old, new = [conn.execute("SELECT project_seq FROM timeline_commit_history WHERE publication_id=?",
                                     (published,)).fetchone()[0] for published in (first, head)]
            for published, ordinal in ((first, new + 100), (head, old), (first, new)):
                conn.execute("UPDATE timeline_commit_history SET project_seq=? WHERE publication_id=?", (ordinal, published))
    calls = _replays(monkeypatch)
    with pytest.raises(RealmAdmissionError) as retained:
        RuntimeService(root)
    retained_calls = calls.copy()
    _uncheckpoint(root)
    calls.clear()
    with pytest.raises(RealmAdmissionError) as uncached:
        RuntimeService(root)
    assert retained.value.details["checks"]["revisions"] == uncached.value.details["checks"]["revisions"]
    assert [published for _, published in retained_calls] == [published for _, published in calls]


def test_installed_verifier_change_cannot_relabel_earlier_proofs(service, monkeypatch):
    original = timeline_commit_store.version
    timeline_commit_store.replay_checkpoint_version.cache_clear()
    try:
        provider(service)
        commit(service, body(service))
        _history(service, service.test_project)
        monkeypatch.setattr(timeline_commit_store, "version",
                            lambda name: "changed" if name == "jsonschema" else original(name))
        service.close()
        assert _CHECKPOINT not in json.loads(_state(service.store.root).read_text())
    finally:
        timeline_commit_store.replay_checkpoint_version.cache_clear()


def test_interrupted_replacement_leaves_no_usable_checkpoint(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    project = service.test_project
    expected = _history(service, project)
    root = service.store.root
    path = _state(root)
    active = path.read_bytes()
    replace = platform.durable_replace
    attempted = []

    def crash(temporary, destination):
        if destination == path:
            attempted.append(json.loads(Path(temporary).read_bytes()))
            raise OSError("interrupted before admission replacement")
        return replace(temporary, destination)

    with monkeypatch.context() as patch:
        patch.setattr(platform, "durable_replace", crash)
        with pytest.raises(OSError, match="interrupted before admission replacement"):
            service.close()
    assert path.read_bytes() == active
    assert attempted[0]["clean_shutdown"] is True
    assert attempted[0][_CHECKPOINT]
    assert not tuple(root.glob(".admission-state-*"))
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert calls[0][1] == accepted["receipt"]["receipt_id"]


def test_process_crash_after_sync_never_admits_temporary_proof(service, monkeypatch):
    root, project, first, head, expected = _seed(service)
    code = """
import os
import sys
from runtime_protocol import platform, timeline_commit_store
from runtime_protocol.service import RuntimeService

# Mirror the parent test's synthetic installation premise in the crash child.
import json
from pathlib import Path
state = json.loads((Path(sys.argv[1]) / "admission-state.json").read_text())
timeline_commit_store._installed_replay_checkpoint_version = lambda: state["timeline_replay_checkpoint"]["version"]

service = RuntimeService(sys.argv[1])
replace = platform.durable_replace

def interrupted(source, destination):
    if destination.name == "admission-state.json":
        os._exit(77)
    return replace(source, destination)

platform.durable_replace = interrupted
service.close()
"""
    result = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 77, result.stderr
    assert json.loads(_state(root).read_text())["clean_shutdown"] is False
    orphans = tuple(root.glob(".admission-state-*"))
    assert len(orphans) == 1
    assert json.loads(orphans[0].read_text())[_CHECKPOINT]
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
    assert {published for path, published in calls if path != root / "realm.sqlite3"} == {first, head}


def test_writer_between_copied_admission_and_live_open_forces_new_admission(service, monkeypatch):
    root, _, _, head, _ = _seed(service)
    original = RealmStore._open

    def change(store, **kwargs):
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (head,))
        return original(store, **kwargs)

    monkeypatch.setattr(RealmStore, "_open", change)
    with pytest.raises(RealmAdmissionError) as refused:
        RuntimeService(root)
    assert not refused.value.details["checks"]["revisions"]["ok"]


def test_first_refused_read_clears_live_checkpoint(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)

    def denied():
        raise AuthorizationError("read denied")

    with closing(RuntimeService(root)) as reopened:
        assert calls == []
        with pytest.raises(AuthorizationError, match="read denied"):
            reopened.list_timeline_commits(project, "main", limit=1, authorize=denied)
        assert _history(reopened, project) == expected
    assert (root / "realm.sqlite3", head) in calls


def test_external_unrelated_writer_also_clears_live_checkpoint(service, monkeypatch):
    root, project, _, head, expected = _seed(service)
    calls = _replays(monkeypatch)
    with closing(RuntimeService(root)) as reopened:
        assert _history(reopened, project) == expected
        assert calls == []
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE projects SET updated_at='external' WHERE id=?", (project,))
        assert _history(reopened, project) == expected
    assert (root / "realm.sqlite3", head) in calls


@pytest.mark.parametrize("retain", [True, False])
def test_external_history_write_before_commit_still_refuses(service, retain):
    root, project, _, head, expected = _seed(service)
    if not retain:
        _uncheckpoint(root)
    with closing(RuntimeService(root)) as reopened:
        reopened.test_project = project
        reopened.test_provider = port_tests.PreparedProvider()
        reopened.register_timeline_commit_provider(reopened.test_provider)
        provider(reopened)
        request = _next(reopened, prior="second", note="third")
        assert _history(reopened, project) == expected
        with closing(sqlite3.connect(root / "realm.sqlite3")) as conn, conn:
            conn.execute("UPDATE timeline_commit_history SET records_json='{}' WHERE publication_id=?", (head,))
        before = rows(reopened)
        with pytest.raises((CommitRejected, RuntimeErrorBase), match="corrupt|history"):
            commit(reopened, request, key="must-refuse")
        assert rows(reopened) == before


@pytest.fixture
def installed_replay_take(tmp_path, stage1_runtime_environment):
    """Use an offline Runtime wheel in the version/profile layout the installer selects."""
    import shutil
    from importlib.metadata import distribution

    if sys.platform != "linux":
        pytest.skip("checkpoint attestation currently supports the Linux installed layout")
    take = tmp_path / "program" / "versions" / "0123456789ab"
    prefix = take / "py"
    shutil.copytree(stage1_runtime_environment, prefix, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    site = next(prefix.glob("lib/python*/site-packages"))
    for package in ("attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py",
                    "typing-extensions"):
        dist = distribution(package)
        for path in dist.files:
            if path.parts[0] == ".." or path.suffix == ".pyc":
                continue
            destination = site / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dist.locate_file(path), destination)
    python = prefix / "bin" / "python"
    (take / "r").mkdir()
    (site / "astrid").mkdir()
    (take / "manifest.json").write_text(json.dumps({"release": 77, "runtime": {"sha": "a" * 40}}))
    profile = take / "profile.json"
    profile.write_text(json.dumps({"runtime_environment": str(prefix), "runtime_checkout": str(take / "r"),
                                   "source_checkout": str(site / "astrid")}))
    (take / "version.json").write_text(json.dumps({
        "root": str(take), "python": str(python), "profile": str(profile),
        "identity": {"release": 77, "managed_by": None},
    }))
    return python


_INSTALLED_REPLAY_PROBE = r'''
import base64
import csv
import hashlib
import json
import sys
from contextlib import closing
from pathlib import Path

mode, realm, project, tests, test_dependencies, source = sys.argv[1:]
if mode == "development":
    sys.path.insert(0, source)
from runtime_protocol import timeline_commit_store
from runtime_protocol.errors import RealmAdmissionError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol import timeline_commit_validation

runtime = Path(timeline_commit_store.__file__)
if mode != "development":
    assert runtime.is_relative_to(sys.prefix), runtime
else:
    assert runtime.is_relative_to(source), runtime
sys.path.extend((tests, test_dependencies))
import test_timeline_replay_checkpoint as witness

calls = []
def observe(frame, event, arg):
    if event == "call" and frame.f_code.co_name == "_verify_accepted_replay":
        calls.append((str(frame.f_locals["self"].store.db_path),
                      frame.f_locals["edge"]["publication_id"]))

sys.setprofile(observe)
result = {"module": str(runtime)}
if mode in ("seed", "before-first-sample"):
    if mode == "before-first-sample":
        # A same-version replacement after import and before the first store
        # sees fresh wheel metadata and stale executing validation code.
        path = Path(timeline_commit_validation.__file__)
        old = path.read_text()
        new = old.replace("    finite_json(value)\n    from jsonschema.exceptions",
                          "    if definition == 'CommitContext':\n"
                          "        raise ValidationError('incompatible verifier')\n"
                          "    finite_json(value)\n    from jsonschema.exceptions")
        assert old != new
        path.write_text(new)
        site = path.parent.parent
        record, = site.glob("astrid_runtime-*.dist-info/RECORD")
        with record.open(newline="") as stream:
            entries = list(csv.reader(stream))
        for entry in entries:
            if entry[0] == path.relative_to(site).as_posix():
                changed = path.read_bytes()
                entry[1:] = ["sha256=" + base64.urlsafe_b64encode(hashlib.sha256(changed).digest()).rstrip(b"=").decode(),
                             str(len(changed))]
                break
        else:
            raise AssertionError("wheel did not record verifier source")
        with record.open("w", newline="") as stream:
            csv.writer(stream).writerows(entries)
    RealmStore.initialize(realm).close()
    service = RuntimeService(realm)
    service.test_provider = witness.port_tests.PreparedProvider()
    service.register_timeline_commit_provider(service.test_provider)
    project = service.create_project({"slug": "checkpoint", "name": "Checkpoint"})["id"]
    service.test_created = service.create_timeline(project, "main", idempotency_key="create-main")
    service.test_project = project
    from test_timeline_commit_sequential_verifier import _provider_with_capture
    _provider_with_capture(service)
    first = witness.commit(service, witness.body(service))["receipt"]["receipt_id"]
    head = witness.commit(service, witness._next(service), key="edit-2")["receipt"]["receipt_id"]
    for publication in (first, head):
        metadata = service.store.conn.execute(
            "SELECT metadata_json FROM timeline_commit_history WHERE publication_id=?", (publication,)
        ).fetchone()[0]
        assert "_sequential_execution" in json.loads(metadata)
    history = witness._history(service, project)
    service.close()
    result.update(project=project, publications=[first, head], history=history)
else:
    if mode == "loaded-dependency":
        from jsonschema import _keywords
        original = _keywords.type
        assert timeline_commit_store.replay_checkpoint_version() is not None
        def incompatible(validator, types, instance, schema):
            raise ValueError("incompatible schema dependency")
        original.__code__ = incompatible.__code__
    if mode == "identity-error":
        try:
            from runtime_protocol import timeline_replay_identity
        except ImportError:
            pass
        else:
            assert timeline_commit_store.replay_checkpoint_version() is not None
            def unavailable(self):
                raise OSError("identity computation is unavailable")
            type(timeline_replay_identity._installation)._schema_matches = unavailable
    try:
        with closing(RuntimeService(realm)) as service:
            if mode == "cached-resource":
                # Change the resource reached by the already-compiled schema
                # resolver after copied admission and live handoff.
                bundle, _ = timeline_commit_validation._schema_resources()
                validator = timeline_commit_validation._validator("CommitContext")
                resolver = timeline_commit_validation._validator_resolver(validator).resolver
                effective = resolver.lookup(bundle["root"]).contents
                effective["$defs"]["CommitContext"]["required"].append("incompatible_resource")
            result["history"] = witness._history(service, project)
    except (RealmAdmissionError, RuntimeErrorBase) as exc:
        result["refusal"] = type(exc).__name__
        if isinstance(exc, RealmAdmissionError):
            result["revisions"] = exc.details["checks"]["revisions"]
sys.setprofile(None)
result["calls"] = calls
result["checkpoint"] = "timeline_replay_checkpoint" in json.loads((Path(realm) / "admission-state.json").read_text())
print(json.dumps(result))
'''


def _installed_probe(python, mode, realm, project=""):
    tests = Path(__file__).resolve().parent
    result = subprocess.run(
        [str(python), "-I", "-B", "-c", _INSTALLED_REPLAY_PROBE, mode, str(realm), project,
         str(tests), str(Path(pytest.__file__).resolve().parents[1]), str(tests.parent)],
        cwd=realm.parent, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_verified_installed_restart_hits_checkpoint(installed_replay_take, tmp_path):
    realm = tmp_path / "realm"
    seeded = _installed_probe(installed_replay_take, "seed", realm)
    replayed = _installed_probe(installed_replay_take, "restart", realm, seeded["project"])
    assert seeded["checkpoint"]
    assert replayed["checkpoint"]
    assert replayed["history"] == seeded["history"]
    assert replayed["calls"] == []


def test_wheel_replacement_after_import_cannot_relabel_replay(installed_replay_take, tmp_path):
    realm = tmp_path / "realm"
    seeded = _installed_probe(installed_replay_take, "before-first-sample", realm)
    restarted = _installed_probe(installed_replay_take, "restart", realm, seeded["project"])
    assert seeded["calls"]
    assert not seeded["checkpoint"]
    assert restarted["refusal"] == "RealmAdmissionError"
    assert not restarted["revisions"]["ok"]
    assert restarted["calls"]


@pytest.mark.parametrize("mode", ["development", "missing-attestation", "identity-error"])
def test_unverified_installation_replays_and_does_not_publish(installed_replay_take, tmp_path, mode):
    realm = tmp_path / "realm"
    seeded = _installed_probe(installed_replay_take, "seed", realm)
    assert seeded["checkpoint"]
    if mode == "missing-attestation":
        (installed_replay_take.parents[2] / "profile.json").unlink()
    restarted = _installed_probe(installed_replay_take, mode, realm, seeded["project"])
    assert restarted["history"] == seeded["history"]
    assert {publication for path, publication in restarted["calls"]
            if path != str(realm / "realm.sqlite3")} == set(seeded["publications"])
    assert not restarted["checkpoint"]


@pytest.mark.parametrize(("mode", "refusal"), [
    ("loaded-dependency", "RealmAdmissionError"),
    ("cached-resource", "ProtocolError"),
])
def test_effective_verifier_drift_cannot_skip_semantic_refusal(installed_replay_take, tmp_path, mode, refusal):
    realm = tmp_path / "realm"
    seeded = _installed_probe(installed_replay_take, "seed", realm)
    assert seeded["checkpoint"]
    restarted = _installed_probe(installed_replay_take, mode, realm, seeded["project"])
    assert restarted.get("refusal") == refusal
    assert restarted["calls"]
    if mode == "cached-resource":
        assert all(path == str(realm / "realm.sqlite3") for path, _ in restarted["calls"])
        assert not restarted["checkpoint"]
