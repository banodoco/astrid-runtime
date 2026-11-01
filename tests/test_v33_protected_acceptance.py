"""Populated Runtime-owned §10 witnesses. No Agent/App or T-05b pass is implied.

Historical executables come from immutable Git objects. Public API captures
retain their original receipts/events; schema-family fixtures copy those facts
by column name and never insert publication history. The prepared provider is
an explicit ABI fixture, not shared Agent integration evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

from runtime_protocol import v33_lifecycle as life, upgrade
from runtime_protocol.errors import ConflictError, ValidationError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, SCHEMA_VERSION
from runtime_protocol.util import canonical_json
from test_v33_manifest import database, legacy_database, _REVISION_TABLES
from test_timeline_commit_port import PreparedProvider, commit, request

R0 = "6d53a19070faf63fc15ae1f81417722edc2c8a5f"
R1 = "8d208074669a31eed7efc4d964a602d6cd27e425"
M32 = "8f3d1091ada773af63f730f6340226a40e86ecc4"
REPO = Path(__file__).resolve().parents[1]


def tree(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file() and p.name != "owner.lock"}


def extract_executable(ref, destination):
    raw = subprocess.check_output(["git", "archive", ref], cwd=REPO)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(destination, filter="data")
    return destination


def historical_run(checkout, code, *args):
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(checkout), str(checkout / "tests"))), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run([sys.executable, "-B", "-c", code, *map(str, args)], cwd=checkout,
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


CAPTURE = '''
import hashlib, json, sys
from pathlib import Path
from test_generation_publish_v1_settlement import _fixture, _output, _settle
from test_shot_composition_runtime import _publication
from runtime_protocol.util import canonical_json
from runtime_protocol.store import SCHEMA_VERSION
service, project, task, attempt, effect = _fixture(Path(sys.argv[1]), slug="realm")
outputs = [_output(b"first", output_port="video", group_key="main", variant_key="first", ordinal=0, filename="first.mp4"),
           _output(b"second", output_port="video", group_key="main", variant_key="second", ordinal=1, filename="second.mp4"),
           _output(b"audio", output_port="audio", group_key="audio", variant_key="original", ordinal=0)]
_settle(service, attempt, outputs, effect=effect)
service.create_timeline(project["id"], "main", idempotency_key="timeline")
html = "<!doctype html><html><body>immutable R0 scene</body></html>"
entry = service.ingest(project["id"],html.encode(),media_type="text/html",original_name="scene.html",idempotency_key="scene-html")["data"]
package_body = {"manifest":{"formatVersion":1,"entry":"scene.html","duration":3,"authoredFps":30},
                "entry":{"object_id":entry["object_id"],"digest":entry["digest"],"media_type":"text/html","size":len(html.encode()),"filename":"scene.html"},"assets":[]}
encoded = canonical_json(package_body)
scene = service.ingest(project["id"],encoded.encode(),media_type="application/json",original_name="scene.json",idempotency_key="scene-json")["data"]["object_id"]
audio = service.ingest(project["id"],b"source-audio",media_type="audio/wav",idempotency_key="scene-audio")["data"]["object_id"]
body = _publication(project["id"])
body["internal_timeline_revisions"] = []; body["shot_revisions"] = []
body["parent_composition"]["occurrences"] = []
body["parent_composition"]["config"] = {"output":{"fps":30},"tracks":[{"id":"video","kind":"visual"}],
    "clips":[{"id":"scene","clipType":"haus.astrid.liveScene","at":0,"hold":1,"track":"video",
      "app":{"liveScene":{"revision":scene,"source":{"objectId":scene,"revision":scene},"packageBody":encoded,"html":html}}}]}
body["dependency_manifest"] = {"media":[{"media_id":scene,"content_digest":scene},{"media_id":audio,"content_digest":audio}]}
accepted = service.publish_parent_composition(project["id"],"main",body,idempotency_key="original-publication")
service.create_timeline(project["id"], "cuts", idempotency_key="cuts-timeline")
cuts = _publication(project["id"],parent_revision_id="parent-cuts",shot_revision_id="shot-cuts")
cuts["timeline_id"] = "cuts"
cuts["internal_timeline_revisions"][0].update(timeline_id="cuts",revision_id="internal-cuts")
cuts["shot_revisions"][0]["internal_timeline_revision_id"] = "internal-cuts"
service.publish_parent_composition(project["id"],"cuts",cuts,idempotency_key="original-cuts-publication")
result = {"schema": SCHEMA_VERSION, "project": project["id"], "realm": service.realm["id"],
          "publication": accepted, "scene": scene, "audio": audio}
assert service.store.integrity_report()["ok"]
service.close()
print(json.dumps(result))
'''


@pytest.fixture(scope="module")
def captures(tmp_path_factory):
    base = tmp_path_factory.mktemp("authentic-v33-captures")
    result = {}
    for label, ref in (("R0", R0), ("R1", R1), ("M32", M32)):
        checkout = extract_executable(ref, base / (label + "-executable"))
        target = base / label
        target.mkdir()
        facts = historical_run(checkout, CAPTURE, target)
        result[label] = (checkout, target / "realm", facts)
    return result


def copy_capture(captures, label, destination):
    checkout, source, facts = captures[label]
    shutil.copytree(source, destination)
    return checkout, facts


def _copy_family_rows(source, target, *, selected=None):
    source.row_factory = sqlite3.Row
    tables = {r[0] for r in target.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    source_tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in sorted(tables & source_tables):
        if table in {"runtime_schema", "realm"} or (selected is not None and table not in selected):
            continue
        names = [r[1] for r in target.execute(f'PRAGMA table_info("{table}")')]
        old_names = {r[1] for r in source.execute(f'PRAGMA table_info("{table}")')}
        for row in source.execute(f'SELECT * FROM "{table}"'):
            values = {}
            for name in names:
                if name in old_names:
                    values[name] = row[name]
                elif name == "spec_json":
                    values[name] = source.execute("SELECT body_json FROM task_specs WHERE digest=?", (row["spec_digest"],)).fetchone()[0]
            columns = ",".join('"' + name + '"' for name in values)
            target.execute(f'INSERT INTO "{table}" ({columns}) VALUES (' + ",".join("?" for _ in values) + ")", list(values.values()))


def family_realm(captures, root, family, *, components=(), populated_revisions=True):
    _, source, facts = captures["R0"]
    legacy = family.startswith("L23")
    target = legacy_database(family.endswith("-nullable"), components) if legacy else database(family)
    target.execute("DELETE FROM realm")
    with sqlite3.connect(source / "realm.sqlite3") as old:
        realm = old.execute("SELECT * FROM realm").fetchone()
        target.execute("INSERT INTO realm VALUES (?,?,?,?)", realm)
        selected = None
        if legacy and not populated_revisions:
            selected = {r[0] for r in target.execute("SELECT name FROM sqlite_master WHERE type='table'")} - set(_REVISION_TABLES)
        _copy_family_rows(old, target, selected=selected)
    # At least two rows require a deterministic SQL backfill, independently of
    # already-tagged settlement rows. Existing values and import rules still win.
    target.execute("UPDATE generations SET metadata_json=json_set(metadata_json, '$.params', json('{\"model\":\"fixture-model\",\"modality\":\"video\"}'))")
    root.mkdir()
    with sqlite3.connect(root / "realm.sqlite3") as out:
        target.commit(); target.backup(out)
    target.close()
    shutil.copytree(source / "cas", root / "cas")
    (root / "staging").mkdir(exist_ok=True)
    return facts


def current_service(root):
    # DESIGN rev 3 §8 (migration): U33 provider activation is offline; current service requires V34.
    from custody_schema_fixtures import activate_fixture_to_current
    if upgrade.inspect_realm_schema(root)['kind'] == 'U33':
        life.check_startup(root)
        activate_fixture_to_current(root)
    return RuntimeService(root)


def migrate(root):
    identity = upgrade.inspect_realm_schema(root)
    if identity["version"] == 23:
        return upgrade.upgrade_realm(root, retain_backup=True, archive_root=root.parent / "archives",
                                     confirmation=f"UPGRADE {identity['realm_id']}")
    # DESIGN rev 3 §8 (migration): the historical backfill remains explicitly U33.
    migrate_stage = upgrade.migrate_canonical_to_current if identity['kind'] == 'V34' else upgrade.migrate_canonical_to_v33
    return migrate_stage(root, confirmation=f"MIGRATE CANONICAL {identity['realm_id']}")


def witness(connection, tables):
    return {table: [tuple(row) for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')] for table in tables}


def assert_registration_restart(root, project):
    service = current_service(root)
    try:
        # DESIGN rev 3 §8 (migration): the U33 offline gate is complete; this V34 process must register anew.
        with pytest.raises(ConflictError, match="v33 provider registration is required for this process before requests and fresh pins"):
            service.get_project_media_selection(project, {}, authorize=lambda: None)
        service.register_timeline_commit_provider(PreparedProvider())
        before = witness(service.store.conn, ("timeline_commit_history", "command_idempotency", "timeline_events"))
        assert service.timeline_recovery_inventory(project, "main", authorize=lambda: None)["access"] == "verified"
        with pytest.raises(ValidationError, match="startup-only"):
            service.register_timeline_commit_provider(PreparedProvider())
        assert witness(service.store.conn, before) == before
    finally:
        service.close()
    service = current_service(root)
    service.register_timeline_commit_provider(PreparedProvider())
    assert witness(service.store.conn, before) == before
    return service


@pytest.mark.parametrize("family", ["C24", "C24-nullable", "C25", "C25-nullable", "C26", "C26-nullable", "C27", "C27-nullable", "C28", "C29", "C30", "C31"])
def test_V33_POPULATED_C24_through_C31(captures, tmp_path, family):
    root = tmp_path / "realm"
    facts = family_realm(captures, root, family)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        before = witness(connection, ("projects", "timeline_events", "command_idempotency", "parent_composition_revisions", "generation_variants"))
        old_columns = {table: [r[1] for r in connection.execute(f'PRAGMA table_info("{table}")')] for table in before}
    cas_before = tree(root / "cas")
    result = migrate(root)
    assert result["target_schema_version"] == 33
    assert life.activation(root)[1]["state"] == "backfill_complete"
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        # Added nullable manifest column is the sole change to old revision rows.
        for table in before:
            names = old_columns[table]
            actual = [tuple(r) for r in connection.execute(f'SELECT ' + ",".join(names) + f' FROM "{table}" ORDER BY rowid')]
            assert actual == before[table]
    assert tree(root / "cas") == cas_before
    service = assert_registration_restart(root, facts["project"])
    try:
        assert service.store.integrity_report()["ok"]
    finally:
        service.close()


@pytest.mark.parametrize("label,version", [("R0", 31), ("R1", 31), ("M32", 32)])
def test_V33_AUTHENTIC_R0_R1_M32(captures, tmp_path, label, version):
    root = tmp_path / "realm"
    _, facts = copy_capture(captures, label, root)
    assert facts["schema"] == version
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        before = witness(connection, ("projects", "generations", "generation_variants", "command_idempotency", "timeline_events"))
    migrate(root)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        for table in ("projects", "generation_variants", "command_idempotency", "timeline_events"):
            assert witness(connection, (table,))[table] == before[table]
    service = assert_registration_restart(root, facts["project"])
    try:
        service.test_project = facts["project"]
        accepted = commit(service, request(service), key="verified-runtime-edit")
        assert accepted["data"]["status"] == "accepted"
        selected = {"project_id": facts["project"], "timeline_id": "main",
                    "revision_id": accepted["data"]["accepted_revision_id"],
                    "publication_id": accepted["receipt"]["receipt_id"],
                    "content_digest": accepted["data"]["canonical_document"]["parent_revision"]["content_digest"]}
        render = service.create_task({"project": facts["project"], "capability_id": "rendering.render",
                    "capability_digest": "sha256:" + hashlib.sha256(b"rendering.render").hexdigest(),
                    "input_object_ids": [], "idempotency_key": "verified-runtime-edit:render",
                    "spec": {"family": "render", "params": {"timeline_ref": "main", "selector": "rendering.remotion", "canonical_revision": selected}}})
        authority = render["task"]["spec"]["spec"]["inputs"]["timeline_authority"]
        assert authority["parent_revision_id"] == selected["revision_id"]
        assert authority["parent_content_digest"] == selected["content_digest"]
        assert service.create_task({"project": facts["project"], "capability_id": "rendering.render",
                    "capability_digest": "sha256:" + hashlib.sha256(b"rendering.render").hexdigest(),
                    "input_object_ids": [], "idempotency_key": "verified-runtime-edit:render",
                    "spec": {"family": "render", "params": {"timeline_ref": "main", "selector": "rendering.remotion", "canonical_revision": selected}}}) == render
    finally:
        service.close()


@pytest.mark.parametrize("family", ["H31", "TL32"])
def test_V33_POPULATED_H31_TL32(captures, tmp_path, family):
    from precut_realm_fixture import _extract_archive, FIXTURE_BACKUP_KEY
    from runtime_protocol.backup import restore_backup, verify_backup
    archive = _extract_archive(tmp_path / "historical", REPO / "tests/fixtures/precut-v31.tar.gz")
    assert verify_backup(archive, key=FIXTURE_BACKUP_KEY, older_schema=True)["manifest"]["schema"]["version"] == 31
    root = tmp_path / "realm"
    restore_backup(archive, root, key=FIXTURE_BACKUP_KEY, older_schema=True)
    if family == "TL32":
        with sqlite3.connect(root / "realm.sqlite3") as connection:
            upgrade._apply_v31_to_v32(connection)
    assert upgrade.inspect_realm_schema(root)["kind"] == family
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        before = witness(connection, ("timeline_commit_history", "timeline_document_input_contents", "timeline_events", "command_idempotency"))
    migrate(root)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert witness(connection, before) == before
    service = current_service(root)
    service.register_timeline_commit_provider(PreparedProvider())
    assert service.store.integrity_report()["ok"]
    service.close()


OPTIONALS = ("user_preferences", "user_app_state", "task_specs", *_REVISION_TABLES)
L23_CASES = [(), *((name,) for name in OPTIONALS), OPTIONALS,
             ("internal_timeline_revisions", "shot_revisions")]


@pytest.mark.parametrize("nullable", [False, True])
@pytest.mark.parametrize("components", L23_CASES, ids=lambda x: "none" if not x else "+".join(x))
def test_V33_L23_ADDITIVE_VARIANTS(captures, tmp_path, nullable, components):
    root = tmp_path / "realm"
    complete = set(_REVISION_TABLES).issubset(components)
    facts = family_realm(captures, root, "L23-nullable" if nullable else "L23", components=components,
                         populated_revisions=complete)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        if "user_preferences" in components:
            connection.execute("INSERT INTO user_preferences(actor_id,id,content,version,created_at,updated_at) VALUES ('author','kept','{\"theme\":\"dark\"}',1,'t','t')")
        if "user_app_state" in components:
            connection.execute("INSERT INTO user_app_state VALUES ('author','outbox','{\"key\":\"original\"}',1,'t','t')")
        if components == ("internal_timeline_revisions", "shot_revisions"):
            with sqlite3.connect(captures["R0"][1] / "realm.sqlite3") as source:
                _copy_family_rows(source, connection, selected=set(components))
        preserved = witness(connection, [t for t in components if t != "task_specs"])
        if not complete and "parent_composition_heads" in components:
            # No legacy head is fabricated for the intentionally partial fixture.
            assert connection.execute("SELECT COUNT(*) FROM parent_composition_heads").fetchone()[0] == 0
    result = migrate(root)
    assert result["backup_retained"]
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        for table, expected in preserved.items():
            names = [r[1] for r in connection.execute(f'PRAGMA table_info("{table}")') if r[1] not in {"publication_id", "commit_manifest_json"}]
            actual = [tuple(r) for r in connection.execute('SELECT ' + ",".join(names) + f' FROM "{table}" ORDER BY rowid')]
            assert actual == expected
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None
        assert connection.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 2
    assert life.read_record(Path(result["recovery_set"]) / "backfill-complete.json")["inventory"]


def test_V33_L23_DANGLING_REFUSAL(captures, tmp_path):
    root = tmp_path / "realm"
    family_realm(captures, root, "L23", components=_REVISION_TABLES)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        connection.execute("INSERT INTO composition_revision_dependencies VALUES ('missing-parent','media','missing-object','missing-digest',0)")
    before = tree(root)
    with pytest.raises(ValidationError, match="foreign-key"):
        migrate(root)
    assert tree(root) == before


@pytest.mark.parametrize("family", ["C31", "L23"])
@pytest.mark.parametrize("boundary", ["schema_committed", "plan_persisted", "during_apply", "backfill_committed", "backfill_complete", "during_provider", "after_provider"])
def test_V33_BACKFILL_RESTART_BOUNDARIES(captures, tmp_path, boundary, family):
    root = tmp_path / "realm"
    facts = family_realm(captures, root, family, components=OPTIONALS if family == "L23" else ())
    script = '''
import os,signal,sqlite3,sys
from pathlib import Path
from runtime_protocol import upgrade, v33_lifecycle as life
from runtime_protocol.service import RuntimeService
from test_timeline_commit_port import PreparedProvider
from runtime_protocol.timeline_commit_store import TimelineCommitStore
root=Path(sys.argv[1]); boundary=sys.argv[2]
original=life.phase
def phase(archive,record,state,**facts):
    original(archive,record,state,**facts)
    if state==boundary: os.kill(os.getpid(),signal.SIGKILL)
life.phase=phase
if boundary=='during_apply':
    original_reconcile=__import__('runtime_protocol.v33_backfill_plan',fromlist=['reconcile_generation_plan']).reconcile_generation_plan
    import runtime_protocol.v33_backfill_plan as plan
    def reconcile(connection,value,**kwargs):
        connection.set_trace_callback(lambda sql: os.kill(os.getpid(),signal.SIGKILL) if sql.startswith('UPDATE generations') else None)
        return original_reconcile(connection,value,**kwargs)
    plan.reconcile_generation_plan=reconcile
identity=upgrade.inspect_realm_schema(root)
if identity['version']==23:
    upgrade.upgrade_realm(root,confirmation='UPGRADE '+identity['realm_id'],retain_backup=True,archive_root=root.parent/'archives')
else:
    upgrade.migrate_canonical_to_current(root,confirmation='MIGRATE CANONICAL '+identity['realm_id'])
if boundary=='during_provider':
    original_install=TimelineCommitStore._install_entries
    def install(self,*args,**kwargs):
        original_install(self,*args,**kwargs)
        os.kill(os.getpid(),signal.SIGKILL)
    TimelineCommitStore._install_entries=install
service=RuntimeService(root)
service.register_timeline_commit_provider(PreparedProvider())
if boundary=='after_provider': os.kill(os.getpid(),signal.SIGKILL)
'''
    # DESIGN rev 3 §8 (migration): exercise the frozen U33 provider gate with its owning binary.
    from custody_schema_fixtures import v33_executable
    owning = v33_executable(root)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(owning), str(REPO / "tests")))}
    result = subprocess.run([sys.executable, "-c", script, str(root), boundary], cwd=owning, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == -signal.SIGKILL, result.stderr
    archive, record = life.activation(root)
    if record["state"] not in {"backfill_complete", "ready"}:
        with pytest.raises(ConflictError, match="activation incomplete"):
            RuntimeService(root)
    frozen = life.read_record(archive / "backfill-plan.json") if (archive / "backfill-plan.json").exists() else None
    migrate(root)
    if frozen:
        assert life.read_record(archive / "backfill-plan.json") == frozen
    service = current_service(root)
    service.register_timeline_commit_provider(PreparedProvider())
    expected = life.read_record(archive / "backfill-plan.json")
    for entry in expected["entries"]:
        row = service.store.conn.execute("SELECT id,metadata_json,version,updated_at FROM generations WHERE id=?", (entry["before"]["id"],)).fetchone()
        assert dict(row) == entry["after"]
    service.close()


def test_V33_MIXED_BACKFILL_REFUSES_WITH_ZERO_EFFECTS(captures, tmp_path, monkeypatch):
    root = tmp_path / "realm"
    family_realm(captures, root, "C31")
    original = life.phase
    def lose_ack(archive, record, state, **facts):
        original(archive, record, state, **facts)
        if state == "plan_persisted":
            raise KeyboardInterrupt("uncatchable coordinator interruption")
    with monkeypatch.context() as patch:
        patch.setattr(life, "phase", lose_ack)
        with pytest.raises(KeyboardInterrupt): migrate(root)
    archive, record = life.activation(root)
    plan = life.read_record(archive / "backfill-plan.json")
    changed = [e for e in plan["entries"] if e["before"] != e["after"]]
    assert len(changed) == 2
    entry = changed[0]["after"]
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        connection.execute("UPDATE generations SET metadata_json=?,version=?,updated_at=? WHERE id=?", (entry["metadata_json"],entry["version"],entry["updated_at"],entry["id"]))
    before = tree(root)
    with pytest.raises(ConflictError, match="mixed or changed"): migrate(root)
    assert tree(root) == before
    assert not (archive / "backfill-complete.json").exists()


@pytest.mark.parametrize("variant", ["single", "history", "legacy-document", "empty", "opaque-config", "explicit-media"])
def test_V33_TIMELINE_USABLE_OR_ACTIONABLE(tmp_path, variant):
    from baseline_fixture import load_baseline_fixture
    from runtime_protocol.timeline_recovery import offline_export
    service, project, _ = load_baseline_fixture(tmp_path, variant)
    root = service.store.root
    try:
        if variant in {"explicit-media", "opaque-config"}:
            service.store.conn.execute("DELETE FROM command_idempotency WHERE command_kind='parent_composition.publish'")
        before = witness(service.store.conn, ("parent_composition_revisions", "command_idempotency", "timeline_events"))
        service.register_timeline_commit_provider(PreparedProvider())
        result = service.timeline_recovery_inventory(project, "main", authorize=lambda: None)
        valid = variant in {"single", "history", "empty"}
        assert result["access"] == ("verified" if valid else "read_only")
        if not valid:
            assert result["reason"]["code"] == "history_unavailable"
            assert result["actions"] and result["backup"]["location"]
            assert witness(service.store.conn, before) == before
    finally:
        service.close()
    before = tree(root)
    exported = offline_export(root, project, "main", destination=tmp_path / "support-export")
    assert exported["rows"]["parent_composition_revisions"]
    assert tree(root) == before
    assert (tmp_path / "support-export" / "inventory.json").is_file()


def test_V33_IDEMPOTENT_U33_AFTER_AUTHORIZED_WRITES(captures, tmp_path):
    root = tmp_path / "realm"
    facts = family_realm(captures, root, "C31")
    migrate(root)
    service = assert_registration_restart(root, facts["project"])
    service.rename_timeline(facts["project"], "main", {"name":"After activation"}, idempotency_key="later-write")
    service.store.conn.execute("UPDATE generations SET version=version+1, updated_at='authorized-later-write'")
    service.close()
    before = tree(root)
    assert migrate(root)["changed"] is False
    assert migrate(root)["changed"] is False
    assert tree(root) == before
    service = current_service(root)
    service.register_timeline_commit_provider(PreparedProvider())
    assert service.store.conn.execute("SELECT min(updated_at) FROM generations").fetchone()[0] == "authorized-later-write"
    service.close()


@pytest.mark.parametrize("failure", ["before_ddl_commit", "schema_committed", "backfill_committed"])
def test_V33_INTERRUPT_FULL_RESTORE_WITH_WAL(captures, tmp_path, monkeypatch, failure):
    root = tmp_path / "realm"
    _, facts = copy_capture(captures, "R0", root)
    subprocess.run([sys.executable, "-c", "import os,sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA wal_autocheckpoint=0'); c.execute(\"UPDATE realm SET display_name='WAL only preserved'\"); c.commit(); os._exit(0)", str(root / "realm.sqlite3")], check=True)
    assert (root / "realm.sqlite3-wal").is_file()
    before = tree(root)
    original = life.phase
    def interrupt(archive, record, state, **details):
        original(archive, record, state, **details)
        if state == failure:
            (root / "cas" / "candidate-only").write_bytes(b"failed candidate")
            raise RuntimeError("injected activation failure")
    def fail_ddl(connection, family):
        raise RuntimeError("injected activation failure")
    with monkeypatch.context() as patch:
        patch.setattr(life, "phase", interrupt)
        if failure == "before_ddl_commit":
            patch.setattr(upgrade, "_apply_v32_to_v33", fail_ddl)
        with pytest.raises(RuntimeError, match="injected activation failure"):
            migrate(root)
    assert tree(root) == before
    identity = upgrade.inspect_realm_schema(root)
    assert identity["kind"] == "C31"
    archive = next((tmp_path / ".v33-recovery").iterdir())
    record = life.read_record(archive / "activation.json")
    assert record["state"] == "restored"
    life.verify_tree(archive / "realm", record["inventory"])
    life.verify_sqlite_image(root, realm_id=facts["realm"], fingerprint=identity["fingerprint"])


def test_V33_RECLASSIFY_UNDER_LOCK(captures, tmp_path, monkeypatch):
    from contextlib import contextmanager
    root = tmp_path / "realm"
    copy_capture(captures, "R0", root)
    original = upgrade._owner_fence
    @contextmanager
    def racing_owner(path):
        with sqlite3.connect(path / "realm.sqlite3") as connection:
            connection.execute("CREATE INDEX racing_index ON generations(id)")
        with original(path): yield
    with monkeypatch.context() as patch:
        patch.setattr(upgrade, "_owner_fence", racing_owner)
        with pytest.raises(ValidationError, match="unsupported canonical"):
            migrate(root)
    assert not (root / life.MARKER).exists()
    assert not (tmp_path / ".v33-recovery").exists()


@pytest.mark.parametrize("archive_profile", ["fixture", "production"])
@pytest.mark.parametrize("workers", [False, True])
def test_V33_L23_ARCHIVAL_BYTES_AND_WORKERS(captures, tmp_path, archive_profile, workers):
    root = tmp_path / "realm"
    family_realm(captures, root, "L23", components=OPTIONALS)
    ref = "f11686875be9907f12da6d7eb73f02c9b76d7adc"
    connection = sqlite3.connect(root / "realm.sqlite3")
    if archive_profile == "production":
        for filename in ("010_migration_event_ledger.sql", "011_migration_owner_data.sql", "017_backfill_canonical_receipts.sql"):
            connection.executescript(subprocess.check_output(["git", "show", ref + ":runtime_protocol/migrations/" + filename], cwd=REPO, text=True))
        connection.execute("INSERT INTO canonical_receipt_backfills VALUES (1,16,7,'retained')")
        connection.execute("INSERT INTO migration_event_streams(source_stream_id,destination_stream_id,stream_type,aggregate_id,head_seq,created_at) VALUES ('source','dest','legacy','a',1,'t')")
        connection.execute("INSERT INTO migration_events(source_event_id,destination_event_id,source_stream_id,destination_stream_id,seq,kind,payload_json,created_at) VALUES ('s-event','d-event','source','dest',1,'original','{\"bytes\":\"retained\"}','t')")
        connection.execute("INSERT INTO migration_owner_records VALUES ('legacy','key',0,'{\"draft\":true}','hash','t')")
    else:
        connection.executescript("""
        CREATE TABLE canonical_receipt_backfills(id INTEGER PRIMARY KEY,detail TEXT);
        CREATE TABLE lost_and_found(id INTEGER PRIMARY KEY,payload BLOB);
        CREATE TABLE migration_event_streams(id TEXT PRIMARY KEY,payload TEXT);
        CREATE TABLE migration_events(id TEXT PRIMARY KEY,payload TEXT);
        CREATE TABLE migration_owner_records(id TEXT PRIMARY KEY,payload TEXT);
        INSERT INTO canonical_receipt_backfills VALUES (1,'original');
        INSERT INTO migration_event_streams VALUES ('stream','original');
        INSERT INTO migration_events VALUES ('event','original');
        INSERT INTO migration_owner_records VALUES ('owner','original');
        """)
        connection.execute("INSERT INTO lost_and_found VALUES (1,?)", (b"\x00\xfforiginal-archive",))
    if workers:
        old = sqlite3.connect(":memory:")
        paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", ref, "runtime_protocol/migrations"], cwd=REPO, text=True).splitlines()
        for filename in paths[:18]:
            old.executescript(subprocess.check_output(["git", "show", ref + ":" + filename], cwd=REPO, text=True))
        connection.execute(old.execute("SELECT sql FROM sqlite_master WHERE name='workers'").fetchone()[0])
        connection.execute("INSERT INTO workers(id,capabilities_json,max_concurrency,resource_keys_json,created_at,last_seen_at) VALUES ('retained-worker','[]',1,'[]','t','t')")
        old.close()
    selected = set(upgrade.LEGACY_TABLES) & {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected = witness(connection, selected)
    connection.commit(); connection.close()
    result = migrate(root)
    archive = Path(result["archive"])
    with life.sqlite_observation(archive) as copy, sqlite3.connect(copy / "realm.sqlite3") as connection:
        assert witness(connection, selected) == expected
    manifest = json.loads((archive / "manifest.json").read_text())
    assert set(manifest["legacy_tables"]) == selected
    life.verify_tree(Path(result["recovery_set"]) / "realm", life.activation(root)[1]["inventory"])
    exported = life.inspect_recovery_set(result["recovery_set"], destination=tmp_path / "original-export")
    assert exported["verified"] and set(expected) <= set(exported["tables"])
    assert (tmp_path / "original-export/realm/realm.sqlite3").is_file()


@pytest.mark.parametrize("recovery_mode", ["automatic", "explicit_interruption", "interrupted_restore"])
def test_V33_ACTUAL_R0_ROLLBACK_FULL_SET_BEFORE_EXECUTABLE_LAUNCH(captures, tmp_path, monkeypatch, recovery_mode, request):
    # DESIGN rev 3 §8 (migration): retain the U33-only rollback journey on its owning binary.
    if SCHEMA_VERSION == 34:
        from custody_schema_fixtures import historical_case
        return historical_case(tmp_path, 'test_V33_ACTUAL_R0_ROLLBACK_FULL_SET_BEFORE_EXECUTABLE_LAUNCH[' + recovery_mode + ']', record_property=lambda name, value: request.node.user_properties.append((name, value)))
    from astrid_runtime import operator_upgrade as operator
    from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile
    from astrid_runtime.paths import RuntimePaths
    from http_helpers import Api
    prior_checkout, original, facts = captures["R0"]
    paths = RuntimePaths.current(home=tmp_path, data_root=tmp_path / "support")
    paths.ensure_support_dirs()
    root = paths.realms_dir / facts["realm"]
    shutil.copytree(original, root)
    prior = SourceProfile(profile="astrid", runtime_checkout=str(prior_checkout), source_checkout=str(prior_checkout))
    target = SourceProfile(profile="astrid", runtime_checkout=str(REPO), source_checkout=str(prior_checkout))
    paths.catalog_path.write_text(json.dumps({"version":1,"selected_realm_id":facts["realm"],
        "realms":[{"realm_id":facts["realm"],"display_name":"Original","data_root":str(root)}],"source_profiles":{"astrid":prior.as_dict()}}))
    (paths.source_profiles_dir / "astrid.json").write_text(json.dumps(prior.as_dict()))
    (paths.app_support / "outbox.json").write_text('{"key":"original-key","payload":"original-payload","state":"unaccepted"}')
    original_outbox = (paths.app_support / "outbox.json").read_bytes()
    before = tree(root)
    children, launched = [], []
    class Boundary:
        def prepare_restart(self, **kwargs): pass
        def stop_owner(self, **kwargs): raise AssertionError("no running candidate owner was published")
        def is_pid_alive(self, pid): return False
        def health(self, *, endpoint, **kwargs):
            token = (paths.runtime_support / "credentials" / "owner.token").read_text().strip()
            return Api(endpoint, token).health()["status"] == "ok"
        def connect(self, *, endpoint, credential, **kwargs):
            return SimpleNamespace(doctor=lambda: Api(endpoint, credential).request("GET", "/v1/doctor"))
    def start(selected_paths, boundary, config):
        selected = Path(config.source_profile.runtime_checkout)
        if selected == REPO:
            service = current_service(root)
            service.register_timeline_commit_provider(PreparedProvider())
            assert upgrade.inspect_realm_schema(root)["version"] == 33
            assert life.activation(root)[1]["state"] == "provider_verified"
            service.close()
            (root / "cas" / "candidate-only").write_bytes(b"candidate failure evidence")
            (paths.app_support / "outbox.json").write_text('{"mutated":"candidate"}')
            if recovery_mode == "explicit_interruption":
                raise KeyboardInterrupt("lost coordinator after candidate registration")
            raise RuntimeError("candidate failed readiness after committed migration and backfill")
        # These assertions run before Python is launched. The source tree and
        # complete matching data/outbox have already been restored and verified.
        assert tree(root) == before
        assert (paths.app_support / "outbox.json").read_bytes() == original_outbox
        assert (selected / "runtime_protocol/store.py").read_bytes() == subprocess.check_output(["git","show",R0+":runtime_protocol/store.py"],cwd=REPO)
        assert json.loads(paths.catalog_path.read_text())["selected_realm_id"] == facts["realm"]
        script = '''
import json,sys
from pathlib import Path
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import SCHEMA_VERSION
import runtime_protocol.store as executable
assert SCHEMA_VERSION==31
runtime=RuntimeDaemon(Path(sys.argv[1]),support_root=Path(sys.argv[2]),owner_lock=Path(sys.argv[2])/'instance.lock',log_directory=Path(sys.argv[2])/'logs')
runtime.start()
assert runtime.service.get_project(sys.argv[3])['id']==sys.argv[3]
assert len(runtime.service.list_generations(sys.argv[3])['items'])==2
print(json.dumps({'schema':SCHEMA_VERSION,'module':executable.__file__,'endpoint':runtime.endpoint}),flush=True)
sys.stdin.readline()
runtime.stop()
'''
        env = {**os.environ,"PYTHONPATH":str(selected),"PYTHONDONTWRITEBYTECODE":"1"}
        process = subprocess.Popen([sys.executable,"-u","-B","-c",script,str(root),str(paths.runtime_support),facts["project"]],cwd=selected,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(process)
        import select
        assert select.select([process.stdout],[],[],20)[0], "R0 daemon did not report startup"
        line = process.stdout.readline()
        assert line, process.stderr.read()
        proof = json.loads(line)
        launched.append(proof)
        assert proof["schema"] == 31 and str(selected) in proof["module"]
        discovery = json.loads(paths.discovery_path.read_text())
        return SimpleNamespace(endpoint=proof["endpoint"],pid=process.pid,runtime_instance_id=discovery["runtime_instance_id"])
    monkeypatch.setattr(operator,"_bootstrap_locked",start)
    if recovery_mode == "interrupted_restore":
        original_phase = life.phase
        interrupted = []
        def lost_restore_ack(archive,record,state,**facts):
            original_phase(archive,record,state,**facts)
            if state == "restored" and not interrupted:
                interrupted.append(True)
                raise KeyboardInterrupt("lost durable restore acknowledgement")
        monkeypatch.setattr(life,"phase",lost_restore_ack)
    try:
        if recovery_mode in {"explicit_interruption", "interrupted_restore"}:
            with pytest.raises(KeyboardInterrupt):
                operator.upgrade_workspace(paths,Boundary(),BootstrapConfig(source_profile=target))
            assert operator.recover_workspace(paths,Boundary(),BootstrapConfig(source_profile=target))["state"] == "rolled_back"
        else:
            with pytest.raises(operator.OperatorUpgradeError,match="candidate failed readiness"):
                operator.upgrade_workspace(paths,Boundary(),BootstrapConfig(source_profile=target))
        assert len(launched)==1
        journal = json.loads((paths.runtime_support / "upgrade-journal.json").read_text())
        assert journal["state"] == "rolled_back" and journal.get("recovery_error") is None
        archive = Path(journal["recovery_set"])
        assert life.read_record(archive / "activation.json")["state"] == "restored"
        assert any(archive.glob("failed-*"))
        assert (paths.app_support / "outbox.json").read_bytes() == original_outbox
    finally:
        for process in children:
            if process.poll() is None:
                process.communicate("stop\n",timeout=20)


@pytest.mark.parametrize("family", ["C27", "C27-nullable", "C28", "L23"])
def test_V33_V28_V29_SNAPSHOT_ORDER_AND_REPLAY(captures, tmp_path, family):
    from runtime_protocol.snapshot_refs import restore_spec_snapshots
    root = tmp_path / "realm"
    facts = family_realm(captures, root, family, components=OPTIONALS if family == "L23" else ())
    snapshot = {"config":{"clips":[{"id":"retained-inline","hold":2}]},"registry":{"assets":{}}}
    parent = facts["publication"]["data"]
    spec = {"spec":{"timeline_snapshot":snapshot,"inputs":{"timeline_authority":{
        "project_id":facts["project"],"timeline_id":"main","parent_revision_id":parent["parent_revision_id"],
        "parent_content_digest":parent["content_digest"]}}},"input_object_ids":[]}
    body = canonical_json(spec)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        if family == "C28":
            checksum = hashlib.sha256(body.encode()).hexdigest()
            connection.execute("INSERT INTO task_specs VALUES (?,?,?)",(checksum,body,'t'))
            for table in ("runs","tasks"):
                connection.execute(f"UPDATE {table} SET spec_digest=?",(checksum,))
        else:
            for table in ("runs","tasks"):
                connection.execute(f"UPDATE {table} SET spec_json=?",(body,))
    result = migrate(root)
    if family == "L23":
        service = current_service(root)
        try:
            retained = service.store.conn.execute("SELECT s.body_json FROM tasks t JOIN task_specs s ON s.digest=t.spec_digest").fetchone()[0]
            assert retained == body
            assert json.loads(retained)["spec"]["timeline_snapshot"] == snapshot
        finally:
            service.close()
        return
    versions = [(s["source_schema_version"],s["target_schema_version"]) for s in result["steps"]]
    assert versions.index((28,29)) < versions.index((29,30))
    if family.startswith("C27"):
        assert versions.index((27,28)) < versions.index((28,29))
    step = next(s for s in result["steps"] if s["source_schema_version"] == 28)
    assert step["referenced_pairs"] == 1
    service = current_service(root)
    try:
        raw = json.loads(service.store.conn.execute("SELECT s.body_json FROM tasks t JOIN task_specs s ON s.digest=t.spec_digest").fetchone()[0])
        ref = raw["spec"]["timeline_snapshot_ref"]
        assert json.loads(service.cas.read(ref["digest"].removeprefix("sha256:"))) == snapshot
        replay = restore_spec_snapshots(raw,lambda r: json.loads(service.cas.read(r["digest"].removeprefix("sha256:"))))
        replay["input_object_ids"] = []
        assert replay == spec
    finally:
        service.close()


def test_V33_EXISTING_PINS_AFFECTED_AND_UNAFFECTED(captures, tmp_path):
    import threading
    from runtime_protocol.cas import ContentAddressedStore
    from runtime_protocol.timeline_commit_port import MediaReads
    root = tmp_path / "realm"
    _, facts = copy_capture(captures,"R0",root)
    original = {}
    # Explicit imported fixture rows use retained public-API-owned audio bytes.
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        for name in ("affected","unaffected"):
            metadata = {"provenance":{"origin":"imported"},"params":{"duration_seconds":1,"modality":"audio","model":"fixture"}}
            if name == "unaffected": metadata["gen"] = {"kind":"audio","model":"fixture","origin":"imported"}
            connection.execute("INSERT INTO generations(id,project_id,type,status,metadata_json,version,created_at,updated_at) VALUES (?,?,'audio','completed',?,1,'t','t')",(name,facts["project"],canonical_json(metadata)))
            connection.execute("INSERT INTO generation_variants(id,generation_id,object_id,variant_type,metadata_json,created_at) VALUES (?,?,?,'original','{}','t')",(name+'-variant',name,facts["audio"].removeprefix('sha256:')))
    # DESIGN rev 3 §8 (migration): release the historical SQLite writer before offline activation.
    connection.close()
    # This is a read of inactive historical input, never a service activation.
    with life.sqlite_observation(root) as copy:
        connection=sqlite3.connect(copy / "realm.sqlite3"); connection.row_factory=sqlite3.Row
        store=SimpleNamespace(conn=connection,_mutex=threading.RLock(),get_project=lambda p:dict(connection.execute("SELECT * FROM projects WHERE id=?",(p,)).fetchone()))
        def verify_bytes(digest,size,**kwargs):
            data=(root/'cas/sha256'/digest[:2]/digest[2:]).read_bytes()
            assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
        source=SimpleNamespace(store=store,realm={"id":facts["realm"]},cas=ContentAddressedStore(root/'cas/sha256'),_verify_child_object_bytes=verify_bytes)
        for name in ("affected","unaffected"):
            original[name]=MediaReads(source).selection(facts["project"],asset=name,generation_id=name,variant_id=name+'-variant')
        connection.close()
    preserved=canonical_json(original)
    pinned = historical_run(captures["R0"][0], """
import json,sys
from pathlib import Path
from runtime_protocol.service import RuntimeService
from test_shot_composition_runtime import _publication
service=RuntimeService(Path(sys.argv[1])); project=sys.argv[2]; pin=json.loads(sys.argv[3])
body=_publication(project,expected_head='parent-1',parent_revision_id='affected-parent')
body['internal_timeline_revisions']=[];body['shot_revisions']=[];body['parent_composition']['occurrences']=[]
body['parent_composition']['config']={'tracks':[{'id':'audio','kind':'audio'}],'clips':[{'id':'old-input','clipType':'media','at':0,'hold':1,'track':'audio','object_id':pin['object_id'],'media_selection':pin}]}
body['dependency_manifest']={'media':[{'media_id':pin['object_id'],'content_digest':pin['object_id']}]}
accepted=service.publish_parent_composition(project,'main',body,idempotency_key='original-pinned-publication')
service.close();print(json.dumps(accepted))
""",root,facts["project"],canonical_json(original["affected"]))
    migrate(root)
    service=current_service(root)
    try:
        # DESIGN rev 3 §8 (migration): a fresh V34 process still requires provider registration.
        with pytest.raises(ConflictError,match="v33 provider registration is required for this process before requests and fresh pins"):
            service.get_project_media_selection(facts["project"],{"asset":"affected","generation_id":"affected","variant_id":"affected-variant"},authorize=lambda:None)
        provider = PreparedProvider()
        service.register_timeline_commit_provider(provider)
        blocked = service.timeline_recovery_inventory(facts["project"],"main",authorize=lambda:None)
        assert blocked["access"] == "read_only" and blocked["actions"] and blocked["backup"]
        assert service.timeline_recovery_inventory(facts["project"],"cuts",authorize=lambda:None)["access"] == "verified"
        service.test_project = facts["project"]
        with pytest.raises(RuntimeErrorBase) as refusal:
            commit(service,request(service,base_publication_id=pinned["receipt"]["receipt_id"]),key="blocked-old-pin")
        assert refusal.value.status == 409 and refusal.value.details["reason"] == "history_unavailable"
        assert provider.calls == 0
        head=service.get_project_timeline(facts["project"],"cuts")
        body=request(service,timeline_id="cuts",base_revision_id=head["head_revision_id"],base_publication_id=head["head_publication_id"])
        from runtime_protocol.timeline_commit_port import route_path
        assert service.commit_timeline(facts["project"],"cuts",body,idempotency_key="unaffected-new-edit",publisher="editor",invocation_path=route_path(facts["project"],"cuts"),authorize=lambda:None)["data"]["status"] == "accepted"
        assert service.get_project_verified_media(facts["project"],original["unaffected"],authorize=lambda:None)["selection"]==original["unaffected"]
        with pytest.raises(ConflictError,match="catalog digest changed"):
            service.get_project_verified_media(facts["project"],original["affected"],authorize=lambda:None)
        fresh=service.get_project_media_selection(facts["project"],{"asset":"affected","generation_id":"affected","variant_id":"affected-variant"},authorize=lambda:None)
        assert fresh["catalog_digest"]!=original["affected"]["catalog_digest"]
        assert canonical_json(original)==preserved
        # No payload/key is silently replaced: callers must explicitly choose
        # fresh selections as new work. Disconnected App outbox is external.
        document={"project_id":facts["project"],"parent_revision":{"payload":{"media_selection":original["affected"]}}}
        with pytest.raises(ConflictError,match="read-only"):
            service._verify_legacy_media_selections(document)
    finally:
        service.close()


_ACCEPTED_CELLS = {(30,False,False,False),(31,True,False,False),(31,False,True,False),
                   (32,True,False,True),(32,True,True,False),(33,True,True,True)}
_REFUSED_CELLS = [(v,a,t,g) for v in (30,31,32,33) for a in (False,True) for t in (False,True) for g in (False,True)
                  if (v,a,t,g) not in _ACCEPTED_CELLS]


@pytest.mark.parametrize("version,app,timeline,generation_index",_REFUSED_CELLS)
def test_V33_REFUSE_MATRIX_ZERO_EFFECTS(captures,tmp_path,monkeypatch,version,app,timeline,generation_index):
    root=tmp_path/'realm'
    facts=family_realm(captures,root,'U33')
    with sqlite3.connect(root/'realm.sqlite3') as connection:
        if not app: connection.execute('DROP TABLE user_app_state')
        if not timeline:
            for table in ('timeline_document_input_links','timeline_document_input_bindings','timeline_document_input_contents','timeline_commit_history'):
                connection.execute(f'DROP TABLE {table}')
            connection.execute('ALTER TABLE parent_composition_heads DROP COLUMN publication_id')
            connection.execute('ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json')
        if not generation_index: connection.execute('DROP INDEX idx_generations_gen')
        connection.execute('UPDATE runtime_schema SET version=?',(version,))
    before=tree(root)
    def forbidden(*args,**kwargs): raise AssertionError('refusal reached lifecycle mutation')
    monkeypatch.setattr(upgrade,'_owner_fence',forbidden)
    monkeypatch.setattr(life,'begin',forbidden)
    with pytest.raises(ValidationError):
        upgrade.migrate_canonical_to_current(root,expected_realm_id=facts['realm'],confirmation='MIGRATE CANONICAL '+facts['realm'])
    assert tree(root)==before
    assert not (tmp_path/'.v33-recovery').exists()


@pytest.mark.parametrize("damage",['wrong_format','wrong_realm','trigger','view','generated_column','extra_column','missing_index','wrong_index','partial_timeline','newer_schema'])
def test_V33_REFUSE_DAMAGED_POPULATED_ZERO_EFFECTS(captures,tmp_path,monkeypatch,damage):
    root=tmp_path/'realm';facts=family_realm(captures,root,'U33')
    mutations={
        'wrong_format':"UPDATE runtime_schema SET format_id='wrong'",
        'wrong_realm':"UPDATE realm SET id='wrong'",
        'trigger':'CREATE TRIGGER forbidden AFTER INSERT ON projects BEGIN SELECT 1; END',
        'view':'CREATE VIEW forbidden AS SELECT id FROM generations',
        'generated_column':'ALTER TABLE generations ADD COLUMN hidden TEXT GENERATED ALWAYS AS (id) VIRTUAL',
        'extra_column':'ALTER TABLE generations ADD COLUMN unexpected TEXT',
        'missing_index':'DROP INDEX idx_generations_gen',
        'wrong_index':'DROP INDEX idx_generations_gen; CREATE INDEX idx_generations_gen ON generations(id)',
        'partial_timeline':'DROP TABLE timeline_document_input_links',
        'newer_schema':'UPDATE runtime_schema SET version=34',
    }
    with sqlite3.connect(root/'realm.sqlite3') as connection: connection.executescript(mutations[damage])
    before=tree(root)
    def forbidden(*args,**kwargs): raise AssertionError('refusal reached lifecycle mutation')
    monkeypatch.setattr(upgrade,'_owner_fence',forbidden)
    with pytest.raises(ValidationError):
        upgrade.migrate_canonical_to_current(root,expected_realm_id=facts['realm'],confirmation='MIGRATE CANONICAL '+facts['realm'])
    assert tree(root)==before and not (tmp_path/'.v33-recovery').exists()


def test_V33_RESTART_REQUIRES_FRESH_PROVIDER_BEFORE_PINS(captures,tmp_path):
    root=tmp_path/'realm';facts=family_realm(captures,root,'C31');migrate(root)
    service=assert_registration_restart(root,facts['project']);service.close()
    service=current_service(root)
    try:
        with pytest.raises(ConflictError,match='registration is required for this process'):
            service.get_project_media_selection(facts['project'],{},authorize=lambda:None)
        service.register_timeline_commit_provider(PreparedProvider())
        assert life.activation(root)[1]['state']=='ready'
    finally: service.close()
    before=tree(root)
    archive,record=life.activation(root)
    with upgrade._owner_fence(root):
        with pytest.raises(ConflictError,match='pre-admission'):
            life.restore(root,archive)
    assert tree(root)==before


@pytest.mark.parametrize("version",range(24,30))
@pytest.mark.parametrize("app,timeline,generation_index",[(a,t,g) for a in (False,True) for t in (False,True) for g in (False,True) if a or t or g])
def test_V33_REFUSE_OLDER_HYBRIDS_POPULATED(captures,tmp_path,monkeypatch,version,app,timeline,generation_index):
    from runtime_protocol.canonical_schema import TIMELINE_COMMIT_SCHEMA_SQL, GENERATION_TAG_INDEX_SQL
    from runtime_protocol.timeline_commit_inputs import DOCUMENT_INPUT_SCHEMA_SQL
    root=tmp_path/'realm';facts=family_realm(captures,root,'C'+str(version))
    with sqlite3.connect(root/'realm.sqlite3') as connection:
        if app:
            target=database('U33')
            connection.execute(target.execute("SELECT sql FROM sqlite_master WHERE name='user_app_state'").fetchone()[0]);target.close()
        if timeline:
            connection.execute('ALTER TABLE parent_composition_heads ADD COLUMN publication_id TEXT REFERENCES timeline_commit_history(publication_id)')
            connection.execute('ALTER TABLE parent_composition_revisions ADD COLUMN commit_manifest_json TEXT CHECK (commit_manifest_json IS NULL OR json_valid(commit_manifest_json))')
            connection.execute(TIMELINE_COMMIT_SCHEMA_SQL)
            connection.executescript(DOCUMENT_INPUT_SCHEMA_SQL)
        if generation_index: connection.execute(GENERATION_TAG_INDEX_SQL)
    before=tree(root)
    def forbidden(*args,**kwargs): raise AssertionError('hybrid reached lifecycle mutation')
    monkeypatch.setattr(upgrade,'_owner_fence',forbidden)
    with pytest.raises(ValidationError):
        upgrade.migrate_canonical_to_current(root,expected_realm_id=facts['realm'],confirmation='MIGRATE CANONICAL '+facts['realm'])
    assert tree(root)==before and not (tmp_path/'.v33-recovery').exists()


def test_V33_INTERRUPT_SNAPSHOT_CAS_RESTORES_FULL_IMAGE(captures,tmp_path,monkeypatch):
    root=tmp_path/'realm';facts=family_realm(captures,root,'C28')
    parent=facts['publication']['data']
    snapshot={'config':{'clips':[{'id':'preserve-me','hold':2}]},'registry':{}}
    spec={'spec':{'timeline_snapshot':snapshot,'inputs':{'timeline_authority':{'project_id':facts['project'],'timeline_id':'main',
          'parent_revision_id':parent['parent_revision_id'],'parent_content_digest':parent['content_digest']}}},'input_object_ids':[]}
    body=canonical_json(spec);checksum=hashlib.sha256(body.encode()).hexdigest()
    with sqlite3.connect(root/'realm.sqlite3') as connection:
        connection.execute('INSERT INTO task_specs VALUES (?,?,?)',(checksum,body,'t'))
        for table in ('runs','tasks'):connection.execute(f'UPDATE {table} SET spec_digest=?',(checksum,))
    before=tree(root);original_cas=tree(root/'cas')
    def interrupt(connection):
        assert len(tree(root/'cas')) > len(original_cas)
        raise RuntimeError('interrupted after snapshot CAS publication')
    monkeypatch.setattr(upgrade,'_apply_v29_to_v30',interrupt)
    with pytest.raises(RuntimeError,match='snapshot CAS publication'):migrate(root)
    assert tree(root)==before
    archive=next((tmp_path/'.v33-recovery').iterdir());record=life.read_record(archive/'activation.json')
    assert record['state']=='restored'
    assert len(tree(Path(record['failed_image'])/'cas'))>len(original_cas)


def test_V33_BACKUP_FAILURE_PRECEDES_SCHEMA_AND_BACKFILL(captures,tmp_path,monkeypatch):
    root=tmp_path/'realm';copy_capture(captures,'R0',root);before=tree(root)
    def fail_backup(*args,**kwargs):raise OSError('injected recovery storage failure')
    monkeypatch.setattr(life,'snapshot_tree',fail_backup)
    with pytest.raises(OSError,match='recovery storage failure'):migrate(root)
    assert tree(root)==before
    assert upgrade.inspect_realm_schema(root)['kind']=='C31'
    assert not (root/life.MARKER).exists()


def test_V33_RELOCATION_REBINDS_ONLY_COMPLETED_ACTIVATION(captures,tmp_path,request):
    # DESIGN rev 3 §8 (migration): U33 relocation stays covered; V34 relocation has a separate refusal regression.
    if SCHEMA_VERSION == 34:
        from custody_schema_fixtures import historical_case
        return historical_case(tmp_path, 'test_V33_RELOCATION_REBINDS_ONLY_COMPLETED_ACTIVATION', record_property=lambda name, value: request.node.user_properties.append((name, value)))
    root=tmp_path/'realm';facts=family_realm(captures,root,'C31');migrate(root)
    service=assert_registration_restart(root,facts['project']);service.close()
    archive,_=life.activation(root);archived=tree(archive/'realm')
    moved=tmp_path/'relocated-realm';root.rename(moved)
    with pytest.raises(ConflictError,match='binding mismatch'):RuntimeService(moved)
    life.rebind_after_relocation(moved,root)
    service=RuntimeService(moved);service.register_timeline_commit_provider(PreparedProvider());service.close()
    assert life.activation(moved)[1]['realm_root']==str(moved)
    assert tree(archive/'realm')==archived
    assert life.inspect_recovery_set(archive)['verified']
    moved.rename(root);life.rebind_after_relocation(root,moved)
    assert life.activation(root)[1]['state']=='ready'


def test_V33_DIRECTORY_REBIND_REFUSES_STALE_PLAN(captures,tmp_path,monkeypatch):
    from contextlib import contextmanager
    root=tmp_path/'realm';family_realm(captures,root,'C31')
    prior=upgrade._owner_fence
    @contextmanager
    def rebound(path):
        moved=tmp_path/'old-inode';path.rename(moved);path.mkdir()
        os.link(moved/'realm.sqlite3',path/'realm.sqlite3')
        shutil.copytree(moved/'cas',path/'cas');(path/'staging').mkdir()
        with prior(path):yield
    monkeypatch.setattr(upgrade,'_owner_fence',rebound)
    with pytest.raises(ConflictError,match='directory identity changed'):migrate(root)
    assert not (root/life.MARKER).exists() and not (tmp_path/'.v33-recovery').exists()
