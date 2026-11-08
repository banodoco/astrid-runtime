"""Real foreground and child CLI composition of writer-owned admission files."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from astrid_runtime.bootstrap import SourceProfile
from astrid_runtime.runtime_boundary import ForegroundRuntimeBoundary, LocalRuntimeBoundary
from runtime_protocol.store import RealmStore
from tests.test_runtime_pack_admissions import _write_installed_pack
from tests.test_runtime_pack_assets import PACK_ID
from tests.test_runtime_pack_http import _request

ROOT = Path(__file__).resolve().parents[1]

# Pre-main maps the "astrid" source profile to the trusted Agent Timeline
# authoring provider, which startup loads before admission. Like the other
# real astrid-profile startup tests, those below need the Agent checkout
# (ASTRID_CHECKOUT) and carry the integration marker.


def _write_committed_pack(root):
    _root, record, expected = _write_installed_pack(root.parent)
    return record, expected


def _repo(root):
    root.mkdir()
    for args in (("init", "-q"), ("config", "user.name", "Fixture"),
                 ("config", "user.email", "fixture@example.invalid")):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    (root / "declared.txt").write_text("test-owned provenance\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "Fixture [skip ci]"], check=True, capture_output=True)
    return root


@pytest.mark.integration
def test_foreground_uses_source_profile_installed_packs_without_callback(tmp_path, astrid_importable):
    agent = _repo(tmp_path / "agent")
    runtime = _repo(tmp_path / "runtime-provenance")
    admission, expected = _write_committed_pack(agent / "astrid" / "packs" / PACK_ID)
    realm = tmp_path / "realm"
    store = RealmStore.initialize(realm)
    realm_id = store.conn.execute("SELECT id FROM realm").fetchone()[0]
    store.close()
    boundary = ForegroundRuntimeBoundary()
    try:
        boundary.start(realm_id=realm_id, realm_root=realm,
                       owner_lock=tmp_path / "support" / "instance.lock",
                       source_profile=SourceProfile(profile="astrid", runtime_checkout=str(runtime), source_checkout=str(agent)))
        boundary.check_running()
        daemon = boundary.daemon
        status, _headers, body = _request(daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token)
        assert status == 200 and json.loads(body)["packs"][0]["digest"] == admission["digest"]
        path = f"/api/runtime/packs/assets/{PACK_ID}/{admission['digest']}/index.js"
        status, _headers, body = _request(daemon.endpoint, path, token=daemon.token)
        assert status == 200 and body == expected["index.js"][0]
    finally:
        boundary.stop()


@pytest.mark.integration
@pytest.mark.parametrize("source", ["profile", "explicit_collection"])
def test_real_cli_child_reads_persisted_admissions_and_restarts(tmp_path, owned_process_groups, source, astrid_importable):
    agent = _repo(tmp_path / "agent")
    runtime = _repo(tmp_path / "runtime-provenance")
    collection = (agent / "astrid" / "packs") if source == "profile" else tmp_path / "selected-packs"
    admission, expected = _write_committed_pack(collection / PACK_ID)
    realm = tmp_path / "realm"
    store = RealmStore.initialize(realm)
    realm_id = store.conn.execute("SELECT id FROM realm").fetchone()[0]
    store.close()
    support = tmp_path / "support"
    home, temp = tmp_path / "home", tmp_path / "tmp"
    home.mkdir()
    temp.mkdir()
    profile = SourceProfile(profile="astrid", runtime_checkout=str(runtime), source_checkout=str(agent))
    for revision in (7, 8):
        admission["committedRevision"] = revision
        (collection / PACK_ID / ".build" / "admission.json").write_text(json.dumps(admission))
        token_file = tmp_path / f"bootstrap-{revision}"
        token = f"test-owned-bootstrap-{revision}"
        token_file.write_text(token)
        token_file.chmod(0o600)
        log_path = LocalRuntimeBoundary()._log_path(support)
        if log_path.exists():
            log_path.unlink()
        argv = LocalRuntimeBoundary()._argv(profile, realm_id=realm_id, realm_root=realm,
            support_root=support, display_name="Fixture", owner_lock=support / "instance.lock", token_file=token_file)
        if source == "explicit_collection":
            argv += ["--installed-pack-root", str(collection)]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "TMPDIR": str(temp),
               "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": os.pathsep.join((str(ROOT / "packages" / "python"), str(ROOT), str(astrid_importable)))}
        process = owned_process_groups.popen(argv, env=env, cwd=tmp_path, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            # Ordinary startup deliberately redirects its readiness line into
            # Runtime's declared log. Observe that real publication path.
            deadline = time.monotonic() + 30
            ready = None
            log = LocalRuntimeBoundary()._log_path(support)
            while ready is None and time.monotonic() < deadline:
                if log.exists():
                    for line in log.read_text().splitlines():
                        try:
                            value = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(value, dict) and "endpoint" in value:
                            ready = value
                if process.poll() is not None:
                    break
                if ready is None:
                    time.sleep(0.02)
            assert ready is not None, (log.read_text() if log.exists() else "no Runtime log")
            status, _headers, body = _request(ready["endpoint"], "/api/runtime/packs/inventory", token=token)
            assert status == 200
            inventory = json.loads(body)
            assert inventory["revision"] == revision
            assert inventory["packs"][0]["packId"] == PACK_ID
            path = f"/api/runtime/packs/assets/{PACK_ID}/{admission['digest']}/chunks/lazy.js"
            assert _request(ready["endpoint"], path)[0] == 401
            status, headers, body = _request(ready["endpoint"], path, token=token, headers={"Range": "bytes=0-3"})
            assert status == 206 and body == expected["chunks/lazy.js"][0][:4]
            status, headers, body = _request(ready["endpoint"], path, "HEAD", token=token, headers={"Range": "bytes=0-3"})
            assert status == 206 and body == b"" and headers["Content-Length"] == "4"
        finally:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
            output, errors = process.communicate(timeout=15)
            assert process.returncode == 0, (output, errors)


# --- PK-13: one node per startup composition refusal kind --------------------
# Startup selects exactly one admission authority. These nodes need no Agent
# provider: they use the neutral daemon composition directly.


def test_startup_refusal_kind_reader_and_collection_both_selected(tmp_path):
    from runtime_protocol.daemon import RuntimeDaemon

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    with pytest.raises(ValueError, match="select either an installed pack collection or an admission reader"):
        RuntimeDaemon(realm, support_root=tmp_path / "support",
                      pack_admissions=lambda: {"version": 1, "revision": 0, "packs": []},
                      installed_pack_root=tmp_path / "installed")


def test_startup_refusal_kind_collection_not_absolute(tmp_path):
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.errors import ValidationError

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    for value in ("relative/installed", str(tmp_path / "x" / ".." / "installed")):
        with pytest.raises(ValidationError, match="installed pack collection must be an absolute folder"):
            RuntimeDaemon(realm, support_root=tmp_path / "support", installed_pack_root=value)


def test_startup_refusal_kind_reader_not_callable(tmp_path):
    from runtime_protocol.errors import ValidationError
    from runtime_protocol.service import RuntimeService

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    with pytest.raises(ValidationError, match="pack_admissions must be an installed admission snapshot reader"):
        RuntimeService(realm, pack_admissions={"version": 1, "revision": 0, "packs": []})


def test_startup_refusal_kind_cli_collection_not_absolute(tmp_path, capsys):
    from runtime_protocol import cli

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    status = cli.main(["start", "--root", str(realm), "--support-root", str(tmp_path / "support"),
                       "--installed-pack-root", "relative/installed"])
    output = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert status == 1
    assert output["ok"] is False
    assert output["error"]["code"] == "validation_error"
    assert output["error"]["message"] == "installed pack collection must be an absolute folder"


def test_startup_refusal_kind_unsafe_default_home_collection(tmp_path, monkeypatch):
    """A symlinked ~/Astrid/packs collection is composed but never served."""
    from runtime_protocol.daemon import RuntimeDaemon

    agent = _repo(tmp_path / "agent")
    runtime = _repo(tmp_path / "runtime-provenance")
    actual = tmp_path / "actual-packs"
    _write_committed_pack(actual / PACK_ID)
    home = tmp_path / "home"
    (home / "Astrid").mkdir(parents=True)
    (home / "Astrid" / "packs").symlink_to(actual, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support",
                           agent_checkout=agent, runtime_checkout=runtime).start()
    try:
        status, _headers, body = _request(daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token)
        assert status == 409
        assert json.loads(body)["message"].startswith("installed pack admission files are unavailable or unsafe")
        assert daemon.service._pack_leases == {}
    finally:
        daemon.stop()
