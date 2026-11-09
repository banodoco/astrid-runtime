from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
import subprocess

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.store import RealmStore
from tests.test_runtime_pack_assets import (
    ENTRY_PATH,
    PACK_ID,
    SOURCE_DIGEST,
    _canonical,
    _sha,
    _write_pack,
)


def _write_installed_pack(collection: Path, *, pack_id: str = PACK_ID):
    """Persist the exact M1 post-commit file shape around the r2 artifact fixture."""
    assert pack_id == PACK_ID  # r2's established writer helper has a fixed fixture id.
    root = collection / pack_id
    old_admission, expected = _write_pack(root)
    manifest = old_admission["artifactManifest"]
    manifest_bytes = _canonical(manifest)
    build = root / ".build"
    (build / f"{SOURCE_DIGEST}.artifact-manifest.json").write_bytes(manifest_bytes)
    record = {
        "version": 1,
        "packId": pack_id,
        "sourceDigest": SOURCE_DIGEST,
        "digest": old_admission["digest"],
        "artifactManifestDigest": _sha(manifest_bytes),
        "committedRevision": 7,
        "transactionId": "m1-test-transaction-7",
    }
    (build / "admission.json").write_bytes(_canonical(record))
    return root, record, expected


def _http(endpoint: str, token: str, method: str, path: str):
    request = urllib.request.Request(
        f"{endpoint}{path}",
        method=method,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def _start_daemon(tmp_path: Path, installed_root: Path | None):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    kwargs = {} if installed_root is None else {"installed_pack_root": installed_root}
    return RuntimeDaemon(realm, support_root=tmp_path / "support", **kwargs).start()


def _inventory(daemon):
    status, _headers, body = _http(daemon.endpoint, daemon.token, "GET", "/api/runtime/packs/inventory")
    assert status == 200
    return json.loads(body)


def test_reader_loads_exact_committed_fixture_and_ignores_packs_without_admissions(tmp_path):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    ordinary = collection / "ordinary_python_pack"
    ordinary.mkdir()
    retired = collection / ".astrid-retired" / "retired-txn-7"
    retired_root, _retired_record, _retired_expected = _write_installed_pack(retired)
    assert retired_root.name == PACK_ID

    snapshot = InstalledPackAdmissions(collection)()
    assert snapshot["version"] == 1
    assert snapshot["revision"] == record["committedRevision"]
    assert len(snapshot["packs"]) == 1
    loaded = snapshot["packs"][0]
    assert loaded["packId"] == PACK_ID
    assert loaded["sourceDigest"] == SOURCE_DIGEST
    assert loaded["digest"] == record["digest"]
    assert loaded["artifactManifestDigest"] == record["artifactManifestDigest"]
    assert loaded["root"] == str(root)
    assert loaded["enabled"] is True
    assert "rootIdentity" in loaded
    assert len(loaded["artifactManifest"]["files"]) == 4
    assert set(json.loads((root / ".build/admission.json").read_bytes())) == {
        "version", "packId", "sourceDigest", "digest", "artifactManifestDigest",
        "committedRevision", "transactionId",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 2),
        ("packId", "another_pack"),
        ("sourceDigest", "bad"),
        ("digest", "bad"),
        ("artifactManifestDigest", "bad"),
        ("committedRevision", True),
        ("committedRevision", -1),
        ("transactionId", ""),
        ("extra", "unsupported"),
    ],
)
def test_reader_rejects_wrong_admission_types_or_exact_shape(tmp_path, field, value):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    invalid = dict(record)
    invalid[field] = value
    (root / ".build/admission.json").write_bytes(_canonical(invalid))
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()


def test_reader_rejects_missing_and_escaped_admission_metadata(tmp_path):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, _record, _expected = _write_installed_pack(collection)
    (root / ".build/admission.json").unlink()
    assert InstalledPackAdmissions(collection)()["packs"] == []

    outside = tmp_path / "outside-admission.json"
    outside.write_bytes(_canonical({"version": 1}))
    (root / ".build/admission.json").symlink_to(outside)
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()


def test_reader_requires_exact_canonical_manifest_bytes(tmp_path):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    manifest_path = root / f".build/{SOURCE_DIGEST}.artifact-manifest.json"
    canonical = manifest_path.read_bytes()
    manifest_path.write_bytes(canonical + b"\n")
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()

    manifest = json.loads(canonical)
    noncanonical = json.dumps(manifest, indent=2, ensure_ascii=False).encode()
    manifest_path.write_bytes(noncanonical)
    (root / ".build/admission.json").write_bytes(
        _canonical({**record, "artifactManifestDigest": _sha(noncanonical)})
    )
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()

    duplicate_key_bytes = canonical.replace(b'{"digest":', b'{"version":1,"digest":', 1)
    manifest_path.write_bytes(duplicate_key_bytes)
    (root / ".build/admission.json").write_bytes(
        _canonical({**record, "artifactManifestDigest": _sha(duplicate_key_bytes)})
    )
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()


def test_reader_rejects_missing_manifest_and_wrong_pack_folder(tmp_path):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    (root / f".build/{SOURCE_DIGEST}.artifact-manifest.json").unlink()
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()

    _root2, _record2, _expected2 = _write_installed_pack(collection / "other")
    wrong_folder = collection / "other" / PACK_ID
    admission_path = wrong_folder / ".build/admission.json"
    admission_path.write_bytes(_canonical({**record, "packId": "wrong_folder"}))
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection / "other")()


@pytest.mark.parametrize("target", ["admission", "manifest", "build", "collection"])
def test_reader_refuses_symlinked_metadata_or_root_components(tmp_path, target):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    if target == "admission":
        path = root / ".build/admission.json"
        saved = path.with_name("admission.saved")
        path.rename(saved)
        path.symlink_to(saved.name)
    elif target == "manifest":
        path = root / f".build/{SOURCE_DIGEST}.artifact-manifest.json"
        saved = path.with_suffix(".saved")
        path.rename(saved)
        path.symlink_to(saved.name)
    elif target == "build":
        build = root / ".build"
        saved = root / "build.saved"
        build.rename(saved)
        build.symlink_to(saved, target_is_directory=True)
    else:
        saved = collection.with_name("installed.saved")
        collection.rename(saved)
        collection.symlink_to(saved, target_is_directory=True)
    with pytest.raises((ValidationError, ConflictError)):
        InstalledPackAdmissions(collection)()


@pytest.mark.parametrize("mutation", ["file_hash", "file_mime"])
def test_real_http_refuses_hash_or_mime_mismatch(tmp_path, mutation):
    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    if mutation == "file_hash":
        chunk = root / f".build/{SOURCE_DIGEST}/chunks/lazy.js"
        chunk.write_bytes(chunk.read_bytes() + b"tamper")
    else:
        manifest_path = root / f".build/{SOURCE_DIGEST}.artifact-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][1]["mime"] = "application/x-executable"
        body = _canonical(manifest)
        manifest_path.write_bytes(body)
        (root / ".build/admission.json").write_bytes(
            _canonical({**record, "artifactManifestDigest": _sha(body)})
        )
    daemon = _start_daemon(tmp_path, collection)
    try:
        status, _headers, _body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}",
        )
        assert status in (400, 409, 422)
    finally:
        daemon.stop()


def test_asset_request_revalidates_the_entire_file_set(tmp_path):
    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    (root / f".build/{SOURCE_DIGEST}/chunks/lazy.js").write_bytes(b"corrupt sibling")
    daemon = _start_daemon(tmp_path, collection)
    try:
        status, _headers, _body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}",
        )
        assert status in (400, 409, 422)
    finally:
        daemon.stop()


def test_http_inventory_uses_only_installed_records_and_live_withdrawal(tmp_path):
    collection = tmp_path / "installed"
    root, record, expected = _write_installed_pack(collection)
    (collection / "not_installed").mkdir()
    _write_installed_pack(collection / ".astrid-retired" / "retired-txn-7")
    daemon = _start_daemon(tmp_path, collection)
    try:
        inventory = _inventory(daemon)
        assert inventory["version"] == 1 and inventory["revision"] == 7
        assert [item["packId"] for item in inventory["packs"]] == [PACK_ID]
        status, headers, body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}",
        )
        assert status == 200 and body == expected[ENTRY_PATH][0]
        assert headers.get_content_type() == "text/javascript"
        status, _headers, _body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/unlisted.js",
        )
        assert status == 404

        (root / ".build/admission.json").unlink()
        assert _inventory(daemon) == {"version": 1, "revision": 0, "packs": []}
        status, _headers, _body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}",
        )
        assert status == 404
    finally:
        daemon.stop()


def test_default_home_root_is_composed_and_restart_rereads_files(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    agent = tmp_path / "agent"
    runtime_checkout = tmp_path / "runtime-checkout"
    for checkout in (agent, runtime_checkout):
        checkout.mkdir()
        subprocess.run(["git", "-C", str(checkout), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(checkout), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Test"], check=True)
        (checkout / "tracked.txt").write_text("initial\n")
        subprocess.run(["git", "-C", str(checkout), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "initial [skip ci]"], check=True)
    # Where the Agent's `astrid packs install` writes (Path.home()/Astrid/packs).
    collection = home / "Astrid" / "packs"
    root, record, expected = _write_installed_pack(collection)
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(
        realm, support_root=tmp_path / "support", agent_checkout=agent,
        runtime_checkout=runtime_checkout,
    ).start()
    try:
        inventory = _inventory(daemon)
        assert inventory["packs"][0]["packId"] == PACK_ID
        status, _headers, body = _http(
            daemon.endpoint, daemon.token, "GET",
            f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}",
        )
        assert status == 200 and body == expected[ENTRY_PATH][0]
        daemon.stop()
        (root / ".build/admission.json").unlink()
        restarted = RuntimeDaemon(
            realm, support_root=tmp_path / "support", agent_checkout=agent,
            runtime_checkout=runtime_checkout,
        ).start()
        try:
            assert _inventory(restarted) == {"version": 1, "revision": 0, "packs": []}
        finally:
            restarted.stop()
    finally:
        daemon.stop()


def test_open_asset_stream_survives_folder_rename_and_admission_withdrawal(tmp_path):
    collection = tmp_path / "installed"
    root, record, expected = _write_installed_pack(collection)
    daemon = _start_daemon(tmp_path, collection)
    stream = None
    try:
        _metadata, stream = daemon.service.open_pack_asset(PACK_ID, record["digest"], ENTRY_PATH)
        moved = tmp_path / "retained-installed-pack"
        root.rename(moved)
        (moved / ".build/admission.json").unlink()
        assert stream.read() == expected[ENTRY_PATH][0]
        assert (moved / f".build/{SOURCE_DIGEST}.js").read_bytes() == expected[ENTRY_PATH][0]
        assert (moved / f".build/{SOURCE_DIGEST}.artifact-manifest.json").exists()
        assert _inventory(daemon) == {"version": 1, "revision": 0, "packs": []}
    finally:
        if stream is not None:
            stream.close()
        daemon.stop()


# --- PK-13: one node per installed-admission refusal kind --------------------
# Each node names one refusal the installed reader (InstalledPackAdmissions) or
# the committed-snapshot gate (read_pack_admissions) can raise, and asserts its
# exact error class and message, so a kind cannot pass by tripping another one.


class _OsProxy:
    """Delegate to the real os module, overriding only the named calls."""

    def __init__(self, real, **overrides):
        self._real, self._overrides = real, overrides

    def __getattr__(self, name):
        return self._overrides.get(name) or getattr(self._real, name)


def _reader_refusal(tmp_path, monkeypatch, kind):
    from runtime_protocol import store as store_module
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)
    build = root / ".build"
    admission_path = build / "admission.json"
    manifest_path = build / f"{SOURCE_DIGEST}.artifact-manifest.json"
    if kind == "collection_not_absolute":
        for value in ("relative/installed", str(tmp_path / "x" / ".." / "installed")):
            with pytest.raises(ValidationError, match="absolute folder"):
                InstalledPackAdmissions(value)
        return None
    if kind == "metadata_not_bounded_regular_file":
        admission_path.unlink()
        admission_path.mkdir()
    elif kind == "metadata_changed_during_read":
        real = store_module.os
        appended = []

        def fdopen(fd, *args, **kwargs):
            stream = real.fdopen(fd, *args, **kwargs)
            if not appended:
                appended.append(True)
                with open(admission_path, "ab") as concurrent_writer:
                    concurrent_writer.write(b" ")
            return stream

        monkeypatch.setattr(store_module, "os", _OsProxy(real, fdopen=fdopen))
    elif kind == "metadata_ambiguous_json":
        admission_path.write_bytes(_canonical(record).replace(b'{"artifactManifestDigest"', b'{"version":1,"artifactManifestDigest"', 1))
    elif kind == "folder_identities_collide":
        (collection / PACK_ID.upper()).mkdir()
    elif kind == "folder_is_symlink":
        target = tmp_path / "elsewhere"
        target.mkdir()
        (collection / "linked_pack").symlink_to(target, target_is_directory=True)
    elif kind == "admission_fields_invalid":
        admission_path.write_bytes(_canonical({**record, "transactionId": ""}))
    elif kind == "admission_digest_malformed":
        admission_path.write_bytes(_canonical({**record, "sourceDigest": SOURCE_DIGEST.upper()}))
    elif kind == "manifest_bytes_not_canonical":
        manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
    elif kind == "metadata_unavailable_or_unsafe":
        manifest_path.unlink()
    else:
        raise AssertionError(kind)
    return InstalledPackAdmissions(collection)


READER_REFUSALS = {
    "collection_not_absolute": (ValidationError, "installed pack collection must be an absolute folder"),
    "metadata_not_bounded_regular_file": (ValidationError, "installed pack metadata must be a bounded regular JSON file"),
    "metadata_changed_during_read": (ConflictError, "installed pack metadata changed during admission"),
    "metadata_ambiguous_json": (ValidationError, "installed pack metadata must be unambiguous UTF-8 JSON"),
    "folder_identities_collide": (ConflictError, "installed pack folder identities collide"),
    "folder_is_symlink": (ConflictError, "installed pack folder must not be a symlink"),
    "admission_fields_invalid": (ValidationError, "installed pack admission fields or folder identity are invalid"),
    "admission_digest_malformed": (ValidationError, "pack admission sourceDigest must be a full lowercase SHA-256"),
    "manifest_bytes_not_canonical": (ConflictError, "installed pack manifest bytes differ from canonical admission digest"),
    "metadata_unavailable_or_unsafe": (ConflictError, "installed pack admission files are unavailable or unsafe"),
}


@pytest.mark.parametrize("kind", sorted(READER_REFUSALS))
def test_installed_reader_refusal_kind(tmp_path, monkeypatch, kind):
    error, message = READER_REFUSALS[kind]
    reader = _reader_refusal(tmp_path, monkeypatch, kind)
    if reader is None:
        return
    with pytest.raises(error, match=message):
        reader()


def test_installed_reader_refuses_oversized_metadata(tmp_path):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, _record, _expected = _write_installed_pack(collection)
    (root / ".build/admission.json").write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValidationError, match="bounded regular JSON file"):
        InstalledPackAdmissions(collection)()


@pytest.mark.parametrize("body", [b'{"version":NaN}', b'{"version":1,"version":1}', b'{"packId":"\xff"}'])
def test_installed_reader_ambiguous_json_forms_share_one_refusal(tmp_path, body):
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, _record, _expected = _write_installed_pack(collection)
    (root / ".build/admission.json").write_bytes(body)
    with pytest.raises(ValidationError, match="unambiguous UTF-8 JSON"):
        InstalledPackAdmissions(collection)()


def _snapshot_record(tmp_path):
    from tests.test_runtime_pack_assets import _write_pack

    admission, _expected = _write_pack(tmp_path / "installed" / PACK_ID)
    return admission


SNAPSHOT_REFUSALS = {
    "snapshot_unreadable": (ConflictError, "installed pack admissions cannot be read"),
    "snapshot_not_version_1": (ValidationError, "must return a version 1 committed snapshot"),
    "record_not_object": (ValidationError, "installed pack admission must be an object"),
    "record_pack_id_invalid": (ValidationError, "installed pack admission packId is invalid"),
    "record_ids_collide": (ConflictError, "installed pack admission ids collide"),
    "record_enabled_not_boolean": (ValidationError, "installed pack admission enabled must be boolean"),
    "record_fields_unsupported": (ValidationError, "installed browser pack admission has missing or unsupported fields"),
    "record_root_not_canonical": (ValidationError, "installed pack admission root must be an absolute canonical folder"),
}


@pytest.mark.parametrize("kind", sorted(SNAPSHOT_REFUSALS))
def test_committed_snapshot_refusal_kind(tmp_path, kind):
    from runtime_protocol.store import read_pack_admissions

    record = _snapshot_record(tmp_path)
    packs = [record]
    snapshot = {"version": 1, "revision": 1, "packs": packs}
    if kind == "snapshot_unreadable":
        def reader():
            raise OSError("installer record unavailable")
    else:
        if kind == "snapshot_not_version_1":
            snapshot["version"] = 2
        elif kind == "record_not_object":
            packs[:] = [PACK_ID]
        elif kind == "record_pack_id_invalid":
            packs[:] = [{**record, "packId": "../escape"}]
        elif kind == "record_ids_collide":
            packs.append({**record, "packId": PACK_ID.upper()})
        elif kind == "record_enabled_not_boolean":
            packs[:] = [{**record, "enabled": 1}]
        elif kind == "record_fields_unsupported":
            packs[:] = [{**record, "unexpected": True}]
        elif kind == "record_root_not_canonical":
            packs[:] = [{**record, "root": "relative/installed/" + PACK_ID}]
        else:
            raise AssertionError(kind)

        def reader():
            return snapshot
    error, message = SNAPSHOT_REFUSALS[kind]
    with pytest.raises(error, match=message):
        read_pack_admissions(reader)


def test_installed_folder_replaced_after_admission_is_refused(tmp_path):
    """The reader's folder identity binds every later open of that admission."""
    import shutil

    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import InstalledPackAdmissions

    collection = tmp_path / "installed"
    root, record, _expected = _write_installed_pack(collection)

    class ReplacedAfterSnapshot(InstalledPackAdmissions):
        def __call__(self, *, pack_id=None):
            snapshot = super().__call__(pack_id=pack_id)
            # The installer replaces the folder with identical bytes right
            # after the committed snapshot was taken.
            copy = root.with_name("copy")
            shutil.copytree(root, copy, symlinks=True)
            shutil.rmtree(root)
            copy.rename(root)
            return snapshot

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    service = RuntimeService(realm, pack_admissions=ReplacedAfterSnapshot(collection))
    try:
        for call in (service.pack_inventory,
                     lambda: service.acquire_pack_lease(PACK_ID, record["digest"]),
                     lambda: service.open_pack_asset(PACK_ID, record["digest"], ENTRY_PATH)):
            with pytest.raises(ConflictError, match="installed pack folder changed after admission"):
                call()
        assert service._pack_leases == {}
    finally:
        service.close()


def test_production_default_ignores_agent_checkout_packs_and_reads_home_root(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("ASTRID_PACKS_PATH", str(tmp_path / "extra"))
    # The retired fallback location must not be read.
    _write_installed_pack(tmp_path / "agent" / "astrid" / "packs")
    _root, record, expected = _write_installed_pack(home / "Astrid" / "packs")
    daemon = _start_daemon(tmp_path, None)  # production arguments: no installed_pack_root
    try:
        inventory = _inventory(daemon)
        assert [p["packId"] for p in inventory["packs"]] == [PACK_ID]
        status, _h, body = _http(daemon.endpoint, daemon.token, "GET",
                                 f"/api/runtime/packs/assets/{PACK_ID}/{record['digest']}/{ENTRY_PATH}")
        assert status == 200 and body == expected[ENTRY_PATH][0]
    finally:
        daemon.stop()
