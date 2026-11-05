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


def test_default_agent_checkout_root_is_composed_and_restart_rereads_files(tmp_path):
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
    collection = agent / "astrid" / "packs"
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
