from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


PACK_ID = "hello_ext"
SOURCE_DIGEST = "a" * 64
LOCK_DIGEST = "b" * 64
ENTRY_PATH = "index.js"
ENTRY_PRELUDE = "/* astrid-graph-index-sha256:{} */\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write_pack(root: Path) -> tuple[dict, dict[str, bytes]]:
    """Write an installed builder-shaped pack, then return its admission data."""
    files = {
        "chunks/lazy.js": b'export const answer = "ready";\n',
        "styles/main.css": b".badge { background: url(../assets/pixel.png); }\n",
        "assets/pixel.png": b"\x89PNG\r\n\x1a\nfixture-pixel",
    }
    graph = [
        {
            "logical_path": path,
            "sha256": _sha(data),
            "size": len(data),
            "mime": {
                ".js": "text/javascript",
                ".css": "text/css",
                ".png": "image/png",
            }[Path(path).suffix],
        }
        for path, data in sorted(files.items())
    ]
    graph_digest = _sha(_canonical(graph))
    entry = ENTRY_PRELUDE.format(graph_digest).encode("utf-8") + (
        b'import("./chunks/lazy.js");\nimport "./styles/main.css";\n'
        b"export default {};\n"
    )
    payloads = {ENTRY_PATH: entry, **files}
    manifest_files = []
    for path, data in sorted(payloads.items()):
        mime = {
            ".js": "text/javascript",
            ".css": "text/css",
            ".png": "image/png",
        }[Path(path).suffix]
        disk = f".build/{SOURCE_DIGEST}.js" if path == ENTRY_PATH else f".build/{SOURCE_DIGEST}/{path}"
        destination = root / disk
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        manifest_files.append(
            {"path": path, "disk": disk, "sha256": _sha(data), "size": len(data), "mime": mime}
        )

    manifest = {
        "version": 1,
        "packId": PACK_ID,
        "sourceDigest": SOURCE_DIGEST,
        "digest": _sha(entry),
        "graphIndexDigest": graph_digest,
        "toolchainDigest": LOCK_DIGEST,
        "entry": ENTRY_PATH,
        "extensionManifest": {"id": "example.extension", "version": "1.0.0"},
        "sharedModules": {},
        "files": manifest_files,
    }
    admission = {
        "packId": PACK_ID,
        "sourceDigest": SOURCE_DIGEST,
        "digest": manifest["digest"],
        "artifactManifestDigest": _sha(_canonical(manifest)),
        "root": str(root.resolve()),
        "artifactManifest": manifest,
        "enabled": True,
    }
    expected = {
        ENTRY_PATH: (entry, "text/javascript"),
        **{
            path: (data, {".js": "text/javascript", ".css": "text/css", ".png": "image/png"}[Path(path).suffix])
            for path, data in files.items()
        },
    }
    return admission, expected


def _snapshot(*packs: dict, revision: int = 1) -> dict:
    return {"version": 1, "revision": revision, "packs": list(packs)}


@pytest.fixture
def runtime(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    service = RuntimeService(realm)
    try:
        yield service
    finally:
        service.close()


@pytest.fixture
def admitted_runtime(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    pack_root = tmp_path / "installed" / PACK_ID
    admission, expected = _write_pack(pack_root)
    state = {"snapshot": _snapshot(admission)}
    service = RuntimeService(realm, pack_admissions=lambda: state["snapshot"])
    try:
        yield service, state, admission, expected, pack_root
    finally:
        service.close()


def test_default_inventory_is_empty_and_revision_zero(runtime):
    assert runtime.pack_inventory() == {"version": 1, "revision": 0, "packs": []}


def test_inventory_is_public_frozen_projection_and_assets_stream_exact_bytes(admitted_runtime):
    service, _state, admission, expected, _root = admitted_runtime

    inventory = service.pack_inventory()
    assert inventory == {
        "version": 1,
        "revision": 1,
        "packs": [
            {
                "packId": PACK_ID,
                "sourceDigest": SOURCE_DIGEST,
                "digest": admission["digest"],
                "artifactManifestDigest": admission["artifactManifestDigest"],
                "artifactManifest": admission["artifactManifest"],
                "url": f"/api/runtime/packs/assets/{PACK_ID}/{admission['digest']}/index.js",
                "enabled": True,
            }
        ],
    }
    assert "root" not in inventory["packs"][0]
    assert _sha(_canonical(inventory["packs"][0]["artifactManifest"])) == admission["artifactManifestDigest"]

    for path, (expected_bytes, media_type) in expected.items():
        metadata, stream = service.open_pack_asset(PACK_ID, admission["digest"], path)
        try:
            assert metadata == {
                "digest": _sha(expected_bytes),
                "size": len(expected_bytes),
                "media_type": media_type,
            }
            assert stream.read() == expected_bytes
        finally:
            stream.close()


def test_installed_snapshot_updates_disable_and_uninstall_are_immediate(admitted_runtime):
    service, state, admission, _expected, _root = admitted_runtime
    state["snapshot"] = _snapshot(admission, revision=2)
    assert service.pack_inventory()["revision"] == 2

    disabled = {**admission, "enabled": False}
    state["snapshot"] = _snapshot(disabled, revision=3)
    assert service.pack_inventory() == {"version": 1, "revision": 3, "packs": []}
    with pytest.raises(NotFoundError):
        service.open_pack_asset(PACK_ID, admission["digest"], ENTRY_PATH)

    state["snapshot"] = _snapshot(revision=4)
    assert service.pack_inventory() == {"version": 1, "revision": 4, "packs": []}
    with pytest.raises(NotFoundError):
        service.open_pack_asset(PACK_ID, admission["digest"], ENTRY_PATH)


def test_ordinary_python_pack_without_artifact_manifest_is_not_advertised(admitted_runtime):
    service, state, admission, _expected, _root = admitted_runtime
    ordinary_pack = {
        **admission,
        "packId": "ordinary_python_pack",
        "artifactManifest": None,
        "artifactManifestDigest": None,
    }
    state["snapshot"] = _snapshot(ordinary_pack)
    assert service.pack_inventory() == {"version": 1, "revision": 1, "packs": []}


@pytest.mark.parametrize(
    ("pack_id", "digest", "path"),
    [
        ("unknown", "a" * 64, ENTRY_PATH),
        (PACK_ID, "c" * 64, ENTRY_PATH),
    ],
)
def test_unknown_pack_bundle_or_file_is_not_found(admitted_runtime, pack_id, digest, path):
    service, _state, _admission, _expected, _root = admitted_runtime
    with pytest.raises(NotFoundError):
        service.open_pack_asset(pack_id, digest, path)


def test_unlisted_existing_file_is_not_served(admitted_runtime):
    service, _state, admission, _expected, root = admitted_runtime
    unlisted = root / f".build/{SOURCE_DIGEST}/unlisted.js"
    unlisted.write_bytes(b"export default 'not admitted';")
    with pytest.raises(NotFoundError, match="not listed"):
        service.open_pack_asset(PACK_ID, admission["digest"], "unlisted.js")


@pytest.mark.parametrize("path", ["../secret.js", "chunks/../../secret.js", "chunks\\lazy.js", "%2e%2e/secret.js", "index.js?x=1", "index.js#fragment", "/index.js", "chunks//lazy.js", "chunks/./lazy.js", "CON.js", "chunk:stream.js", "chunks/lazy.js ", "nul\x00.js", "control\x7f.js", "cafe\u0301.js", "\ud800.js"])
def test_unsafe_or_decorated_logical_paths_are_rejected(admitted_runtime, path):
    service, _state, admission, _expected, _root = admitted_runtime
    with pytest.raises((ValidationError, ConflictError)):
        service.open_pack_asset(PACK_ID, admission["digest"], path)


@pytest.mark.parametrize("mutation", ["digest", "malformed_digest", "size", "missing", "manifest_digest", "graph_digest", "prelude", "duplicate", "case_collision", "bad_mime"])
def test_bad_admission_manifest_or_installed_bytes_are_refused(tmp_path, mutation):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    pack_root = tmp_path / "installed" / PACK_ID
    admission, _expected = _write_pack(pack_root)
    manifest = json.loads(json.dumps(admission["artifactManifest"]))

    if mutation == "digest":
        manifest["files"][1]["sha256"] = "0" * 64
    elif mutation == "malformed_digest":
        manifest["files"][1]["sha256"] = "not-a-sha256"
    elif mutation == "size":
        manifest["files"][1]["size"] += 1
    elif mutation == "missing":
        (pack_root / manifest["files"][1]["disk"]).unlink()
    elif mutation == "manifest_digest":
        admission["artifactManifestDigest"] = "f" * 64
    elif mutation == "graph_digest":
        manifest["graphIndexDigest"] = "0" * 64
    elif mutation == "prelude":
        entry_row = next(row for row in manifest["files"] if row["path"] == ENTRY_PATH)
        entry_path = pack_root / entry_row["disk"]
        entry_path.write_bytes(entry_path.read_bytes().replace(b"astrid-graph-index-sha256:", b"astrid-graph-index-sha256-x:", 1))
        entry_row["sha256"] = _sha(entry_path.read_bytes())
        entry_row["size"] = entry_path.stat().st_size
        manifest["digest"] = _sha(entry_path.read_bytes())
        admission["digest"] = manifest["digest"]
    elif mutation == "duplicate":
        manifest["files"].append(dict(manifest["files"][1]))
    elif mutation == "case_collision":
        row = dict(manifest["files"][1])
        row["path"] = row["path"].upper()
        manifest["files"].append(row)
    elif mutation == "bad_mime":
        manifest["files"][1]["mime"] = "application/x-executable"

    if mutation != "manifest_digest":
        admission["artifactManifestDigest"] = _sha(_canonical(manifest))
    admission["artifactManifest"] = manifest
    state = {"snapshot": _snapshot(admission)}
    service = RuntimeService(realm, pack_admissions=lambda: state["snapshot"])
    try:
        with pytest.raises((ValidationError, ConflictError)):
            service.pack_inventory()
    finally:
        service.close()


def test_tampered_asset_and_confined_symlink_are_refused(admitted_runtime):
    service, _state, admission, _expected, pack_root = admitted_runtime
    chunk = pack_root / f".build/{SOURCE_DIGEST}/chunks/lazy.js"
    original = chunk.read_bytes()
    chunk.write_bytes(original + b"// tampered")
    with pytest.raises((ConflictError, ValidationError)):
        service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")
    chunk.write_bytes(original)

    link = pack_root / f".build/{SOURCE_DIGEST}/chunks/linked.js"
    link.write_bytes(original)
    chunk.unlink()
    chunk.symlink_to(link)
    with pytest.raises((ConflictError, ValidationError)):
        service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")


def test_prior_success_does_not_hide_same_size_tamper(admitted_runtime):
    service, _state, admission, _expected, root = admitted_runtime
    _metadata, stream = service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")
    stream.close()
    chunk = root / f".build/{SOURCE_DIGEST}/chunks/lazy.js"
    original = chunk.read_bytes()
    chunk.write_bytes(b"x" * len(original))
    with pytest.raises(ConflictError, match="hash"):
        service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")


@pytest.mark.parametrize("target", ["root", "build", "chunks"])
def test_symlink_directory_is_refused(admitted_runtime, tmp_path, target):
    service, state, admission, _expected, root = admitted_runtime
    directory = {"root": root, "build": root / ".build", "chunks": root / f".build/{SOURCE_DIGEST}/chunks"}[target]
    moved = tmp_path / f"retained-{target}"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ConflictError):
        service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")


@pytest.mark.parametrize("disk", ["../outside.js", "/outside.js", f".build/{SOURCE_DIGEST}/../outside.js", f".build/{SOURCE_DIGEST}/unlisted.js"])
def test_manifest_disk_path_cannot_redirect_admitted_file(admitted_runtime, disk):
    service, _state, admission, _expected, _root = admitted_runtime
    manifest = admission["artifactManifest"]
    manifest["files"][1]["disk"] = disk
    admission["artifactManifestDigest"] = _sha(_canonical(manifest))
    with pytest.raises(ValidationError, match="disk path"):
        service.open_pack_asset(PACK_ID, admission["digest"], "chunks/lazy.js")


def test_selected_asset_does_not_validate_unselected_pack_manifest(admitted_runtime):
    service, state, admission, expected, _root = admitted_runtime
    state["snapshot"]["packs"].append({**admission, "packId": "unselected", "artifactManifest": {"broken": True}})
    _metadata, stream = service.open_pack_asset(PACK_ID, admission["digest"], ENTRY_PATH)
    with stream:
        assert stream.read() == expected[ENTRY_PATH][0]


@pytest.mark.parametrize("snapshot", [None, {}, {"version": True, "revision": 1, "packs": []}, {"version": 1, "revision": -1, "packs": []}, {"version": 1, "revision": 1, "packs": {}}])
def test_malformed_installed_snapshot_refuses_before_serving(admitted_runtime, snapshot):
    service, state, admission, _expected, _root = admitted_runtime
    state["snapshot"] = snapshot
    with pytest.raises(ValidationError):
        service.pack_inventory()
    with pytest.raises(ValidationError):
        service.open_pack_asset(PACK_ID, admission["digest"], ENTRY_PATH)


# --- PK-13: one node per artifact-manifest, asset and lease refusal kind -----
# Each node names one refusal of validate_pack_artifact, pack_asset_path, the
# service's asset open, or the lease API, asserting exact class and message.


def _mutate_manifest(manifest, admission, kind):
    files = manifest["files"]
    chunk = next(row for row in files if row["path"] == "chunks/lazy.js")
    if kind == "manifest_not_canonical_json":
        manifest["extensionManifest"] = {"id": "example.extension", "weight": float("nan")}
    elif kind == "manifest_fields_unsupported":
        del manifest["toolchainDigest"]
    elif kind == "manifest_hash_differs":
        return "f" * 64
    elif kind == "manifest_identity_differs":
        manifest["entry"] = "main.js"
    elif kind == "manifest_digest_malformed":
        manifest["toolchainDigest"] = "not-a-sha256"
    elif kind == "manifest_sections_not_objects":
        manifest["sharedModules"] = []
    elif kind == "shared_module_lock_malformed":
        manifest["sharedModules"] = {"react": {"url": "/vendor/react.js"}}
    elif kind == "shared_module_version_unpinned":
        manifest["sharedModules"] = {"react": {"url": "/vendor/react.js", "sha256": "d" * 64, "version": "^18.3.1"}}
    elif kind == "shared_module_url_not_host_relative":
        manifest["sharedModules"] = {"react": {"url": "https://cdn.example/react.js", "sha256": "d" * 64, "version": "18.3.1"}}
    elif kind == "files_empty":
        manifest["files"] = []
    elif kind == "file_fields_unsupported":
        chunk["executable"] = True
    elif kind == "file_paths_collide":
        files.append({**chunk, "path": chunk["path"].upper()})
    elif kind == "file_disk_outside_build_layout":
        chunk["disk"] = "../outside.js"
    elif kind == "file_size_invalid":
        chunk["size"] = -1
    elif kind == "file_mime_differs_from_extension":
        chunk["mime"] = "application/x-executable"
    elif kind == "files_unsorted_or_without_entry":
        files.reverse()
    elif kind == "entry_hash_differs_from_bundle":
        next(row for row in files if row["path"] == ENTRY_PATH)["sha256"] = "0" * 64
    elif kind == "graph_index_differs_from_files":
        manifest["graphIndexDigest"] = "0" * 64
    else:
        raise AssertionError(kind)
    return _sha(_canonical(manifest))


MANIFEST_REFUSALS = {
    "manifest_not_canonical_json": (ValidationError, "pack artifact manifest must contain canonical UTF-8 JSON"),
    "manifest_fields_unsupported": (ValidationError, "pack artifact manifest has missing or unsupported fields"),
    "manifest_hash_differs": (ConflictError, "pack artifact manifest hash differs from installed admission"),
    "manifest_identity_differs": (ConflictError, "pack artifact identity differs from installed admission"),
    "manifest_digest_malformed": (ValidationError, "pack admission toolchainDigest must be a full lowercase SHA-256"),
    "manifest_sections_not_objects": (ValidationError, "extensionManifest and sharedModules must be objects"),
    "shared_module_lock_malformed": (ValidationError, "pack artifact shared module lock is malformed"),
    "shared_module_version_unpinned": (ValidationError, "pack artifact shared module version must be pinned"),
    "shared_module_url_not_host_relative": (ValidationError, "pack artifact shared module URL must be host-relative"),
    "files_empty": (ValidationError, "pack artifact files must be a nonempty sorted list"),
    "file_fields_unsupported": (ValidationError, "pack artifact file has missing or unsupported fields"),
    "file_paths_collide": (ValidationError, "pack artifact file paths collide"),
    "file_disk_outside_build_layout": (ValidationError, "pack artifact disk path differs from the confined build layout"),
    "file_size_invalid": (ValidationError, "pack artifact file size must be a nonnegative safe integer"),
    "file_mime_differs_from_extension": (ValidationError, "pack artifact MIME differs from its supported file extension"),
    "files_unsorted_or_without_entry": (ValidationError, "pack artifact files must be sorted and include index.js"),
    "entry_hash_differs_from_bundle": (ConflictError, "pack artifact entry hash differs from admitted bundle digest"),
    "graph_index_differs_from_files": (ConflictError, "pack artifact graph index hash differs from its file membership"),
}


@pytest.mark.parametrize("kind", sorted(MANIFEST_REFUSALS))
def test_artifact_manifest_refusal_kind(admitted_runtime, kind):
    service, state, admission, _expected, _root = admitted_runtime
    manifest = admission["artifactManifest"]
    admission["artifactManifestDigest"] = _mutate_manifest(manifest, admission, kind)
    error, message = MANIFEST_REFUSALS[kind]
    with pytest.raises(error, match=message):
        service.pack_inventory()
    with pytest.raises(error, match=message):
        service.open_pack_asset(PACK_ID, admission["digest"], ENTRY_PATH)


ASSET_PATH_REFUSALS = {
    "path_not_normalized_or_decorated": ("chunks\\lazy.js", "pack asset path must be a normalized confined UTF-8 name"),
    "path_not_valid_utf8": ("\ud800.js", "pack asset path must be valid UTF-8"),
    "path_unsafe_or_aliased_component": ("chunks/../index.js", "pack asset path contains an unsafe or aliased component"),
}


@pytest.mark.parametrize("kind", sorted(ASSET_PATH_REFUSALS))
def test_asset_logical_path_refusal_kind(admitted_runtime, kind):
    service, _state, admission, _expected, _root = admitted_runtime
    path, message = ASSET_PATH_REFUSALS[kind]
    with pytest.raises(ValidationError, match=message):
        service.open_pack_asset(PACK_ID, admission["digest"], path)


class _OsProxy:
    def __init__(self, real, **overrides):
        self._real, self._overrides = real, overrides

    def __getattr__(self, name):
        return self._overrides.get(name) or getattr(self._real, name)


def _rewrite_entry_prelude(admission, root):
    manifest = admission["artifactManifest"]
    entry_row = next(row for row in manifest["files"] if row["path"] == ENTRY_PATH)
    entry_path = root / entry_row["disk"]
    entry = entry_path.read_bytes().replace(b"astrid-graph-index-sha256:", b"astrid-graph-index-sha256-x:", 1)
    entry_path.write_bytes(entry)
    entry_row.update(sha256=_sha(entry), size=len(entry))
    manifest["digest"] = admission["digest"] = _sha(entry)
    admission["artifactManifestDigest"] = _sha(_canonical(manifest))


ASSET_OPEN_REFUSALS = {
    "asset_pack_id_invalid": (ValidationError, "pack asset packId is invalid"),
    "asset_bundle_digest_malformed": (ValidationError, "pack asset bundle digest must be a full lowercase SHA-256"),
    "bundle_not_installed_or_admitted": (NotFoundError, "pack bundle is not installed and admitted"),
    "asset_not_listed": (NotFoundError, "pack asset is not listed in the admitted manifest"),
    "artifact_bytes_missing": (ConflictError, "installed pack artifact bytes are missing; reinstall the admitted bundle"),
    "artifact_not_accessible_regular_file": (ConflictError, "installed pack artifact must be an accessible regular file"),
    "artifact_not_regular_file": (ConflictError, "pack asset chunks/lazy.js must be a regular file"),
    "artifact_size_differs": (ConflictError, "pack asset chunks/lazy.js size does not match staged metadata"),
    "artifact_hash_differs": (ConflictError, "pack asset chunks/lazy.js hash or size does not match staged metadata"),
    "artifact_unreadable": (ConflictError, "pack asset chunks/lazy.js is unavailable"),
    "entry_does_not_commit_graph_index": (ConflictError, "pack entry does not commit the admitted graph index"),
}


@pytest.mark.parametrize("kind", sorted(ASSET_OPEN_REFUSALS))
def test_asset_open_refusal_kind(admitted_runtime, monkeypatch, kind):
    from runtime_protocol import service as service_module

    service, _state, admission, _expected, root = admitted_runtime
    pack_id, digest, path = PACK_ID, admission["digest"], "chunks/lazy.js"
    chunk = root / f".build/{SOURCE_DIGEST}/chunks/lazy.js"
    if kind == "asset_pack_id_invalid":
        pack_id = "../escape"
    elif kind == "asset_bundle_digest_malformed":
        digest = digest.upper()
    elif kind == "bundle_not_installed_or_admitted":
        digest = "c" * 64
    elif kind == "asset_not_listed":
        (chunk.parent / "unlisted.js").write_bytes(b"export default 0;\n")
        path = "chunks/unlisted.js"
    elif kind == "artifact_bytes_missing":
        chunk.unlink()
    elif kind == "artifact_not_accessible_regular_file":
        moved = chunk.with_name("moved.js")
        chunk.rename(moved)
        chunk.symlink_to(moved.name)
    elif kind == "artifact_not_regular_file":
        chunk.unlink()
        chunk.mkdir()
    elif kind == "artifact_size_differs":
        chunk.write_bytes(chunk.read_bytes() + b"// appended\n")
    elif kind == "artifact_hash_differs":
        chunk.write_bytes(b"x" * chunk.stat().st_size)
    elif kind == "artifact_unreadable":
        real = service_module.os

        def read(fd, size):
            if real.fstat(fd).st_ino == chunk.stat().st_ino:
                raise OSError(5, "Input/output error")
            return real.read(fd, size)

        monkeypatch.setattr(service_module, "os", _OsProxy(real, read=read))
    elif kind == "entry_does_not_commit_graph_index":
        _rewrite_entry_prelude(admission, root)
        digest = admission["digest"]
    else:
        raise AssertionError(kind)
    error, message = ASSET_OPEN_REFUSALS[kind]
    with pytest.raises(error, match=message):
        service.open_pack_asset(pack_id, digest, path)


LEASE_REFUSALS = {
    "lease_pack_id_invalid": (ValidationError, "packId must identify one installed pack"),
    "lease_digest_malformed": (ValidationError, "pack digest must be a lowercase SHA-256"),
    "lease_revision_not_admitted": (NotFoundError, "only an installed admitted revision can acquire a lease"),
    "lease_bytes_fail_verification": (ConflictError, "hash or size does not match staged metadata"),
    "lease_token_malformed": (ValidationError, "pack lease must be a lowercase SHA-256 token"),
}


@pytest.mark.parametrize("kind", sorted(LEASE_REFUSALS))
def test_lease_refusal_kind(admitted_runtime, kind):
    service, _state, admission, _expected, root = admitted_runtime
    error, message = LEASE_REFUSALS[kind]
    if kind == "lease_token_malformed":
        call = lambda: service.release_pack_lease("not-a-lease")  # noqa: E731
    else:
        pack_id, digest = PACK_ID, admission["digest"]
        if kind == "lease_pack_id_invalid":
            pack_id = "../escape"
        elif kind == "lease_digest_malformed":
            digest = "short"
        elif kind == "lease_revision_not_admitted":
            digest = "c" * 64
        elif kind == "lease_bytes_fail_verification":
            chunk = root / f".build/{SOURCE_DIGEST}/chunks/lazy.js"
            chunk.write_bytes(b"x" * chunk.stat().st_size)
        call = lambda: service.acquire_pack_lease(pack_id, digest)  # noqa: E731
    with pytest.raises(error, match=message):
        call()
    # A refused lease never retains a folder handle.
    assert service._pack_leases == {}
