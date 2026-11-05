from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.store import RealmStore
from tests.door_helpers import HOSTED, write_owner_only
from tests.test_runtime_pack_assets import (
    ENTRY_PATH,
    ENTRY_PRELUDE,
    PACK_ID,
    _snapshot,
    _write_pack,
)


def _request(base: str, path: str, method: str = "GET", *, token: str | None = None,
             headers: dict[str, str] | None = None, origin: str | None = None):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    if origin is not None:
        request_headers["Origin"] = origin
    request = urllib.request.Request(base + path, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def _add_unicode_asset(admission: dict, expected: dict[str, tuple[bytes, str]]) -> None:
    manifest = admission["artifactManifest"]
    logical_path = "assets/café icon.png"
    data = b"fixture unicode asset"
    disk = f".build/{admission['sourceDigest']}/{logical_path}"
    target = Path(admission["root"]) / disk
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    manifest["files"].append({
        "path": logical_path, "disk": disk,
        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "mime": "image/png",
    })
    manifest["files"].sort(key=lambda row: row["path"])
    graph = [
        {"logical_path": row["path"], "sha256": row["sha256"],
         "size": row["size"], "mime": row["mime"]}
        for row in manifest["files"] if row["path"] != ENTRY_PATH
    ]
    graph_digest = hashlib.sha256(json.dumps(
        graph, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    entry_row = next(row for row in manifest["files"] if row["path"] == ENTRY_PATH)
    entry_file = Path(admission["root"]) / entry_row["disk"]
    entry = entry_file.read_bytes().replace(
        ENTRY_PRELUDE.format(manifest["graphIndexDigest"]).encode("utf-8"),
        ENTRY_PRELUDE.format(graph_digest).encode("utf-8"), 1,
    )
    entry_file.write_bytes(entry)
    entry_row["sha256"] = hashlib.sha256(entry).hexdigest()
    entry_row["size"] = len(entry)
    expected[ENTRY_PATH] = (entry, "text/javascript")
    manifest["graphIndexDigest"] = graph_digest
    manifest["digest"] = entry_row["sha256"]
    admission["digest"] = entry_row["sha256"]
    admission["artifactManifestDigest"] = hashlib.sha256(json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    expected[logical_path] = (data, "image/png")


@pytest.fixture
def running_runtime(tmp_path: Path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    pack_root = tmp_path / "installed" / PACK_ID
    admission, expected = _write_pack(pack_root)
    _add_unicode_asset(admission, expected)
    state = {"snapshot": _snapshot(admission)}
    credential_file = tmp_path / "astrid.json"
    daemon = RuntimeDaemon(
        realm,
        support_root=tmp_path / "support",
        pack_admissions=lambda: state["snapshot"],
        door=DoorConfig(origin=HOSTED, port=0, credential_file=credential_file),
    ).start()
    try:
        # Provision the door identity through the real Runtime HTTP route, then
        # give the door the same owner-only credential file the product writes.
        product_token = "door-pack-http-test-token"
        # Provision the product actor through the owner's real HTTP route.
        body = b""
        request = urllib.request.Request(
            daemon.endpoint + "/v1/credentials",
            data=json.dumps({
                "actor_id": "astrid-pack-http-test",
                "credential": product_token,
                "scope": "astrid",
            }).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
        assert status == 201, body
        write_owner_only(credential_file, {
            "version": 1,
            "scope": "astrid",
            "actor_id": "astrid-pack-http-test",
            "token": product_token,
        })
        yield daemon, state, admission, expected, product_token
    finally:
        daemon.stop()


def _asset_path(admission: dict, logical_path: str = ENTRY_PATH) -> str:
    return f"/api/runtime/packs/assets/{PACK_ID}/{admission['digest']}/{logical_path}"


def test_runtime_daemon_composes_admissions_and_serves_inventory_and_assets(running_runtime):
    daemon, state, admission, expected, _product_token = running_runtime

    status, headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token
    )
    assert status == 200
    assert headers.get_content_type() == "application/json"
    inventory = json.loads(body)
    assert inventory["revision"] == 1
    assert inventory["packs"] == [{
        "packId": PACK_ID,
        "sourceDigest": admission["sourceDigest"],
        "digest": admission["digest"],
        "artifactManifestDigest": admission["artifactManifestDigest"],
        "artifactManifest": admission["artifactManifest"],
        "url": _asset_path(admission),
        "enabled": True,
    }]

    for method in ("GET", "HEAD"):
        status, _headers, body = _request(
            daemon.endpoint, "/api/runtime/packs/inventory", method,
            token=daemon.token,
        )
        assert status == 200
        if method == "GET":
            assert json.loads(body) == inventory
        else:
            assert body == b""

    entry, mime = expected[ENTRY_PATH]
    status, headers, body = _request(
        daemon.endpoint, _asset_path(admission), token=daemon.token
    )
    assert status == 200
    assert body == entry
    assert headers.get_content_type() == mime
    assert headers["ETag"] == f'"sha256:{hashlib.sha256(entry).hexdigest()}"'
    assert headers["Accept-Ranges"] == "bytes"

    etag = headers["ETag"]
    status, headers, body = _request(
        daemon.endpoint, _asset_path(admission), token=daemon.token,
        headers={"Range": "bytes=0-7", "If-Range": etag},
    )
    assert status == 206 and body == entry[:8]
    assert headers["Content-Range"] == f"bytes 0-7/{len(entry)}"

    status, _headers, body = _request(
        daemon.endpoint, _asset_path(admission), token=daemon.token,
        headers={"Range": "bytes=0-7", "If-Range": '"stale"'},
    )
    assert status == 200 and body == entry

    status, headers, body = _request(
        daemon.endpoint, _asset_path(admission), "HEAD", token=daemon.token,
        headers={"Range": "bytes=0-7"},
    )
    assert status == 206
    assert body == b""
    assert headers["Content-Range"] == f"bytes 0-7/{len(entry)}"
    assert headers["Content-Length"] == "8"

    state["snapshot"] = _snapshot(admission, revision=2)
    status, _headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token
    )
    assert status == 200 and json.loads(body)["revision"] == 2

    state["snapshot"] = _snapshot(revision=3)
    status, _headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token
    )
    assert status == 200 and json.loads(body) == {
        "version": 1, "revision": 3, "packs": [],
    }
    status, _headers, _body = _request(
        daemon.endpoint, _asset_path(admission), token=daemon.token
    )
    assert status == 404


def test_pack_http_requires_bearer_and_door_forwards_public_reads(running_runtime):
    daemon, _state, admission, expected, product_token = running_runtime
    asset_path = _asset_path(admission, "chunks/lazy.js")

    status, _headers, _body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory"
    )
    assert status == 401
    status, _headers, _body = _request(daemon.endpoint, asset_path)
    assert status == 401

    door_base = daemon.door_endpoint
    status, headers, body = _request(
        door_base, "/api/runtime/packs/inventory", origin=HOSTED,
    )
    assert status == 200
    assert json.loads(body)["packs"][0]["packId"] == PACK_ID
    assert headers["Access-Control-Allow-Origin"] == HOSTED

    chunk, mime = expected["chunks/lazy.js"]
    status, headers, body = _request(
        door_base, asset_path, origin=HOSTED,
    )
    assert status == 200
    assert body == chunk
    assert headers.get_content_type() == mime
    etag = headers["ETag"]

    status, headers, body = _request(
        door_base, asset_path, "GET", origin=HOSTED,
        headers={"Range": "bytes=0-4", "If-Range": etag},
    )
    assert status == 206
    assert body == chunk[:5]
    assert headers["Content-Range"] == f"bytes 0-4/{len(chunk)}"

    status, headers, body = _request(
        door_base, asset_path, "HEAD", origin=HOSTED,
        headers={"Range": "bytes=0-4"},
    )
    assert status == 206 and body == b""
    assert headers["Content-Range"] == f"bytes 0-4/{len(chunk)}"

    status, _headers, body = _request(
        door_base, asset_path, "GET", origin=HOSTED,
        headers={"Range": "bytes=0-4", "If-Range": '"stale"'},
    )
    assert status == 200 and body == chunk


def test_pack_http_enforces_objects_read_scope(running_runtime):
    daemon, _state, admission, _expected, _product_token = running_runtime
    token, _credential_path = daemon.credentials.provision(
        "pack-http-insufficient", ["tasks:read"],
    )
    for path in ("/api/runtime/packs/inventory", _asset_path(admission)):
        status, _headers, _body = _request(daemon.endpoint, path, token=token)
        assert status == 401


def test_pack_door_preflight_and_browser_request_boundary(running_runtime):
    daemon, _state, admission, _expected, _product_token = running_runtime
    path = _asset_path(admission, "chunks/lazy.js")

    status, headers, body = _request(
        daemon.door_endpoint, path, "OPTIONS", origin=HOSTED,
        headers={
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "range, if-range",
        },
    )
    assert status == 204 and body == b""
    assert headers["Access-Control-Allow-Origin"] == HOSTED
    assert headers["Access-Control-Allow-Methods"] == "GET"
    assert headers["Access-Control-Allow-Headers"] == "range, if-range"

    status, _headers, _body = _request(
        daemon.door_endpoint, path, origin="https://foreign.example",
    )
    assert status == 403

    status, _headers, _body = _request(
        daemon.door_endpoint, path, token="browser-supplied-token", origin=HOSTED,
    )
    assert status == 403

    status, _headers, _body = _request(
        daemon.door_endpoint, path, "POST", origin=HOSTED,
    )
    assert status == 404


def test_pack_http_refuses_unknown_bundle_unlisted_and_traversal(running_runtime):
    daemon, _state, admission, _expected, _product_token = running_runtime
    digest = admission["digest"]
    paths = (
        f"/api/runtime/packs/assets/unknown/{'a' * 64}/index.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{'c' * 64}/index.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/unlisted.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/%2e%2e/secret.js",
    )
    for path in paths:
        status, _headers, _body = _request(daemon.endpoint, path, token=daemon.token)
        assert status in (400, 404), path


def test_pack_http_detects_tampered_admitted_bytes(running_runtime):
    daemon, _state, admission, _expected, _product_token = running_runtime
    pack_root = Path(admission["root"])
    asset = pack_root / f".build/{admission['sourceDigest']}/chunks/lazy.js"
    original = asset.read_bytes()
    asset.write_bytes(original + b"// changed")
    try:
        status, _headers, _body = _request(
            daemon.endpoint, _asset_path(admission, "chunks/lazy.js"),
            token=daemon.token,
        )
        assert status in (409, 422)
    finally:
        asset.write_bytes(original)


def test_door_rejects_encoded_separator_malformed_percent_and_extra_path_syntax(running_runtime):
    daemon, _state, admission, _expected, _product_token = running_runtime
    digest = admission["digest"]
    paths = (
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks%2Flazy.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks//lazy.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks/%ZZ.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks/%FF.js",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks/lazy.js%23fragment",
        f"/api/runtime/packs/assets/{PACK_ID}/{digest}/chunks/lazy.js?download=1",
    )
    for path in paths:
        status, _headers, _body = _request(
            daemon.door_endpoint, path, origin=HOSTED,
        )
        assert status in (400, 404), path


@pytest.mark.parametrize("suffix", ["chunks%2Flazy.js", "chunks//lazy.js", "chunks/%FF.js"])
def test_runtime_listener_refuses_malformed_asset_paths(running_runtime, suffix):
    daemon, _state, admission, _expected, _product_token = running_runtime
    path = _asset_path(admission, suffix)
    status, _headers, _body = _request(daemon.endpoint, path, token=daemon.token)
    assert status in (400, 404), path


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_pack_asset_rejects_unsatisfiable_range_for_get_and_head(running_runtime, method):
    daemon, _state, admission, expected, _product_token = running_runtime
    data = expected["chunks/lazy.js"][0]
    status, headers, _body = _request(
        daemon.endpoint, _asset_path(admission, "chunks/lazy.js"), method,
        token=daemon.token, headers={"Range": f"bytes={len(data)}-"},
    )
    assert status == 416
    assert headers["Content-Range"] == f"bytes */{len(data)}"


def test_door_decodes_unicode_and_space_logical_path_before_manifest_lookup(running_runtime):
    daemon, _state, admission, expected, _product_token = running_runtime
    path = _asset_path(admission, "assets/caf%C3%A9%20icon.png")
    status, headers, body = _request(
        daemon.door_endpoint, path, origin=HOSTED,
    )
    assert status == 200
    assert body == expected["assets/café icon.png"][0]
    assert headers.get_content_type() == "image/png"


def test_snapshot_disable_uninstall_and_daemon_restart_are_live(running_runtime):
    daemon, state, admission, _expected, _product_token = running_runtime
    state["snapshot"] = _snapshot(admission, revision=2)
    status, _headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token,
    )
    assert status == 200 and json.loads(body)["revision"] == 2

    state["snapshot"] = _snapshot({**admission, "enabled": False}, revision=3)
    status, _headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token,
    )
    assert status == 200 and json.loads(body) == {
        "version": 1, "revision": 3, "packs": [],
    }
    status, _headers, _body = _request(
        daemon.endpoint, _asset_path(admission), token=daemon.token,
    )
    assert status == 404
    status, _headers, body = _request(
        daemon.door_endpoint, "/api/runtime/packs/inventory", origin=HOSTED,
    )
    assert status == 200 and json.loads(body) == {
        "version": 1, "revision": 3, "packs": [],
    }
    status, _headers, _body = _request(
        daemon.door_endpoint, _asset_path(admission), origin=HOSTED,
    )
    assert status == 404

    state["snapshot"] = _snapshot(admission, revision=4)
    daemon.stop()
    daemon.start()
    status, _headers, body = _request(
        daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token,
    )
    assert status == 200 and json.loads(body)["revision"] == 4


def test_browser_lease_retains_verified_lazy_bytes_and_release_revokes(running_runtime, tmp_path):
    daemon, state, admission, expected, _token = running_runtime
    lease_url = f"/api/runtime/packs/leases/{PACK_ID}/{admission['digest']}"
    # Exact POST route, same door/auth admission as the inventory and assets.
    status, _, body = _request(daemon.door_endpoint, lease_url, "POST", origin=HOSTED)
    assert status == 201, body
    lease = json.loads(body)["lease"]
    root = Path(admission["root"])
    retained = root.with_name("retained-old")
    root.rename(retained)
    replacement, _ = _write_pack(root)
    # A valid new admission with a distinct entry identity, as after M1 commit.
    entry_row = next(r for r in replacement["artifactManifest"]["files"] if r["path"] == ENTRY_PATH)
    entry = root / entry_row["disk"]
    entry.write_bytes(entry.read_bytes() + b"// replacement\n")
    entry_row.update(sha256=hashlib.sha256(entry.read_bytes()).hexdigest(), size=entry.stat().st_size)
    replacement["digest"] = replacement["artifactManifest"]["digest"] = entry_row["sha256"]
    replacement["artifactManifestDigest"] = hashlib.sha256(json.dumps(
        replacement["artifactManifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    state["snapshot"] = _snapshot(replacement, revision=2)
    assert _request(daemon.endpoint, lease_url, "POST", token=daemon.token)[0] == 404
    old_chunk = _asset_path(admission, "chunks/lazy.js")
    status, _, body = _request(daemon.door_endpoint, old_chunk, origin=HOSTED)
    assert status == 200 and body == expected["chunks/lazy.js"][0]
    # Retention never admits unlisted files or hides old-byte tampering.
    assert _request(daemon.endpoint, _asset_path(admission, "unlisted.js"), token=daemon.token)[0] == 404
    chunk = retained / f".build/{admission['sourceDigest']}/chunks/lazy.js"
    chunk.write_bytes(chunk.read_bytes() + b"tampered")
    assert _request(daemon.endpoint, old_chunk, token=daemon.token)[0] == 409
    chunk.write_bytes(expected["chunks/lazy.js"][0])
    release = f"/api/runtime/packs/leases/{lease}"
    assert _request(daemon.door_endpoint, release, "DELETE", origin=HOSTED)[0] == 200
    assert _request(daemon.endpoint, release, "DELETE", token=daemon.token)[0] == 200
    assert _request(daemon.endpoint, old_chunk, token=daemon.token)[0] == 404
    assert daemon.service._pack_leases == {}


def test_lease_refusals_disable_and_shutdown_cleanup(running_runtime):
    daemon, state, admission, _expected, _token = running_runtime
    base = "/api/runtime/packs/leases/"
    for url in (base + f"unknown/{admission['digest']}", base + f"{PACK_ID}/{'f' * 64}"):
        assert _request(daemon.endpoint, url, "POST", token=daemon.token)[0] == 404
    for suffix in (f"../{admission['digest']}", f"{PACK_ID}/%2e%2e", f"{PACK_ID}/{admission['digest']}?x=1"):
        assert _request(daemon.door_endpoint, base + suffix, "POST", origin=HOSTED)[0] in (400, 404)
    url = base + f"{PACK_ID}/{admission['digest']}"
    assert _request(daemon.endpoint, url, "POST")[0] == 401
    limited, _ = daemon.credentials.provision("pack-lease-insufficient", ["tasks:read"])
    assert _request(daemon.endpoint, url, "POST", token=limited)[0] == 401
    assert _request(daemon.door_endpoint, url, "GET", origin=HOSTED)[0] == 404
    assert _request(daemon.door_endpoint, url, "POST", origin="https://foreign.example")[0] == 403
    assert _request(daemon.endpoint, url, "POST", token=daemon.token)[0] == 201
    retained_fd = next(iter(daemon.service._pack_leases.values()))[1]
    state["snapshot"] = _snapshot({**admission, "enabled": False}, revision=3)
    assert _request(daemon.endpoint, _asset_path(admission), token=daemon.token)[0] == 404
    import os
    with pytest.raises(OSError):
        os.fstat(retained_fd)
    assert daemon.service._pack_leases == {}
    state["snapshot"] = _snapshot(admission, revision=4)
    entry = Path(admission["root"]) / f".build/{admission['sourceDigest']}.js"
    original = entry.read_bytes()
    entry.write_bytes(original + b"tampered")
    assert _request(daemon.endpoint, url, "POST", token=daemon.token)[0] == 409
    assert daemon.service._pack_leases == {}
    entry.write_bytes(original)
    assert _request(daemon.endpoint, url, "POST", token=daemon.token)[0] == 201
    retained_fd = next(iter(daemon.service._pack_leases.values()))[1]
    state["snapshot"] = _snapshot(revision=5)
    assert _request(daemon.endpoint, "/api/runtime/packs/inventory", token=daemon.token)[0] == 200
    with pytest.raises(OSError):
        os.fstat(retained_fd)
    assert daemon.service._pack_leases == {}
    state["snapshot"] = _snapshot(admission, revision=6)
    assert _request(daemon.endpoint, url, "POST", token=daemon.token)[0] == 201
    retained_fd = next(iter(daemon.service._pack_leases.values()))[1]
    daemon.stop()
    with pytest.raises(OSError):
        os.fstat(retained_fd)
