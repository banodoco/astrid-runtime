"""LS-6/D14: install only bytes verified by the caller and the complete sender."""
from __future__ import annotations

import hashlib
import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


MEDIA_TYPE = "application/vnd.astrid.verified-object.v1"
MARKER = b"\nASTRID-OBJECT-COMPLETE-v1\n"


def _identity(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("size", [0, 17, 9 * 1024 * 1024 + 13])
def test_streamed_object_installs_independent_verified_file(tmp_path, size):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        data = (b"0123456789abcdef" * ((size + 15) // 16))[:size]
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        stored = client.ingest_object(data, media_type="application/octet-stream", idempotency_key="object")
        target = tmp_path / "caller.bin"
        target.write_bytes(b"prior")
        receipt = client.get_object(stored["object_id"], destination=target, expected_size=size)
        assert receipt.path == str(target)
        assert receipt.digest == _identity(data)
        assert receipt.size == size
        assert receipt.stream_verified is True
        assert target.read_bytes() == data
        target.write_bytes(b"caller changes")
        assert client.get_object(stored["object_id"]).data == data
    finally:
        daemon.stop()


@pytest.mark.parametrize("failure", ["equal-length", "missing-marker", "short", "extra", "wrong-length", "wrong-identity"])
def test_claimed_success_cannot_install_bad_or_incomplete_bytes(tmp_path, failure):
    data = b"the authorized result"
    object_id = _identity(data)
    payload = data
    headers = {"Content-Type": MEDIA_TYPE, "X-Content-Digest": object_id,
               "X-Object-Length": str(len(data))}
    marker = MARKER
    if failure == "equal-length":
        payload = b"x" * len(data)
    elif failure == "missing-marker":
        marker = b""
    elif failure == "short":
        payload = data[:-1]
    elif failure == "extra":
        marker += b"unframed"
    elif failure == "wrong-length":
        headers["X-Object-Length"] = str(len(data) + 1)
    elif failure == "wrong-identity":
        headers["X-Content-Digest"] = _identity(b"different")

    def transport(method, path, request_headers, body):
        assert method == "GET" and request_headers["Accept"] == MEDIA_TYPE
        return 200, headers, payload + marker

    client = WorkspaceClient("http://runtime", transport=transport)
    target = tmp_path / "result.bin"
    target.write_bytes(b"prior")
    with pytest.raises(ApiError):
        client.get_object(object_id, destination=target, expected_size=len(data))
    assert target.read_bytes() == b"prior"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["result.bin"]


def test_runtime_mutation_while_transmitting_withholds_completion(tmp_path, monkeypatch):
    data = b"a" * (2 * 1024 * 1024)
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        stored = client.ingest_object(data, media_type="application/octet-stream", idempotency_key="object")
        original = daemon.service.open_object

        class MutatingStream:
            def __init__(self, stream):
                self.stream = stream
                self.first = True

            def __getattr__(self, key):
                return getattr(self.stream, key)

            def read(self, length):
                chunk = self.stream.read(length)
                if self.first:
                    self.first = False
                    digest = stored["object_id"].removeprefix("sha256:")
                    path = daemon.service.cas.root / digest[:2] / digest[2:]
                    with path.open("r+b") as changing:
                        changing.seek(len(chunk))
                        changing.write(b"z" * (len(data) - len(chunk)))
                return chunk

        def opened(*args, **kwargs):
            metadata, stream = original(*args, **kwargs)
            return metadata, MutatingStream(stream)

        monkeypatch.setattr(daemon.service, "open_object", opened)
        target = tmp_path / "result.bin"
        target.write_bytes(b"prior")
        with pytest.raises(ApiError):
            client.get_object(stored["object_id"], destination=target, expected_size=len(data))
        assert target.read_bytes() == b"prior"
        assert not list(tmp_path.glob(".astrid-object-*"))
    finally:
        daemon.stop()


@pytest.mark.parametrize("corrupt", [False, True])
def test_legacy_and_range_delivery_keep_independent_caller_hash(tmp_path, corrupt):
    data = b"abcdef"
    target = tmp_path / "legacy.bin"
    target.write_bytes(b"prior")
    calls = []

    def transport(method, path, headers, body):
        calls.append(headers)
        ranged = "Range" in headers
        payload = data[1:4] if ranged else data
        return (206 if ranged else 200), {}, (b"x" * len(payload) if corrupt else payload)

    client = WorkspaceClient("http://runtime", transport=transport)
    for byte_range, expected in [(None, data), ((1, 3), data[1:4])]:
        if corrupt:
            with pytest.raises(ApiError):
                client.get_object(_identity(data), destination=target, expected_size=len(expected),
                                  byte_range=byte_range, expected_digest=_identity(expected))
            assert target.read_bytes() == b"prior"
        else:
            receipt = client.get_object(_identity(data), destination=target, expected_size=len(expected),
                                        byte_range=byte_range, expected_digest=_identity(expected))
            assert target.read_bytes() == expected
            assert receipt.digest == _identity(expected)
            assert receipt.stream_verified is False
    assert calls[-1]["Range"] == "bytes=1-3"
