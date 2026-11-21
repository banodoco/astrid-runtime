"""Digest proofs are process-local and belong to a specific physical file."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from runtime_protocol import cas as cas_module
from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.errors import ConflictError


def test_repeated_reads_reuse_verification_across_instances(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    payload = b"unchanged CAS object"
    digest = cas.put(payload)["digest"]
    with patch.object(cas_module.hashlib, "sha256", wraps=cas_module.hashlib.sha256) as hashed:
        assert cas.read(digest) == payload
        other = ContentAddressedStore(cas.root)
        assert other.read(digest) == payload
        assert other.verified_identity(digest)[2] == len(payload)
        assert other.existing_identity(digest, len(payload)) is not None
        assert hashed.call_count == 1


def test_explicit_verify_rehashes_after_cached_read(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    payload = b"explicit verification is always fresh"
    digest = cas.put(payload)["digest"]
    with patch.object(cas_module.hashlib, "sha256", wraps=cas_module.hashlib.sha256) as hashed:
        assert cas.read(digest) == payload
        assert hashed.call_count == 1
        assert cas.verify(digest) == {"digest": digest, "size": len(payload), "verified": True}
        assert hashed.call_count == 2


def test_concurrent_reads_allow_duplicate_hashing_then_reuse_proof(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    payload = b"concurrent object" * 10000
    digest = cas.put(payload)["digest"]
    with patch.object(cas_module.hashlib, "sha256", wraps=cas_module.hashlib.sha256) as hashed:
        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(cas.read, [digest] * 8)) == [payload] * 8
        assert hashed.call_count >= 1
        count_after_concurrent_reads = hashed.call_count
        assert cas.read(digest) == payload
        assert hashed.call_count == count_after_concurrent_reads


@pytest.mark.parametrize("mutation", ["rewrite", "replace", "restore-mtime"])
def test_changed_identity_rejects_same_size_corruption(tmp_path, mutation):
    cas = ContentAddressedStore(tmp_path / "cas")
    digest = cas.put(b"original")["digest"]
    assert cas.read(digest) == b"original"
    path = cas.path_for(digest)
    initial = path.stat()
    if mutation == "replace":
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"tampered")
        os.utime(replacement, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        replacement.replace(path)
    else:
        path.write_bytes(b"tampered")
        mtime = initial.st_mtime_ns + 1_000_000_000 if mutation == "rewrite" else initial.st_mtime_ns
        os.utime(path, ns=(initial.st_atime_ns, mtime))
    with pytest.raises(ConflictError, match="hash verification"):
        cas.read(digest)


def test_corrupt_first_read_is_never_cached(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    digest = cas.put(b"original")["digest"]
    cas.path_for(digest).write_bytes(b"tampered")
    for _ in range(2):
        with pytest.raises(ConflictError, match="hash verification"):
            cas.read(digest)


def test_changed_metadata_reverifies_healthy_bytes(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    digest = cas.put(b"original")["digest"]
    with patch.object(cas_module.hashlib, "sha256", wraps=cas_module.hashlib.sha256) as hashed:
        assert cas.read(digest) == b"original"
        path = cas.path_for(digest)
        initial = path.stat()
        os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))
        assert cas.verified_identity(digest)[2] == len(b"original")
        assert cas.read(digest) == b"original"
        assert hashed.call_count == 2
