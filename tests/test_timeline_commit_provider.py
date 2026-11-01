from types import SimpleNamespace

import pytest

from runtime_protocol import timeline_commit_provider as seam
from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import ValidationError


class Provider:
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def commit(self, context, port):
        return {"context": context, "port": port}


def test_provider_abi_requires_exact_identity_digest_and_sync_signature():
    assert seam.validate_timeline_commit_provider(Provider()) is not None

    for field, value in (
        ("provider_id", "other"),
        ("interface_version", 2),
        ("contract_digest", "sha256:" + "0" * 64),
    ):
        candidate = Provider()
        setattr(candidate, field, value)
        with pytest.raises(ValidationError):
            seam.validate_timeline_commit_provider(candidate)

    class AsyncProvider(Provider):
        async def commit(self, context, port):
            return None

    with pytest.raises(ValidationError):
        seam.validate_timeline_commit_provider(AsyncProvider())


def test_authoring_loader_is_fixed_zero_argument_factory(monkeypatch):
    imported = []

    def import_provider(name):
        imported.append(name)
        return SimpleNamespace(create_runtime_commit_service=Provider)

    monkeypatch.setattr(seam.importlib, "import_module", import_provider)
    assert seam.load_timeline_commit_provider("astrid").provider_id == "astrid-v1"
    assert imported == ["astrid.sdk.timeline.commit"]

    class NeedsAnArgument:
        def __call__(self, required):
            return Provider()

    monkeypatch.setattr(
        seam.importlib,
        "import_module",
        lambda name: SimpleNamespace(create_runtime_commit_service=NeedsAnArgument()),
    )
    with pytest.raises(ValidationError):
        seam.load_timeline_commit_provider("astrid")


def test_neutral_loader_does_not_import_agent(monkeypatch):
    def unexpected_import(_name):
        raise AssertionError("neutral startup imported Agent")

    monkeypatch.setattr(seam.importlib, "import_module", unexpected_import)
    assert seam.load_timeline_commit_provider("neutral") is None
    assert seam.load_timeline_commit_provider(None) is None


def test_missing_provider_is_a_neutral_503():
    error = seam.TimelineCommitUnavailable()
    assert error.status == 503
    assert error.as_dict() == {
        "code": "not_ready",
        "message": "timeline commit provider is unavailable",
        "details": {"reason": "runtime_unavailable"},
    }
