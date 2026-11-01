"""Provider admission failure must release the service before readiness."""
from types import SimpleNamespace

import pytest

from runtime_protocol import daemon as daemon_module
from runtime_protocol.errors import ConflictError


@pytest.mark.parametrize("missing_register", [False, True])
def test_provider_failure_closes_service_and_forwards_composition(tmp_path, monkeypatch, missing_register):
    provider, composition = object(), object()
    seen = {}
    class Service:
        def __init__(self, root, **kwargs):
            seen["composition"] = kwargs["_local_worker_composition"]
            seen["required"] = kwargs["_local_worker_composition_required"]
            seen["closed"] = False
            if missing_register:
                self.register_timeline_commit_provider = None
        def register_timeline_commit_provider(self, value):
            assert value is provider
            raise RuntimeError("provider failed")
        def close(self):
            seen["closed"] = True
    instance = daemon_module.RuntimeDaemon(tmp_path / "realm")
    instance._local_worker_composition = composition
    instance._local_worker_composition_required = True
    monkeypatch.setattr(instance, "_bind_startup_identity", lambda: None)
    monkeypatch.setattr(instance, "_load_installed_timeline_commit_provider", lambda: provider)
    monkeypatch.setattr(instance, "_read_epoch_floor", lambda: 0)
    monkeypatch.setattr(daemon_module, "RuntimeService", Service)
    monkeypatch.setattr(daemon_module.process_control, "configure_from", lambda _: None)
    monkeypatch.setattr(daemon_module.process_control, "announce", lambda _: None)
    monkeypatch.setattr(daemon_module.platform, "process_control_probe", lambda: SimpleNamespace())
    with pytest.raises(ConflictError if missing_register else RuntimeError):
        instance.start()
    assert seen == {"composition": composition, "required": True, "closed": True}
    assert instance.service is None
    assert instance.httpd is None
    assert instance.credentials is None
