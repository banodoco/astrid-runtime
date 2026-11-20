"""Explicit provider registration for restored, upgraded test realms.

The archive loaders perform the real offline migration and leave its fence in
place. Every new service owner must then register its provider. These helpers
use that startup path; they never edit activation evidence or bypass readiness.
Host-boundary tests may supply their existing prepared provider. Omitting one
selects the installed Astrid authoring profile, exactly as normal daemon startup.
"""
from __future__ import annotations

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from runtime_protocol.v33_lifecycle import require_ready


def register_migrated_provider(service, provider=None):
    """Verify retained baselines through registration and ``provider_ready``."""
    if provider is None:
        provider = load_timeline_commit_provider("astrid")
    service.register_timeline_commit_provider(provider)
    require_ready(service.store.root)
    return service


def open_migrated_service(root, *, provider=None, **kwargs):
    """Open one upgraded realm with fresh registration for this service owner."""
    service = RuntimeService(root, **kwargs)
    try:
        return register_migrated_provider(service, provider)
    except BaseException:
        service.close()
        raise


class MigratedRealmDaemon(RuntimeDaemon):
    """Select authoring before admission, retaining an explicit host test double."""

    def __init__(self, root, *, provider=None, **kwargs):
        super().__init__(root, authoring_profile="astrid", **kwargs)
        self._fixture_provider = provider

    def _load_installed_timeline_commit_provider(self):
        if self._fixture_provider is not None:
            return self._fixture_provider
        return super()._load_installed_timeline_commit_provider()
