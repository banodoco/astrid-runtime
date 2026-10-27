import pytest

from astrid_runtime.bootstrap import BootstrapConfig, LegacyRootCollisionError, bootstrap
from astrid_runtime.paths import RuntimePaths
import test_bootstrap as fixtures


def test_credential_only_home_can_launch_without_changing_credentials():
    fixture = fixtures.BootstrapTests()
    fixture.setUp()
    try:
        fixture._configure()
        credential = fixture.paths.home / ".astrid" / "astrid.env"
        credential.parent.mkdir()
        credential.write_text("RUNPOD_API_KEY=fixture-only\n")
        credential.chmod(0o600)
        before = credential.read_bytes(), credential.stat().st_mode
        assert bootstrap(fixture.paths, fixture.boundary, fixture.config).ready
        assert (credential.read_bytes(), credential.stat().st_mode) == before
    finally:
        fixture.tearDown()


@pytest.mark.parametrize("marker", [
    "astrid.sqlite3", "workspace.sqlite3", "realm.sqlite3", "projects", "runtime", "realms",
])
def test_credentials_do_not_hide_legacy_realm_markers(tmp_path, marker):
    paths = RuntimePaths.sandbox(tmp_path)
    legacy = paths.home / ".astrid"
    legacy.mkdir()
    (legacy / "astrid.env").touch()
    # Even a dangling marker is a collision; no legacy data is opened.
    (legacy / marker).symlink_to(tmp_path / "missing")
    with pytest.raises(LegacyRootCollisionError):
        bootstrap(paths, None, BootstrapConfig(source_profile=fixtures.PROFILE))
    assert not paths.catalog_path.exists()


def test_explicit_legacy_root_still_refuses_empty_directory(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    legacy = tmp_path / "explicit-legacy"
    legacy.mkdir()
    with pytest.raises(LegacyRootCollisionError):
        bootstrap(paths, None, BootstrapConfig(legacy_roots=(legacy,)))
