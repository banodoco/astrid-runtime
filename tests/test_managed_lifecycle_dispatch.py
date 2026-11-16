from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from astrid_runtime import cli
from astrid_runtime.bootstrap import BootstrapError
from astrid_runtime.paths import RuntimePaths


@pytest.mark.parametrize('action', ['up', 'restart'])
def test_managed_dispatch_uses_selected_product_without_generic_launch(tmp_path, monkeypatch, action):
    paths = RuntimePaths.sandbox(tmp_path / 'home')
    source = tmp_path / 'program' / 'versions' / 'release13' / 'py' / 'lib' / 'python3.11' / 'site-packages'
    config = SimpleNamespace(resolve_source_profile=lambda _: SimpleNamespace(source_checkout=str(source)))
    calls = []

    @contextmanager
    def selected(path):
        assert path == str(source)
        def lifecycle(**kwargs):
            calls.append(kwargs)
            return {'ok': True, 'status': 'restarted'}
        yield lifecycle

    monkeypatch.setattr('astrid_runtime.selected_source.selected_managed_lifecycle', selected)
    monkeypatch.setattr(cli, '_read_support_json', lambda _: None)
    result = cli._managed_lifecycle(paths, config, action, wait=True)
    assert result['ok'] is True
    assert calls == [{'action': action, 'source_checkout': source, 'data_root': paths.app_support, 'wait': True}]


def test_bad_managed_checkout_fails_before_launch(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / 'home')
    source = tmp_path / 'source'
    config = SimpleNamespace(resolve_source_profile=lambda _: SimpleNamespace(source_checkout=str(source)))
    monkeypatch.setattr(cli, '_read_support_json', lambda _: {
        'owner': 'haus.astrid.runtime', 'data_root': str(paths.app_support),
    })
    with pytest.raises(BootstrapError, match='does not match'):
        cli._managed_lifecycle(paths, config, 'restart')


def test_source_checkout_remains_unmanaged(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / 'home')
    config = SimpleNamespace(resolve_source_profile=lambda _: SimpleNamespace(source_checkout=str(tmp_path / 'source')))
    monkeypatch.setattr(cli, '_read_support_json', lambda _: None)
    assert cli._managed_lifecycle(paths, config, 'restart') is None


def test_controller_must_confirm_success(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / 'home')
    source = tmp_path / 'program' / 'versions' / 'broken' / 'a'
    config = SimpleNamespace(resolve_source_profile=lambda _: SimpleNamespace(source_checkout=str(source)))
    @contextmanager
    def selected(_):
        yield lambda **kwargs: None
    monkeypatch.setattr('astrid_runtime.selected_source.selected_managed_lifecycle', selected)
    monkeypatch.setattr(cli, '_read_support_json', lambda _: None)
    with pytest.raises(BootstrapError, match='did not confirm'):
        cli._managed_lifecycle(paths, config, 'restart')


def test_managed_raw_run_refused_but_canonical_context_accepted(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path / 'home')
    manifest = tmp_path / 'profile.json'
    config = SimpleNamespace(source_manifest=manifest)
    monkeypatch.setattr(cli, '_paths', lambda _: paths)
    monkeypatch.setattr(cli, '_config', lambda *_: config)
    monkeypatch.setattr(cli, '_managed_source', lambda *_: tmp_path / 'managed')
    monkeypatch.setattr(cli, '_run_foreground', lambda *_args, **_kwargs: 0)
    assert cli.main(['run', '--json']) == 1
    assert 'installation service' in capsys.readouterr().out
    assert cli.main(['run', '--json'], managed_launch={
        'data_root': str(paths.app_support), 'profile': str(manifest),
    }) == 0
    assert cli.main(['run', '--json'], managed_launch={
        'data_root': str(tmp_path / 'wrong'), 'profile': str(manifest),
    }) == 1
