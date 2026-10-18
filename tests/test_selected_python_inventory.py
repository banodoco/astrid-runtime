"""Offline selected-interpreter authority vectors; no Host/Worker starts."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime_protocol import local_worker_composition as composition
from runtime_protocol import verified_host_launch as gate
from test_verified_host_launch import fixture_authority

QUALIFIED_PYTHON = sys.executable


def write_host_records(root):
    """Offline wheel-shaped records; never provisions or qualifies a profile."""
    import base64
    import csv
    import hashlib
    import io
    existing = {gate.re.sub(r'[-_.]+', '-', d.metadata['Name']).lower(): Path(d._path)
                for d in gate.importlib.metadata.distributions(path=[str(root)])}
    for name, modules in gate.HOST_DISTRIBUTIONS.items():
        directory = existing.get(name, root / (name.replace('-', '_') + '-1.0.dist-info'))
        directory.mkdir(exist_ok=True)
        metadata = directory / 'METADATA'
        if not metadata.exists():
            metadata.write_text('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n')
        paths = list(directory.rglob('*'))
        for module in modules:
            target = root / module
            if module in {'schemas', '_yaml'} and not target.exists():
                continue
            if module.endswith('.py'):
                if not target.exists(): target.write_text('VALUE=1\n')
                paths.append(target)
            else:
                target.mkdir(exist_ok=True)
                if module != 'schemas' and not (target/'__init__.py').exists(): (target/'__init__.py').write_text('')
                paths.extend(target.rglob('*'))
        stream = io.StringIO(newline=''); writer = csv.writer(stream)
        for path in sorted(set(paths)):
            if not path.is_file() or path.name == 'RECORD' or '__pycache__' in path.parts or path.suffix in {'.pyc', '.pyo'}:
                continue
            data = path.read_bytes()
            pin = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
            writer.writerow([str(path.relative_to(root)), 'sha256='+pin, len(data)])
        writer.writerow([str(directory.relative_to(root))+'/RECORD', '', ''])
        (directory/'RECORD').write_bytes(stream.getvalue().encode())


def selected_case(tmp_path, monkeypatch):
    f = fixture_authority(tmp_path)
    stdlib = f.runtime / 'lib/python3.11'
    extensions = stdlib / 'lib-dynload'
    ambient = stdlib / 'site-packages'
    for root in (extensions, ambient): root.mkdir(parents=True)
    (stdlib / 'selected_stdlib.py').write_text('VALUE=42\n')
    (extensions / ('selected_native' + gate.importlib.machinery.EXTENSION_SUFFIXES[0])).write_bytes(b'FAKE NOT LOADED')
    (ambient / 'ambient_only.py').write_text('raise RuntimeError("ambient")\n')
    (ambient / 'ambient-1.dist-info').mkdir()
    (ambient / 'ambient-1.dist-info/METADATA').write_text('Name: ambient\nVersion: 1\n')
    selected_data = f.source/'astrid/resources/site-packages'
    selected_data.mkdir(parents=True)
    (selected_data/'keep.data').write_bytes(b'selected resource, not an ambient package root')
    huge = ambient / 'oversized.dylib'
    with huge.open('wb') as stream: stream.truncate(gate.LIMIT + 1)
    venv = tmp_path / 'venv'
    (venv / 'bin').mkdir(parents=True)
    executable = venv / 'bin/python'
    executable.symlink_to(f.runtime / 'bin/python')
    (venv / 'pyvenv.cfg').write_text('include-system-site-packages = false\n')
    monkeypatch.setattr(gate.sys, 'prefix', str(venv))
    monkeypatch.setattr(gate.sys, 'base_prefix', str(f.runtime))
    monkeypatch.setattr(gate.sys, 'executable', str(executable))
    monkeypatch.setattr(gate.sysconfig, 'get_paths', lambda **kw: {'purelib':str(ambient), 'platlib':str(ambient)})
    monkeypatch.setattr(gate.sysconfig, 'get_path', lambda name: str(stdlib) if name == 'stdlib' else str(f.source))
    monkeypatch.setattr(gate.sysconfig, 'get_config_var', lambda name: str(extensions) if name == 'DESTSHARED' else None)
    profile = f.args['preparation']['profile']
    profile.update(host_executable=str(executable), execution_mode='host_only_cpu',
                   support_root=f.args['config']['support_root'], realm_root=str(tmp_path/'realm'))
    f.args['host_argv'][0] = str(executable)
    f.args['environment'].update(ASTRID_OUTPUT_ROOT=str(tmp_path/'support/host-output'),
                                BANODOCO_LOCAL_DATA_ROOT=str(tmp_path/'realm'))
    monkeypatch.setattr(composition, '_verify_installed_host_records', lambda *args: None)
    monkeypatch.setattr(composition, '_selected_profile_payload', lambda _: profile)
    write_host_records(f.source)
    profile['release_digest'] = 'sha256:' + gate.raw_digest(gate.installed_host_closure(f.source)['distributions'])
    f.record = composition._installed_host_release(SimpleNamespace(**profile), f.args['config'])
    f.verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    f.stdlib, f.extensions, f.ambient, f.venv = stdlib, extensions, ambient, venv
    return f


@pytest.fixture
def selected(tmp_path, monkeypatch):
    return selected_case(tmp_path, monkeypatch)


def test_selected_roles_keep_runtime_provenance_separate_and_exclude_before_walk(selected, monkeypatch):
    f = selected
    read, walk = gate._bounded_source, Path.iterdir
    def bounded(path, *args):
        assert not Path(path).is_relative_to(f.ambient)
        return read(path, *args)
    def children(path):
        assert not path.is_relative_to(f.ambient)
        return walk(path)
    monkeypatch.setattr(gate, '_bounded_source', bounded)
    monkeypatch.setattr(Path, 'iterdir', children)
    profile = SimpleNamespace(**f.args['preparation']['profile'])
    record = composition._installed_host_release(profile, f.args['config'])
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=record)
    proof = verifier.verify(**f.args)
    _, data = verifier.claim(proof, **f.args, binding_fd=3)
    payload = json.loads(data)
    assert payload['mapping']['selected_stdlib']['path'] == str(f.stdlib/'selected_stdlib.py')
    assert payload['mapping']['selected_native']['kind'] == 'extension'
    assert 'ambient_only' not in payload['mapping']
    assert payload['selected_python']['roots']['installed-packages'] == str(f.source)
    entries = record['import_binding']['import_roots']
    assert [e['path'] for e in entries] == [str(f.source), str(f.stdlib), str(f.extensions)]
    runtime = record['inventories'][record['import_binding']['python_runtime_inventory_digest']]
    assert runtime['root'] == str(f.runtime) and 'bin/python' in runtime['files']
    assert all('site-packages' not in name for inv in record['inventories'].values()
               if inv['selection']['role'] != 'installed-packages' for name in inv['files'])
    selected_inventory = next(inv for inv in record['inventories'].values() if inv['root'] == str(f.source))
    assert 'astrid/resources/site-packages/keep.data' in selected_inventory['files']
    finder = gate.MappedImports(payload['mapping'], trusted_local=True, distribution_metadata=payload['distribution_metadata'])
    with pytest.raises(ModuleNotFoundError): finder.find_spec('ambient_only')
    assert not list(finder.find_distributions(gate.importlib.metadata.DistributionFinder.Context(name='ambient', path=[str(f.ambient)])))


def test_ambient_internal_changes_do_not_invalidate_selected_installation(selected):
    f = selected
    (f.ambient/'ambient_only.py').write_text('CHANGED=1\n')
    (f.ambient/'new.py').write_text('NEW=1\n')
    proof = f.verifier.verify(**f.args)
    f.verifier.claim(proof, **f.args, binding_fd=3)


def test_distinct_base_purelib_and_platlib_are_both_fixed_exclusions(selected, monkeypatch):
    f = selected
    platlib = f.runtime/'lib64/python3.11/site-packages'
    platlib.mkdir(parents=True)
    with (platlib/'oversized.dylib').open('wb') as stream: stream.truncate(gate.LIMIT + 1)
    monkeypatch.setattr(gate.sysconfig, 'get_paths', lambda **kw: {'purelib':str(f.ambient), 'platlib':str(platlib)})
    with pytest.raises(gate.HostLaunchError): f.verifier.verify(**f.args)
    record = composition._installed_host_release(SimpleNamespace(**f.args['preparation']['profile']), f.args['config'])
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=record)
    proof = verifier.verify(**f.args)
    _, data = verifier.claim(proof, **f.args, binding_fd=3)
    assert {row['path'] for row in json.loads(data)['selected_python']['excluded_roots']} == {str(f.ambient), str(platlib)}


@pytest.mark.parametrize('edge', ['zip', 'broken-zip-alias', 'config', 'boundary-alias', 'root-alias', 'interpreter-alias', 'new-source', 'replaced', 'alias-excluded', 'alias-outside'])
def test_selected_drift_refuses_before_issue(selected, edge):
    f = selected
    if edge == 'zip': (f.stdlib.parent/f'python{gate.sys.version_info.major}{gate.sys.version_info.minor}.zip').write_bytes(b'new archive')
    if edge == 'broken-zip-alias': (f.stdlib.parent/f'python{gate.sys.version_info.major}{gate.sys.version_info.minor}.zip').symlink_to('missing.zip')
    if edge == 'config': (f.venv/'pyvenv.cfg').write_text('include-system-site-packages = true\n')
    if edge == 'boundary-alias':
        moved = f.ambient.with_name('moved-ambient'); f.ambient.rename(moved); f.ambient.symlink_to(moved)
    if edge == 'root-alias':
        moved = f.source.with_name('moved-source'); f.source.rename(moved); f.source.symlink_to(moved)
    if edge == 'interpreter-alias':
        executable = Path(f.args['host_argv'][0]); executable.unlink(); executable.symlink_to(str(f.runtime/'bin')+'/./python')
    if edge == 'new-source': (f.source/'new.py').write_text('NEW=1\n')
    if edge == 'replaced':
        replacement = f.source/'replacement'; replacement.write_text('REPLACED=1'); replacement.replace(f.source/'astrid/version.py')
    if edge in ('alias-excluded', 'alias-outside'):
        path = f.source/'astrid/version.py'; path.unlink()
        target = f.ambient/'ambient_only.py'
        if edge == 'alias-outside': target=f.source.parent/'outside.py'; target.write_text('OUTSIDE=1')
        path.symlink_to(target)
    with pytest.raises(gate.HostLaunchError): f.verifier.verify(**f.args)
    assert not f.verifier._issued


@pytest.mark.parametrize('edge', ['role', 'exclusion', 'root', 'file-escape', 'runtime-as-import', 'profile', 'release'])
def test_caller_cannot_forge_inventory_selection(selected, edge):
    f = selected
    record = copy.deepcopy(f.record)
    inventory = next(iter(record['inventories'].values()))
    if edge == 'role': inventory['selection']['role'] = 'caller-selected'
    if edge == 'exclusion': inventory['selection']['layout']['excluded_roots'] = []
    if edge == 'root': inventory['root'] = str(f.ambient)
    if edge == 'file-escape': inventory['files']['../outside.py'] = '0'*64
    if edge == 'runtime-as-import': record['import_binding']['import_roots'].append({'path':str(f.runtime), 'inventory_digest':record['import_binding']['python_runtime_inventory_digest']})
    if edge == 'profile': f.args['preparation']['profile']['profile_digest'] = 'sha256:'+'0'*64
    if edge == 'release': f.args['preparation']['profile']['release_digest'] = 'sha256:'+'0'*64
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=record)
    with pytest.raises(gate.HostLaunchError): verifier.verify(**f.args)
    assert not verifier._issued


def test_selected_huge_file_refuses_producer_without_byte_read(selected, monkeypatch):
    f = selected
    huge = f.source/'selected-oversized.data'
    with huge.open('wb') as stream: stream.truncate(gate.LIMIT + 1)
    real = gate.os.read
    def read(fd, count):
        assert os.fstat(fd).st_size <= gate.LIMIT
        return real(fd, count)
    monkeypatch.setattr(gate.os, 'read', read)
    with pytest.raises(gate.HostLaunchError, match='undeclared file'):
        gate.installed_inventory(f.source, python_role='installed-packages', selected_source=f.source)


def test_startup_drift_after_verify_refuses_claim(selected):
    f = selected
    proof = f.verifier.verify(**f.args)
    (f.venv/'pyvenv.cfg').write_text('changed\n')
    with pytest.raises(gate.HostLaunchError, match='boundary changed'):
        f.verifier.claim(proof, **f.args, binding_fd=3)


def test_dependency_drift_after_verify_refuses_claim(selected):
    f = selected
    proof = f.verifier.verify(**f.args)
    path = f.source/'jsonschema/__init__.py'
    path.write_text('# changed after verification\n')
    with pytest.raises(gate.HostLaunchError, match='RECORD'):
        f.verifier.claim(proof, **f.args, binding_fd=3)


def test_private_selected_boundary_crosses_existing_cold_launcher(selected, tmp_path):
    f = selected
    (f.source/'astrid/core/execution/generic_host.py').write_text(
        'import json\nprint(json.dumps(_RETAINED_SELECTED_PYTHON["roots"],sort_keys=True))\n')
    profile = f.args['preparation']['profile']
    profile['host_protocol']['source_closure_digest'] = gate.source_checkout_closure(f.source)['digest']
    write_host_records(f.source)
    profile['release_digest'] = 'sha256:' + gate.raw_digest(gate.installed_host_closure(f.source)['distributions'])
    record = composition._installed_host_release(SimpleNamespace(**profile), f.args['config'])
    verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=record)
    proof = verifier.verify(**f.args)
    _, data = verifier.claim(proof, **f.args, binding_fd=3)
    # This tiny synthetic stdlib has no email parser. Actual cold metadata and
    # eager Host imports are covered with the real stdlib in the closure cohort.
    body = json.loads(data); body['distribution_metadata'] = []
    payload = tmp_path/'retained.json'; payload.write_text(json.dumps(body))
    program = (
        'import importlib.util,json,sys; '
        's=importlib.util.spec_from_file_location("gate",sys.argv[1]); '
        'g=importlib.util.module_from_spec(s);s.loader.exec_module(g); '
        'g.launch_from_binding(json.load(open(sys.argv[2])))')
    child = subprocess.run([QUALIFIED_PYTHON, '-I', '-S', '-B', '-c', program, gate.__file__, str(payload)],
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == gate.selected_python_layout(f.source)['roots']


@pytest.fixture(scope='module')
def real_host_installation(tmp_path_factory):
    """Materialize offline test fixtures from retained bytes, without an install.

    The historical inputs are read-only. Runtime bytes come from this receiver;
    wheel-shaped fixture RECORDs explicitly belong only to these test copies.
    """
    import shutil
    installed = os.environ.get('HOST_LAUNCH_TEST_INSTALLED_SOURCE')
    dependencies = os.environ.get('HOST_LAUNCH_TEST_DEPENDENCIES')
    if not installed or not dependencies:
        pytest.skip('select retained installed SDK and dependency artifacts')
    root = tmp_path_factory.mktemp('cold-host')/'site-packages'; root.mkdir()
    normalize = lambda name: gate.re.sub(r'[-_.]+', '-', name).lower()
    for source, names in ((Path(installed), {'astrid'}),
                          (Path(dependencies), set(gate.HOST_DISTRIBUTIONS)-{'astrid', 'banodoco-workspace-runtime'})):
        found = set()
        for dist in gate.importlib.metadata.distributions(path=[str(source)]):
            name = normalize(dist.metadata['Name'])
            if name not in names: continue
            assert name not in found
            found.add(name)
            for relative in dist.files:
                if '..' in relative.parts or '__pycache__' in relative.parts or relative.suffix in {'.pyc', '.pyo'}:
                    continue
                path = source/relative
                assert path.is_file() and not path.is_symlink()
                target = root/relative; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        assert found == names
    for package in ('runtime_protocol', 'banodoco_local'):
        shutil.copytree(Path(__file__).parents[1]/package, root/package,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    write_host_records(root)
    (root/'retained-dependencies.pth').write_text(dependencies+'\n')
    gate.installed_host_closure(root)
    return root


@pytest.fixture(scope='module')
def real_python_inventories(real_host_installation):
    layout = gate.selected_python_layout(real_host_installation)
    return {role: gate.installed_inventory(path, python_role=role, selected_source=real_host_installation)
            for role, path in layout['roots'].items()}


@pytest.mark.parametrize('edge', ['valid', 'omitted', 'missing-yaml', 'missing-pillow', 'missing-dotenv'])
def test_actual_cold_host_import_discovery_schema_resources_metadata(real_host_installation, real_python_inventories, tmp_path, edge):
    root = real_host_installation
    inventories = copy.deepcopy(real_python_inventories)
    # Omissions deliberately recreate the old incomplete inventory, while all
    # ambient escape routes still point at real installed dependency artifacts.
    prefixes = {'omitted': ('jsonschema/',), 'missing-yaml': ('yaml/', '_yaml/'),
                'missing-pillow': ('PIL/',), 'missing-dotenv': ('dotenv/',)}.get(edge, ())
    inventory = inventories['installed-packages']
    inventory['files'] = {p: pin for p, pin in inventory['files'].items() if not p.startswith(prefixes)}
    pins = {gate.raw_digest(i): i for i in inventories.values()}
    entries = [{'path':inventories[r]['root'], 'inventory_digest':gate.raw_digest(inventories[r])}
               for r in ('installed-packages', 'python-stdlib', 'python-extensions')]
    mapping = gate._mapping(entries, pins, inventories['python-runtime'], trusted_local=True)
    metadata = gate._distribution_metadata(entries, pins)
    payload = tmp_path/'binding.json'
    payload.write_text(json.dumps({'mapping':mapping, 'metadata':metadata, 'root':str(root)}))
    ambient = tmp_path/'ambient'; ambient.mkdir()
    (ambient/'sitecustomize.py').write_text('raise RuntimeError("ambient executed")')
    (ambient/'dependency.pth').write_text(os.environ['HOST_LAUNCH_TEST_DEPENDENCIES'])
    (ambient/'_editable_host.pth').write_text('import sitecustomize')
    for name in ('jsonschema', 'yaml', 'PIL', 'dotenv'):
        (ambient/(name+'.py')).write_text('raise RuntimeError("ambient CWD import executed")')
    program = r'''
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('cold_gate',sys.argv[1])
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
payload=json.load(open(sys.argv[2]))
assert not any(n in sys.modules for n in ('astrid','jsonschema','yaml','PIL','dotenv','rpds'))
finder=gate.MappedImports(payload['mapping'],trusted_local=True)
sys.path[:]=[];sys.path_hooks[:]=[];sys.path_importer_cache.clear();sys.meta_path[:]=[finder]
finder._bind_distribution_metadata(payload['metadata'])
from astrid.core.execution import generic_host
from astrid.core.pack.canonical import validate_canonical_pack, CanonicalPackValidationError
from astrid.core.pack.discovery import discover_pack_metadata
from pathlib import Path
from importlib.metadata import version
from importlib.resources import files
import jsonschema, attr, attrs, referencing, rpds, typing_extensions, yaml, PIL, dotenv
root=Path(payload['root'])
generation=root/'astrid/packs/generation'
pack=validate_canonical_pack(generation)
assert pack.id=='generation'
discovered=discover_pack_metadata(project_root=root,extra_pack_roots=(str(generation),))
assert any(p.pack.id=='generation' for p in discovered)
resource=files('jsonschema_specifications').joinpath('schemas/draft202012/metaschema.json')
schema=json.loads(resource.read_text())
jsonschema.Draft202012Validator.check_schema(schema)
jsonschema.Draft202012Validator({'type':'integer'}).validate(3)
try: jsonschema.Draft202012Validator({'type':'integer'}).validate('invalid')
except jsonschema.ValidationError: pass
else: raise AssertionError('invalid schema instance admitted')
invalid=Path(sys.argv[3]);invalid.write_text('schema_version: 3\nid: INVALID\n')
try: validate_canonical_pack(invalid.parent)
except CanonicalPackValidationError: pass
else: raise AssertionError('invalid pack admitted')
versions={n:version(n) for n in gate.HOST_DISTRIBUTIONS}
assert rpds.HashTrieMap({'a':1})['a']==1
assert PIL.__file__==str(root/'PIL/__init__.py')
assert dotenv.__file__==str(root/'dotenv/__init__.py')
print(json.dumps({'versions':versions,'pack':pack.id,'discovered':len(discovered),'schema':schema['$schema']},sort_keys=True))
'''
    invalid = tmp_path/'invalid'/'pack.yaml'; invalid.parent.mkdir()
    child = subprocess.run([QUALIFIED_PYTHON,'-I','-S','-B','-c',program,gate.__file__,str(payload),str(invalid)],
        cwd=ambient, env={'PATH':os.environ.get('PATH',''), 'HOME':str(ambient),
            'ASTRID_SOURCE_STATE':str(ambient/'absent-source-state.json'),
            'XDG_STATE_HOME':str(ambient/'state'), 'XDG_DATA_HOME':str(ambient/'data'),
            'PYTHONPATH':os.environ['HOST_LAUNCH_TEST_DEPENDENCIES'],
            'PYTHONUSERBASE':str(ambient), 'PYTHONSTARTUP':str(ambient/'sitecustomize.py')},
        capture_output=True,text=True,timeout=30)
    (tmp_path/'cold-result.json').write_text(json.dumps({'edge':edge, 'argv':child.args,
        'exit':child.returncode, 'stdout':child.stdout, 'stderr':child.stderr}, indent=2)+'\n')
    if edge == 'valid':
        assert child.returncode == 0, child.stderr
        result = json.loads(child.stdout)
        assert set(result['versions']) == set(gate.HOST_DISTRIBUTIONS)
        assert result['pack'] == 'generation'
    else:
        assert child.returncode != 0
        missing = {'omitted':'jsonschema','missing-yaml':'yaml','missing-pillow':'PIL','missing-dotenv':'dotenv'}[edge]
        assert 'outside the reviewed import mapping: '+missing in child.stderr


@pytest.mark.parametrize('edge', ['version', 'origin', 'record', 'source', 'resource', 'native',
                                'transitive', 'missing-coverage', 'symlink', 'undeclared', 'editable', 'duplicate-sdk', 'unrelated'])
def test_installed_host_dependency_drift_fails_closed(real_host_installation, tmp_path, edge):
    import shutil
    root = tmp_path/'site-packages'; shutil.copytree(real_host_installation, root)
    inventory = gate.installed_inventory(root, python_role='installed-packages', selected_source=root)
    distribution = next(root.glob('jsonschema-*.dist-info'))
    if edge == 'version':
        path = distribution/'METADATA'; path.write_text(path.read_text().replace('Version: 4.26.0','Version: 4.27.0'))
    if edge == 'origin':
        distribution.rename(root/'substituted.dist-info')
    if edge == 'record':
        path = distribution/'RECORD'; path.write_bytes(path.read_bytes()+b'\n')
    if edge == 'source':
        path = root/'jsonschema/__init__.py'; path.write_bytes(path.read_bytes()+b'\n# changed\n')
    if edge == 'resource':
        path = root/'jsonschema_specifications/schemas/draft202012/metaschema.json'; path.write_bytes(path.read_bytes()+b'\n')
    if edge == 'native':
        path = next(p for p in (root/'rpds').rglob('*') if p.name.endswith(tuple(gate.importlib.machinery.EXTENSION_SUFFIXES)))
        path.write_bytes(path.read_bytes()+b'changed')
    if edge == 'transitive':
        shutil.rmtree(next(root.glob('referencing-*.dist-info')))
    if edge == 'missing-coverage':
        path = distribution/'RECORD'; path.write_text('\n'.join(row for row in path.read_text().splitlines() if not row.startswith('jsonschema/__init__.py,'))+'\n')
    if edge == 'symlink':
        path=root/'jsonschema/__init__.py';outside=tmp_path/'outside.py';outside.write_bytes(path.read_bytes());path.unlink();path.symlink_to(outside)
    if edge == 'undeclared': (root/'jsonschema/new.py').write_text('NEW=1')
    if edge == 'unrelated': (root/'unrelated.py').write_text('UNRELATED=1')
    if edge == 'editable': (distribution/'direct_url.json').write_text('{"dir_info":{"editable":true}}')
    if edge == 'duplicate-sdk': shutil.copytree(next(root.glob('astrid-*.dist-info')),root/'astrid-stale.dist-info')
    with pytest.raises((gate.HostLaunchError, FileNotFoundError)):
        gate._local_inventory(inventory)
