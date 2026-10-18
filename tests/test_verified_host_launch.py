"""Fake/offline G1b vectors; no selected interpreter, host or kernel launch."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pickle
import sys
import subprocess
import sysconfig
from types import ModuleType, SimpleNamespace

import pytest
from runtime_protocol import verified_host_launch as gate


def _metadata_binding(tmp_path):
    root=tmp_path/'installed';metadata=root/'astrid-7.2.dist-info'
    metadata.mkdir(parents=True)
    (metadata/'METADATA').write_text('Metadata-Version: 2.1\nName: astrid\nVersion: 7.2\n')
    (metadata/'top_level.txt').write_text('astrid\n')
    inventory=gate.installed_inventory(root);identity=gate.raw_digest(inventory)
    rows=gate._distribution_metadata([{'path':str(root),'inventory_digest':identity}],{identity:inventory})
    return root,metadata,rows


def test_mapped_distribution_metadata_real_version_with_empty_sys_path(tmp_path,monkeypatch):
    root,metadata,rows=_metadata_binding(tmp_path)
    finder=gate.MappedImports({},trusted_local=True,distribution_metadata=rows)
    monkeypatch.setattr(sys,'meta_path',[finder]);monkeypatch.setattr(sys,'path',[])
    assert gate.importlib.metadata.version('Astrid')=='7.2'
    source=Path(os.environ.get('HOST_LAUNCH_TEST_ASTRID_SOURCE', Path(__file__).parents[2]/'Astrid--integration-reconciled'))
    version_path=source/'astrid/version.py'
    item={'path':str(version_path),'sha256':hashlib.sha256(version_path.read_bytes()).hexdigest(),'package':False}
    selected_version=ModuleType('selected_version')
    gate._SourceLoader(item,trusted_local=True).exec_module(selected_version)
    assert selected_version.__version__=='7.2'
    assert gate.importlib.metadata.distribution('astrid').read_text('top_level.txt')=='astrid\n'
    with pytest.raises(gate.importlib.metadata.PackageNotFoundError):
        gate.importlib.metadata.version('unreviewed-distribution')
    candidates=list(finder.find_distributions(gate.importlib.metadata.DistributionFinder.Context(name='astrid',path=['/ambient'])))
    assert len(candidates)==1
    with pytest.raises(gate.HostLaunchError,match='outside'):
        candidates[0].locate_file('../outside')


@pytest.mark.parametrize('edge',['missing','changed','escape','duplicate','strict','null'])
def test_mapped_distribution_metadata_fails_closed(tmp_path,edge):
    root,metadata,rows=_metadata_binding(tmp_path)
    trusted=True
    if edge=='missing':(metadata/'METADATA').unlink()
    if edge=='changed':(metadata/'METADATA').write_text('Name: astrid\nVersion: forged\n')
    if edge=='escape':rows[0]['distributions'][0]['directory']='../astrid-7.2.dist-info'
    if edge=='duplicate':rows[0]['distributions']*=2
    if edge=='strict':trusted=False
    if edge=='null':rows={}
    with pytest.raises((gate.HostLaunchError,FileNotFoundError)):
        gate.MappedImports({},trusted_local=trusted,distribution_metadata=rows)


def test_mapped_distribution_metadata_cannot_fill_missing_selected_astrid_from_second_root(tmp_path):
    root,metadata,rows=_metadata_binding(tmp_path)
    selected=tmp_path/'selected';selected.mkdir();(selected/'selected.py').write_text('VALUE=1')
    inventories=[gate.installed_inventory(p) for p in [selected,root]]
    pins={gate.raw_digest(v):v for v in inventories}
    entries=[{'path':v['root'],'inventory_digest':gate.raw_digest(v)} for v in inventories]
    with pytest.raises(gate.HostLaunchError,match='outside the selected'):
        gate._distribution_metadata(entries,pins)


def test_mapped_distribution_metadata_is_emitted_from_reviewed_trusted_binding_only(tmp_path):
    f=local_fixture(tmp_path)
    metadata=f.source/'astrid-7.2.dist-info';metadata.mkdir()
    (metadata/'METADATA').write_text('Name: astrid\nVersion: 7.2\n')
    inventory=gate.installed_inventory(f.source);identity=gate.raw_digest(inventory)
    old=f.record['import_binding']['import_roots'][0]['inventory_digest']
    del f.record['inventories'][old]
    f.record['inventories'][identity]=inventory
    f.record['import_binding']['import_roots'][0]['inventory_digest']=identity
    verifier=gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof=verifier.verify(**f.args);_,data=verifier.claim(proof,**f.args,binding_fd=3)
    body=json.loads(data)
    assert body['distribution_metadata'][0]['root']==str(f.source)
    assert body['distribution_metadata'][0]['files']['astrid-7.2.dist-info/METADATA']==inventory['files']['astrid-7.2.dist-info/METADATA']
    finder=gate.MappedImports(body['mapping'],trusted_local=True,distribution_metadata=body['distribution_metadata'])
    candidate=list(finder.find_distributions(gate.importlib.metadata.DistributionFinder.Context(name='astrid')))[0]
    assert candidate.version=='7.2'


@pytest.mark.parametrize("edge", ["valid", "unmapped-parser", "tampered-metadata"])
def test_cold_launch_binds_metadata_after_exact_importer_without_parser_preload(tmp_path, edge):
    # A fresh isolated interpreter exercises lazy stdlib imports; pytest's
    # already imported email modules cannot make this fixture pass.
    root, metadata, rows = _metadata_binding(tmp_path)
    files = {
        "astrid/__init__.py": "from importlib.metadata import version\n__version__=version('astrid')\n",
        "astrid/core/__init__.py": "",
        "astrid/core/execution/__init__.py": "",
        "astrid/core/execution/generic_host.py":
            "import sys\n"
            "from astrid.core.execution import generic_host as retained_host\n"
            "assert retained_host is sys.modules['__main__'], 'Host executed twice'\n"
            "assert retained_host._RETAINED_SELECTED_PYTHON is _RETAINED_SELECTED_PYTHON\n"
            "import astrid, email.parser, email.feedparser, email.policy\n"
            "from importlib.metadata import distribution\n"
            "assert distribution('astrid').read_text('top_level.txt')=='astrid\\n'\n"
            "print('COLD_MAPPED_METADATA:'+astrid.__version__)\n",
    }
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    (root / 'unexecuted.pth').write_text('import sys; sys.exit("PTH EXECUTED")\n')
    ambient = tmp_path / 'ambient-cwd'
    ambient.mkdir()
    (ambient / 'email.py').write_text('raise RuntimeError("ambient shadow")\n')
    (ambient / 'sitecustomize.py').write_text('raise RuntimeError("ambient startup")\n')
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    inventories = [gate.installed_inventory(root), gate.installed_inventory(stdlib, python_role='python-stdlib', selected_source=root)]
    pins = {gate.raw_digest(i): i for i in inventories}
    import_roots = [{"path": i["root"], "inventory_digest": gate.raw_digest(i)} for i in inventories]
    mapping = gate._mapping(import_roots, pins, inventories[1], trusted_local=True)
    if edge == "unmapped-parser":
        del mapping["email.parser"]
    if edge == "tampered-metadata":
        (metadata / "METADATA").write_text("Name: astrid\nVersion: forged\n")
    payload = {"schema_version": 1, "mode": gate.TRUSTED_LOCAL_MODE,
               "module": gate.HOST_MODULE, "mapping": mapping,
               "distribution_metadata": rows, "host_argv": [],
               "selected_python": gate.selected_python_layout(root)}
    manifest = tmp_path / "cold-binding.json"
    manifest.write_text(json.dumps(payload))
    program = """
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('cold_gate',sys.argv[1])
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
assert 'email.parser' not in sys.modules, 'parser unexpectedly preloaded'
with open(sys.argv[2]) as stream: payload=json.load(stream)
gate.launch_from_binding(payload)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", program, gate.__file__, str(manifest)],
                            cwd=ambient, env={**os.environ, 'PYTHONPATH':str(ambient),
                                'PYTHONUSERBASE':str(ambient), 'PYTHONSTARTUP':str(ambient/'sitecustomize.py')},
                            capture_output=True, text=True, timeout=30)
    if edge == "valid":
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "COLD_MAPPED_METADATA:7.2"
    else:
        assert result.returncode != 0
        assert "COLD_MAPPED_METADATA:" not in result.stdout
        if edge == "unmapped-parser":
            assert "outside the reviewed import mapping: email.parser" in result.stderr
        else:
            assert "HostLaunchError: import source differs from its reviewed pin" in result.stderr


def fixture_authority(tmp_path):
    source = tmp_path / 'source'; runtime = tmp_path / 'runtime'
    source_files = {
        'astrid/__init__.py': '', 'astrid/version.py': '__version__="fake"\n',
        'astrid/__main__.py': '', 'astrid/runtime_cli.py': '', 'astrid/omp_agent.py': '',
        'astrid/core/__init__.py': '', 'astrid/core/execution/__init__.py': '',
        'astrid/core/execution/generic_host.py': 'ANSWER=7\n',
        'astrid/sdk/__init__.py': '', 'banodoco_workspace_client/__init__.py': '',
    }
    for relative, content in source_files.items():
        path=source/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
    python=runtime/'bin/python';python.parent.mkdir(parents=True);python.write_bytes(b'FAKE NOT EXECUTABLE PYTHON')
    launcher=tmp_path/'fake-loader.py';launcher.write_text('# Fake standalone artifact; never launched\n')
    def inventory(root):
        return {'root':str(root),'files':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}}
    invs=[inventory(source),inventory(runtime)];pins={gate.raw_digest(i):i for i in invs}
    closure=gate.source_checkout_closure(source)
    protocol={'version':gate.CURRENT_ROLES_VERSION,'module':gate.HOST_MODULE,'source_closure_digest':closure['digest']}
    profile={'profile_id':'fake-profile','profile_digest':'sha256:'+'1'*64,'release_digest':'sha256:'+'2'*64,'host_executable':str(python),'host_artifact_digest':'sha256:'+hashlib.sha256(python.read_bytes()).hexdigest(),'host_protocol':protocol}
    preparation={'profile':profile,'operation_id':'op','channel_id':'channel','owner_epoch':'epoch','custody_scope':str(tmp_path/'custody')}
    config={'source_checkout':str(source),'support_root':str(tmp_path/'support')}
    argv=[str(python),'-m',gate.HOST_MODULE,'run'];env={'PATH':'/fake/bin'}
    record={'selected_profile_digest':gate.raw_digest(profile),'profile_digest':profile['profile_digest'],'release_digest':profile['release_digest'],'host_protocol':protocol,'source_checkout':str(source),'source_components':closure['components'],'inventories':pins,
        'import_binding':{'schema_version':1,'mode':gate.MODE,'launcher':{'path':str(launcher),'sha256':hashlib.sha256(launcher.read_bytes()).hexdigest()},'python_runtime_inventory_digest':gate.raw_digest(invs[1]),'import_roots':[{'path':i['root'],'inventory_digest':gate.raw_digest(i)} for i in invs]}}
    # Explicit fake protection: it observes files only, not an installed immutable
    # boundary. Nothing in these tests qualifies production materialization.
    class FakeProtection:
        broken=False
        def verify(self):
            if self.broken: raise gate.HostLaunchError('fake protection lost')
    lease=FakeProtection()
    verifier=gate.HostLaunchVerifier(authority_resolver=lambda selected:copy.deepcopy(record),protected_materialization=lambda reviewed:lease)
    args={'preparation':preparation,'config':config,'host_argv':argv,'environment':env}
    return SimpleNamespace(source=source,runtime=runtime,launcher=launcher,record=record,args=args,verifier=verifier,lease=lease)


def test_private_retained_result_selects_exact_isolated_launch_once(tmp_path):
    f=fixture_authority(tmp_path);proof=f.verifier.verify(**f.args)
    argv,payload=f.verifier.claim(proof,**f.args,binding_fd=31)
    assert argv==[f.args['host_argv'][0],'-I','-S',str(f.launcher),'--binding-fd','31']
    body=json.loads(payload);assert body['host_argv'][-2:]==['--source-closure-digest',f.record['host_protocol']['source_closure_digest']]
    assert body['mapping'][gate.HOST_MODULE]['path']==str(f.source/'astrid/core/execution/generic_host.py')
    assert body['mapping']['astrid.core.execution']['package']
    with pytest.raises(TypeError):pickle.dumps(proof)
    with pytest.raises(gate.HostLaunchError): f.verifier.claim(proof,**f.args,binding_fd=31)
    child=SimpleNamespace(pid=41);identity={'pid':41,'uid':501,'birth_id':'fake-birth'}
    assert f.verifier.bind_child(proof,child=child,identity=identity)==gate.CURRENT_ROLES_VERSION
    f.verifier.verify_child(proof,child=child,identity=identity)
    with pytest.raises(gate.HostLaunchError):f.verifier.verify_child(proof,child=SimpleNamespace(pid=41),identity=identity)
    with pytest.raises(gate.HostLaunchError):f.verifier.bind_child(proof,child=child,identity=identity)


def test_no_default_authority_or_manifest_self_authentication(tmp_path):
    f=fixture_authority(tmp_path)
    with pytest.raises(gate.HostLaunchError,match='no independently reviewed'):gate.HostLaunchVerifier().verify(**f.args)
    with pytest.raises(gate.HostLaunchError,match='protection'):gate.HostLaunchVerifier(authority_resolver=lambda _:f.record,protected_materialization=lambda _:True).verify(**f.args)
    with pytest.raises(gate.HostLaunchError):f.verifier.claim(json.loads(gate.canonical(f.record)),**f.args,binding_fd=1)
    proof=f.verifier.verify(**f.args)
    other=gate.HostLaunchVerifier(authority_resolver=lambda _:f.record,protected_materialization=lambda _:f.lease)
    with pytest.raises(gate.HostLaunchError):other.claim(proof,**f.args,binding_fd=1)


@pytest.mark.parametrize('key,value',[('version',2),('version','v1'),('module','shadow.host'),('source_closure_digest','sha256:'+'a'*64),('source_closure_digest','A'*64),('source_closure_digest',None)])
def test_exact_protocol_fields(tmp_path,key,value):
    f=fixture_authority(tmp_path);p=copy.deepcopy(f.record['host_protocol']);p[key]=value
    with pytest.raises(gate.HostLaunchError):gate.validate_host_protocol(p)


@pytest.mark.parametrize('value',[None,{}, {'version':gate.CURRENT_ROLES_VERSION}, {'version':gate.CURRENT_ROLES_VERSION,'module':gate.HOST_MODULE,'source_closure_digest':'a'*64,'approved':True}])
def test_protocol_partial_unknown_or_null(value):
    with pytest.raises(gate.HostLaunchError):gate.validate_host_protocol(value)


@pytest.mark.parametrize('edge',['profile','release','component','closure','inventory','interpreter','module','protection','launcher'])
def test_failed_authority_materialization_edges_never_issue(tmp_path,edge):
    f=fixture_authority(tmp_path)
    if edge=='profile':f.record['selected_profile_digest']='a'*64
    if edge=='release':f.record['release_digest']='sha256:'+'3'*64
    if edge=='component':f.record['source_components'][0]['sha256']='a'*64
    if edge=='closure':f.args['preparation']['profile']['host_protocol']['source_closure_digest']='a'*64
    if edge=='inventory':next(iter(f.record['inventories'].values()))['files']['astrid/version.py']='a'*64
    if edge=='interpreter':f.args['preparation']['profile']['host_artifact_digest']='sha256:'+'a'*64
    if edge=='module':f.args['host_argv'][2]='shadow.host'
    if edge=='protection':f.lease.broken=True
    if edge=='launcher':f.launcher.write_text('changed')
    with pytest.raises(gate.HostLaunchError):f.verifier.verify(**f.args)
    assert f.verifier._issued=={}


@pytest.mark.parametrize('override',['PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','LD_PRELOAD','DYLD_INSERT_LIBRARIES'])
def test_ambient_environment_cannot_enable_or_shadow(tmp_path,override):
    f=fixture_authority(tmp_path);f.args['environment'][override]='/shadow'
    with pytest.raises(gate.HostLaunchError,match='environment'):f.verifier.verify(**f.args)


@pytest.mark.parametrize('edge',['owner_epoch','channel','operation','argv','cwd','environment'])
def test_changed_launch_or_session_permanently_consumes_proof(tmp_path,edge):
    f=fixture_authority(tmp_path);proof=f.verifier.verify(**f.args);bad=copy.deepcopy(f.args)
    if edge=='owner_epoch':bad['preparation']['owner_epoch']='other'
    if edge=='channel':bad['preparation']['channel_id']='other'
    if edge=='operation':bad['preparation']['operation_id']='other'
    if edge=='argv':bad['host_argv'].append('--other')
    if edge=='cwd':bad['config']['support_root']='/other'
    if edge=='environment':bad['environment']['PATH']='/other'
    with pytest.raises(gate.HostLaunchError):f.verifier.claim(proof,**bad,binding_fd=4)
    with pytest.raises(gate.HostLaunchError):f.verifier.claim(proof,**f.args,binding_fd=4)
    with pytest.raises(gate.HostLaunchError):f.verifier.bind_child(proof,child=SimpleNamespace(pid=3),identity={'pid':3,'birth_id':'fake'})


def test_failed_child_binding_and_lost_protection_are_fenced(tmp_path):
    f=fixture_authority(tmp_path);proof=f.verifier.verify(**f.args);f.verifier.claim(proof,**f.args,binding_fd=4)
    child=SimpleNamespace(pid=41)
    with pytest.raises(gate.HostLaunchError):f.verifier.bind_child(proof,child=child,identity={'pid':42,'birth_id':'fake'})
    with pytest.raises(gate.HostLaunchError):f.verifier.bind_child(proof,child=child,identity={'pid':41,'birth_id':'fake'})
    f=fixture_authority(tmp_path/'second');proof=f.verifier.verify(**f.args);f.verifier.claim(proof,**f.args,binding_fd=4)
    identity={'pid':41,'birth_id':'fake'};f.verifier.bind_child(proof,child=child,identity=identity)
    f.lease.broken=True
    with pytest.raises(gate.HostLaunchError):f.verifier.verify_child(proof,child=child,identity=identity)
    f.lease.broken=False
    with pytest.raises(gate.HostLaunchError):f.verifier.verify_child(proof,child=child,identity=identity)


@pytest.mark.parametrize('relative',['astrid/core/execution/__init__.py','astrid/version.py'])
def test_package_initializer_or_source_substitution_fails(tmp_path,relative):
    f=fixture_authority(tmp_path);(f.source/relative).write_text('changed')
    with pytest.raises(gate.HostLaunchError):f.verifier.verify(**f.args)


@pytest.mark.parametrize('extra',['shadow.py','cache.pyc','unreviewed.pth'])
def test_unexpected_importable_or_bytecode_rejected(tmp_path,extra):
    f=fixture_authority(tmp_path);(f.source/extra).write_text('unexpected')
    with pytest.raises(gate.HostLaunchError):f.verifier.verify(**f.args)


def test_symlink_and_missing_component_fail_closed(tmp_path):
    f=fixture_authority(tmp_path);p=f.source/'astrid/version.py';p.unlink();p.symlink_to(f.source/'astrid/runtime_cli.py')
    with pytest.raises(gate.HostLaunchError):f.verifier.verify(**f.args)
    p.unlink()
    with pytest.raises(gate.HostLaunchError):gate.source_checkout_closure(f.source)


def test_source_loader_executes_verified_bytes_without_reopening_or_pyc(tmp_path,monkeypatch):
    f=fixture_authority(tmp_path);proof=f.verifier.verify(**f.args);_,payload=f.verifier.claim(proof,**f.args,binding_fd=4)
    item=json.loads(payload)['mapping'][gate.HOST_MODULE];path=Path(item['path'])
    original=gate.read_source
    def replace_after_read(path,pin):
        data=original(path,pin);path.write_text('ANSWER=99\n');return data
    monkeypatch.setattr(gate,'read_source',replace_after_read)
    module=ModuleType('fake_host');gate._SourceLoader(item).exec_module(module)
    assert module.ANSWER==7 and module.__cached__ is None
    assert not list(path.parent.glob('__pycache__/*'))
    with pytest.raises(gate.HostLaunchError):gate._SourceLoader(item).exec_module(ModuleType('changed'))


def test_mapping_ignores_cwd_site_editable_and_alternate_loaders(tmp_path):
    f=fixture_authority(tmp_path);proof=f.verifier.verify(**f.args);_,payload=f.verifier.claim(proof,**f.args,binding_fd=4)
    finder=gate.MappedImports(json.loads(payload)['mapping'])
    spec=finder.find_spec('astrid.core.execution.generic_host',path=['/cwd/shadow','/site-packages'])
    assert spec.origin==str(f.source/'astrid/core/execution/generic_host.py')
    with pytest.raises(ModuleNotFoundError):finder.find_spec('editable_fake')
    with pytest.raises(ModuleNotFoundError):finder.find_spec('namespace_fake')
    assert finder.find_spec('sys').origin=='built-in'


def test_native_extensions_require_protected_runtime_inventory(tmp_path):
    f=fixture_authority(tmp_path);source_inv=next(i for i in f.record['inventories'].values() if i['root']==str(f.source))
    suffix=gate.importlib.machinery.EXTENSION_SUFFIXES[0];p=f.source/('fake'+suffix);p.write_bytes(b'NOT EXECUTABLE')
    source_inv['files'][p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
    old=next(k for k,v in f.record['inventories'].items() if v is source_inv);new=gate.raw_digest(source_inv)
    f.record['inventories'][new]=f.record['inventories'].pop(old);f.record['import_binding']['import_roots'][0]['inventory_digest']=new
    with pytest.raises(gate.HostLaunchError,match='native dependency'):f.verifier.verify(**f.args)


def test_nine_component_measurement_parity_without_importing_astrid(tmp_path):
    f=fixture_authority(tmp_path)
    source=Path(os.environ.get('HOST_LAUNCH_TEST_ASTRID_SOURCE', Path(__file__).resolve().parents[2]/'Astrid--integration'))
    host=source/'astrid/core/execution/generic_host.py'
    tree=ast.parse(host.read_bytes());names={'_canonical_digest','_source_digest','source_checkout_closure'}
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    # Only measurement functions, not any host package/module import or startup.
    module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),*nodes],type_ignores=[])
    ns={'Path':Path,'hashlib':hashlib,'json':json};exec(compile(ast.fix_missing_locations(module),str(host),'exec'),ns)
    assert gate.source_checkout_closure(f.source)==ns['source_checkout_closure'](f.source)


def test_wrong_kernel_interpreter_pin_and_namespace_mapping_fail(tmp_path):
    f=fixture_authority(tmp_path)
    f.args['preparation']['profile'].update(host_os_executable=str(f.runtime/'bin/python'),host_os_artifact_digest='sha256:'+'0'*64)
    f.record['selected_profile_digest']=gate.raw_digest(f.args['preparation']['profile'])
    with pytest.raises(gate.HostLaunchError,match='kernel interpreter pin'):f.verifier.verify(**f.args)
    f=fixture_authority(tmp_path/'second')
    source=next(v for v in f.record['inventories'].values() if v['root']==str(f.source))
    (f.source/'namespace').mkdir();(f.source/'namespace/child.py').write_text('')
    source['files']['namespace/child.py']=hashlib.sha256(b'').hexdigest()
    old=next(k for k,v in f.record['inventories'].items() if v is source);new=gate.raw_digest(source)
    f.record['inventories'][new]=f.record['inventories'].pop(old);f.record['import_binding']['import_roots'][0]['inventory_digest']=new
    with pytest.raises(gate.HostLaunchError,match='namespace'):f.verifier.verify(**f.args)


def test_duplicate_import_roots_and_declared_bytecode_are_unsupported(tmp_path):
    f=fixture_authority(tmp_path);f.record['import_binding']['import_roots'].append(dict(f.record['import_binding']['import_roots'][0]))
    with pytest.raises(gate.HostLaunchError,match='duplicate'):f.verifier.verify(**f.args)
    f=fixture_authority(tmp_path/'second');inv=next(v for v in f.record['inventories'].values() if v['root']==str(f.source))
    path=f.source/'module.pyc';path.write_bytes(b'fake');inv['files']['module.pyc']=hashlib.sha256(b'fake').hexdigest()
    old=next(k for k,v in f.record['inventories'].items() if v is inv);new=gate.raw_digest(inv)
    f.record['inventories'][new]=f.record['inventories'].pop(old);f.record['import_binding']['import_roots'][0]['inventory_digest']=new
    with pytest.raises(gate.HostLaunchError,match='representation'):f.verifier.verify(**f.args)


def local_fixture(tmp_path):
    f = fixture_authority(tmp_path)
    f.record['import_binding']['mode'] = gate.TRUSTED_LOCAL_MODE
    f.verifier = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    return f


@pytest.mark.parametrize('reader', [gate.read_source, gate._local_read])
def test_selected_import_file_keeps_64_mib_bound_before_read(tmp_path, monkeypatch, reader):
    oversized = tmp_path / 'selected.py'
    with oversized.open('wb') as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    assert gate.LIMIT == 67_108_864
    def unexpected_read(*args):
        pytest.fail('oversized selected file must be refused before reading bytes')
    monkeypatch.setattr(gate.os, 'read', unexpected_read)
    with pytest.raises(gate.HostLaunchError, match='bounded regular file'):
        reader(oversized, '0' * 64)


def test_trusted_local_selected_file_replacement_refuses_retained_pin(tmp_path):
    selected = tmp_path / 'selected.py'
    selected.write_bytes(b'VALUE=1\n')
    inventory = gate.installed_inventory(tmp_path)
    replacement = tmp_path / 'replacement'
    replacement.write_bytes(b'VALUE=2\n')
    replacement.replace(selected)
    with pytest.raises(gate.HostLaunchError, match='differs from its reviewed pin'):
        gate._local_inventory(inventory)


def test_trusted_local_explicit_constructor_keeps_default_closed_and_record_private(tmp_path):
    f = local_fixture(tmp_path)
    # Mutating the caller's record cannot replace the retained selected release.
    f.record['source_components'][0]['sha256'] = '0' * 64
    proof = f.verifier.verify(**f.args)
    argv, data = f.verifier.claim(proof, **f.args, binding_fd=9)
    assert argv[1:3] == ['-I', '-S']
    assert json.loads(data)['mode'] == gate.TRUSTED_LOCAL_MODE
    with pytest.raises(gate.HostLaunchError): gate.HostLaunchVerifier().verify(**f.args)
    with pytest.raises(TypeError): pickle.dumps(proof)
    with pytest.raises(gate.HostLaunchError): f.verifier.claim(proof, **f.args, binding_fd=9)
    child = SimpleNamespace(pid=41); identity = {'pid':41, 'birth_id':'observed-local-child'}
    assert f.verifier.bind_child(proof, child=child, identity=identity) == gate.CURRENT_ROLES_VERSION
    f.verifier.verify_child(proof, child=child, identity=identity)
    with pytest.raises(gate.HostLaunchError):
        f.verifier.verify_child(proof, child=SimpleNamespace(pid=41), identity=identity)


@pytest.mark.parametrize('edge', ['profile', 'release', 'component', 'inventory', 'launcher', 'source', 'interpreter', 'environment'])
def test_trusted_local_mismatch_before_claim_and_spawn(tmp_path, edge):
    f = local_fixture(tmp_path)
    if edge == 'profile': f.args['preparation']['profile']['profile_id'] = 'foreign'
    if edge == 'release': f.args['preparation']['profile']['release_digest'] = 'sha256:' + '0'*64
    if edge == 'component': (f.source/'astrid/version.py').write_text('changed')
    if edge == 'inventory': (f.source/'unexpected.py').write_text('changed')
    if edge == 'launcher': f.launcher.write_text('changed')
    if edge == 'source': (f.source/'astrid/core/execution/generic_host.py').write_text('changed')
    if edge == 'interpreter': (f.runtime/'bin/python').write_bytes(b'changed')
    if edge == 'environment': f.args['environment']['PYTHONPATH'] = '/task-override'
    with pytest.raises(gate.HostLaunchError): f.verifier.verify(**f.args)
    assert not f.verifier._issued


def test_trusted_local_measures_installed_bytecode_ignores_it_and_maps_native_dependency(tmp_path):
    f = fixture_authority(tmp_path)
    site = tmp_path/'site'; site.mkdir()
    suffix = gate.importlib.machinery.EXTENSION_SUFFIXES[0]
    (site/('fake_native'+suffix)).write_bytes(b'FAKE NOT LOADED')
    (site/'namespace').mkdir(); (site/'namespace/child.py').write_text('ANSWER=1')
    (site/'__pycache__').mkdir(); (site/'__pycache__/ignored.pyc').write_bytes(b'NOT LOADED')
    inv = gate.installed_inventory(site); pin = gate.raw_digest(inv)
    assert list(inv['files']) == ['fake_native'+suffix, 'namespace/child.py']
    f.record['inventories'][pin] = inv
    f.record['import_binding']['import_roots'].append({'path':str(site), 'inventory_digest':pin})
    f.record['import_binding']['mode'] = gate.TRUSTED_LOCAL_MODE
    local = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof = local.verify(**f.args); _, data = local.claim(proof, **f.args, binding_fd=8)
    mapping = json.loads(data)['mapping']
    assert mapping['fake_native']['kind'] == 'extension'
    assert mapping['namespace']['kind'] == 'namespace'
    finder = gate.MappedImports(mapping, trusted_local=True)
    assert finder.find_spec('namespace').submodule_search_locations == [str(site/'namespace')]
    with pytest.raises(ModuleNotFoundError): finder.find_spec('unrecorded_module')
    f.record['import_binding']['mode'] = gate.MODE
    strong = gate.HostLaunchVerifier(authority_resolver=lambda _:f.record, protected_materialization=lambda _:f.lease)
    with pytest.raises(gate.HostLaunchError): strong.verify(**f.args)


def test_trusted_local_recorded_python_alias_does_not_claim_tamper_protection(tmp_path):
    f = fixture_authority(tmp_path)
    alias = tmp_path/'venv-python'; alias.symlink_to(f.runtime/'bin/python')
    f.args['preparation']['profile']['host_executable'] = str(alias)
    f.args['host_argv'][0] = str(alias)
    f.record['selected_profile_digest'] = gate.raw_digest(f.args['preparation']['profile'])
    f.record['import_binding']['mode'] = gate.TRUSTED_LOCAL_MODE
    local = gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof = local.verify(**f.args); local.claim(proof, **f.args, binding_fd=8)
    # Observed changes fail; this does not assert that an attacker cannot race
    # an observation, startup or native extension loader between these checks.
    alias.unlink(); alias.write_bytes(b'other interpreter')
    with pytest.raises(gate.HostLaunchError):
        local.bind_child(proof, child=SimpleNamespace(pid=4), identity={'pid':4,'birth_id':'real-retained-fake'})
    with pytest.raises(gate.HostLaunchError):
        local.bind_child(proof, child=SimpleNamespace(pid=4), identity={'pid':4,'birth_id':'real-retained-fake'})


def test_trusted_local_verified_source_bytes_and_recorded_namespace_only(tmp_path, monkeypatch):
    f=local_fixture(tmp_path); proof=f.verifier.verify(**f.args)
    _, data=f.verifier.claim(proof, **f.args, binding_fd=3)
    item=json.loads(data)['mapping'][gate.HOST_MODULE]
    original=gate._local_read
    def replace_after_read(path, pin):
        data=original(path, pin); Path(path).write_text('ANSWER=99'); return data
    monkeypatch.setattr(gate, '_local_read', replace_after_read)
    module=ModuleType('fake_host'); gate._SourceLoader(item, trusted_local=True).exec_module(module)
    assert module.ANSWER == 7 and module.__cached__ is None


def test_trusted_local_alias_targets_are_retained_without_directory_import_discovery(tmp_path):
    root=tmp_path/'installed';root.mkdir();target=tmp_path/'ambient';target.mkdir()
    (target/'shadow.py').write_text('NOT_SELECTED=1')
    (root/'selected.py').write_text('SELECTED=1')
    (root/'site-packages').symlink_to(target,target_is_directory=True)
    inv=gate.installed_inventory(root)
    assert inv['aliases']['site-packages']=={'target':str(target),'kind':'directory'}
    assert 'site-packages/shadow.py' not in inv['files']
    assert gate._local_inventory(inv)==inv
    other=tmp_path/'other';other.mkdir();(root/'site-packages').unlink();(root/'site-packages').symlink_to(other,target_is_directory=True)
    with pytest.raises(gate.HostLaunchError,match='unexpected'):
        gate._local_inventory(inv)


@pytest.mark.parametrize('namespace', ['astrid', 'banodoco_workspace_client', 'runtime_protocol', 'banodoco_local'])
def test_trusted_local_namespace_cannot_fall_back_to_stale_installed_astrid(tmp_path, namespace):
    f=fixture_authority(tmp_path);site=tmp_path/'site';(site/namespace/'core').mkdir(parents=True)
    (site/namespace/'__init__.py').write_text('STALE=1')
    (site/namespace/'core/extra.py').write_text('STALE=1')
    inv=gate.installed_inventory(site);pin=gate.raw_digest(inv)
    f.record['inventories'][pin]=inv;f.record['import_binding']['mode']=gate.TRUSTED_LOCAL_MODE
    f.record['import_binding']['import_roots'].append({'path':str(site),'inventory_digest':pin})
    local=gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof=local.verify(**f.args);_,data=local.claim(proof,**f.args,binding_fd=3)
    mapping=json.loads(data)['mapping']
    assert mapping['astrid']['path']==str(f.source/'astrid/__init__.py')
    assert namespace+'.core.extra' not in mapping


def test_trusted_local_standard_resources_use_selected_package_only(tmp_path):
    import importlib.resources
    f=fixture_authority(tmp_path)
    data=f.source/'astrid/selected.json'; data.write_text('{"selected":true}')
    root=f.record['import_binding']['import_roots'][0]
    inv=gate.installed_inventory(f.source); pin=gate.raw_digest(inv)
    f.record['inventories'].pop(root['inventory_digest']); f.record['inventories'][pin]=inv
    root['inventory_digest']=pin; f.record['import_binding']['mode']=gate.TRUSTED_LOCAL_MODE
    local=gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof=local.verify(**f.args); _,payload=local.claim(proof,**f.args,binding_fd=8)
    mapping=json.loads(payload)['mapping']; spec=gate.MappedImports(mapping,trusted_local=True).find_spec('astrid')
    package=ModuleType('astrid'); package.__spec__=spec
    resources=importlib.resources.files(package)
    assert resources==f.source/'astrid'
    assert json.loads(resources.joinpath('selected.json').read_text())=={'selected':True}
    # Exact installed data remains part of the existing before-issue check.
    data.write_text('{"changed":true}')
    with pytest.raises(gate.HostLaunchError):local.verify(**f.args)


def test_resource_reader_keeps_strict_and_nonpackage_behavior_closed(tmp_path):
    p=tmp_path/'module.py'; p.write_text('')
    item={'path':str(p),'sha256':hashlib.sha256(b'').hexdigest(),'package':True,'kind':'source'}
    assert gate._SourceLoader(item).get_resource_reader('fake') is None
    assert gate._SourceLoader({**item,'package':False},trusted_local=True).get_resource_reader('fake') is None


def test_host_only_trusted_local_variant_still_requires_owner_record_and_original_child(tmp_path, monkeypatch):
    from test_selected_python_inventory import selected_case
    f=selected_case(tmp_path, monkeypatch)
    verifier=gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    proof=verifier.verify(**f.args)
    argv,payload=verifier.claim(proof,**f.args,binding_fd=31)
    assert isinstance(payload,bytes) and gate.canonical(json.loads(payload))==payload
    child=SimpleNamespace(pid=42);identity={'pid':42,'uid':501,'birth_id':'original'}
    verifier.bind_child(proof,child=child,identity=identity)
    verifier.verify_child(proof,child=child,identity=identity)
    with pytest.raises(gate.HostLaunchError):
        verifier.verify_child(proof,child=SimpleNamespace(pid=42),identity=identity)


def host_only_environment_fixture(tmp_path):
    f=fixture_authority(tmp_path)
    profile=f.args['preparation']['profile']
    profile.update(execution_mode='host_only_cpu',support_root=f.args['config']['support_root'],realm_root=str(tmp_path/'realm'))
    f.args['environment'].update(ASTRID_OUTPUT_ROOT=str(tmp_path/'support/host-output'),BANODOCO_LOCAL_DATA_ROOT=str(tmp_path/'realm'))
    f.record['selected_profile_digest']=gate.raw_digest(profile)
    f.record['import_binding']['mode']=gate.TRUSTED_LOCAL_MODE
    f.verifier=gate.TrustedLocalHostLaunchVerifier(installed_release=f.record)
    return f


@pytest.mark.parametrize('edge',['output','realm','missing','config','PYTHONPATH','PYTHONDONTWRITEBYTECODE','BANODOCO_RUNTIME_OWNER_TOKEN'])
def test_host_only_environment_rejects_unadmitted_roots_and_ambient_before_inventory(tmp_path,monkeypatch,edge):
    f=host_only_environment_fixture(tmp_path)
    if edge=='output': f.args['environment']['ASTRID_OUTPUT_ROOT']=str(tmp_path/'other')
    elif edge=='realm': f.args['environment']['BANODOCO_LOCAL_DATA_ROOT']=str(tmp_path/'other')
    elif edge=='missing': del f.args['environment']['ASTRID_OUTPUT_ROOT']
    elif edge=='config': f.args['config']['support_root']=str(tmp_path/'other')
    else: f.args['environment'][edge]='/ambient'
    observed=[]
    monkeypatch.setattr(f.verifier,'_inventory',lambda value:observed.append(value))
    with pytest.raises(gate.HostLaunchError,match='environment'):
        f.verifier.verify(**f.args)
    assert observed==[]


def test_strict_provider_does_not_admit_host_only_product_roots(tmp_path,monkeypatch):
    f=host_only_environment_fixture(tmp_path)
    f.record['import_binding']['mode']=gate.MODE
    verifier=gate.HostLaunchVerifier(authority_resolver=lambda _:copy.deepcopy(f.record),protected_materialization=lambda _:f.lease)
    observed=[]
    monkeypatch.setattr(verifier,'_inventory',lambda value:observed.append(value))
    with pytest.raises(gate.HostLaunchError,match='environment'):
        verifier.verify(**f.args)
    assert observed==[]


def test_host_only_environment_validates_selected_release_before_accepting_roots(tmp_path,monkeypatch):
    f=host_only_environment_fixture(tmp_path)
    f.args['preparation']['profile']['release_digest']='sha256:'+'f'*64
    observed=[]
    monkeypatch.setattr(f.verifier,'_inventory',lambda value:observed.append(value))
    with pytest.raises(gate.HostLaunchError,match='release differs'):
        f.verifier.verify(**f.args)
    assert observed==[]
