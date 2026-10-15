"""Candidate contract checks only: no service, live store, or observed App payloads."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import yaml

from generators import generate

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'contract/schemas/timeline-commit.json').read_text())
FIXTURE = json.loads((ROOT / 'conformance/fixtures/timeline-commit-candidate.json').read_text())
CASES = {case['id']: case for case in FIXTURE['cases']}
ROUTE = '/astrid/v1/projects/{project_id}/timelines/{timeline_id}/commit'


def validator(definition):
    opcall = generate.opcall_schema()
    registry = Registry().with_resource(opcall['$id'], Resource.from_contents(opcall))
    return Draft202012Validator({'$schema': SCHEMA['$schema'], '$defs': SCHEMA['$defs'], '$ref': '#/$defs/' + definition}, registry=registry)


def value(case):
    return copy.deepcopy(CASES[case]['value'])


def test_candidate_schema_and_case_identity():
    Draft202012Validator.check_schema(SCHEMA)
    assert len(CASES) == len(FIXTURE['cases']) == 93
    assert 'NOT observed App' in FIXTURE['provenance']
    assert 'CONTRACT-COMMAND' in SCHEMA['$defs']['CommitCommand']['description']


@pytest.mark.parametrize('case', FIXTURE['cases'], ids=lambda case: case['id'])
def test_fixture(case):
    errors = list(validator(case['definition']).iter_errors(case['value']))
    assert (not errors) == case['valid'], '\n'.join(str(error) for error in errors)


def test_openapi_adds_only_one_route_and_typed_http_results():
    current = yaml.safe_load((ROOT / 'contract/openapi/workspace-v1.yaml').read_text())
    before = yaml.safe_load(subprocess.check_output(['git', 'show', '7d5eed5a851933e6ad03262351d5e74523109009:contract/openapi/workspace-v1.yaml'], cwd=ROOT, text=True))
    assert set(current['paths']) - set(before['paths']) == {ROUTE}
    assert {key: val for key, val in current['paths'].items() if key != ROUTE} == before['paths']
    operation = current['paths'][ROUTE]['post']
    assert operation['operationId'] == 'commitTimeline'
    assert set(operation['responses']) == {'200', '400', '503'}
    assert operation['requestBody']['content']['application/json']['schema']['$ref'].endswith('/CommitRequest')
    for status, definition in [('200', 'CommitHttpSuccess'), ('400', 'CommitHttpBadRequest'), ('503', 'CommitHttpUnavailable')]:
        assert operation['responses'][status]['content']['application/json']['schema']['$ref'].endswith('/' + definition)
    # Every added component resolves to the existing Runtime schema home.
    for name in set(current['components']['schemas']) - set(before['components']['schemas']):
        ref = current['components']['schemas'][name]['$ref']
        path, fragment = ref.split('#')
        target = json.loads((ROOT / 'contract/openapi' / path).resolve().read_text())
        assert fragment.removeprefix('/$defs/') in target['$defs']
    assert set(SCHEMA['x-runtime-interface']) == set(current['x-astrid-runtime-acceptance']) - {'description'}
    assert current['security'] == before['security']


def test_absence_clear_null_opaque_fields_and_authored_units_remain_distinct():
    request = value('CC-REQ-COMMAND')
    cleared = request['change']['commands'][0]
    variants = []
    for replacement in [{}, {'params.caption': None}, {'params.caption': {'op': 'clear'}}]:
        candidate = copy.deepcopy(request)
        candidate['change']['commands'][0]['args'] = replacement
        validator('CommitRequest').validate(candidate)
        variants.append(json.dumps(candidate, sort_keys=True))
    assert len(set(variants)) == 3
    assert cleared['args']['intent.on'].endswith('+9f')
    assert cleared['resolved'] == ['occurrence:O1/clip:c08-app']
    document = value('CC-DOCUMENT-SHEET')
    before = copy.deepcopy(document)
    validator('CommitRequest').validate(document)
    assert document == before  # validation must never normalize/default/strip
    assert 'content' not in value('CC-SCOPE-CONTENT-OMITTED')['scope']
    assert SCHEMA['$defs']['CommitScope']['properties']['complete'].get('default') is None


def test_whole_request_hash_distinguishes_intended_change_and_exact_retry():
    # Specification calculation only; durable replay/CAS belongs to ACCEPT.
    def digest(request):
        return 'sha256:' + hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()
    request = value('CC-REQ-COMMAND')
    assert digest(request) == digest(json.loads(json.dumps(request)))
    identity = tuple(request[key] for key in ('project_id', 'timeline_id', 'request_id'))
    for path, replacement in [(['dry_run'], True), (['base_revision_id'], 'different-exact-base'), (['scope', 'complete'], ['clips']), (['change', 'commands', 0, 'args', 'intent.on'], '"viral" +10f')]:
        changed = copy.deepcopy(request)
        item = changed
        for key in path[:-1]:
            item = item[key]
        item[path[-1]] = replacement
        assert tuple(changed[key] for key in ('project_id', 'timeline_id', 'request_id')) == identity
        assert digest(changed) != digest(request)


def load_client():
    path = ROOT / 'packages/python/banodoco_workspace_client/generated.py'
    spec = importlib.util.spec_from_file_location('timeline_commit_client', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('http,case', [(200, 'CC-RESULT-PREVIEW'), (200, 'CC-RESULT-CONFLICT'), (400, 'CC-HTTP-400-REQUEST_ID_CONFLICT'), (503, 'CC-RESULT-UNAVAILABLE')])
def test_python_client_transports_exact_request_and_typed_result(http, case):
    module = load_client()
    response = value(case)
    calls = []
    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body)))
        return http, {}, json.dumps(response).encode()
    client = module.WorkspaceClient('http://unused', 'test-token', transport=transport)
    request = value('CC-REQ-DRY-RUN')
    request['project_id'] = 'p/with space'
    request['timeline_id'] = 't?#'
    original = copy.deepcopy(request)
    assert client.commit_timeline(request) == response
    assert client.commit_timeline(request) == response
    assert request == original
    assert calls[0][0:2] == calls[1][0:2]
    assert calls[0][3] == calls[1][3]  # exact semantic retry, no preview cache
    assert calls[0][2]['X-Request-ID'] != calls[1][2]['X-Request-ID']  # diagnostic attempt ids are not semantic identity
    for header in ('Idempotency-Key', 'X-Astrid-Session', 'Authorization'):
        assert calls[0][2][header] == calls[1][2][header]
    method, path, headers, body = calls[0]
    assert method == 'POST'
    assert path == ROUTE.replace('{project_id}', quote(request['project_id'], safe='')).replace('{timeline_id}', quote(request['timeline_id'], safe=''))
    assert headers['Idempotency-Key'] == body['request_id']
    assert headers['X-Astrid-Session'] == body['session_id']
    assert headers['Authorization'] == 'Bearer test-token'
    assert 'publisher' not in body
    assert body == request
    assert module.CommitScope.__required_keys__ >= {'target', 'complete', 'projection_version'}
    assert module.AcceptRequest.__required_keys__ >= {'expected_head_revision_id', 'result', 'evidence'}
    assert module.AcceptResponse.__required_keys__ >= {'outcome', 'stored_result', 'receipt'}
    assert module.CommitRequest.__optional_keys__ >= {'asserted_actor', 'label', 'reason'}


def test_generation_is_deterministic_and_schema_derived(tmp_path, monkeypatch):
    python = generate.render_python_client()
    typescript = generate.render_typescript_client()
    assert python == generate.render_python_client()
    assert typescript == generate.render_typescript_client()
    assert python == (ROOT / 'packages/python/banodoco_workspace_client/generated.py').read_text()
    assert typescript == (ROOT / 'packages/typescript/src/generated.ts').read_text()
    changed = copy.deepcopy(SCHEMA)
    changed['$defs']['CommitRequest']['properties']['probe'] = {'type': 'boolean'}
    path = tmp_path / 'changed-schema.json'
    path.write_text(json.dumps(changed))
    monkeypatch.setattr(generate, 'COMMIT_SCHEMA', path)
    assert generate.render_python_client() != python
    assert generate.render_typescript_client() != typescript


def test_generated_drift_detection_for_python_typescript_and_openapi(tmp_path, monkeypatch):
    check = [sys.executable, str(ROOT / 'generators/generate.py'), '--check']
    output = tmp_path / 'generated.py'
    output.write_text(generate.render_python_client().replace("'dry_run': 'bool'", "'dry_run': 'str'"))
    assert subprocess.run([*check, '--python-output', str(output)], capture_output=True).returncode != 0
    output = tmp_path / 'generated.ts'
    original = (ROOT / 'packages/typescript/src/generated.ts').read_text()
    output.write_text(original.replace('"dry_run": boolean', '"dry_run": string'))
    assert subprocess.run([*check, '--typescript-output', str(output)], capture_output=True).returncode != 0
    monkeypatch.setattr(generate, 'TYPESCRIPT_CLIENT_OUTPUT', output)
    assert generate.render_typescript_client() != output.read_text()
    # OpenAPI drift invalidates both languages' metadata and Python operation projection.
    contract_root = tmp_path / 'source'
    (contract_root / 'contract/openapi').mkdir(parents=True)
    source = (ROOT / 'contract/openapi/workspace-v1.yaml').read_text()
    (contract_root / 'contract/openapi/workspace-v1.yaml').write_text(source.replace('operationId: commitTimeline', 'operationId: changedCommitTimeline'))
    monkeypatch.setattr(generate, 'ROOT', contract_root)
    assert generate.operation_index() != list(load_client().OPERATIONS)
    with pytest.raises(SystemExit, match='route missing'):
        generate.commit_route()


def test_product_copy_check_rejects_drift(tmp_path):
    astrid = tmp_path / 'astrid/banodoco_workspace_client'
    app = tmp_path / 'app/src/integrations/runtime'
    astrid.mkdir(parents=True)
    app.mkdir(parents=True)
    for target, source in [(astrid / 'generated.py', 'packages/python/banodoco_workspace_client/generated.py'), (astrid / 'contract_metadata.py', 'packages/python/banodoco_workspace_client/contract_metadata.py'), (app / 'generated.ts', 'packages/typescript/src/generated.ts'), (app / 'generated-contract-metadata.ts', 'packages/typescript/src/contract-metadata.ts')]:
        target.write_bytes((ROOT / source).read_bytes())
    opcall = astrid.parents[0] / 'schemas/change-contract/opcall.schema.json'
    opcall.parent.mkdir(parents=True)
    opcall.write_bytes(generate.OPCALL_SCHEMA.read_bytes())
    check = [sys.executable, str(ROOT / 'generators/generate.py'), '--check', '--astrid-root', str(astrid.parents[0]), '--app-root', str(app.parents[2])]
    assert subprocess.run(check, capture_output=True).returncode == 0
    for path in [astrid / 'generated.py', app / 'generated.ts']:
        original = path.read_bytes()
        path.write_bytes(original + b'\n# drift\n')
        assert subprocess.run(check, capture_output=True).returncode != 0
        path.write_bytes(original)


@pytest.mark.parametrize('http,case', [(400, 'CC-HTTP-400-BAD_REQUEST'), (503, 'CC-RESULT-UNAVAILABLE')])
def test_python_real_http_error_path_returns_commit_result(monkeypatch, http, case):
    import io
    import urllib.error
    import urllib.request
    module = load_client()
    response = value(case)
    stream = io.BytesIO(json.dumps(response).encode())
    def urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, http, 'contract error', {}, stream)
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    assert module.WorkspaceClient('http://unused').commit_timeline(value('CC-REQ-COMMAND')) == response
    assert stream.closed
