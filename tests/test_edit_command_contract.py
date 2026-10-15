"""Synthetic command conformance; no timing engine, service or data-store access."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from generators import generate
from runtime_protocol.edit_command import OPCALL_SCHEMA, validate_edit_command, validate_edit_command_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'conformance/fixtures/edit-command-candidate.json').read_text())


def test_single_schema_projection_matches_source():
    assert OPCALL_SCHEMA == generate.opcall_schema()
    schema = json.loads((ROOT / 'contract/schemas/timeline-commit.json').read_text())
    assert schema['$defs']['CommitCommand']['$ref'] == OPCALL_SCHEMA['$id']
    assert 'EditCommand = TypedDict' in generate.commit_types('python')
    assert 'CommitCommand = EditCommand' in generate.commit_types('python')
    assert 'export type CommitCommand = EditCommand' in generate.commit_types('typescript')


@pytest.mark.parametrize('case', FIXTURE['command_cases'], ids=lambda c: c['id'])
def test_shared_command(case):
    value = copy.deepcopy(case['value'])
    before = copy.deepcopy(value)
    assert Draft202012Validator(OPCALL_SCHEMA).is_valid(value) == case['valid']
    if case['valid']:
        assert validate_edit_command(value) is value
        raw = case['raw'].encode('utf-8')
        assert hashlib.sha256(raw).hexdigest() == case['sha256']
        assert json.loads(raw) == value
        assert validate_edit_command_bytes(raw) is raw
    else:
        with pytest.raises(ValueError):
            validate_edit_command(value)
    assert value == before


def test_non_json_numbers_and_duplicate_fields_are_refused():
    value = {'op': 'clip.set', 'select': None, 'args': {'number': float('nan')}}
    with pytest.raises(ValueError):
        validate_edit_command(value)
    with pytest.raises(ValueError, match='duplicate'):
        validate_edit_command_bytes(b'{"op":"clip.set","op":"clip.clear","select":null,"args":{}}')


def test_absence_null_clear_and_opaque_values_remain_distinct():
    cases = {c['id']: c['value'] for c in FIXTURE['command_cases']}
    values = [cases[id] for id in ['CMD-ABSENT', 'CMD-CLEAR', 'CMD-NULL', 'CMD-OPAQUE']]
    assert len({json.dumps(validate_edit_command(v), sort_keys=True) for v in values}) == 4
    assert 'version' not in cases['CMD-ABSENT']
    assert cases['CMD-EXPLICIT-NULL-OUTPUT']['version'] is None
    assert validate_edit_command(cases['CMD-EXECUTED'])['resolved'] == ['c1.rocket']


@pytest.mark.parametrize('exchange', FIXTURE['exchanges'], ids=lambda c: c['id'])
def test_shared_request_result_schema(exchange):
    # Existing CommitExchange only: no new request envelope or acceptance behavior.
    from test_timeline_commit_contract import validator
    validator('CommitExchange').validate({'request': exchange['request'], 'result': exchange['result']})


def test_source_schema_mutation_changes_generated_consumers(tmp_path, monkeypatch):
    before = [generate.commit_types(lang) for lang in ['python', 'typescript']]
    schema = generate.opcall_schema()
    schema['required'].append('version')
    path = tmp_path / 'opcall.json'
    path.write_text(json.dumps(schema))
    monkeypatch.setattr(generate, 'OPCALL_SCHEMA', path)
    assert all(generate.commit_types(lang) != old for lang, old in zip(['python', 'typescript'], before))
