"""Published canonical command schemas never lose existing definitions or operations."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from generators.command_schema_compatibility import compatibility_errors, legacy_022_compatibility_errors

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/published-command-schemas'


def baseline(name='runtime-0.2.3'):
    filename = name + '.json'
    source = json.loads((FIXTURES / 'sources.json').read_text())[filename]
    raw = (FIXTURES / filename).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == source['sha256'], source
    return json.loads(raw)


def test_current_canonical_schema_preserves_latest_ordinary_publication():
    assert compatibility_errors(baseline(), json.loads((ROOT / 'contract/schemas/edit-command.json').read_bytes())) == []


@pytest.mark.parametrize('name', ['runtime-0.2.2', 'runtime-0.2.3'])
def test_exact_unchanged_published_artifacts_pass(name):
    assert compatibility_errors(baseline(name), baseline(name)) == []


def test_withdrawn_exact_10c_schema_reports_every_lost_definition_and_operation():
    errors = compatibility_errors(baseline(), baseline('withdrawn-10c'))
    assert {e.split('/')[2].split(':')[0] for e in errors if ': missing definition' in e} == {
        'ClipSetArgs', 'ClipSplitArgs', 'ClipTrimArgs', 'DocumentPin', 'MediaSelection',
        'OccurrenceAddMediaArgs', 'OccurrenceSwapMediaArgs', 'TrackCreateArgs'}
    assert {e.split('/allOf/')[1].split(':')[0] for e in errors
            if ': missing supported operation' in e} == {
        'occurrence.add-media', 'occurrence.swap-media', 'placement.move', 'track.create',
        'clip.set', 'clip.trim', 'clip.split'}
    assert any('/properties/schema_source' in e for e in errors)
    assert any('/ScopedId/pattern' in e for e in errors)


@pytest.mark.parametrize(('definition', 'path', 'value'), [
    ('ClipMoveArgs', ('required',), ['on', 'new_required_argument']),
    ('Intent', ('properties', 'ownership', 'enum'), ['occurrence']),
    ('ClipAddArgs', ('properties', 'row', 'properties', 'hold', 'exclusiveMinimum'), 1),
    ('ID', ('minLength',), 2),
    ('ScopedId', ('pattern',), '^parent$'),
    ('ClipMoveArgs', ('properties', 'on', 'type'), 'integer'),
    ('ClipMoveArgs', ('properties', 'on', 'maximum'), 1),
    ('ID', ('pattern',), '^x$'),
    ('ClipAddArgs', ('properties', 'row', 'additionalProperties'), False),
    ('ID', ('unrecognizedValidationKeyword',), 1),
    ('AgentState', ('oneOf',), [{'type': 'null'}]),
])
def test_narrowing_or_unsupported_changes_fail(definition, path, value):
    current = baseline()
    node = current['$defs'][definition]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    assert compatibility_errors(baseline(), current)


@pytest.mark.parametrize('drop', ['definition', 'clip.delete', 'timeline.inverse',
                                'timeline.restore', 'property'])
def test_dropping_published_structure_fails(drop):
    current = baseline()
    if drop == 'definition':
        del current['$defs']['TrackSetArgs']
    elif drop != 'property':
        current['$defs']['EditCommand']['allOf'] = [
            c for c in current['$defs']['EditCommand']['allOf']
            if c['if']['properties']['op']['const'] != drop]
    else:
        del current['$defs']['ClipSetParamsArgs']['properties']['schema_source']
    assert compatibility_errors(baseline(), current)


@pytest.mark.parametrize('name', ['ScopedId', 'EntityRef', 'TargetKey', 'AnchorIdentity'])
def test_materialization_regex_requires_the_full_old_pattern_as_an_alternative(name):
    current = baseline()
    old = current['$defs'][name]['pattern']
    new = baseline('withdrawn-10c')['$defs'][name]['pattern']
    current['$defs'][name]['pattern'] = f'(?:{old})|(?:{new})'
    assert compatibility_errors(baseline(), current) == []
    current['$defs'][name]['pattern'] = baseline('withdrawn-10c')['$defs'][name]['pattern']
    assert compatibility_errors(baseline(), current)


def test_new_refs_and_union_require_a_structurally_retained_old_branch():
    current = baseline()
    current['$defs']['MoreMoveArgs'] = {'anyOf': [
        {'$ref': '#/$defs/ClipMoveArgs'}, {'type': 'object'}]}
    condition = next(c for c in current['$defs']['EditCommand']['allOf']
                     if c['if']['properties']['op']['const'] == 'clip.move')
    condition['then']['properties']['args'] = {'$ref': '#/$defs/MoreMoveArgs'}
    assert compatibility_errors(baseline(), current) == []
    current['$defs']['MoreMoveArgs']['anyOf'] = [{'type': 'object'}, {'type': 'null'}]
    assert compatibility_errors(baseline(), current)  # Retain the actual old branch.


def test_new_definitions_and_operations_are_allowed_but_not_new_constraints_on_old_operations():
    current = baseline()
    current['$defs']['NewArgs'] = {'type': 'object'}
    condition = copy.deepcopy(current['$defs']['EditCommand']['allOf'][0])
    condition['if']['properties']['op']['const'] = 'new.operation'
    condition['then']['properties']['args'] = {'$ref': '#/$defs/NewArgs'}
    current['$defs']['EditCommand']['allOf'].append(condition)
    assert compatibility_errors(baseline(), current) == []
    condition['if']['properties']['op']['const'] = 'clip.move'
    assert compatibility_errors(baseline(), current)  # Duplicate condition can narrow an old op.


def test_widening_required_enum_ranges_and_property_schemas_is_allowed():
    current = baseline()
    current['$defs']['ClipMoveArgs']['required'] = []
    current['$defs']['Intent']['properties']['ownership']['enum'].append('new-owner')
    current['$defs']['ClipMoveArgs']['properties']['on']['minimum'] = -1
    current['$defs']['ClipMoveArgs']['additionalProperties'] = True
    current['$defs']['ClipMoveArgs']['properties']['new_optional'] = {'type': 'string'}
    assert compatibility_errors(baseline(), current) == []


def test_union_cannot_hide_sibling_constraints_and_unknown_changes_require_review():
    current = baseline()
    current['$defs']['ID'] = {'anyOf': [baseline()['$defs']['ID'], {'type': 'null'}],
                             'maxLength': 1}
    assert compatibility_errors(baseline(), current)
    previous = baseline()
    previous['$defs']['ID']['unrecognizedValidationKeyword'] = 1
    assert compatibility_errors(previous, baseline())


def test_unknown_keyword_with_null_value_is_not_treated_as_absent():
    previous = baseline('runtime-0.2.2')
    current = copy.deepcopy(previous)
    current['$defs']['ID']['unrecognizedValidationKeyword'] = None
    assert compatibility_errors(previous, current)
    assert legacy_022_compatibility_errors(previous, current)


def test_equivalent_refs_pass_but_unproductive_ref_cycles_require_review():
    current = baseline()
    current['$defs']['Alias'] = copy.deepcopy(current['$defs']['ClipMoveArgs'])
    current['$defs']['ClipMoveArgs'] = {'$ref': '#/$defs/Alias'}
    assert compatibility_errors(baseline(), current) == []
    current['$defs']['Alias'] = {'$ref': '#/$defs/Alias'}
    assert compatibility_errors(baseline(), current)


@pytest.mark.parametrize('replacement', [True, {'type': 'object'}])
def test_widening_the_envelope_does_not_preserve_supported_operations(replacement):
    current = baseline()
    current['$defs']['EditCommand'] = replacement
    errors = compatibility_errors(baseline(), current)
    assert sum(': missing supported operation' in e for e in errors) == 14


def test_an_unconstrained_root_does_not_preserve_published_definitions():
    errors = compatibility_errors(baseline(), True)
    assert sum(': missing definition' in e for e in errors) == 35


@pytest.mark.parametrize(('name', 'digest'), [
    ('runtime-0.2.2', '460e61c70702f1f6bfa5cd033c8da859c913c3c8839f2a5b928df7691e08a388'),
    ('runtime-0.2.3', '472622c45fa6b5c7a425c949516a64a52d83192d3749e78a0f000decd088aee9'),
    ('withdrawn-10c', '10c1610b61ad151259149c97061493d9e36ae0a9220ba4983b45f22e8ac7e3b1'),
    ('runtime-0.2.10', '472622c45fa6b5c7a425c949516a64a52d83192d3749e78a0f000decd088aee9'),
    ('agent-0a0ac7ba', '30da4fde84c328e7cb44035b50eb53fd2cd9637a14a0c948f4412f6469ce34bd'),
    ('agent-26ef2bbb', 'a6f1aaa9dfcc31828bd04c908158fd7fd9a825df6c9f88f79b81779273a190ef'),
])
def test_frozen_fixture_digests(name, digest):
    assert hashlib.sha256((FIXTURES / (name + '.json')).read_bytes()).hexdigest() == digest
    baseline(name)  # Also verify the independently copied provenance metadata.


def test_actual_d13_guard_is_a_complete_ordinary_superset():
    # Agent 1441bdf1a4795aad318cf27e8b26331146bc0d92:
    # astrid/core/timeline/schema/edit-command.schema.json (positive only, not a floor).
    raw = (FIXTURES / 'producer-guard-1bffd.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '1bffd6556396ca8c3d451d2889185f505254815422bca7be851cd00d441e0bd8'
    current = json.loads(raw)
    assert len(current['$defs']['EditCommand']['allOf']) > len(baseline()['$defs']['EditCommand']['allOf'])
    assert compatibility_errors(baseline(), current) == []


def test_historical_regex_rewrites_are_not_claimed_as_proven_widenings():
    errors = compatibility_errors(baseline('runtime-0.2.2'), baseline())
    assert len(errors) == 5
    assert all('/pattern:' in error and 'review required' in error for error in errors)


def test_registered_args_cannot_be_rebound_to_a_narrower_ref():
    current = baseline()
    current['$defs']['NarrowMoveArgs'] = copy.deepcopy(current['$defs']['ClipMoveArgs'])
    current['$defs']['NarrowMoveArgs']['properties']['on']['minimum'] = 100
    condition = next(c for c in current['$defs']['EditCommand']['allOf']
                     if c['if']['properties']['op']['const'] == 'clip.move')
    condition['then']['properties']['args'] = {'$ref': '#/$defs/NarrowMoveArgs'}
    errors = compatibility_errors(baseline(), current)
    assert any('/allOf/clip.move/properties/args/properties/on/minimum:' in e for e in errors)


def generator_checkout(tmp_path):
    for directory in ('contract', 'generators', 'packages', 'runtime_protocol'):
        shutil.copytree(ROOT / directory, tmp_path / directory,
                        ignore=shutil.ignore_patterns('__pycache__', 'node_modules', 'dist', 'build', '*.egg-info'))
    shutil.copytree(FIXTURES, tmp_path / 'tests/fixtures/published-command-schemas')


def file_bytes(root):
    return {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def run_generator(root, check):
    return subprocess.run(
        [sys.executable, str(root / 'generators/generate.py'), *(['--check'] if check else [])],
        cwd=root, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize('check', [False, True], ids=['regenerate', 'check'])
def test_normal_generation_preserves_all_current_artifact_bytes(tmp_path, check):
    generator_checkout(tmp_path)
    before = file_bytes(tmp_path)
    result = run_generator(tmp_path, check)
    assert result.returncode == 0, result.stdout + result.stderr
    assert file_bytes(tmp_path) == before


@pytest.mark.parametrize('check', [False, True], ids=['regenerate', 'check'])
def test_normal_generation_refuses_actual_withdrawn_schema_before_any_write(tmp_path, check):
    generator_checkout(tmp_path)
    shutil.copyfile(FIXTURES / 'withdrawn-10c.json', tmp_path / 'contract/schemas/edit-command.json')
    before = file_bytes(tmp_path)
    result = run_generator(tmp_path, check)
    assert result.returncode != 0
    assert 'command schema compatibility failed against runtime-0.2.3.json' in result.stderr
    assert result.stderr.count(': missing definition') == 8
    assert result.stderr.count(': missing supported operation') == 7
    assert file_bytes(tmp_path) == before


def test_normal_generation_refuses_a_modified_floor_before_any_write(tmp_path):
    generator_checkout(tmp_path)
    with (tmp_path / 'tests/fixtures/published-command-schemas/runtime-0.2.3.json').open('ab') as floor:
        floor.write(b'\n')
    before = file_bytes(tmp_path)
    result = run_generator(tmp_path, False)
    assert result.returncode != 0
    assert 'published command schema floor digest mismatch' in result.stderr
    assert file_bytes(tmp_path) == before


@pytest.mark.parametrize('name', ['runtime-0.2.2', 'runtime-0.2.3', 'runtime-0.2.10', 'agent-0a0ac7ba', 'agent-26ef2bbb'])
def test_current_union_preserves_each_exact_floor(name):
    current = json.loads((ROOT / 'contract/schemas/edit-command.json').read_bytes())
    check = legacy_022_compatibility_errors if name == 'runtime-0.2.2' else compatibility_errors
    assert check(baseline(name), current) == []


@pytest.mark.parametrize('name', ['ScopedId', 'EntityRef', 'TargetKey', 'AnchorIdentity'])
def test_legacy_regex_proof_does_not_hide_other_constraints(name):
    current = baseline('agent-0a0ac7ba')
    current['$defs'][name]['maxLength'] = 1
    assert legacy_022_compatibility_errors(baseline('runtime-0.2.2'), current)
    current = baseline('agent-0a0ac7ba')
    current['$defs'][name]['pattern'] = '^parent$'
    assert legacy_022_compatibility_errors(baseline('runtime-0.2.2'), current)


def test_legacy_regex_proof_does_not_hide_track_selection_narrowing():
    current = baseline('agent-0a0ac7ba')
    condition = next(c for c in current['$defs']['EditCommand']['allOf']
                     if c['if']['properties']['op']['const'] == 'track.set')
    condition['then']['properties']['select']['pattern'] = '^parent/track:only$'
    assert legacy_022_compatibility_errors(baseline('runtime-0.2.2'), current)


@pytest.mark.parametrize('name', list(baseline('agent-0a0ac7ba')['$defs']))
def test_frozen_union_rejects_each_lost_definition(name):
    current = baseline('agent-0a0ac7ba')
    del current['$defs'][name]
    assert compatibility_errors(baseline('agent-0a0ac7ba'), current)


@pytest.mark.parametrize('op', [c['if']['properties']['op']['const'] for c in
                              baseline('agent-0a0ac7ba')['$defs']['EditCommand']['allOf']])
def test_frozen_union_rejects_each_lost_operation(op):
    current = baseline('agent-0a0ac7ba')
    current['$defs']['EditCommand']['allOf'] = [
        c for c in current['$defs']['EditCommand']['allOf']
        if c['if']['properties']['op']['const'] != op]
    assert compatibility_errors(baseline('agent-0a0ac7ba'), current)


@pytest.mark.parametrize('check', [False, True], ids=['regenerate', 'check'])
def test_normal_generation_refuses_old_ordinary_schema_before_any_write(tmp_path, check):
    generator_checkout(tmp_path)
    shutil.copyfile(FIXTURES / 'runtime-0.2.10.json', tmp_path / 'contract/schemas/edit-command.json')
    before = file_bytes(tmp_path)
    result = run_generator(tmp_path, check)
    assert result.returncode != 0
    assert 'command schema compatibility failed against agent-0a0ac7ba.json' in result.stderr
    assert file_bytes(tmp_path) == before


@pytest.mark.parametrize('check', [False, True], ids=['regenerate', 'check'])
def test_normal_generation_refuses_s1_without_s2_element_pin_before_any_write(tmp_path, check):
    generator_checkout(tmp_path)
    shutil.copyfile(FIXTURES / 'agent-0a0ac7ba.json', tmp_path / 'contract/schemas/edit-command.json')
    before = file_bytes(tmp_path)
    result = run_generator(tmp_path, check)
    assert result.returncode != 0
    assert 'command schema compatibility failed against agent-26ef2bbb.json' in result.stderr
    assert '/ClipSetElementArgs/properties/schema_source' in result.stderr
    assert file_bytes(tmp_path) == before
