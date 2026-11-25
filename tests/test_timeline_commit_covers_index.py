import pytest

from runtime_protocol.timeline_commit_auth import _CoversIndex, covers


class Explodes:
    def __eq__(self, other):
        raise ValueError("nested equality evaluated")


def outcome(function):
    try:
        return ("return", function())
    except Exception as error:
        return ("raise", type(error), str(error))


def test_later_metaclass_equality_is_never_called_after_earlier_match():
    calls = []

    class RaisesOnTypeEquality(type):
        def __eq__(cls, other):
            calls.append((cls, other))
            raise AssertionError("metaclass equality evaluated")

    class Odd(metaclass=RaisesOnTypeEquality):
        pass

    read = {"kind": "field", "ref": "parent", "path": ["x"], "state": 1}
    later = {"kind": "field", "ref": "other", "path": ["x"], "state": Odd()}
    dependencies = [read, later]
    assert outcome(lambda: covers(dependencies, read)) == ("return", True)
    assert outcome(lambda: _CoversIndex(dependencies).covers(read)) == ("return", True)
    assert calls == []


@pytest.mark.parametrize("shared_side", ["dependency", "read"])
def test_shared_container_dag_falls_back_and_matches_loop(shared_side):
    read = {"kind": "field", "ref": "parent", "path": ["x"], "state": 1}
    dependencies = [read]
    if shared_side == "dependency":
        shared = {"leaf": []}
        dependencies.append({"kind": "field", "ref": "other", "path": [],
                             "state": [shared, shared]})
    else:
        shared = {"leaf": []}
        read["state"] = [shared, shared]
        dependencies = [{"kind": "field", "ref": "parent", "path": ["x"],
                         "state": [{"leaf": []}, {"leaf": []}]}]
    index = _CoversIndex(dependencies)
    if shared_side == "dependency":
        assert not index.valid
    else:
        assert index.covers(read) is True
        assert not index.valid
    assert outcome(lambda: index.covers(read)) == outcome(lambda: covers(dependencies, read))


@pytest.mark.parametrize("other_ref", [False, True])
def test_earlier_nested_equality_is_not_skipped(other_ref):
    read = {"state": {"value": Explodes()}, "kind": "field", "ref": "parent", "path": ["clips"]}
    field = {"state": {"value": Explodes()}, "kind": "field", "ref": "other" if other_ref else "parent", "path": ["clips"]}
    dependencies = [field, {"kind": "scope", "ref": "parent", "path": []}]
    index = _CoversIndex(dependencies)
    assert outcome(lambda: index.covers(read)) == outcome(lambda: covers(dependencies, read))


@pytest.mark.parametrize("dependencies, read", [
    ([{"kind": "scope", "ref": "parent", "path": []}], {"kind": "field", "ref": "parent", "path": ["x"]}),
    ([{"kind": "field", "ref": "parent", "path": ["x"], "state": {"value": True}}], {"kind": "field", "ref": "parent", "path": ["x"], "state": {"value": 1}}),
    ([{}], {}),
    ([{"kind": "field", "ref": "parent", "path": []}], {"kind": "scope", "ref": "other", "path": []}),
])
def test_filter_matches_loop(dependencies, read):
    index = _CoversIndex(dependencies)
    assert outcome(lambda: index.covers(read)) == outcome(lambda: covers(dependencies, read))



@pytest.mark.parametrize('count', [300, 600, 1200])
def test_synthetic_validate_step_differential_and_counters(count, monkeypatch):
    import copy
    import time
    import runtime_protocol.timeline_commit_auth as auth
    import runtime_protocol.timeline_commit_producer as producer

    dependencies = [
        {'kind': 'field', 'ref': f'clip:{i}', 'path': ['config', 'clips'],
         'state': {'state': 'present', 'value': {'position': i, 'name': f'clip {i}'}}}
        for i in range(count)
    ]
    reads = copy.deepcopy(dependencies)
    request = {'commands': []}
    records = {'commands': []}
    step = {'id': 'synthetic', 'dependencies': dependencies, 'command_ordinals': [], 'patch': []}
    original_index, original_equal, original_plain = auth._CoversIndex, auth.value_equal, auth._covers_plain

    class OriginalIndex:
        def __init__(self, values):
            self.values = values
        def covers(self, value):
            return auth.covers(self.values, value)

    def run(index_class):
        counts = {'equal': 0, 'guard_roots': 0, 'guard_nodes': 0, 'indexes': 0, 'deepcopy_bytes': 0, 'equal_nodes': 0}
        class CountedIndex(index_class):
            def __init__(self, values):
                counts['indexes'] += 1
                super().__init__(values)
        def equal(*args):
            counts['equal'] += 1
            counts['equal_nodes'] += 1
            return original_equal(*args)
        def recursive_equal(*args):
            counts['equal_nodes'] += 1
            return original_equal(*args)
        def plain(value):
            counts['guard_roots'] += 1
            pending = [value]
            while pending:
                item = pending.pop()
                counts['guard_nodes'] += 1
                if type(item) is dict:
                    pending.extend(item.values())
                elif type(item) is list:
                    pending.extend(item)
            return original_plain(value)
        original_deepcopy = copy.deepcopy
        def counted_copy(value, *args, **kwargs):
            import json
            counts['deepcopy_bytes'] += len(json.dumps(value, ensure_ascii=False).encode('utf-8'))
            return original_deepcopy(value, *args, **kwargs)
        monkeypatch.setattr(auth.copy, 'deepcopy', counted_copy)
        monkeypatch.setattr(auth, '_CoversIndex', CountedIndex)
        monkeypatch.setattr(auth, 'value_equal', equal)
        monkeypatch.setattr(producer, 'value_equal', recursive_equal)
        monkeypatch.setattr(auth, '_covers_plain', plain)
        started = time.perf_counter()
        result = outcome(lambda: auth.validate_step(request, records, step, {}, reads, {}))
        elapsed = time.perf_counter() - started
        monkeypatch.setattr(auth.copy, 'deepcopy', original_deepcopy)
        monkeypatch.setattr(producer, 'value_equal', original_equal)
        return result, counts, elapsed
    before = run(OriginalIndex)
    after = run(original_index)
    assert before[0] == after[0] == ('return', None)
    print(f'clips={count} before={before[2]:.4f}s after={after[2]:.4f}s '
          f'roots_equal={before[1]["equal"]}/{after[1]["equal"]} '
          f'equal_nodes={before[1]["equal_nodes"]}/{after[1]["equal_nodes"]} '
          f'guard_nodes={before[1]["guard_nodes"]}/{after[1]["guard_nodes"]} '
          f'index_builds={before[1]["indexes"]}/{after[1]["indexes"]}; '
          f'deepcopy_bytes={before[1]["deepcopy_bytes"]}/{after[1]["deepcopy_bytes"]}')
    assert after[1]['equal'] < before[1]['equal']


def test_generated_json_corpus_and_malformed_fallback():
    import copy
    import random
    rng = random.Random(7204)
    states = [None, True, 1, 1.0, -0.0, 'α', {'nested': [1, False, None]}, []]
    for _ in range(500):
        dependencies = []
        for _ in range(rng.randrange(0, 16)):
            kind = rng.choice(['field', 'scope', 'collection'])
            item = {'kind': kind, 'ref': rng.choice(['parent', 'timeline', 'other']),
                    'path': rng.choice([[], ['clips'], ['clips', 'id'], ['other']])}
            if kind != 'scope':
                item['state'] = copy.deepcopy(rng.choice(states))
            dependencies.append(item)
        read = {'kind': rng.choice(['field', 'scope', 'collection']),
                'ref': rng.choice(['parent', 'timeline', 'other']),
                'path': rng.choice([[], ['clips'], ['clips', 'id'], ['other']]),
                'state': copy.deepcopy(rng.choice(states))}
        assert outcome(lambda: _CoversIndex(dependencies).covers(read)) == outcome(lambda: covers(dependencies, read))
    cycle = []
    cycle.append(cycle)
    for dependencies, read in [([{}], {}), ([{'kind': 'field'}], {}),
                               ([{'kind': 'field', 'ref': 'x', 'path': [], 'state': cycle}],
                                {'kind': 'field', 'ref': 'x', 'path': [], 'state': cycle})]:
        assert outcome(lambda: _CoversIndex(dependencies).covers(read)) == outcome(lambda: covers(dependencies, read))


def test_step_acceptance_and_refusal_differential(monkeypatch):
    import runtime_protocol.timeline_commit_auth as auth
    class OriginalIndex:
        def __init__(self, values):
            self.values = values
        def covers(self, value):
            return auth.covers(self.values, value)
    original_index = auth._CoversIndex
    read = {'kind': 'field', 'ref': 'parent', 'path': ['clips'], 'state': {'state': 'absent'}}
    for dependencies in ([read], [], [{'kind': 'scope', 'ref': 'other', 'path': []}]):
        step = {'id': 'x', 'dependencies': dependencies, 'command_ordinals': [], 'patch': []}
        def run(index):
            monkeypatch.setattr(auth, '_CoversIndex', index)
            return outcome(lambda: auth.validate_step({'commands': []}, {'commands': []}, step, {}, [read], {}))
        assert run(original_index) == run(OriginalIndex)


@pytest.mark.parametrize('count', [300, 600, 1200])
def test_film_shaped_full_state_comparisons(count, monkeypatch):
    import copy
    import time
    import runtime_protocol.timeline_commit_auth as auth
    state = {'state': 'present', 'value': [
        {'id': f'clip-{i}', 'track': 'picture', 'duration': 24,
         'effects': [{'type': 'gain', 'value': 1.0}]}
        for i in range(count)]}
    read = {'kind': 'field', 'ref': 'parent', 'path': ['config', 'clips'], 'state': state}
    dependencies = [copy.deepcopy(read)]
    reads = [copy.deepcopy(read) for _ in range(10)]
    step = {'id': 'film', 'dependencies': dependencies, 'command_ordinals': [], 'patch': []}
    candidate = auth._CoversIndex
    class OriginalIndex:
        def __init__(self, values):
            self.values = values
        def covers(self, value):
            return auth.covers(self.values, value)
    original_plain, original_equal = auth._covers_plain, auth.value_equal
    def run(index):
        counts = {'guard_nodes': 0, 'equal_roots': 0}
        def plain(value):
            pending = [value]
            while pending:
                item = pending.pop()
                counts['guard_nodes'] += 1
                if type(item) is dict:
                    pending.extend(item.values())
                elif type(item) is list:
                    pending.extend(item)
            return original_plain(value)
        def equal(*args):
            counts['equal_roots'] += 1
            return original_equal(*args)
        monkeypatch.setattr(auth, '_CoversIndex', index)
        monkeypatch.setattr(auth, '_covers_plain', plain)
        monkeypatch.setattr(auth, 'value_equal', equal)
        start = time.perf_counter()
        result = outcome(lambda: auth.validate_step({'commands': []}, {'commands': []}, step, {}, reads, {}))
        return result, time.perf_counter() - start, counts
    before, after = run(OriginalIndex), run(candidate)
    assert before[0] == after[0] == ('return', None)
    print(f'film-shaped clips={count} full-state reads=10 before={before[1]:.4f}s after={after[1]:.4f}s '
          f'equal_roots={before[2]["equal_roots"]}/{after[2]["equal_roots"]} '
          f'guard_nodes={before[2]["guard_nodes"]}/{after[2]["guard_nodes"]}')
