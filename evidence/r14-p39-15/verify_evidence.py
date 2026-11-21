"""Verify sealed native receipts without extracting files or executing tests."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    folder = Path(__file__).resolve().parent
    repo = folder.parents[1]
    archive = folder / 'native-evidence.tar.gz'
    envelope = json.loads((folder / 'artifacts.json').read_text())[archive.name]
    assert sha(archive.read_bytes()) == envelope['sha256']
    assert archive.stat().st_size == envelope['bytes']
    with tarfile.open(archive, 'r:gz') as tar:
        names = tar.getnames()
        assert len(names) == len(set(names)) == envelope['members']
        assert all(member.isfile() for member in tar.getmembers())
        payload = {name: tar.extractfile(name).read() for name in names}
    manifest = json.loads(payload['payload-manifest.json'])
    assert set(manifest) == set(payload) - {'payload-manifest.json'}
    for name, expected in manifest.items():
        assert len(payload[name]) == expected['bytes'], name
        assert sha(payload[name]) == expected['sha256'], name

    roster = json.loads(payload['evidence-local/candidate-compact-roster.json'])
    original = payload['evidence-original/original-ids.txt'].decode().splitlines()
    assert len(original) == len(set(original)) == len(roster) == 366
    assert set(original) == {row['nodeid'] for row in roster}
    grouped = defaultdict(Counter)
    union = {}
    lanes = {}
    source_snapshot = None
    for lane, expected_count in [('unit', 358), ('nightly', 8)]:
        prefix = f'evidence-local/candidate-{lane}/'
        events = [json.loads(line) for line in payload[prefix + 'events.jsonl'].splitlines()]
        finish = [row for row in events if row.get('event') == 'finish']
        assert finish == [{'collected': expected_count, 'event': 'finish', 'exitstatus': 1}]
        assert int(payload[prefix + 'exit.txt']) == 1
        phases = defaultdict(dict)
        for event in events:
            if event.get('event') != 'test_report':
                continue
            nodeid, phase = event['nodeid'], event['when']
            assert not event.get('wasxfail') and not event.get('subtest')
            assert phase not in phases[nodeid], (nodeid, phase)
            phases[nodeid][phase] = event['outcome']
        assert len(phases) == expected_count
        invocation = json.loads(payload[prefix + 'invocation.json'])
        assert set(invocation['requested_nodeids']) == set(phases)
        if source_snapshot is None:
            source_snapshot = invocation['source_files']
        assert source_snapshot == invocation['source_files']
        expected_rows = {row['nodeid']: row for row in roster if row['lane'] == lane}
        assert set(phases) == set(expected_rows)
        counts = Counter()
        for nodeid, observed in phases.items():
            assert observed.get('teardown') == 'passed'
            assert 'skipped' not in observed.values()
            failed = [phase for phase, outcome in observed.items() if outcome == 'failed']
            outcome = 'ERROR' if any(phase != 'call' for phase in failed) else 'FAILED' if failed else 'PASSED'
            assert outcome == expected_rows[nodeid]['candidate_outcome']
            assert nodeid not in union
            union[nodeid] = outcome
            counts[outcome] += 1
            grouped[expected_rows[nodeid]['group']][outcome] += 1
        lanes[lane] = dict(counts)
    assert set(union) == set(original)
    assert Counter(union.values()) == {'PASSED': 309, 'FAILED': 5, 'ERROR': 52}
    assert len(source_snapshot) == 373
    for name, expected in source_snapshot.items():
        assert sha((repo / name).read_bytes()) == expected, name
    print(json.dumps({'payload_digests_verified': len(manifest), 'source_hashes_verified': len(source_snapshot),
                      'original_distinct_ids': len(union), 'lanes': lanes, 'groups': grouped,
                      'qualification': 'BLOCKED: 57 retained nonpassing IDs; hosted candidate receipts pending'}, indent=2))


if __name__ == '__main__':
    main()
