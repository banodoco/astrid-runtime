import runtime_protocol.timeline_commit_auth as auth

checks = 0
before_covers = auth.covers
indexed = auth._CoversIndex.covers

def observed(fn):
    try:
        return ('return', fn())
    except Exception as e:
        return ('raise', type(e), str(e))

def compare(self, read):
    global checks
    if self.valid and auth._covers_plain(read):
        expected = observed(lambda: before_covers(self.dependencies, read))
        actual = observed(lambda: indexed(self, read))
        checks += 1
        assert actual == expected, (expected, actual)
    return indexed(self, read)

auth._CoversIndex.covers = compare

def pytest_sessionfinish(session, exitstatus):
    print(f'\nSV4 CORPUS PAIRS CHECKED: {checks}')
