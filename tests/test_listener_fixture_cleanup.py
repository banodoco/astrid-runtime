"""Fixture refusal/cleanup contracts, with no native capability substituted."""
import errno
from types import SimpleNamespace

import pytest

from tests import listener_fixtures as fixtures


@pytest.mark.parametrize("stage,number", [("open", errno.ENOSYS), ("signal", errno.EPERM)])
def test_owner_loss_requires_native_primitives_before_creating_resources(monkeypatch, stage, number):
    events = []
    refusal = OSError(number, "native fixture capability refused")

    def open_reference(pid):
        events.append(("open", pid))
        if stage == "open":
            raise refusal
        return 73

    def probe(fd, signum):
        events.append(("signal", fd, signum))
        raise refusal

    def forbidden(*args, **kwargs):
        pytest.fail("fixture created resources before its native capability probe")

    monkeypatch.setattr(fixtures.platform, "pidfd_open", open_reference)
    monkeypatch.setattr(fixtures.platform, "pidfd_send_signal", probe)
    monkeypatch.setattr(fixtures.platform, "spawn_tree", forbidden)
    monkeypatch.setattr(fixtures, "os", SimpleNamespace(getpid=lambda: 59,
                                                        close=lambda fd: events.append(("close", fd))))
    monkeypatch.setattr(fixtures, "socket", SimpleNamespace(socketpair=forbidden))
    monkeypatch.setattr(fixtures, "ctypes", SimpleNamespace(CDLL=forbidden))
    with pytest.raises(OSError) as caught:
        fixtures.owner_loss()
    assert caught.value is refusal
    expected = [("open", 59)]
    if stage == "signal":
        expected.extend((("signal", 73, 0), ("close", 73)))
    assert events == expected
