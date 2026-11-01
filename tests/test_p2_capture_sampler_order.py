"""The first periodic sample is clock-driven, and shutdown wins a late tick."""
from tests.helpers.p2_commit_phase_capture import P2CommitPhaseCapture


def test_sampler_waits_for_capture_clock_before_first_sample():
    clock = [0]
    samples = []
    waits = []
    capture = P2CommitPhaseCapture(enabled=True, clock_ns=lambda: clock[0], sampling_interval=0.02)

    class Ticks:
        def wait(self, interval):
            waits.append(interval)
            if len(waits) == 2:
                clock[0] = 20_000_000
            return len(waits) == 3

        def is_set(self):
            return False

    capture._sampler_stop = Ticks()
    capture._sample_once = lambda: samples.append((len(waits), clock[0]))
    capture.active = True
    capture._start_ns = 0
    capture._sample_stack()
    assert samples == [(2, 20_000_000)]
    assert waits == [0.02, 0.02, 0.02]
    assert capture._sampler_errors == []


def test_sampler_stop_wins_over_a_late_tick():
    samples = []
    capture = P2CommitPhaseCapture(enabled=True, clock_ns=lambda: 20_000_000)

    class Stopped:
        def wait(self, interval):
            return False

        def is_set(self):
            return True

    capture._sampler_stop = Stopped()
    capture._sample_once = lambda: samples.append('late sample')
    capture.active = True
    capture._start_ns = 0
    capture._sample_stack()
    assert samples == []
    assert capture._sampler_errors == []
