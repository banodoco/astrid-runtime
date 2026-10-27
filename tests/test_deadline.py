"""Real signals run in isolated children; pytest keeps its normal watchdog."""
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX interval timers")


def run_scope(program):
    root = str(Path(__file__).resolve().parents[1])
    header = f"import sys; sys.path.insert(0, {root!r})\n"
    header += "import os, signal, time\nfrom runtime_protocol.deadline import bounded_operation\n"
    result = subprocess.run([sys.executable, "-I", "-S", "-c", header + textwrap.dedent(program)],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("ending", ["normal", "timeout", "error", "stop"])
def test_real_scope_unwinds_and_restores_handlers_and_timer(ending):
    run_scope(f'''
        ending = {ending!r}
        signals = (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)
        def prior(*args):
            raise AssertionError('prior handler ran inside scope')
        for sig in signals:
            signal.signal(sig, prior)
        before = {{sig: signal.getsignal(sig) for sig in signals}}
        events = []
        started = time.monotonic()
        try:
            with bounded_operation(0.05 if ending == 'timeout' else 1):
                try:
                    events.append('entered')
                    if ending == 'timeout':
                        time.sleep(10)
                    if ending == 'error':
                        raise ValueError('operation failed')
                    if ending == 'stop':
                        os.kill(os.getpid(), signal.SIGTERM)
                finally:
                    events.append('unwound')
        except (TimeoutError, ValueError, KeyboardInterrupt) as exc:
            expected = {{'timeout': TimeoutError, 'error': ValueError, 'stop': KeyboardInterrupt}}
            assert type(exc) is expected[ending]
        else:
            assert ending == 'normal'
        assert events == ['entered', 'unwound']
        assert time.monotonic() - started < 2
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        assert {{sig: signal.getsignal(sig) for sig in signals}} == before
        # Cleanup has a fresh budget after the expired/failed operation.
        with bounded_operation(1, stop='ignore'):
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGTERM)
        assert {{sig: signal.getsignal(sig) for sig in signals}} == before
    ''')


def test_occupied_timer_is_preserved_and_still_expires():
    run_scope('''
        def prior(*args):
            raise LookupError('original deadline')
        signal.signal(signal.SIGALRM, prior)
        signal.setitimer(signal.ITIMER_REAL, 0.15, 0.4)
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
        try:
            try:
                with bounded_operation(0.01, stop='ignore'):
                    raise AssertionError('entered with an occupied timer')
            except RuntimeError as exc:
                assert 'unused interval timer' in str(exc)
            remaining, interval = signal.getitimer(signal.ITIMER_REAL)
            assert 0 < remaining <= 0.15 and interval == 0.4
            assert {sig: signal.getsignal(sig) for sig in before} == before
            try:
                time.sleep(2)
            except LookupError:
                pass
            else:
                raise AssertionError('original deadline was lost')
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    ''')


def test_nested_scope_refuses_without_weakening_outer_deadline():
    run_scope('''
        try:
            with bounded_operation(0.05):
                try:
                    with bounded_operation(10):
                        raise AssertionError('nested scope entered')
                except RuntimeError:
                    pass
                time.sleep(2)
        except TimeoutError:
            pass
        else:
            raise AssertionError('outer deadline was lost')
    ''')


@pytest.mark.parametrize("duration,exception", [
    ("0", "TimeoutError"), ("-1", "TimeoutError"),
    ("float('nan')", "ValueError"), ("float('inf')", "ValueError"),
    ("True", "ValueError"), ("'1'", "ValueError"),
])
def test_invalid_or_expired_budget_never_enters_or_changes_native_state(duration, exception):
    run_scope(f'''
        signals = (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)
        before = {{sig: signal.getsignal(sig) for sig in signals}}
        try:
            with bounded_operation({duration}):
                raise AssertionError('invalid scope entered')
        except {exception}:
            pass
        else:
            raise AssertionError('invalid budget accepted')
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        assert {{sig: signal.getsignal(sig) for sig in signals}} == before
    ''')


def test_non_main_thread_fails_before_changing_native_state():
    run_scope('''
        import threading
        errors = []
        def worker():
            try:
                with bounded_operation(1):
                    raise AssertionError('worker scope entered')
            except RuntimeError as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert errors == ['operation deadline requires the main thread']
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    ''')
