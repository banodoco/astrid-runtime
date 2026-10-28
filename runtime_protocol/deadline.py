"""Synchronous POSIX operation deadlines at the native boundary (stdlib only).

The caller retains custody: expiration unwinds the calling thread, including
its finally blocks. No background operation is abandoned or replayed. Cleanup
must run in a separate scope after this one has restored the signal state.
"""
from contextlib import contextmanager
import math
import signal
import threading


@contextmanager
def bounded_operation(seconds: float, *, stop: str = "interrupt"):
    """Interrupt a main-thread operation, or protect its bounded cleanup.

    ``stop='interrupt'`` turns SIGINT/SIGTERM into KeyboardInterrupt; ``'ignore'``
    ignores those stop signals during cleanup. The process must have an unused
    real-time interval timer. Refuse an armed timer (including a nested scope)
    before changing any handler, rather than stealing another owner's deadline.
    This is a POSIX primitive; unsupported platforms/threads fail before entry.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds):
        raise ValueError("operation duration must be finite")
    if stop not in {"interrupt", "ignore"}:
        raise ValueError("unsupported stop policy")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("operation deadline requires the main thread")
    if not all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")):
        raise NotImplementedError("operation deadline requires a POSIX interval timer")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("operation deadline requires an unused interval timer")
    if seconds <= 0:
        raise TimeoutError("operation time limit exceeded")

    def expired(_signum, _frame):
        raise TimeoutError("operation time limit exceeded")

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("operation interrupted")

    handlers = {
        signal.SIGALRM: expired,
        signal.SIGINT: signal.SIG_IGN if stop == "ignore" else interrupted,
        signal.SIGTERM: signal.SIG_IGN if stop == "ignore" else interrupted,
    }
    previous = {sig: signal.getsignal(sig) for sig in handlers}
    installed = []
    try:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
            installed.append(sig)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        # Cancel only our own timer, including when handler installation fails.
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig in reversed(installed):
            signal.signal(sig, previous[sig])
