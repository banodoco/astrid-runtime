"""In-process wakeups over the store's existing commit/serialization boundary.

The notification carries no task authority. A waiter always reads durable state
again under the same lock. This is deliberately not a queue or a scheduler.
"""
from __future__ import annotations

import threading


class CommittedChanges:
    def __init__(self, mutex):
        self.condition = threading.Condition(mutex)
        self.closed = False

    def committed(self):
        with self.condition:
            self.condition.notify_all()

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
