"""Opt-in work counts for the verified-head Runtime request."""

import json
import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar


_COUNTERS = (
    "document_schema_cache_hits",
    "document_schema_cache_misses",
    "document_schema_cache_evictions",
    "selected_record_cache_hits",
    "selected_record_verification_attempts",
    "selected_replay_key_hits",
    "selected_record_replay_attempts",
    "isolated_read_retries",
    "snapshot_prefix_history_queries",
    "snapshot_prefix_history_rows_read",
    "snapshot_prefix_receipt_queries",
    "snapshot_prefix_receipt_rows_read",
)
current_verified_head_receipt = ContextVar("current_verified_head_receipt", default=None)


@contextmanager
def observe_verified_head():
    if os.environ.get("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS") != "1":
        yield
        return
    receipt = {"counts": dict.fromkeys(_COUNTERS, 0)}
    token = current_verified_head_receipt.set(receipt)
    try:
        yield
    finally:
        current_verified_head_receipt.reset(token)
        # Both installed Runtime entrypoints route stderr to their existing
        # log sinks. Keep the receipt independent of logging configuration.
        try:
            payload = json.dumps(receipt, separators=(",", ":"))
            sys.stderr.write(f"runtime.timeline_commit.verified_head {payload}\n")
        except Exception:
            # A log sink failure must preserve the request's result.
            pass


def verified_head_counts():
    receipt = current_verified_head_receipt.get()
    return receipt["counts"] if receipt is not None else None


def count_reopen_work(counter):
    counts = verified_head_counts()
    if counts is not None:
        counts[counter] += 1


def count_prefix_materialization(prefix, rows):
    counts = verified_head_counts()
    if counts is not None:
        counts[f"snapshot_prefix_{prefix}_queries"] += 1
        counts[f"snapshot_prefix_{prefix}_rows_read"] += len(rows)
