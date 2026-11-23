"""Proof for request owned memoization of validated producer artifacts."""
from __future__ import annotations

import copy
import json

import pytest

from runtime_protocol import timeline_commit_producer
from runtime_protocol.timeline_commit_port import RequestCommitPort
from test_timeline_producer_guards import (
    _body, _candidate, _context, _execute, _settle,
)
from test_timeline_producer_guards import producer as producer  # noqa: PLC0414


def _port(producer):
    commits, _ = producer.service._timeline_commits()
    context = _context(producer)
    return RequestCommitPort(producer.service, commits, context, lambda: None)


def test_memo_hit_skips_parse_and_preserves_bytes_accepted_by_real_commit(producer, monkeypatch):
    _settle(producer)
    context = _context(producer)
    port = _port(producer)
    try:
        first_pin = port.producer_attempt(producer.pin)["pin"]
        candidate = _candidate(context, port, first_pin)
        first, = port._producer_captures(candidate)
        encoded = json.dumps(first["proposal"], sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        reader = port._RequestCommitPort__producer_readers[
            next(iter(port._RequestCommitPort__producer_readers))]
        memo_context, memo_pin, memo_bytes, _ = reader._ProducerReads__owned_memo
        assert memo_context is port._RequestCommitPort__context
        assert memo_pin == first_pin
        assert memo_bytes == encoded

        def unexpected_parse(_raw):
            pytest.fail("memo hit must skip parsing and proposal validation")

        monkeypatch.setattr(timeline_commit_producer, "_strict_json", unexpected_parse)
        second, = port._producer_captures(candidate)
        assert second["proposal"] == first["proposal"]
        assert second["artifact"]["descriptor"] == first["artifact"]["descriptor"]
    finally:
        monkeypatch.undo()
        port.close()

    result = _execute(producer)
    assert result["data"]["status"] == "accepted"
    output, = producer.service.task(producer.task)["task"]["result"]["outputs"]
    assert producer.service.cas.read(output["digest"][7:]) == encoded


def test_changed_artifact_bytes_force_parse_for_same_private_context_and_pin(producer, monkeypatch):
    _settle(producer)
    port = _port(producer)
    try:
        port.producer_attempt(producer.pin)
        reader = port._RequestCommitPort__producer_readers[
            next(iter(port._RequestCommitPort__producer_readers))]
        memo_context, memo_pin, memo_bytes, _ = reader._ProducerReads__owned_memo
        assert memo_bytes
        original_output = reader._output
        changed_reads = []

        def changed_output(*args, **kwargs):
            raw, association = original_output(*args, **kwargs)
            if kwargs.get("read_bytes") and args[3].get("name") == "authoring_proposal":
                changed_reads.append(raw)
                return raw + b" ", association
            return raw, association

        monkeypatch.setattr(reader, "_output", changed_output)
        parsed = []
        original_parse = timeline_commit_producer._strict_json

        def track_parse(raw):
            parsed.append(raw)
            return original_parse(raw)

        monkeypatch.setattr(timeline_commit_producer, "_strict_json", track_parse)
        # Reuse the exact objects retained by the request-owned memo.
        captured = reader._capture_owned(memo_context, memo_pin)
        assert changed_reads == [memo_bytes]
        assert parsed == [memo_bytes + b" "]
        assert captured["proposal"] == producer.proposal
        assert reader._ProducerReads__owned_memo[2] == memo_bytes + b" "
    finally:
        port.close()


def test_public_port_context_is_detached_and_has_no_private_memo(producer):
    _settle(producer)
    port = _port(producer)
    try:
        port.producer_attempt(producer.pin)
        private_context = port._RequestCommitPort__context
        public_context = port._provider_context()
        assert public_context == private_context
        assert public_context is not private_context
        reader = timeline_commit_producer.ProducerReads(producer.service)
        assert not any("memo" in key.lower() for key in public_context)
        assert reader._capture(public_context, copy.deepcopy(producer.pin), False)["proposal"] == producer.proposal
        assert reader._capture(public_context, copy.deepcopy(producer.pin), False)["proposal"] == producer.proposal
        assert reader._ProducerReads__owned_memo is None
        public_context["request"]["rationale"] = "mutated public copy"
        assert private_context["request"]["commands"]
        assert private_context["request"]["rationale"] == producer.proposal["rationale"]
    finally:
        port.close()
