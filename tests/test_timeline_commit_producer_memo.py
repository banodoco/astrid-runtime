"""Proof for request owned memoization of validated producer artifacts."""
from __future__ import annotations

import copy
import json

import pytest

from runtime_protocol import timeline_commit_producer
from runtime_protocol.timeline_commit_port import RequestCommitPort
from test_timeline_producer_guards import (
    _body, _candidate, _context, _settle,
)
from test_timeline_producer_guards import producer as producer  # noqa: PLC0414


def _port(producer):
    commits, _ = producer.service._timeline_commits()
    context = _context(producer)
    return context, RequestCommitPort(producer.service, commits, context, lambda: None)


def test_memo_hit_preserves_the_captured_proposal_and_accepted_artifact_bytes(producer):
    _settle(producer)
    context, port = _port(producer)
    try:
        pin = producer.pin
        first_pin = port.producer_attempt(pin)
        candidate = _candidate(context, port, first_pin["pin"])
        first, = port._producer_captures(candidate)
        second, = port._producer_captures(candidate)

        assert second == first
        output, = producer.service.task(producer.task)["task"]["result"]["outputs"]
        accepted_bytes = producer.service.cas.read(output["digest"][7:])
        expected = json.dumps(first["proposal"], sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")
        assert accepted_bytes == expected
    finally:
        port.close()


def test_changed_artifact_bytes_cannot_hit_owned_memo(producer, monkeypatch):
    _settle(producer)
    context, port = _port(producer)
    try:
        first_pin = port.producer_attempt(producer.pin)
        candidate = _candidate(context, port, first_pin["pin"])
        port._producer_captures(candidate)
        reader = port._RequestCommitPort__producer_readers[next(iter(port._RequestCommitPort__producer_readers))]
        original_output = reader._output
        calls = []

        def changed_output(*args, **kwargs):
            result = original_output(*args, **kwargs)
            raw, association = result
            if kwargs.get("read_bytes") and args[3].get("name") == "authoring_proposal":
                calls.append(raw)
                return raw + b" ", association
            return result

        monkeypatch.setattr(reader, "_output", changed_output)
        parsed = []
        original_parse = timeline_commit_producer._strict_json

        def track_parse(raw):
            parsed.append(raw)
            return original_parse(raw)

        monkeypatch.setattr(timeline_commit_producer, "_strict_json", track_parse)
        assert reader._capture_owned(context, first_pin["pin"])["proposal"] == producer.proposal
        assert len(calls) == 1
        assert parsed == [calls[0] + b" "]
    finally:
        port.close()


def test_public_context_capture_does_not_receive_the_private_memo(producer, monkeypatch):
    _settle(producer)
    context, port = _port(producer)
    try:
        first_pin = port.producer_attempt(producer.pin)
        reader = timeline_commit_producer.ProducerReads(producer.service)
        assert not any("memo" in key.lower() for key in context)
        assert reader._capture(context, copy.deepcopy(first_pin["pin"]), False)["proposal"] == producer.proposal
        assert reader._capture(context, copy.deepcopy(first_pin["pin"]), False)["proposal"] == producer.proposal
        assert reader._ProducerReads__owned_memo is None
    finally:
        port.close()
