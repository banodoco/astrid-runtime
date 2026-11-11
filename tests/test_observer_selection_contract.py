"""R12-F2: non-secret retained selection is a closed, bounded contract.

These tests deliberately do not treat record syntax as executable authority.
"""
from __future__ import annotations

import json

import pytest


def _record(tmp_path):
    return {
        "version": 1,
        "operation": "pack-host-observe-v1",
        "selection_id": "a" * 32,
        "endpoint": "http://127.0.0.1:12345",
        "instance_id": "instance",
        "session_id": "session",
        "epoch": 1,
        "data_root": str(tmp_path.resolve()),
        "mode": "installed",
        "interpreter": str(tmp_path / "venv" / "bin" / "python"),
        "import_roots": [],
    }


def _validate(raw, root):
    from astrid_runtime.observer_selection import validate_record

    return validate_record(raw, data_root=root)


def test_closed_record_round_trip(tmp_path):
    record = _record(tmp_path)
    assert _validate(json.dumps(record).encode(), tmp_path) == record


@pytest.mark.parametrize("change", [
    {"version": True}, {"version": 2}, {"operation": "other"},
    {"selection_id": "A" * 32}, {"selection_id": "a" * 31},
    {"epoch": True}, {"epoch": 0}, {"instance_id": ""},
    {"session_id": "x\u0000y"}, {"interpreter": "python"},
    {"mode": "other"}, {"import_roots": ["/unexpected"]},
    {"extra": "discovery cannot select code"},
])
def test_invalid_record_refused(tmp_path, change):
    record = {**_record(tmp_path), **change}
    with pytest.raises(ValueError):
        _validate(json.dumps(record).encode(), tmp_path)


def test_duplicate_unknown_and_oversized_json_refused(tmp_path):
    record = _record(tmp_path)
    raw = json.dumps(record).encode()
    duplicate = raw[:-1] + b', "version": 1}'
    for invalid in (duplicate, raw + b" trailing", b" " * 16385, b"\xff"):
        with pytest.raises(ValueError):
            _validate(invalid, tmp_path)


def test_wrong_data_root_refused(tmp_path):
    record = _record(tmp_path)
    record["data_root"] = str(tmp_path / "foreign")
    with pytest.raises(ValueError):
        _validate(json.dumps(record).encode(), tmp_path)
