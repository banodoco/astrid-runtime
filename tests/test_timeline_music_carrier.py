import json

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService


def _parent(astrid=None):
    config = {}
    if astrid is not None:
        config["app"] = {"astrid": astrid}
    return {"config": config}


def _carrier():
    return {
        "timeline:music-original": {
            "owner": "timeline:music-original",
            "source": {
                "id": "music-original",
                "track": "A1",
                "asset": "music-asset",
                "at": 0,
                "from": 0,
                "to": 12,
                "app": {"vendor": {"nested": {"opaque": ["keep", None, 4]}}},
            },
            "ripple_basis": [{"at_s": 4.25, "delta_s": 2}],
            "outputs": ["music-original", "music-original:cut-1"],
            "extension_metadata": {"future_field": True},
        },
    }


@pytest.mark.parametrize("version", [0, 1])
def test_legacy_format_versions_keep_existing_compatibility_behavior(version):
    RuntimeService._require_music_v2_compatibility(
        _parent({"v": version}), _parent({"v": version, "legacy": {"keep": True}})
    )


def test_v2_carrier_is_validated_as_an_opaque_envelope():
    RuntimeService._require_music_v2_compatibility(
        _parent({"v": 1}), _parent({"v": 2, "music_beds": _carrier()})
    )

    payload = {
        "config": {
            "app": {
                "astrid": {
                    "v": 2,
                    "music_beds": _carrier(),
                    "vendor_extension": {"absence": None, "nested": [{"keep": "exact"}]},
                }
            }
        }
    }
    expected = json.dumps(payload["config"]["app"]["astrid"], separators=(",", ":"))
    completed = RuntimeService._complete_parent_payload(payload)

    assert json.dumps(completed["config"]["app"]["astrid"], separators=(",", ":")) == expected
    assert completed["config"]["app"]["astrid"] is not payload["config"]["app"]["astrid"]


@pytest.mark.parametrize(
    "astrid",
    [
        {"v": 2},
        {"v": 1, "music_beds": {}},
        {"music_beds": {}},
        {"v": 2, "music_beds": []},
    ],
)
def test_malformed_music_version_carrier_pairs_are_refused(astrid):
    with pytest.raises(ValueError):
        RuntimeService._require_music_v2_compatibility(_parent(), _parent(astrid))


def test_feature_bearing_head_cannot_be_downgraded_by_removing_both_fields():
    head = _parent({"v": 2, "music_beds": _carrier()})
    candidate = _parent({})

    with pytest.raises(ConflictError, match="candidate removes app.astrid.v=2 music_beds") as raised:
        RuntimeService._require_writable_composition(head, candidate)

    assert raised.value.details["code"] == "timeline_compatibility"
