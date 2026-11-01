from __future__ import annotations

import json
from pathlib import Path

from runtime_protocol.visual_seam import evaluate_closure

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance/fixtures/visual-seam-cases-v1.json"


def test_shared_visual_seam_cases():
    cases = json.loads(FIXTURE.read_text())["cases"]
    assert len(cases) >= 6
    for case in cases:
        timeline = case["timeline"]
        config = {key: value for key, value in timeline.items() if key != "clips"}
        parent = {"config": config, "registry": {"assets": {}}, "clips": timeline["clips"], "occurrences": []}
        shots, internals = {}, {}
        if "occurrence" in case:
            occurrence = case["occurrence"]
            parent["clips"] = []
            parent["occurrences"] = [{
                "occurrence_id": occurrence["id"], "shot_id": "shared-shot", "shot_revision_id": "shared-rev",
                "placement": {"start_ms": occurrence["start_ms"]}, "duration_ms": occurrence["duration_ms"],
                "track": occurrence["track"], "speed": 1,
            }]
            shots = {("shared-shot", "shared-rev"): {"internal_timeline_revision_id": "shared-internal"}}
            internals = {"shared-internal": {"payload": timeline}}
        report, _ = evaluate_closure(parent, shots, internals, timeline_id="shared-case")
        actual = []
        for issue in report["structuralIssues"]:
            paths = issue.get("paths", [])
            actual.append({
                "code": issue["code"],
                "frame": issue.get("frame"),
                "clips": [path[-1] for path in paths],
            })
        assert actual == case["expected"], case["name"]
        expected_warnings = case.get("expectedWarnings")
        if expected_warnings is not None:
            assert sum(cue["kind"] == "activation" for cue in report["cues"]) == expected_warnings["activation"], case["name"]
            assert len(report["opaqueElements"]) == expected_warnings["opaque"], case["name"]
