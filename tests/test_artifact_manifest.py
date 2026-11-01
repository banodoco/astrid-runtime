"""contract/artifacts.json must match the files it describes (testing plan C1, R-3)."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("artifact_manifest", ROOT / "scripts" / "artifact_manifest.py")
artifact_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(artifact_manifest)

SAMPLE = ["contract/schemas/common.json", "contract/openapi/workspace-v1.yaml"]


def test_committed_artifact_manifest_is_current() -> None:
    assert artifact_manifest.check() == [], "run `python scripts/artifact_manifest.py`"


def test_release_manifest_contains_only_public_client_packages() -> None:
    artifacts = artifact_manifest.build()["artifacts"]
    assert "generators/release.json" in artifacts
    assert "packages/python/pyproject.toml" in artifacts
    assert "packages/typescript/package.json" in artifacts
    assert "packages/typescript/src/index.ts" in artifacts
    assert "packages/typescript/src/operation-handle.ts" in artifacts
    assert not any(path.startswith(("clients/", "conformance/typescript/")) for path in artifacts)


def test_planted_one_byte_change_is_detected_and_named(tmp_path: Path) -> None:
    for relative in SAMPLE:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    artifact_manifest.write(tmp_path, SAMPLE)
    assert artifact_manifest.check(tmp_path, SAMPLE) == []

    planted = tmp_path / SAMPLE[0]
    data = bytearray(planted.read_bytes())
    data[0] ^= 1
    planted.write_bytes(bytes(data))

    assert artifact_manifest.check(tmp_path, SAMPLE) == [f"{SAMPLE[0]}: changed"]
