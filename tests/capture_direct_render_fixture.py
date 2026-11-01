"""One-time capture of the two legacy-shot setup prefixes from M1 9f9b25c.

Run with the M1 source on PYTHONPATH and Python -B. This is capture tooling,
never a compatibility writer used by the M2 tests.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from runtime_protocol.backup import create_backup
from precut_realm_fixture import FIXTURE_BACKUP_KEY


SOURCE_COMMIT = "9f9b25c000485e919f30f1411831fe2d5a3c1316"
CASES = {
    "legacy-shot": "test_direct_managed_render_rejects_legacy_shot_before_claim",
    "nested-shot": "test_direct_managed_render_rejects_nested_shot_before_queueing",
}


def capture(source: Path, destination: Path):
    import runtime_protocol.service

    assert Path(runtime_protocol.service.__file__).resolve().is_relative_to(source.resolve())
    assert subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True,
    ).strip() == SOURCE_COMMIT
    original = subprocess.check_output([
        "git", "-C", str(source), "show", f"{SOURCE_COMMIT}:tests/test_direct_render_admission.py",
    ], text=True)
    tree = ast.parse(original)
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_digest"]
    for label, name in CASES.items():
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        setup = next(node for node in function.body if isinstance(node, ast.Try))
        end = next(index for index, node in enumerate(setup.body) if isinstance(node, ast.With))
        # Retain the original public API setup, stopping before Task admission.
        setup.body = setup.body[:end] + ast.parse("save(service)").body
        module = ast.fix_missing_locations(ast.Module(body=[*imports, *helpers, function], type_ignores=[]))
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            backup = temporary / "backup"
            namespace = {"save": lambda service: create_backup(service.store, backup, key=FIXTURE_BACKUP_KEY)}
            exec(compile(module, "<M1 direct-render setup>", "exec"), namespace)
            namespace[name](temporary)
            with tarfile.open(destination / f"precut-direct-render-{label}-v31.tar.gz", "w:gz") as archive:
                archive.add(backup, arcname="backup")


if __name__ == "__main__":
    capture(Path(sys.argv[1]), Path(sys.argv[2]))
