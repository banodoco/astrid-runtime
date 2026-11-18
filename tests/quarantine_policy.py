"""Compare quarantine contracts with Git history without executing historical code."""

from __future__ import annotations

import ast
import os
import subprocess
from dataclasses import asdict
from pathlib import Path


def policy_from_source(source: str) -> dict:
    assignments = {
        target.id: node.value
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    def literal(node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_xfail_reason":
            name, reason = map(ast.literal_eval, node.args)
            return f"[declared-xfail:{name}] {reason}"
        return ast.literal_eval(node)

    entries = assignments["DECLARED_XFAILS"]
    if not isinstance(entries, ast.Dict):
        raise ValueError("DECLARED_XFAILS must be an explicit dictionary")
    nodes = {}
    for key, call in zip(entries.keys, entries.values, strict=True):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "DeclaredXfail":
            raise ValueError("quarantine entries must be explicit DeclaredXfail values")
        values = dict(zip(("name", "nodeids", "reason", "raises", "strict", "issue", "owner", "expires"), map(literal, call.args)))
        values.update({field.arg: literal(field.value) for field in call.keywords})
        values.setdefault("strict", True)
        if values["name"] != literal(key):
            raise ValueError("quarantine dictionary key does not match its name")
        for nodeid in values.pop("nodeids"):
            if nodeid in nodes:
                raise ValueError(f"duplicate quarantine node: {nodeid}")
            nodes[nodeid] = values.copy()
    return {
        "ceiling": literal(assignments["MAX_DECLARED_XFAIL_TESTS"]),
        "max_days": literal(assignments["MAX_XFAIL_DAYS"]),
        "nodes": nodes,
    }


def compare_policies(current: dict, reference: dict) -> list[str]:
    errors = []
    for field in ("ceiling", "max_days"):
        if current[field] > reference[field]:
            errors.append(f"quarantine {field} increased from merge base: {reference[field]} -> {current[field]}")
    for nodeid, entry in current["nodes"].items():
        before = reference["nodes"].get(nodeid)
        if before is None:
            errors.append(f"new quarantine node absent from merge base: {nodeid}")
            continue
        if entry.get("expires", "") > before.get("expires", ""):
            errors.append(f"quarantine expiry extended for {nodeid}: {before.get('expires')} -> {entry.get('expires')}")
        for field in ("name", "reason", "raises", "strict"):
            if entry.get(field) != before.get(field):
                errors.append(f"quarantine {field} changed against merge base for {nodeid}")
    if len(current["nodes"]) > current["ceiling"]:
        errors.append("quarantined node count exceeds the candidate ceiling")
    return errors


def policy_from_registry(lanes) -> dict:
    nodes = {}
    for declaration in lanes.DECLARED_XFAILS.values():
        contract = asdict(declaration)
        for nodeid in contract.pop("nodeids"):
            if nodeid in nodes:
                raise ValueError(f"duplicate quarantine node: {nodeid}")
            nodes[nodeid] = contract.copy()
    return {"ceiling": lanes.MAX_DECLARED_XFAIL_TESTS, "max_days": lanes.MAX_XFAIL_DAYS, "nodes": nodes}


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE).strip()


def reference_commit(repo: Path, base: str | None = None) -> str:
    """Use the PR merge base; post-merge jobs compare their first parent.

    CI supplies the target via GITHUB_BASE_REF. The plan branch is the local
    fallback, not a candidate-maintained copy of the quarantine table.
    """
    target = base or ("origin/" + os.environ["GITHUB_BASE_REF"] if os.environ.get("GITHUB_BASE_REF") else "origin/release/14/plan-39")
    try:
        reference = _git(repo, "merge-base", "HEAD", target)
        if reference == _git(repo, "rev-parse", "HEAD"):
            reference = _git(repo, "rev-parse", "HEAD^1")
        return reference
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"quarantine merge base unavailable; fetch {target} and its history") from exc


def merge_base_errors(repo: Path, *, base: str | None = None, current: dict | None = None) -> list[str]:
    try:
        reference = reference_commit(repo, base)
        old = _git(repo, "show", f"{reference}:tests/lanes.py")
        new = (repo / "tests/lanes.py").read_text(encoding="utf-8")
        reference_policy = policy_from_source(old)
        errors = compare_policies(policy_from_source(new), reference_policy)
        if current is not None:
            errors.extend(compare_policies(current, reference_policy))
        return errors
    except (ValueError, KeyError, TypeError, SyntaxError, OSError, subprocess.CalledProcessError) as exc:
        return [f"quarantine reference check failed: {exc}"]
