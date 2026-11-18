"""Compare quarantine contracts with Git history without executing historical code."""

from __future__ import annotations

import ast
import json
import os
import re
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
    """Use the PR target or the actual push's immutable previous tip.

    A multi-commit push must compare with event.before, not its last commit's
    parent or an unrelated plan branch. Missing push history fails closed.
    """
    push = not base and os.environ.get("GITHUB_EVENT_NAME") == "push"
    if base:
        target = base
    elif push:
        try:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
            target = event["before"]
            branch = event["ref"]
        except (OSError, KeyError, ValueError) as exc:
            raise ValueError("push merge base unavailable: immutable event.before and pushed ref are required") from exc
        if not isinstance(target, str) or not re.fullmatch(r"[0-9a-f]{40}", target) or target == "0" * 40:
            raise ValueError("push merge base unavailable: event.before must be a nonzero commit SHA")
        if not isinstance(branch, str) or not branch.startswith("refs/heads/") or branch != os.environ.get("GITHUB_REF"):
            raise ValueError("push merge base unavailable: event.ref does not match the pushed branch")
    elif os.environ.get("GITHUB_BASE_REF"):
        target = "origin/" + os.environ["GITHUB_BASE_REF"]
    elif os.environ.get("GITHUB_REF", "").startswith("refs/heads/"):
        target = "origin/" + os.environ["GITHUB_REF"].removeprefix("refs/heads/")
    else:
        target = "origin/release/14/plan-39"
    try:
        reference = _git(repo, "merge-base", "HEAD", target)
        if reference == _git(repo, "rev-parse", "HEAD"):
            if push:
                raise ValueError("push comparison does not precede the candidate")
            reference = _git(repo, "rev-parse", "HEAD^1")
        return reference
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"quarantine merge base unavailable; fetch {target} and its history") from exc


def _binding_pairs(value: dict) -> set[tuple[str, str]]:
    if not isinstance(value, dict):
        raise ValueError("skip bindings must be a dictionary")
    pairs = set()
    for name, nodes in value.items():
        if not isinstance(name, str) or not isinstance(nodes, (list, tuple)) or any(not isinstance(node, str) for node in nodes):
            raise ValueError("skip bindings must map declaration names to explicit node lists")
        if len(nodes) != len(set(nodes)):
            raise ValueError(f"duplicate skip binding in {name}")
        pairs.update((name, node) for node in nodes)
    return pairs


def compare_skip_bindings(current: dict, reference: dict) -> list[str]:
    additions = _binding_pairs(current) - _binding_pairs(reference)
    errors = [f"new skip binding absent from merge base: {name}: {node}" for name, node in sorted(additions)]
    errors.extend(f"new skip binding declaration absent from merge base: {name}" for name in sorted(current.keys() - reference.keys()))
    return errors


def _read_bindings(source: str) -> dict:
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"duplicate skip binding declaration: {name}")
            result[name] = value
        return result
    value = json.loads(source, object_pairs_hook=unique)
    _binding_pairs(value)
    return value


def merge_base_skip_binding_errors(repo: Path, *, base: str | None = None, current: dict | None = None) -> list[str]:
    try:
        reference = reference_commit(repo, base)
        before = _read_bindings(_git(repo, "show", f"{reference}:tests/skip-bindings.json"))
        candidate = _read_bindings((repo / "tests/skip-bindings.json").read_text(encoding="utf-8"))
        errors = compare_skip_bindings(candidate, before)
        if current is not None:
            errors.extend(compare_skip_bindings(current, before))
        return errors
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        return [f"skip binding reference check failed (a missing base registry requires Lead bootstrap): {exc}"]


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
