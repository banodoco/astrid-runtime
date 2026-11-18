"""Read collection authority from source and the original command line."""

from __future__ import annotations

import ast
import configparser
import fnmatch
import os
import shlex
import tomllib
from pathlib import Path


DEFAULTS = {
    "python_files": ["test_*.py", "*_test.py"],
    "python_functions": ["test"],
    "python_classes": ["Test"],
    "norecursedirs": ["*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}"],
    "testpaths": [],
}


def source_config(root: Path) -> dict:
    path = root / "pyproject.toml"
    ini = tomllib.loads(path.read_text(encoding="utf-8")).get("tool", {}).get("pytest", {}).get("ini_options", {}) if path.exists() else {}
    result = {}
    for name, default in DEFAULTS.items():
        value = ini.get(name, default)
        if isinstance(value, str):
            value = shlex.split(value)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"invalid pytest {name} in {path}")
        result[name] = tuple(value)
    addopts = ini.get("addopts", "")
    result["addopts"] = tuple(shlex.split(addopts) if isinstance(addopts, str) else addopts)
    return result


def selection(args: tuple[str, ...] | list[str]) -> tuple[str, str]:
    """Only literal invocation tokens may select -k/-m; preserve last-wins."""
    values = {"-k": "", "-m": ""}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg in values:
            index += 1
            if index == len(args):
                raise ValueError(f"missing expression after {arg}")
            values[arg] = args[index]
        elif arg.startswith(("-k", "-m")) and not arg.startswith("--"):
            values[arg[:2]] = arg[2:].removeprefix("=")
        index += 1
    return values["-k"], values["-m"]


def configuration_errors(root: Path, args: tuple[str, ...] | list[str]) -> list[str]:
    errors = []
    if os.environ.get("PYTEST_ADDOPTS", ""):
        errors.append("PYTEST_ADDOPTS must be empty; selection belongs on the command line")
    forbidden = {"pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "tox.ini", "setup.cfg"}
    paths = {root / name for name in forbidden}
    # Only the project's collection tree is traversed, never sibling installed
    # dependency checkouts. Root candidates are checked even if unused by pytest.
    tests = root / "tests"
    if tests.is_dir():
        paths.update(path for path in tests.rglob("*") if path.name in forbidden)
    for path in sorted(paths):
        if not path.exists():
            continue
        if path.name == "setup.cfg":
            config = configparser.ConfigParser()
            try:
                config.read_string(path.read_text(encoding="utf-8"))
            except (OSError, configparser.Error) as exc:
                errors.append(f"unreadable configuration {path}: {exc}")
                continue
            if not any(name in config for name in ("pytest", "tool:pytest")):
                continue
        errors.append(f"alternate pytest configuration is forbidden: {path}")
    try:
        ini_args = source_config(root)["addopts"]
        if any(arg == "--" or arg.startswith(("-k", "-m", "@")) for arg in ini_args):
            errors.append("pyproject addopts cannot contain -k/-m or argument files; use the command line")
        for arg in (*ini_args, *args):
            if arg.startswith(("--override-ini", "--config-file", "--rootdir", "@")) or arg == "-c" or arg.startswith("-o") or (arg.startswith("-c") and len(arg) > 2):
                errors.append(f"configuration override is forbidden: {arg}")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"cannot read collection configuration: {exc}")
    return errors


def _matches(name: str, patterns: tuple[str, ...]) -> bool:
    return any(name.startswith(pattern) or fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _qualified(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified(node.value) + "." + node.attr
    return ""


def definitions(path: Path, naming: dict) -> set[tuple[str, ...]]:
    """Reuse Agent #397's AST census, without importing test modules."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    aliases, classes = {}, {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            aliases.update({item.asname or item.name: item.name for item in node.names})
        elif isinstance(node, ast.ImportFrom):
            aliases.update({item.asname or item.name: f"{node.module}.{item.name}" for item in node.names})
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node

    def qualified(node):
        first, dot, rest = _qualified(node).partition(".")
        return aliases.get(first, first) + dot + rest

    def testcase(node, seen=frozenset()):
        return node.name not in seen and any(
            qualified(base) == "unittest.TestCase" or
            (isinstance(base, ast.Name) and base.id in classes and testcase(classes[base.id], seen | {node.name}))
            for base in node.bases
        )

    def lineage(node, seen=frozenset()):
        if node.name not in seen:
            for base in reversed(node.bases):
                if isinstance(base, ast.Name) and base.id in classes:
                    yield from lineage(classes[base.id], seen | {node.name})
            yield node

    found = set()

    def visit(body, parents=(), unittest=False):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fixture = any(qualified(mark.func if isinstance(mark, ast.Call) else mark) in {"pytest.fixture", "pytest.yield_fixture"} for mark in node.decorator_list)
                if _matches(node.name, ("test",) if unittest else naming["python_functions"]) and not fixture:
                    found.add((*parents, node.name))
            elif isinstance(node, ast.ClassDef):
                unit = testcase(node)
                if unit or _matches(node.name, naming["python_classes"]):
                    for ancestor in lineage(node):
                        visit(ancestor.body, (*parents, node.name), unit)
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For)):
                visit(node.body, parents, unittest)
                visit(getattr(node, "orelse", []), parents, unittest)
                visit(getattr(node, "finalbody", []), parents, unittest)
                for handler in getattr(node, "handlers", []):
                    visit(handler.body, parents, unittest)

    visit(tree.body)
    return found


class StaticCensus:
    def __init__(self, root: Path, directory: Path, paths: list[str]):
        self.root = root
        naming = source_config(root)
        self.expected = set()
        self.observed = set()
        self.paths = tuple(paths or naming["testpaths"] or [str(directory)])
        for argument in self.paths:
            path_arg, *selector = argument.split("::")
            requested = (directory / path_arg).resolve()
            if requested.is_file():
                files = [requested] if requested.suffix == ".py" else []
            else:
                files = []
                for parent, dirs, names in os.walk(requested):
                    dirs[:] = sorted(name for name in dirs if not name.startswith(".") and not any(
                        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(str(Path(parent) / name), pattern)
                        for pattern in naming["norecursedirs"]))
                    files.extend(Path(parent, name).resolve() for name in sorted(names) if any(
                        fnmatch.fnmatch(name, pattern) for pattern in naming["python_files"]))
            for path in files:
                for names in definitions(path, naming):
                    if len(selector) <= len(names) and all(want.split("[", 1)[0] == got for want, got in zip(selector, names)):
                        self.expected.add((path, names))

    def record(self, item):
        import pytest

        classes = tuple(parent.name for parent in item.listchain() if isinstance(parent, pytest.Class))
        names = (*classes, getattr(item, "originalname", None) or item.name.split("[", 1)[0])
        self.observed.add((item.path.resolve(), names))

    def missing(self):
        return sorted(f"{path.relative_to(self.root) if path.is_relative_to(self.root) else path}::{'::'.join(names)}"
                      for path, names in self.expected - self.observed)
