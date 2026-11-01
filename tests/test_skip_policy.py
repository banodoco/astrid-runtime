"""No test leaves itself out by hand: a skip is a lane marker from the registry in tests/lanes.py.

The runtime guard (tests/test_skip_guard.py) fails a run on any skip that no registry entry declares. This is its
static half: it finds the skip and xfail calls that would only fire on some other machine, so they cannot wait there
to hide a test. tests/lanes.py is the one place that may build a skip.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests import lanes

REPO = Path(__file__).resolve().parents[1]
REGISTRY = "tests/lanes.py"
HIDDEN = {
    "pytest.skip", "pytest.importorskip", "pytest.xfail", "pytest.mark.skip", "pytest.mark.skipif", "pytest.mark.xfail",
    "unittest.skip", "unittest.skipIf", "unittest.skipUnless", "unittest.SkipTest", "unittest.case.SkipTest",
}
HIDDEN_METHODS = {"skipTest"}


def _dotted(node: ast.AST, imported: dict[str, str]) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([imported.get(node.id, node.id), *reversed(parts)])


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _xfail_call(node: ast.AST, imported: dict[str, str]) -> ast.Call | None:
    if not isinstance(node, ast.Call) or _dotted(node.func, imported) != "pytest.mark.xfail":
        return None
    return node


def _xfail_kwargs(call: ast.Call, imported: dict[str, str], module: str) -> tuple[str | None, bool, str | None]:
    values = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
    reason = _literal_string(values.get("reason"))
    strict = isinstance(values.get("strict"), ast.Constant) and values["strict"].value is True
    raises = values.get("raises")
    if raises is None:
        raise_name = None
    else:
        raise_name = _dotted(raises, imported)
        if raise_name is not None and "." not in raise_name and isinstance(raises, ast.Name):
            raise_name = f"{module}.{raise_name}"
        raise_name = {
            "astrid_runtime_client.ApiError": "astrid_runtime_client.generated.ApiError",
        }.get(raise_name, raise_name)
    return reason, strict, raise_name


def _node_functions(tree: ast.AST) -> dict[ast.AST, str]:
    parents: dict[ast.AST, ast.AST] = {}
    functions: dict[ast.AST, str] = {}

    def visit(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            parents[child] = node
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[child] = f"{prefix}{child.name}"
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}::")
            else:
                visit(child, prefix)

    visit(tree)
    return parents, functions


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST], functions: dict[ast.AST, str]) -> str | None:
    current = parents.get(node)
    while current is not None:
        if current in functions:
            return functions[current]
        current = parents.get(current)
    return None


def _xfail_nodeids(path: str, function: str, call: ast.Call, parents: dict[ast.AST, ast.AST]) -> tuple[str, ...]:
    base = f"{path}::{function}"
    current = parents.get(call)
    while current is not None:
        if isinstance(current, ast.Call) and _dotted(current.func, {}) == "pytest.param":
            value = _literal_string(current.args[0] if current.args else None)
            return (f"{base}[{value}]",) if value is not None else ()
        current = parents.get(current)
    return tuple(
        nodeid
        for declaration in lanes.DECLARED_XFAILS.values()
        for nodeid in declaration.nodeids
        if nodeid == base or ("[" in nodeid and nodeid.rsplit("[", 1)[0] == base)
    )


def _declared_xfail_lines(
    source: str, path: str | None, tree: ast.AST, imported: dict[str, str]
) -> tuple[set[int], set[int]]:
    if path is None:
        return set(), set()
    module = path.removesuffix(".py").replace("/", ".")
    parents, functions = _node_functions(tree)
    marker_variables: dict[str, ast.Call] = {}
    calls: list[ast.Call] = []
    invalid: set[int] = set()
    for node in ast.walk(tree):
        call = _xfail_call(node, imported)
        if call is not None:
            calls.append(call)
            if isinstance(node, ast.Call):
                parent = parents.get(node)
                if isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            marker_variables[target.id] = call

    allowed: set[int] = set()
    for call in calls:
        function = _enclosing_function(call, parents, functions)
        if function is not None:
            nodeids = _xfail_nodeids(path, function, call, parents)
            reason, strict, raises = _xfail_kwargs(call, imported, module)
            if any(
                lanes.is_declared_xfail(nodeid, reason, strict=strict, raises=raises)
                for nodeid in nodeids
            ):
                allowed.add(call.lineno)
            else:
                invalid.add(call.lineno)

    uses: dict[str, list[tuple[ast.AST, str]]] = {name: [] for name in marker_variables}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        function = functions[node]
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Name) or decorator.id not in marker_variables:
                continue
            call = marker_variables[decorator.id]
            uses[decorator.id].append((decorator, function))
            reason, strict, raises = _xfail_kwargs(call, imported, module)
            nodeids = _xfail_nodeids(path, function, call, parents)
            if not nodeids or not all(
                lanes.is_declared_xfail(nodeid, reason, strict=strict, raises=raises) for nodeid in nodeids
            ):
                invalid.add(decorator.lineno)
    for name, entries in uses.items():
        call = marker_variables[name]
        if entries and not any(decorator.lineno in invalid for decorator, _ in entries):
            allowed.add(call.lineno)
        else:
            invalid.add(call.lineno)
    return allowed, invalid


def hidden_gates(source: str, *, path: str | None = None) -> list[tuple[int, str]]:
    """Find skip/xfail gates, permitting only exact registered xfail nodes."""
    tree = ast.parse(source)
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imported[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    allowed_xfail_lines, invalid_xfail_lines = _declared_xfail_lines(source, path, tree, imported)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            parts = [node.attr]
            value = node.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                dotted = ".".join([imported.get(value.id, value.id), *reversed(parts)])
                if dotted in HIDDEN or node.attr in HIDDEN_METHODS:
                    if dotted == "pytest.mark.xfail" and node.lineno in allowed_xfail_lines:
                        continue
                    found.append((node.lineno, dotted))
        elif isinstance(node, ast.Name) and imported.get(node.id) in HIDDEN:
            found.append((node.lineno, imported[node.id]))
    found.extend((line, "pytest.mark.xfail") for line in invalid_xfail_lines)
    return sorted(set(found))


@pytest.mark.parametrize("source", [
    "import pytest\npytest.skip('x')\n",
    "import pytest\npytest.importorskip('x')\n",
    "import pytest\n@pytest.mark.skipif(True, reason='x')\ndef test(): pass\n",
    "import pytest\n@pytest.mark.skip(reason='x')\ndef test(): pass\n",
    "import pytest\n@pytest.mark.xfail\ndef test(): pass\n",
    "import pytest\npytest.xfail('x')\n",
    "import unittest\n@unittest.skipUnless(False, 'x')\nclass T(unittest.TestCase): pass\n",
    "import unittest\nclass T(unittest.TestCase):\n    def test(self):\n        self.skipTest('x')\n",
    "import pytest as p\np.skip('x')\n",
    "from pytest import skip as omit\nomit('x')\n",
    "from unittest import SkipTest\nraise SkipTest('x')\n",
], ids=["skip", "importorskip", "skipif", "skip-mark", "xfail-mark", "xfail", "unittest", "skipTest", "alias", "from-import", "SkipTest"])
def test_the_scanner_finds_every_way_to_hide_a_test(source: str) -> None:
    assert hidden_gates(source)


def test_the_scanner_leaves_lane_markers_and_plain_strings_alone() -> None:
    source = "import pytest\n\n@pytest.mark.ffmpeg\ndef test():\n    text = 'pytest.skip is not called'\n"
    assert hidden_gates(source) == []


def test_static_policy_rejects_copied_xfail_reason_without_exact_node_binding() -> None:
    reason = lanes.DECLARED_XFAILS["runtime-domains-update"].reason
    cases = [
        f"import pytest\n@pytest.mark.xfail(strict=True, raises=RuntimeError, reason={reason!r})\n"
        + "def test_new_node(): raise RuntimeError\n",
        f"import pytest\n@pytest.mark.xfail(strict=True, raises=RuntimeError, reason={reason!r})\n"
        + "def test_generated_direct_timeline_shot_reference_writers_are_moved(): raise RuntimeError\n",
        "import pytest\n@pytest.mark.parametrize('case', [pytest.param('added', marks=pytest.mark.xfail("
            f"strict=True, raises=RuntimeError, reason={reason!r}))])\n"
        + "def test_generated_direct_timeline_shot_reference_writers_remain_retired(case): raise RuntimeError\n",
        f"import pytest\n@pytest.mark.xfail(strict=True, raises=RuntimeError, reason={(reason + ' changed')!r})\n"
        + "def test_generated_direct_timeline_shot_reference_writers_remain_retired(): raise RuntimeError\n",
        "import pytest\n@pytest.mark.xfail(strict=True, raises=RuntimeError)\n"
        + "def test_generated_direct_timeline_shot_reference_writers_remain_retired(): raise RuntimeError\n",
    ]
    for source in cases:
        assert any(name == "pytest.mark.xfail" for _, name in hidden_gates(source, path="tests/test_runtime_domains.py"))


def _test_python_files():
    """Every Python file in this repo that holds tests: any tests directory, test_*.py and *_test.py."""
    seen = set()
    for path in REPO.rglob("*.py"):
        parts = set(path.relative_to(REPO).parts)
        if parts & {".venv", "node_modules", ".git", "build", "dist"} or any(p.startswith(".venv") for p in parts):
            continue
        if "tests" in parts or path.name.startswith("test_") or path.name.endswith("_test.py") or path.name == "conftest.py":
            seen.add(path)
    return sorted(seen)


def test_no_test_file_skips_by_hand() -> None:
    offenders = []
    files = _test_python_files()
    assert files, "the scan found no test files"
    for path in files:
        relative = path.relative_to(REPO).as_posix()
        if relative == REGISTRY:
            continue
        offenders += [
            f"{relative}:{line} {name}"
            for line, name in hidden_gates(path.read_text(encoding="utf-8"), path=relative)
        ]
    assert not offenders, "mark the test with an entry from tests/lanes.py instead of skipping by hand: " + ", ".join(offenders)
