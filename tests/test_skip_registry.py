"""Every declared skip is tied to its condition and to the CI jobs that really run the test.

The workflows are parsed, not grepped: for each job the runner OSes, the per-OS ``continue-on-error``, the pytest
commands (their ``-m`` expression and paths) and the triggers. For each registry entry the tests it guards are found
in the test files, and a job counts as running the entry only when its commands select such a test on a runner OS
where the entry's condition is false.
"""

from __future__ import annotations

import ast
import re
import shlex
import sys
import textwrap
import tomllib
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml
from _pytest.mark.expression import Expression

from tests import lanes
from tests.lanes import HOSTS, SKIP_REGISTRY, DeclaredSkip

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
TESTS = REPO / "tests"
LANE_NAMES = set(lanes.LANE_MARKERS)
_this = sys.modules[__name__]
AUTOMATIC_TRIGGERS = {"push", "pull_request", "schedule"}


def _valid_xfail(
    name: str = "known-gap", nodeids: tuple[str, ...] = ("tests/test_example.py::test_gap",)
) -> lanes.DeclaredXfail:
    return lanes.DeclaredXfail(
        name=name,
        nodeids=nodeids,
        reason="Synthetic test declaration",
        raises="builtins.RuntimeError",
        strict=True,
        issue="https://example.invalid/issues/123",
        owner="test-owner",
        expires=(date.today() + timedelta(days=7)).isoformat(),
    )


def test_declared_xfail_registry_has_required_metadata_and_is_within_cap() -> None:
    errors = lanes.declared_xfail_errors()
    assert not errors, "invalid declared xfail registry: " + "; ".join(errors)


def test_xfail_validator_accepts_a_valid_exact_declaration() -> None:
    assert lanes.declared_xfail_errors({"known-gap": _valid_xfail()}) == []


@pytest.mark.parametrize(
    ("field", "message"),
    [("issue", "missing issue URL"), ("owner", "missing owner"), ("expires", "missing expiry")],
)
def test_xfail_validator_rejects_missing_metadata(field: str, message: str) -> None:
    from dataclasses import replace

    declaration = replace(_valid_xfail(), **{field: None})

    errors = lanes.declared_xfail_errors({"known-gap": declaration})

    assert any(message in error for error in errors)


@pytest.mark.parametrize("days", [-1, 0, lanes.MAX_XFAIL_DAYS + 1])
def test_xfail_validator_rejects_expiry_outside_the_allowed_window(days: int) -> None:
    from dataclasses import replace

    declaration = replace(_valid_xfail(), expires=(date.today() + timedelta(days=days)).isoformat())

    errors = lanes.declared_xfail_errors({"known-gap": declaration})

    assert any("expiry must be a future ISO date within" in error for error in errors)


def test_xfail_validator_rejects_non_strict_declarations() -> None:
    from dataclasses import replace

    declaration = replace(_valid_xfail(), strict=False)

    assert any("strict must be true" in error for error in lanes.declared_xfail_errors({"known-gap": declaration}))


def test_xfail_limit_counts_exact_node_ids_even_when_grouped() -> None:
    count = lanes.MAX_DECLARED_XFAIL_TESTS + 1
    nodeids = tuple(f"tests/test_example.py::test_gap_{index}" for index in range(count))
    declaration = _valid_xfail(nodeids=nodeids)

    errors = lanes.declared_xfail_errors({"grouped": declaration})

    message = f"{count} quarantined test node IDs exceed the limit of {lanes.MAX_DECLARED_XFAIL_TESTS}"
    assert any(message in error for error in errors)


def test_xfail_limit_accepts_exactly_the_cap() -> None:
    nodeids = tuple(
        f"tests/test_example.py::test_gap_{index}" for index in range(lanes.MAX_DECLARED_XFAIL_TESTS)
    )

    assert lanes.declared_xfail_errors({"grouped": _valid_xfail(nodeids=nodeids)}) == []


def test_quarantine_cannot_grow_or_extend_against_the_git_merge_base() -> None:
    from tests.quarantine_policy import merge_base_errors, policy_from_registry

    assert not (errors := merge_base_errors(REPO, current=policy_from_registry(lanes))), "\n".join(errors)


@pytest.mark.parametrize("change", ["ceiling", "new-node", "swapped-node", "expiry", "exception", "age-window"])
def test_merge_base_policy_rejects_same_pr_quarantine_edits(change: str) -> None:
    from copy import deepcopy
    import subprocess
    import types
    from tests.quarantine_policy import compare_policies, policy_from_source, reference_commit

    reference = policy_from_source((TESTS / "lanes.py").read_text(encoding="utf-8"))
    current = deepcopy(reference)
    first = next(iter(current["nodes"]))
    if change == "ceiling":
        current["ceiling"] += 1
    elif change in ("new-node", "swapped-node"):
        current["nodes"]["tests/test_new.py::test_hidden_bug"] = deepcopy(current["nodes"][first])
        if change == "swapped-node":
            del current["nodes"][first]
        else:
            current["ceiling"] += 1
    elif change == "expiry":
        current["nodes"][first]["expires"] = (date.fromisoformat(current["nodes"][first]["expires"]) + timedelta(days=1)).isoformat()
    elif change == "exception":
        current["nodes"][first]["raises"] = "builtins.Exception"
    else:
        current["max_days"] += 1
    # Exercise the actual former gate and its same-PR pin, not a reimplementation
    # of their loopholes. Only these isolated modules are forged.
    base = reference_commit(REPO)
    modules = {}
    for filename, module_name in (("lanes.py", "_packet_base_lanes"), ("test_skip_guard.py", "_packet_base_guard")):
        source = subprocess.check_output(["git", "show", f"{base}:tests/{filename}"], cwd=REPO, text=True)
        module = types.ModuleType(module_name)
        module.__file__ = str(TESTS / filename)
        sys.modules[module_name] = module
        try:
            exec(compile(source, f"{base}:tests/{filename}", "exec"), module.__dict__)
        finally:
            del sys.modules[module_name]
        modules[filename] = module
    legacy = modules["lanes.py"]
    legacy.MAX_DECLARED_XFAIL_TESTS = current["ceiling"]
    legacy.MAX_XFAIL_DAYS = current["max_days"]
    grouped = {}
    for nodeid, contract in current["nodes"].items():
        group = grouped.setdefault(contract["name"], {**contract, "nodeids": []})
        group["nodeids"].append(nodeid)
    legacy.DECLARED_XFAILS = {
        name: legacy.DeclaredXfail(**{**contract, "nodeids": tuple(contract["nodeids"])})
        for name, contract in grouped.items()
    }
    reference_day = min(date.fromisoformat(entry["expires"]) for entry in reference["nodes"].values()) - timedelta(days=13)
    assert legacy.declared_xfail_errors(today=reference_day) == []
    old_pin = modules["test_skip_guard.py"]
    old_pin.lanes = legacy
    old_pin._PINNED_XFAILS = old_pin._declared_xfail_contract(legacy.DECLARED_XFAILS)
    old_pin.test_xfail_declarations_are_immutable_and_semantic()
    assert compare_policies(current, reference)


def test_merge_base_policy_allows_removing_fixed_quarantines_and_shortening_expiry() -> None:
    from copy import deepcopy
    from tests.quarantine_policy import compare_policies, policy_from_source

    reference = policy_from_source((TESTS / "lanes.py").read_text(encoding="utf-8"))
    current = deepcopy(reference)
    del current["nodes"][next(iter(current["nodes"]))]
    current["ceiling"] -= 1
    first = next(iter(current["nodes"]))
    current["nodes"][first]["expires"] = (date.fromisoformat(current["nodes"][first]["expires"]) - timedelta(days=1)).isoformat()
    assert compare_policies(current, reference) == []


def test_quarantine_reference_is_read_from_git_not_the_candidate_pin_table(tmp_path) -> None:
    import subprocess
    from tests.quarantine_policy import merge_base_errors

    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    original = (TESTS / "lanes.py").read_text(encoding="utf-8")
    (repo / "tests/lanes.py").write_text(original, encoding="utf-8")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-q")
    git("add", "tests/lanes.py")
    git("-c", "user.name=Guard probe", "-c", "user.email=probe@example.invalid", "commit", "-qm", "reference")
    reference = git("rev-parse", "HEAD")
    (repo / "tests/lanes.py").write_text(original.replace("MAX_DECLARED_XFAIL_TESTS = 19", "MAX_DECLARED_XFAIL_TESTS = 20"), encoding="utf-8")
    # Updating a second, candidate-controlled copy cannot change Git history.
    (repo / "tests/test_skip_guard.py").write_text("_PINNED_XFAILS = {'edited-in-same-pr': True}\n", encoding="utf-8")
    git("add", "tests")
    git("-c", "user.name=Guard probe", "-c", "user.email=probe@example.invalid", "commit", "-qm", "raised both copies")
    assert any("ceiling increased" in error for error in merge_base_errors(repo, base=reference))


# --- workflows -----------------------------------------------------------------

@dataclass
class PytestCommand:
    marker_expression: str
    paths: list[str]  # relative to the repo; empty = the whole suite
    keyword_expression: str | None = None  # the -k expression, if any
    blocking: dict[str, bool] = field(default_factory=dict)  # OS key -> a failure of this step fails CI


@dataclass
class Job:
    workflow: str
    name: str
    oses: dict[str, bool]  # OS key -> blocking (False when continue-on-error holds on it)
    commands: list[PytestCommand] = field(default_factory=list)
    triggers: set[str] = field(default_factory=set)


def _default_marker_expression() -> str:
    addopts = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]["addopts"]
    tokens = shlex.split(addopts)
    return tokens[tokens.index("-m") + 1]


def _os_key(runner: str) -> str:
    for prefix, key in (("ubuntu", "linux"), ("macos", "macos"), ("windows", "windows")):
        if runner.startswith(prefix):
            return key
    raise AssertionError(f"unsupported runner {runner!r}")


_CONTINUE = re.compile(r"^\$\{\{\s*matrix\.os\s*(==|!=)\s*'([^']+)'\s*\}\}$")


def _continue_on_error(value, matrix_os: str | None, where: str) -> bool:
    if value is None or isinstance(value, bool):
        return bool(value)
    match = _CONTINUE.match(str(value).strip())
    if not match or matrix_os is None:
        pytest.fail(f"{where}: continue-on-error expression {value!r} is unsupported; use a bool or ${{{{ matrix.os == 'x' }}}} / !=")
    return (matrix_os == match.group(2)) == (match.group(1) == "==")


def _pytest_commands(run: str) -> list[PytestCommand]:
    commands = []
    for line in re.sub(r"\\\n", " ", run).splitlines():
        if "pytest" not in line:
            continue
        tokens = shlex.split(line)
        if "scripts/ci/run_pytest.py" in tokens:
            start = tokens.index("scripts/ci/run_pytest.py") + 3
            rest = tokens[start:]
            if rest[:1] == ["--"]:
                rest = rest[1:]
        elif "pytest" in tokens:
            rest = tokens[tokens.index("pytest") + 1:]
        else:
            continue
        expression, keyword, paths, i = None, None, [], 0
        while i < len(rest):
            token = rest[i]
            if token == "-m":
                expression = rest[i + 1]
                i += 1
            elif token.startswith("-m="):
                expression = token[3:]
            elif token == "-k":
                keyword = rest[i + 1]
                i += 1
            elif token.startswith("-k") and not token.startswith("--"):
                keyword = token[2:].removeprefix("=")
            elif token == "-n":
                i += 1
            elif token.startswith("tests"):
                paths.append(token.split("::")[0])
            i += 1
        commands.append(PytestCommand(_default_marker_expression() if expression is None else expression, paths, keyword))
    return commands


def _matrix_combos(matrix: dict) -> list[dict]:
    """The legs of a matrix: the cross product of its axes, minus ``exclude``, plus ``include``.

    An ``include`` entry is added to every leg whose axis values it does not contradict; when it matches none it is a
    leg of its own (the GitHub rule, without the overwrite-by-earlier-include subtleties).
    """
    axes = {key: values for key, values in matrix.items() if key not in ("include", "exclude")}
    combos: list[dict] = [{}] if axes else []
    for key, values in axes.items():
        combos = [{**combo, key: value} for combo in combos for value in values]
    exclude = matrix.get("exclude") or []
    combos = [c for c in combos if not any(all(c.get(k) == v for k, v in ex.items()) for ex in exclude)]
    for entry in matrix.get("include") or []:
        matching = [c for c in combos if all(c[k] == v for k, v in entry.items() if k in axes)]
        if matching:
            for combo in matching:
                combo.update(entry)
        else:
            combos.append(dict(entry))
    return combos


def _job_from_spec(workflow: str, name: str, spec: dict, triggers: set[str]) -> Job:
    where = f"{workflow}:{name}"
    runs_on = spec["runs-on"]
    if runs_on == "${{ matrix.os }}":
        combos = _matrix_combos(spec["strategy"]["matrix"])
        assert combos and all("os" in c for c in combos), f"{where}: the matrix has no os on some leg"
        runners = [combo["os"] for combo in combos]
    else:
        assert "${{" not in runs_on, f"{where}: unsupported runs-on {runs_on!r}"
        runners = [runs_on]
    job = Job(workflow, name, {}, triggers=triggers)
    job_blocking = {runner: not _continue_on_error(spec.get("continue-on-error"), runner, where) for runner in runners}
    for runner in runners:  # a failing blocking leg fails CI, so an OS is blocking if any of its legs is
        key = _os_key(runner)
        job.oses[key] = job.oses.get(key, False) or job_blocking[runner]
    for step in spec["steps"]:
        if "run" not in step:
            continue
        commands = _pytest_commands(step["run"])
        for runner in runners:
            blocking = job_blocking[runner] and not _continue_on_error(step.get("continue-on-error"), runner, f"{where} step")
            for command in commands:
                key = _os_key(runner)
                command.blocking[key] = command.blocking.get(key, False) or blocking
        job.commands.extend(commands)
    return job


def _jobs() -> dict[str, Job]:
    jobs: dict[str, Job] = {}
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        triggers = data.get("on", data.get(True))  # PyYAML reads the key ``on`` as True
        triggers = {triggers} if isinstance(triggers, str) else set(triggers)
        for name, spec in data["jobs"].items():
            where = f"{workflow.name}:{name}"
            assert name not in jobs, f"{where}: job name used twice"
            jobs[name] = _job_from_spec(workflow.name, name, spec, triggers)
    return jobs


# --- the tests that use each entry -------------------------------------------------

@dataclass
class Use:
    file: str
    test: str
    marks: frozenset[str]  # lane markers on the test (module + class + function)
    hosts: frozenset[str]  # hosts every declared skip on the test lets it run on
    classes: frozenset[str] = frozenset()  # enclosing class names


def _mark_names(node: ast.AST) -> set[str]:
    """Names of every ``pytest.mark.X`` and every bare name inside a decorator / pytestmark expression."""
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            names.add(sub.attr)
        elif isinstance(sub, ast.Name):
            names.add(sub.id)
    return names


def _entry_for_mark_variable() -> dict[str, DeclaredSkip]:
    found = {}
    for attr, value in vars(lanes).items():
        if attr.startswith("requires_"):
            match = re.match(r"\[declared:([a-z0-9-]+)\]", value.kwargs["reason"])
            found[attr] = SKIP_REGISTRY[match.group(1)]
    return found


def _uses() -> dict[str, list[Use]]:
    """For each entry name, every test function that the entry guards."""
    by_variable = _entry_for_mark_variable()
    uses: dict[str, list[Use]] = {name: [] for name in SKIP_REGISTRY}
    for path in sorted(TESTS.glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        module_marks: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
                module_marks |= _mark_names(node.value)

        def visit(body, inherited: set[str], classes: frozenset[str] = frozenset()):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, inherited | {n for d in node.decorator_list for n in _mark_names(d)}, classes | {node.name})
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                    marks = inherited | {n for d in node.decorator_list for n in _mark_names(d)}
                    entries = {by_variable[n].name for n in marks if n in by_variable}
                    if "darwin_native" in marks:
                        entries.add("darwin-native")
                    # Embedded source strings in guard tests do not call the
                    # runtime helper in this item. Credit actual AST calls.
                    entries |= {
                        call.args[0].value
                        for call in ast.walk(node)
                        if isinstance(call, ast.Call) and call.args
                        and ((isinstance(call.func, ast.Name) and call.func.id == "skip_for_declared_error")
                             or (isinstance(call.func, ast.Attribute) and call.func.attr == "skip_for_declared_error"))
                        and isinstance(call.args[0], ast.Constant)
                        and call.args[0].value in SKIP_REGISTRY
                        and SKIP_REGISTRY[call.args[0].value].only_error
                    }
                    hosts = frozenset(HOSTS)
                    for name in entries:
                        hosts &= SKIP_REGISTRY[name].runs_on()
                    for name in entries:
                        uses[name].append(Use(path.name, node.name, frozenset(marks & LANE_NAMES), hosts, classes))

        visit(tree.body, module_marks)
    return uses


_PLAIN_EXCLUSION = re.compile(r"^\s*not\s+([A-Za-z0-9_.\-]+)\s*$", re.IGNORECASE)


def _k_keeps(expression: str, use: Use) -> bool:
    """True only for ``-k \"not <term>\"`` where <term> matches nothing pytest's -k would look at on this test."""
    match = _PLAIN_EXCLUSION.match(expression)
    if not match:
        return False
    term = match.group(1).lower()
    names = [use.test, Path(use.file).stem, *use.classes, *use.marks]
    return not any(term in name.lower() for name in names)


def _selects(command: PytestCommand, use: Use) -> bool:
    if command.paths and not any(
        (REPO / p).resolve() == (TESTS / use.file).resolve() or (REPO / p).resolve() in (TESTS / use.file).resolve().parents
        for p in command.paths
    ):
        return False
    if command.keyword_expression is not None and not _k_keeps(command.keyword_expression, use):
        return False
    if not command.marker_expression.strip():
        return True
    return Expression.compile(command.marker_expression).evaluate(lambda name: name in use.marks)


def _running_blocking(entry: DeclaredSkip, job: Job, uses: list[Use]) -> dict[str, bool]:
    """Runner OS -> whether a failing step fails CI, for the OSes where ``job`` selects a test that uses ``entry``."""
    running: dict[str, bool] = {}
    for os_key in job.oses:
        if os_key not in entry.runs_on():
            continue
        for use in uses:
            if os_key not in use.hosts:
                continue
            for command in job.commands:
                if _selects(command, use):
                    running[os_key] = running.get(os_key, False) or command.blocking[os_key]
    return running


def _running(entry: DeclaredSkip, job: Job, uses: list[Use]) -> set[str]:
    """The runner OSes of ``job`` where it selects a test that uses ``entry`` on a host the test runs on."""
    return set(_running_blocking(entry, job, uses))


def _bad_k_filters(jobs: dict[str, Job]) -> list[str]:
    return [
        f"{job.workflow}:{name}: pytest -k {command.keyword_expression!r} is not a plain `not <term>`; "
        "it cannot be checked statically, so the job is credited with no declared test"
        for name, job in jobs.items()
        for command in job.commands
        if command.keyword_expression is not None and not _PLAIN_EXCLUSION.match(command.keyword_expression)
    ]


# --- the checks ------------------------------------------------------------------------

def test_every_condition_evaluates_on_every_host() -> None:
    for entry in SKIP_REGISTRY.values():
        for host in HOSTS.values():
            assert isinstance(entry.applies(host), bool), (entry.name, host)


def test_every_entry_has_tests_and_a_condition_that_lets_some_host_run_them() -> None:
    uses = _uses()
    for entry in SKIP_REGISTRY.values():
        assert uses[entry.name], f"{entry.name}: no test uses this entry"
        assert entry.runs_on(), f"{entry.name}: the condition skips on every host"


def test_skip_bindings_match_explicit_platform_lane_uses() -> None:
    expected = {
        name: tuple(sorted({f"tests/{use.file}::" + "::".join([*sorted(use.classes), use.test]) for use in uses}))
        for name, uses in _uses().items()
    }
    assert lanes.DECLARED_SKIP_NODES == expected


def test_every_declared_job_exists_and_runs_a_test_of_the_entry() -> None:
    jobs, uses, problems = _jobs(), _uses(), []
    for entry in SKIP_REGISTRY.values():
        if entry.no_ci:
            if entry.ci:
                problems.append(f"{entry.name}: has both no_ci and ci jobs {entry.ci}")
            continue  # test_no_undeclared_job_runs_a_test_of_the_entry fails if a job does run it
        if not entry.ci:
            problems.append(f"{entry.name}: no CI job runs it where the condition is false; list a job or give no_ci a reason")
        for name in entry.ci:
            if name not in jobs:
                problems.append(f"{entry.name}: no such CI job {name!r}")
            elif not _running(entry, jobs[name], uses[entry.name]):
                problems.append(
                    f"{entry.name}: job {name!r} selects no test that uses it on a runner OS in {sorted(entry.runs_on())} "
                    f"(job OSes {sorted(jobs[name].oses)}, -m {[c.marker_expression for c in jobs[name].commands]})"
                )
    assert not problems, "\n".join(problems)


def test_no_undeclared_job_runs_a_test_of_the_entry() -> None:
    jobs, uses = _jobs(), _uses()
    problems = [
        f"{entry.name}: job {name!r} also runs it; add it to ci"
        for entry in SKIP_REGISTRY.values()
        for name, job in jobs.items()
        if name not in entry.ci and _running(entry, job, uses[entry.name])
    ]
    assert not problems, "\n".join(problems)


def test_some_declared_job_runs_automatically() -> None:
    jobs = _jobs()
    problems = [
        f"{entry.name}: its jobs {entry.ci} are triggered only by {sorted(set().union(*(jobs[j].triggers for j in entry.ci)))}"
        for entry in SKIP_REGISTRY.values()
        if entry.ci and not AUTOMATIC_TRIGGERS & set().union(*(jobs[j].triggers for j in entry.ci))
    ]
    assert not problems, "\n".join(problems)


def test_blocking_says_whether_any_job_that_runs_the_test_can_fail_ci() -> None:
    jobs, uses, problems = _jobs(), _uses(), []
    for entry in SKIP_REGISTRY.values():
        if entry.no_ci:
            continue  # no job runs it; there is nothing to be blocking
        pairs = {
            (name, os_key): blocking
            for name in entry.ci
            for os_key, blocking in _running_blocking(entry, jobs[name], uses[entry.name]).items()
        }
        computed = any(pairs.values())
        if computed != entry.blocking:
            problems.append(
                f"{entry.name}: blocking={entry.blocking} but the workflows say blocking={computed} "
                f"(pairs {sorted(pairs.items())}; True = job fails CI on that OS)"
            )
    assert not problems, "\n".join(problems)


def test_continue_on_error_expressions_are_supported_forms() -> None:
    assert _jobs()  # _continue_on_error fails the test for any form it cannot evaluate


def test_k_filters_are_plain_exclusions() -> None:
    assert not _bad_k_filters(_jobs())


def test_recorded_pytest_runner_keeps_the_same_lane_and_path_selection() -> None:
    plain = _pytest_commands('python -m pytest -q -n 2 -m "integration" tests/test_platform.py')
    recorded = _pytest_commands('python scripts/ci/run_pytest.py "$TEST_RESULTS_DIR" unit -- -q -n 2 -m "integration" tests/test_platform.py')
    assert recorded == plain


# --- the parser itself: one focused test per simplification it used to make ---------------

def _spec(text: str) -> dict:
    return yaml.safe_load(textwrap.dedent(text))


def _use(test: str = "test_a", file: str = "test_x.py", classes=(), marks=()) -> Use:
    return Use(file, test, frozenset(marks), frozenset(HOSTS), frozenset(classes))


_ENTRY = DeclaredSkip("demo", "os_name == 'nt'", "demo", ("j",))


def test_matrix_include_and_exclude_decide_the_runner_oses() -> None:
    job = _job_from_spec("w.yml", "j", _spec("""
        runs-on: ${{ matrix.os }}
        strategy:
          matrix:
            os: [ubuntu-latest, windows-latest]
            exclude:
              - os: windows-latest
            include:
              - os: macos-latest
              - os: ubuntu-latest
                extra: true
        steps:
          - run: python -m pytest -q
        """), {"push"})
    assert sorted(job.oses) == ["linux", "macos"]
    only_include = _job_from_spec("w.yml", "j", _spec("""
        runs-on: ${{ matrix.os }}
        strategy:
          matrix:
            include:
              - os: windows-latest
        steps:
          - run: python -m pytest -q
        """), {"push"})
    assert sorted(only_include.oses) == ["windows"]


def test_step_level_continue_on_error_makes_the_step_non_blocking() -> None:
    job = _job_from_spec("w.yml", "j", _spec("""
        runs-on: ${{ matrix.os }}
        strategy:
          matrix:
            os: [ubuntu-latest, windows-latest]
        steps:
          - run: python -m pytest -q tests/test_x.py
            continue-on-error: ${{ matrix.os == 'windows-latest' }}
        """), {"push"})
    assert job.oses == {"linux": True, "windows": True}  # the job itself would fail CI on both
    assert _running_blocking(_ENTRY, job, [_use()]) == {"linux": True}  # windows: step is non-blocking, but the entry is posix-only
    entry = DeclaredSkip("demo2", "os_name != 'nt'", "demo", ("j",))
    assert _running_blocking(entry, job, [_use()]) == {"windows": False}


def test_k_expression_is_parsed_and_only_a_plain_untouching_exclusion_credits_a_test() -> None:
    def job_with(k: str) -> Job:
        return _job_from_spec("w.yml", "j", _spec(f"""
            runs-on: ubuntu-latest
            steps:
              - run: python -m pytest -q -k "{k}" tests/test_x.py
            """), {"push"})

    keeps = job_with("not slow")
    assert keeps.commands[0].keyword_expression == "not slow"
    assert _running(_ENTRY, keeps, [_use("test_a")]) == {"linux"}
    assert not _bad_k_filters({"j": keeps})
    # the exclusion touches the test (name, class, file or mark): not credited
    assert not _running(_ENTRY, keeps, [_use("test_slow_path")])
    assert not _running(_ENTRY, keeps, [_use(classes=["TestSlow"])])
    assert not _running(_ENTRY, keeps, [_use(file="test_slow.py")])
    assert not _running(_ENTRY, keeps, [_use(marks=["slow"])])
    # anything but a plain `not <term>` is never credited, and is flagged
    for other in ("slow or fast", "not slow and not fast", "slow"):
        bad = job_with(other)
        assert not _running(_ENTRY, bad, [_use("test_a")])
        assert _bad_k_filters({"j": bad})


def test_an_entry_with_neither_a_job_nor_no_ci_is_rejected(monkeypatch) -> None:
    bare = DeclaredSkip("bare", "os_name == 'nt'", "demo", ())
    monkeypatch.setattr(_this, "SKIP_REGISTRY", {"bare": bare})
    monkeypatch.setattr(_this, "_uses", lambda: {"bare": [_use()]})
    with pytest.raises(AssertionError, match="bare: no CI job runs it"):
        test_every_declared_job_exists_and_runs_a_test_of_the_entry()
    monkeypatch.setattr(_this, "SKIP_REGISTRY", {"bare": DeclaredSkip("bare", "os_name == 'nt'", "demo", (), no_ci="not supported")})
    test_every_declared_job_exists_and_runs_a_test_of_the_entry()
