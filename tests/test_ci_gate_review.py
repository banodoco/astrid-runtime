"""Real collection/config injections and immutable-history gate probes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests import test_skip_registry as registry_checks
from tests.quarantine_policy import reference_commit

REPO = Path(__file__).resolve().parents[1]
pytest_plugins = ["pytester"]


@pytest.fixture
def suite(pytester):
    pytester.makeconftest(
        f"import sys\nsys.path.insert(0, {str(REPO)!r})\n"
        "from tests.lanes import pytest_configure\n"
        "from tests.ci_evidence import pytest_addoption\n"
    )
    (pytester.path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\npython_files = ["check_*.py"]\n'
    )
    pytester.makepyfile(check_keep="def test_keep(): pass", check_hidden="def test_hidden(): assert False")
    return pytester


def recorded(suite, *args):
    return subprocess.run(
        [sys.executable, str(REPO / "scripts/ci/run_pytest.py"),
         str(suite.path / "results"), "injection", "--", "-q", *args],
        cwd=suite.path, capture_output=True, text=True, timeout=45,
    )


@pytest.mark.parametrize("workers", [0, 2], ids=["serial", "xdist"])
@pytest.mark.parametrize("drop", ["module-test-flag", "makeitem", "plugin-ignore"])
def test_static_census_catches_drops_before_itemcollected(suite, workers, drop):
    conftest = suite.path / "conftest.py"
    if drop == "module-test-flag":
        (suite.path / "check_hidden.py").write_text("__test__ = False\ndef test_hidden(): assert False\n")
    elif drop == "makeitem":
        conftest.write_text(conftest.read_text() +
            "\ndef pytest_pycollect_makeitem(name, obj):\n"
            "    if name == 'test_hidden': return []\n")
    else:
        conftest.write_text(conftest.read_text() + "\npytest_plugins = ['hider']\n")
        (suite.path / "hider.py").write_text(
            "def pytest_ignore_collect(collection_path):\n"
            "    return collection_path.name == 'check_hidden.py'\n"
        )
    result = recorded(suite, *(("-n", str(workers)) if workers else ()))
    assert result.returncode != 0, result.stdout + result.stderr
    assert "static test census" in result.stdout + result.stderr


@pytest.mark.parametrize("source", ["pytest.ini-k", "pytest.ini-functions", "tox.ini", "setup.cfg", "environment", "pyproject-k"])
def test_alternate_config_and_environment_cannot_select_tests(suite, monkeypatch, source):
    if source == "environment":
        monkeypatch.setenv("PYTEST_ADDOPTS", "-k test_keep")
    elif source == "pyproject-k":
        path = suite.path / "pyproject.toml"
        path.write_text(path.read_text() + 'addopts = "-k test_keep"\n')
    else:
        (suite.path / "pyproject.toml").unlink()
        filename = "pytest.ini" if source.startswith("pytest.ini") else source
        section = "tool:pytest" if filename == "setup.cfg" else "pytest"
        selection = "python_functions = test_keep" if source.endswith("functions") else "addopts = -k test_keep"
        (suite.path / filename).write_text(f"[{section}]\npython_files = check_*.py\n{selection}\n")
    result = recorded(suite, "-n", "2")
    assert result.returncode != 0, result.stdout + result.stderr
    assert "UNDECLARED CONFIG" in result.stdout + result.stderr


@pytest.mark.parametrize("replace_invocation", [False, True])
def test_runner_owns_selection_before_conftest_rewrites_it(suite, replace_invocation):
    conftest = suite.path / "conftest.py"
    conftest.write_text(conftest.read_text() +
        "\nfrom tests.lanes import pytest_configure as runtime_configure\n"
        "from dataclasses import replace\n"
        "def pytest_configure(config):\n"
        "    config.option.keyword = 'test_keep'\n" +
        ("    config.invocation_params = replace(config.invocation_params, args=(*config.invocation_params.args, '-k', 'test_keep'))\n"
         if replace_invocation else "") +
        "    runtime_configure(config)\n"
    )
    result = recorded(suite, "-n", "2")
    assert result.returncode != 0, result.stdout + result.stderr
    assert "-k/-m" in result.stdout + result.stderr


def test_explicit_command_line_selection_keeps_the_static_census(suite):
    result = recorded(suite, "-n", "2", "-k", "test_keep")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


def test_static_census_preserves_inheritance_parameters_and_exact_method_selection(suite):
    (suite.path / "check_hidden.py").write_text(
        "import pytest\nimport unittest\n"
        "class Base:\n    def test_inherited(self): pass\n"
        "class TestInherited(Base): pass\n"
        "class NativeCase(unittest.TestCase):\n    def test_native(self): pass\n"
        "@pytest.mark.parametrize('value', [1, 2])\ndef test_values(value): assert value\n"
    )
    result = recorded(suite, "-n", "2", "check_hidden.py::TestInherited::test_inherited")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout
    result = recorded(suite, "-n", "2", "check_hidden.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "4 passed" in result.stdout


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def commit(repo, message):
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Gate injection", "-c", "user.email=injection@example.invalid", "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


def test_skip_binding_added_with_its_marker_cannot_approve_itself(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    git(repo, "init", "-q")
    bindings = {name: [] for name in registry_checks.SKIP_REGISTRY}
    path = repo / "tests/skip-bindings.json"
    path.write_text(json.dumps(bindings))
    base = commit(repo, "immutable empty binding set")
    git(repo, "update-ref", "refs/remotes/origin/probe-base", base)
    node = "tests/test_hidden.py::test_hidden"
    bindings["windows-process-and-lock-apis"].append(node)
    path.write_text(json.dumps(bindings))
    (repo / "tests/test_hidden.py").write_text(
        "from tests.lanes import requires_windows_process_and_lock_apis\n"
        "@requires_windows_process_and_lock_apis\ndef test_hidden(): assert False\n"
    )
    commit(repo, "self-approved skip")
    monkeypatch.setenv("GITHUB_BASE_REF", "probe-base")
    monkeypatch.setattr(registry_checks, "REPO", repo)
    monkeypatch.setattr(registry_checks, "TESTS", repo / "tests")
    monkeypatch.setattr(registry_checks.lanes, "DECLARED_SKIP_NODES", {k: tuple(v) for k, v in bindings.items()})
    # This is the existing real binding check: source and candidate JSON
    # agree, but neither may enlarge the immutable reference's authority.
    with pytest.raises(AssertionError, match="skip binding"):
        registry_checks.test_skip_bindings_match_explicit_platform_lane_uses()


def test_push_reference_uses_the_pushed_branch_history(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "value").write_text("plan")
    plan = commit(repo, "unrelated plan tip")
    git(repo, "update-ref", "refs/remotes/origin/release/14/plan-39", plan)
    (repo / "value").write_text("published before push")
    before = commit(repo, "pushed branch before")
    (repo / "value").write_text("first commit in this push")
    commit(repo, "first unreviewed pushed commit")
    (repo / "value").write_text("new push")
    head = commit(repo, "pushed candidate")
    git(repo, "update-ref", "refs/remotes/origin/release/14/main", head)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": before, "ref": "refs/heads/release/14/main"}))
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/release/14/main")
    monkeypatch.setenv("GITHUB_REF_NAME", "release/14/main")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert reference_commit(repo) == before


@pytest.mark.parametrize("change", ["missing", "zero", "wrong-branch"])
def test_push_reference_refuses_missing_or_ambiguous_event_authority(tmp_path, monkeypatch, change):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/release/14/main")
    event = tmp_path / "event.json"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    if change != "missing":
        event.write_text(json.dumps({"before": "0" * 40 if change == "zero" else "a" * 40,
                                   "ref": "refs/heads/other" if change == "wrong-branch" else "refs/heads/release/14/main"}))
    with pytest.raises(ValueError, match="push merge base unavailable"):
        reference_commit(tmp_path)


def test_gate_replacement_requires_an_exact_head_owner_approval(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts/ci").mkdir(parents=True)
    git(repo, "init", "-q")
    checker = repo / "scripts/ci/check_test_results.py"
    checker.write_text("raise SystemExit(1)\n")
    (repo / "application.py").write_text("VALUE = 1\n")
    base = commit(repo, "original gate")
    checker.write_text("raise SystemExit(0)\n")
    (repo / "application.py").write_text("VALUE = 2\n")
    commit(repo, "forged candidate gate")
    policy = REPO / "scripts/ci/protect_gate_paths.py"
    # Before the trusted policy exists, CI runs the forged candidate copy.
    command = ([sys.executable, "-I", str(policy), "--base-ref", base]
               if policy.is_file() else [sys.executable, str(checker)])
    result = subprocess.run(command, cwd=repo, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "protected gate changes require" in result.stdout


def test_trusted_gate_approval_is_exact_current_and_revocable():
    from scripts.ci.protect_gate_paths import approving_owner

    head = "a" * 40
    review = {"id": 1, "state": "APPROVED", "commit_id": head, "user": {"login": "gate-owner"}}
    assert approving_owner(head, {"gate-owner"}, [review]) == "gate-owner"
    assert approving_owner("b" * 40, {"gate-owner"}, [review]) is None
    assert approving_owner(head, {"someone-else"}, [review]) is None
    assert approving_owner(head, set(), [review]) is None
    for state in ("CHANGES_REQUESTED", "DISMISSED"):
        assert approving_owner(head, {"gate-owner"}, [review, {**review, "id": 2, "state": state}]) is None


def test_skip_bindings_allow_only_removal_and_require_history(tmp_path):
    from tests.quarantine_policy import compare_skip_bindings, merge_base_skip_binding_errors

    original = {"platform": ["tests/test_a.py::test_a", "tests/test_a.py::test_b"]}
    assert compare_skip_bindings({"platform": original["platform"][:1]}, original) == []
    assert compare_skip_bindings({}, original) == []
    assert compare_skip_bindings({"other-platform": original["platform"]}, original)
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    git(repo, "init", "-q")
    (repo / "application.py").write_text("VALUE = 1\n")
    base = commit(repo, "base without binding table")
    (repo / "tests/skip-bindings.json").write_text(json.dumps(original))
    commit(repo, "candidate-created binding table")
    assert any("missing base registry" in error for error in merge_base_skip_binding_errors(repo, base=base))
