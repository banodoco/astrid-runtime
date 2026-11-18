"""Collection custody and flushed per-report evidence for Runtime pytest jobs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _pytest.mark import KeywordMatcher, MarkMatcher
from _pytest.mark.expression import Expression


def pytest_addoption(parser):
    group = parser.getgroup("Runtime CI evidence")
    group.addoption("--collection-manifest", help="write in --collect-only; verify the same selected IDs during execution")
    group.addoption("--result-log", help="flush each collection and test report as JSONL on the controller")


def configure(config):
    config.pluginmanager.register(CollectionGuard(config), "collection-guard")
    path = config.getoption("--result-log", default=None)
    if path and not hasattr(config, "workerinput"):
        config.pluginmanager.register(ResultLog(Path(path)), "incremental-results")


class CollectionGuard:
    def __init__(self, config):
        self.config = config
        self.collected = {}
        self.errors = set()
        for option in ("deselect", "ignore", "ignore_glob"):
            if config.getoption(option, default=None):
                raise pytest.UsageError(f"UNDECLARED DESELECTION: --{option.replace('_', '-')} is not a declared lane")

    def _reject(self, message):
        if message in self.errors:
            return
        self.errors.add(message)
        # A collection report is transported by xdist. Raising UsageError
        # only in a worker loses the explanation and breaks its scheduler.
        self.config.hook.pytest_collectreport(report=pytest.CollectReport(
            nodeid="collection-policy", outcome="failed", longrepr=message, result=[],
        ))

    def pytest_itemcollected(self, item):
        self.collected[item.nodeid] = item

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, session, config, items):
        # pytest_itemcollected happens before *any* modifyitems hook. Computing
        # the permitted -m/-k selection from those items catches a conftest
        # that silently removes an item, including a tryfirst hook.
        expected = list(self.collected.values())
        if config.option.markexpr:
            expression = Expression.compile(config.option.markexpr)
            expected = [item for item in expected if expression.evaluate(MarkMatcher.from_markers(item.iter_markers()))]
        if config.option.keyword:
            expression = Expression.compile(config.option.keyword.lstrip())
            expected = [item for item in expected if expression.evaluate(KeywordMatcher.from_item(item))]
        expected_ids = {item.nodeid for item in expected}
        result = yield
        actual_ids = {item.nodeid for item in items}
        if actual_ids != expected_ids:
            self._reject(
                "UNDECLARED DESELECTION: collection hooks changed the declared selection; "
                f"missing={sorted(expected_ids - actual_ids)} added={sorted(actual_ids - expected_ids)}"
            )
        return result

    def _check_ignored_paths(self):
        for module in self.config.pluginmanager._conftest_plugins:
            for name in ("collect_ignore", "collect_ignore_glob"):
                if getattr(module, name, None):
                    self._reject(f"UNDECLARED DESELECTION: {module.__file__} sets {name}")
            if hasattr(module, "pytest_ignore_collect"):
                self._reject(f"UNDECLARED DESELECTION: {module.__file__} defines a collection-ignore hook")

    def _check_manifest(self, nodeids):
        path = self.config.getoption("--collection-manifest", default=None)
        if not path:
            return
        manifest = Path(path)
        actual = sorted(nodeids)
        if self.config.option.collectonly:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(json.dumps({"nodeids": actual}, indent=2) + "\n", encoding="utf-8")
            return
        try:
            expected = json.loads(manifest.read_text(encoding="utf-8"))["nodeids"]
        except (OSError, ValueError, KeyError) as exc:
            self._reject(f"collection manifest unavailable: {manifest}: {exc}")
            return
        if not expected or actual != sorted(expected):
            self._reject(
                "UNDECLARED DESELECTION: execution differs from independent --collect-only inventory; "
                f"missing={sorted(set(expected) - set(actual))} added={sorted(set(actual) - set(expected))}"
            )

    def pytest_collection_finish(self, session):
        self._check_ignored_paths()
        # The controller has no local items under xdist. Each worker verifies
        # the same manifest; the controller independently checks its IDs too.
        controller = bool(getattr(session.config.option, "numprocesses", 0)) and not hasattr(session.config, "workerinput")
        if not controller:
            self._check_manifest([item.nodeid for item in session.items])

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        self._check_manifest(ids)


class ResultLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("w", encoding="utf-8", buffering=1)
        self.write("start")

    def write(self, event, **fields):
        self.stream.write(json.dumps({"event": event, **fields}, sort_keys=True) + "\n")
        self.stream.flush()

    def pytest_collection_finish(self, session):
        if session.items:
            self.write("collection", nodeids=[item.nodeid for item in session.items])

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        self.write("collection", worker=node.gateway.id, nodeids=list(ids))

    def pytest_collectreport(self, report):
        if report.failed or report.skipped:
            self.write("collection_report", nodeid=report.nodeid, outcome=report.outcome, detail=str(report.longrepr))

    def pytest_runtest_logreport(self, report):
        self.write(
            "test_report", nodeid=report.nodeid, when=report.when, outcome=report.outcome,
            wasxfail=getattr(report, "wasxfail", None), subtest=hasattr(report, "context"),
            detail=str(report.longrepr) if report.failed or report.skipped else "",
        )

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        self.write("finish", exitstatus=int(session.exitstatus), collected=session.testscollected)

    def pytest_unconfigure(self, config):
        self.stream.close()
