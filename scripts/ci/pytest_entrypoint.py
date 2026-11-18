"""Capture the runner's arguments before importing candidate conftests."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class DeclaredInvocation:
    args: tuple[str, ...]
    directory: Path


class CaptureInvocation:
    def __init__(self, invocation):
        self.invocation = invocation

    @pytest.hookimpl(tryfirst=True)
    def pytest_load_initial_conftests(self, early_config):
        early_config.pluginmanager.register(self.invocation, "runtime-declared-invocation")


def main():
    # Installed pytest is already imported under -I. Restore the paths the
    # tests need only afterward; the trusted script path is protected too.
    directory = Path.cwd()
    sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(directory),
                   *filter(None, os.environ.get("PYTHONPATH", "").split(os.pathsep))]
    from tests.collection_policy import configuration_errors

    invocation = DeclaredInvocation(tuple(sys.argv[1:]), directory)
    errors = configuration_errors(directory, invocation.args)
    if errors:
        for error in errors:
            print(f"UNDECLARED CONFIG: {error}", file=sys.stderr)
        return pytest.ExitCode.USAGE_ERROR
    return pytest.main(list(invocation.args), plugins=[CaptureInvocation(invocation)])


if __name__ == "__main__":
    raise SystemExit(main())
