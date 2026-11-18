"""Run the same pytest selection twice: inventory first, then recorded execution."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def collection_args(args: list[str]) -> list[str]:
    result = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-n", "--numprocesses"}:
            index += 2
            continue
        if arg.startswith("--numprocesses=") or (arg.startswith("-n") and len(arg) > 2):
            index += 1
            continue
        result.append(arg)
        index += 1
    return result


def logged_run(command: list[str], log: Path) -> int:
    with log.open("w", encoding="utf-8", buffering=1) as output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        assert process.stdout is not None
        try:
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                output.write(line)
                output.flush()
            return process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("name")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    args = options.pytest_args
    if args[:1] == ["--"]:
        args = args[1:]
    if any(arg.startswith(("--collection-manifest", "--result-log", "--junit", "--collect-only", "--co")) for arg in args):
        parser.error("the runner owns collection and result output options")
    directory = options.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "collection.json"
    selection = [sys.executable, "-m", "pytest", f"--collection-manifest={manifest}"]
    status = logged_run([*selection, "--collect-only", *collection_args(args)], directory / "collection.log")
    if status:
        return status
    return logged_run([
        *selection, "-rA", f"--junitxml={directory / (options.name + '.xml')}",
        f"--result-log={directory / 'events.jsonl'}", *args,
    ], directory / "pytest.log")


if __name__ == "__main__":
    raise SystemExit(main())
