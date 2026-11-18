#!/bin/sh
# Run the test suite in sandbox process-control mode inside a container whose
# seccomp profile denies what NVIDIA OpenShell's does (see README.md). CI's
# sandbox-process-control job runs this; extra arguments go to pytest.
# Optional ASTRID_CHECKOUT is mounted read-only, then copied into the owned
# workspace with its .git history. Optional ASTRID_TEST_RESULTS_DIR is mounted
# read/write at /test-results for JUnit output.
#   sh tests/seccomp/run-suite.sh [pytest args...]
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
agent_checkout=${ASTRID_CHECKOUT:-}
results_dir=${ASTRID_TEST_RESULTS_DIR:-}

if [ -n "$agent_checkout" ]; then
    case "$agent_checkout" in
        /*) ;;
        *) echo "ASTRID_CHECKOUT must be an absolute path" >&2; exit 2 ;;
    esac
    agent_checkout=$(CDPATH= cd -- "$agent_checkout" && pwd -P) || {
        echo "ASTRID_CHECKOUT is not a readable directory: $ASTRID_CHECKOUT" >&2
        exit 2
    }
    if [ ! -f "$agent_checkout/astrid/core/execution/generic_host.py" ]; then
        echo "ASTRID_CHECKOUT does not contain the pinned Astrid source: $agent_checkout" >&2
        exit 2
    fi
fi

if [ -n "$results_dir" ]; then
    case "$results_dir" in
        /*) ;;
        *) echo "ASTRID_TEST_RESULTS_DIR must be an absolute path" >&2; exit 2 ;;
    esac
    mkdir -p "$results_dir"
    results_dir=$(CDPATH= cd -- "$results_dir" && pwd -P) || {
        echo "ASTRID_TEST_RESULTS_DIR is not a writable directory: $ASTRID_TEST_RESULTS_DIR" >&2
        exit 2
    }
    if [ ! -w "$results_dir" ]; then
        echo "ASTRID_TEST_RESULTS_DIR is not writable: $results_dir" >&2
        exit 2
    fi
fi

python3 - "$root" "$agent_checkout" "$results_dir" "$@" <<'PY'
import os
import subprocess
import sys

root, agent_checkout, results_dir, *pytest_args = sys.argv[1:]
cmd = [
    "docker", "run", "--rm",
    "--security-opt", f"seccomp={root}/tests/seccomp/openshell-like.json",
    "-v", f"{root}:/src:ro",
]
if agent_checkout:
    cmd.extend((
        "--mount", f"type=bind,source={agent_checkout},target=/astrid-agent,readonly",
        "-e", "ASTRID_AGENT_MOUNT=/astrid-agent",
    ))
if results_dir:
    cmd.extend(("--mount", f"type=bind,source={results_dir},target=/test-results"))
# Carry only comparison metadata, never the job token, into the sandbox.
# The push event's immutable before SHA must not become the local plan fallback.
for name in ("GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_REF"):
    if name in os.environ:
        cmd.extend(("-e", f"{name}={os.environ[name]}"))
if event := os.environ.get("GITHUB_EVENT_PATH"):
    cmd.extend(("--mount", f"type=bind,source={event},target=/runtime-github-event.json,readonly",
                "-e", "GITHUB_EVENT_PATH=/runtime-github-event.json"))
cmd.extend(("python:3.11", "python", "/src/tests/seccomp/container-entrypoint.py", *pytest_args))
raise SystemExit(subprocess.run(cmd, check=False).returncode)
PY
