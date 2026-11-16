#!/bin/sh
# Run the test suite in sandbox process-control mode inside a container whose
# seccomp profile denies what OpenShell's does (see README.md). CI's
# sandbox-process-control job runs this; extra arguments go to pytest.
#   sh tests/seccomp/run-suite.sh [pytest args...]
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
results_dir=${ASTRID_TEST_RESULTS_DIR:-$root/test-results}
mkdir -p "$results_dir"
exec docker run --rm --security-opt "seccomp=$root/tests/seccomp/openshell-like.json" \
    -v "$root":/src:ro -v "$results_dir":/test-results python:3.11 sh -ec '
        apt-get update -qq && apt-get install -y -qq ffmpeg nodejs npm >/dev/null
        useradd -m ci
        chown -R ci /test-results
        cp -a /src /home/ci/w && chown -R ci /home/ci/w
        exec su ci -c "cd /home/ci/w && python -m venv /home/ci/v \
            && /home/ci/v/bin/pip install -q -e .[test] -e packages/python \
            && /home/ci/v/bin/python -m pytest -q -n 2 --process-control=sandbox \
               -m \"not integration and not darwin_native and not live and not needs_real_pidfd\" $*"
    ' sh "$@"
