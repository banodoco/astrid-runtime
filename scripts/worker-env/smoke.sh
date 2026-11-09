#!/usr/bin/env bash
# SMOKE check for a single-repo cloud worker (shared astrid-dev utility; see env/README.md).
# Usage, from the product checkout root: bash /home/user/astrid-dev/env/smoke.sh agent|vc|runtime <one pytest selector>
# Runs the matching setup, then that one test. Prints ENV-PASS or ENV-FAIL with the failing step; exit 3 = environment problem.
set -euo pipefail
kind="${1:-}"; sel="${2:-}"
D=$(cd "$(dirname "$0")" && pwd -P)
case "$kind" in
  agent) setup="$D/agent-setup.sh"; run="$D/agent-pytest.sh" ;;
  vc) setup="$D/vc-setup.sh"; run="$D/vc-pytest.sh" ;;
  runtime) setup="$D/runtime-setup.sh"; run="$D/runtime-pytest.sh" ;;
  *) echo "usage: smoke.sh agent|vc|runtime <selector>" >&2; exit 2 ;;
esac
test -n "$sel" || { echo "usage: smoke.sh agent|vc|runtime <selector>" >&2; exit 2; }
bash "$setup" || { echo "ENV-FAIL setup ($kind)"; exit 3; }
bash "$run" -q "$sel" || { echo "ENV-FAIL test $sel"; exit 3; }
echo "ENV-PASS $kind $sel"
