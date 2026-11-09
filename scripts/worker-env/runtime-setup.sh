#!/usr/bin/env bash
# SETUP for an astrid-runtime checkout in a single-repository worker.
# Run from the Runtime checkout root. Builds <checkout>.env/ next to it.
# Installs Runtime test dependencies and the Python client, then fetches the Agent
# at tests/astrid-agent.pin and verifies the exact commit before installing it.
# Needs uv, git, Python 3.13, and public reads from PyPI and GitHub.
set -euo pipefail
trap 'status=$?; echo "ENV: setup failed (exit $status): $BASH_COMMAND" >&2; exit 3' ERR
for t in uv git; do command -v "$t" >/dev/null || { echo "ENV: missing tool $t" >&2; exit 3; }; done
CO=$(pwd -P); E="$CO.env"
test -f "$CO/pyproject.toml" -a -f "$CO/tests/astrid-agent.pin" -a -d "$CO/packages/python" || {
  echo "ENV: not an astrid-runtime checkout: $CO" >&2; exit 3;
}
AGENT_SHA=$(tr -d '[:space:]' < "$CO/tests/astrid-agent.pin")
[[ "$AGENT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "ENV: invalid tests/astrid-agent.pin" >&2; exit 3; }
rm -rf "$E"; mkdir -p "$E/home" "$E/tmp" "$E/cache" "$E/basetemp"
uv venv -q --seed --python 3.13 "$E/venv"
PY="$E/venv/bin/python"
uv pip install -q --python "$PY" -e "$CO[test]"
uv pip install -q --python "$PY" -e "$CO/packages/python"
git init -q "$E/agent"
git -C "$E/agent" fetch -q --depth=1 https://github.com/banodoco/astrid-agent "$AGENT_SHA"
git -C "$E/agent" checkout -q --detach FETCH_HEAD
test "$(git -C "$E/agent" rev-parse HEAD)" = "$AGENT_SHA" || {
  echo "ENV: fetched Agent SHA does not match tests/astrid-agent.pin ($AGENT_SHA)" >&2; exit 3;
}
uv pip install -q --python "$PY" --no-deps "$E/agent"
dirname "$(command -v uv)" > "$E/uv-dir"
printf 'python=%s\nagent=%s\n' "$("$PY" -c 'import sys; print(sys.version.split()[0])')" "$AGENT_SHA" | tee "$E/setup.txt"
