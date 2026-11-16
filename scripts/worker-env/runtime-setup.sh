#!/usr/bin/env bash
# SETUP for an astrid-runtime checkout in a single-repository worker.
# Run from the Runtime checkout root. Builds <checkout>.env/ next to it.
# Installs Runtime test dependencies and the Python client, then fetches the Agent
# at tests/astrid-agent.pin and verifies the exact commit before installing it.
# Installs an environment-local Node 22 and the lockfile's TypeScript compiler.
# Needs uv, git, node/npm, Python 3.13, and public reads from PyPI, npm and GitHub.
set -euo pipefail
trap 'status=$?; echo "ENV: setup failed (exit $status): $BASH_COMMAND" >&2; exit 3' ERR
for t in uv git node npm; do command -v "$t" >/dev/null || { echo "ENV: missing tool $t" >&2; exit 3; }; done
CO=$(pwd -P); E="$CO.env"
test -f "$CO/pyproject.toml" -a -f "$CO/tests/astrid-agent.pin" -a -d "$CO/packages/python" \
  -a -f "$CO/packages/typescript/package.json" -a -f "$CO/packages/typescript/package-lock.json" || {
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
npm install --prefix "$E/node" --no-save --no-package-lock --no-audit --no-fund node@22
export PATH="$E/node/node_modules/.bin:$CO/packages/typescript/node_modules/.bin:$PATH"
NODE_VERSION=$("$E/node/node_modules/.bin/node" --version)
[[ "$NODE_VERSION" =~ ^v22\. ]] || {
  echo "ENV: Runtime worker requires Node 22" >&2; exit 3;
}
npm ci --prefix "$CO/packages/typescript" --include=dev --no-audit --no-fund
TSC_VERSION=$("$CO/packages/typescript/node_modules/.bin/tsc" --version)
PYTHON_VERSION=$("$PY" -c 'import sys; print(sys.version.split()[0])')
dirname "$(command -v uv)" > "$E/uv-dir"
printf 'python=%s\nagent=%s\nnode=%s\ntsc=%s\n' \
  "$PYTHON_VERSION" "$AGENT_SHA" "$NODE_VERSION" "$TSC_VERSION" | tee "$E/setup.txt"
