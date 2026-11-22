#!/usr/bin/env bash
# Run pytest in the Runtime worker environment created by runtime-setup.sh.
set -euo pipefail
CO=$(pwd -P); E="$CO.env"
test -x "$E/venv/bin/python" -a -x "$E/node/node_modules/.bin/node" \
  -a -x "$CO/packages/typescript/node_modules/.bin/tsc" -a -f "$E/uv-dir" || {
  echo "ENV: run runtime-setup.sh first in $CO" >&2; exit 3;
}
BT="$E/basetemp/$(date +%s%N)"
exec env -i PATH="$E/venv/bin:$E/node/node_modules/.bin:$CO/packages/typescript/node_modules/.bin:$(cat "$E/uv-dir"):/usr/local/bin:/usr/bin:/bin" \
  HOME="$E/home" TMPDIR="$E/tmp" PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-}" \
  XDG_CACHE_HOME="$E/cache" LANG=C.UTF-8 PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  ASTRID_CHECKOUT="$E/agent" PYTHONPATH="$CO/packages/python" \
  "$E/venv/bin/python" -m pytest -p no:cacheprovider --basetemp="$BT" "$@"
