"""Explicit central qualification against frozen private init artifacts."""
import os
from pathlib import Path
import subprocess

WORKER = Path('/tmp/claude-0/-home-user-repo/7dc61be1-7066-52e0-a5d0-94f90e61430a/scratchpad/orch/workers/rt-m2-absent-head-shell-repair')


def test_private_init_and_commit_neighbors():
    python = '/home/user/work/venv-agent/bin/python'
    subprocess.run([python, str(WORKER / 'prepare-private.py'), str(Path.cwd())], check=True)
    candidate = WORKER / 'runtime-private'
    result = subprocess.run([
        python, '-m', 'pytest', '-q', '-ra', '-o', 'addopts=', '-p', 'no:cacheprovider', '--runxfail',
        'tests/test_timeline_pristine_initialize_integration.py',
        'tests/test_timeline_absent_head_repair_integration.py',
        'tests/test_repaired_init_durability.py',
        'tests/test_timeline_commit_integration.py',
        'tests/test_timeline_projection_occupancy.py::test_actual_provider_historical_slot_rematerializes_after_verified_restore',
    ], cwd=candidate, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(candidate),
                           'ASTRID_CHECKOUT': str(WORKER.parent / 'rt-m2-init-current-private-qualification/agent-source')},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (WORKER / 'central-private.log').write_text(result.stdout)
    assert result.returncode == 0, result.stdout
