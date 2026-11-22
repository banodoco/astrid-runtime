"""Manual qualification against explicitly supplied private init artifacts.

ASTRID_PRIVATE_QUALIFICATION_ROOT must contain prepare-private.py. The Agent
source is selected by tests.astrid_checkout, exactly as in the integration lane.
The private artifacts are not part of the repository or ordinary CI coverage.
"""
import os
from pathlib import Path
import subprocess
import sys

from tests.astrid_checkout import astrid_checkout


def test_private_init_and_commit_neighbors():
    configured = os.environ.get('ASTRID_PRIVATE_QUALIFICATION_ROOT')
    assert configured, 'set ASTRID_PRIVATE_QUALIFICATION_ROOT to the private qualification artifacts'
    worker = Path(configured).resolve()
    prepare = worker / 'prepare-private.py'
    assert prepare.is_file(), f'private qualification preparation script is unavailable: {prepare}'
    agent = astrid_checkout()
    python = sys.executable
    runtime = Path(__file__).resolve().parents[1]
    subprocess.run([python, str(prepare), str(runtime)], check=True)
    candidate = worker / 'runtime-private'
    result = subprocess.run([
        python, '-m', 'pytest', '-q', '-ra', '-o', 'addopts=', '-p', 'no:cacheprovider', '--runxfail',
        'tests/test_timeline_pristine_initialize_integration.py',
        'tests/test_timeline_absent_head_repair_integration.py',
        'tests/test_repaired_init_durability.py',
        'tests/test_timeline_commit_integration.py',
        'tests/test_timeline_projection_occupancy.py::test_actual_provider_historical_slot_rematerializes_after_verified_restore',
    ], cwd=candidate, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(candidate),
                           'ASTRID_CHECKOUT': str(agent)},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (worker / 'central-private.log').write_text(result.stdout)
    assert result.returncode == 0, result.stdout
