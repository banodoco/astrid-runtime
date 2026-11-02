from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from astrid_runtime import custody_broker as custody


@pytest.mark.skipif(sys.platform == "win32", reason="native POSIX directory modes")
def test_public_native_scope_is_refused_without_publishing_custody(tmp_path: Path):
    scope = tmp_path / "PUBLIC_NATIVE"
    scope.mkdir(mode=0o700)
    scope.chmod(0o777)
    child = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"])
    try:
        identity = custody.default_process_identity(child.pid)
        assert identity is not None
        target = {key: identity[key] for key in ("pid", "uid", "birth_id")}
        instance = custody.NativeProcessCustody(scope, target)

        with pytest.raises(custody.CustodyError, match="native custody parent is not privately owned"):
            instance.publish()

        assert scope.stat().st_mode & 0o777 == 0o777
        assert not instance.path.exists()
        assert not instance.lock.exists()
    finally:
        child.kill()
        child.wait(timeout=5)
