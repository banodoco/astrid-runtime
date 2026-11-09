"""Locate the second checkout the integration lane needs: Astrid.

``ASTRID_CHECKOUT`` names the Astrid repository root (the folder that holds the
``astrid`` package). Without it the sibling ``../astrid`` is used. A missing
checkout fails the test; it is never a skip.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

RUNTIME_ROOT = Path(__file__).resolve().parents[1]


def astrid_checkout() -> Path:
    root = Path(os.environ.get("ASTRID_CHECKOUT") or RUNTIME_ROOT.parent / "astrid").resolve()
    if not (root / "astrid" / "core" / "execution" / "generic_host.py").is_file():
        raise AssertionError(
            f"Astrid checkout is unavailable: {root} (set ASTRID_CHECKOUT to the Astrid repository root)"
        )
    return root


@pytest.fixture
def astrid_importable(monkeypatch):
    """Import ``astrid`` from the checkout; its third-party dependencies come from the interpreter."""
    monkeypatch.syspath_prepend(str(astrid_checkout()))
    for name in [n for n in sys.modules if n == "astrid" or n.startswith("astrid.")]:
        if not str(getattr(sys.modules[name], "__file__", "") or "").startswith(str(astrid_checkout())):
            monkeypatch.delitem(sys.modules, name)
    return astrid_checkout()


_STUB_SERVICES = '''"""Minimal selected Agent for Runtime `down` dispatch tests."""
CALLS = []


def prepare_pack_host_shutdown(*, support_root, source_checkout, runtime_instance_id):
    CALLS.append({"support_root": support_root, "source_checkout": source_checkout,
                  "runtime_instance_id": runtime_instance_id})
    return None
'''


def _agent_module(name: str) -> bool:
    return name.split(".", 1)[0] in {"astrid", "astrid_runtime_client"}


@pytest.fixture
def selected_agent_stub(tmp_path, monkeypatch):
    """A real, symlink-free selected Agent checkout defining only the shutdown helper.

    CLI ``down`` selects the manifest's Agent (``selected_shutdown_owner``) and
    refuses an already imported foreign Agent, so unit tests that dispatch
    ``down`` need a selected checkout but not the full Astrid one. Foreign
    cached Agent modules are hidden for the test and restored after it; the
    stub's own modules never outlive it.
    """
    root = (tmp_path / "selected-agent").resolve()
    (root / "astrid").mkdir(parents=True)
    (root / "astrid" / "__init__.py").write_text("")
    (root / "astrid" / "services.py").write_text(_STUB_SERVICES)
    for name in [n for n in sys.modules if _agent_module(n)]:
        monkeypatch.delitem(sys.modules, name)
    yield root
    for name in [n for n in sys.modules if _agent_module(n)]:
        origin = getattr(sys.modules[name], "__file__", None) or ""
        if origin.startswith(str(root)):
            del sys.modules[name]
