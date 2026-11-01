"""Capture the immutable product/source identity for one Runtime owner."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def capture_startup_identity(*, runtime_checkout: str | Path | None = None,
                             agent_checkout: str | Path | None = None,
                             environ: Mapping[str, str] | None = None) -> dict:
    # Read both installer fields from one point-in-time mapping so a concurrent
    # environment update cannot produce a mixed identity.
    env = dict(os.environ if environ is None else environ)
    # An installed profile may point at unpacked archive directories. Its
    # stamped install identity is authoritative and those paths are not Git.
    if "ASTRID_INSTALL_RELEASE" not in env and "ASTRID_INSTALL_MANAGED_BY" not in env and (runtime_checkout is not None or agent_checkout is not None):
        if runtime_checkout is None or agent_checkout is None:
            raise ValueError("source startup identity requires both Runtime and agent checkouts")
        runtime_root, agent_root = Path(runtime_checkout), Path(agent_checkout)
        # Only two existing, absolute non-checkout directories imply an
        # unstamped installed profile. Mixed or invalid roots still go through
        # strict source validation and cannot silently lose source provenance.
        installed_roots = all(p.is_absolute() and p.is_dir() and not (p / ".git").exists()
                              and not (p / ".git").is_symlink()
                              for p in (runtime_root, agent_root))
        if not installed_roots:
            from .source_identity import capture_source_identity
            return capture_source_identity(runtime_root, agent_root)
    raw_release = env.get("ASTRID_INSTALL_RELEASE", "0")
    try:
        release = int(raw_release, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError("ASTRID_INSTALL_RELEASE must be a nonnegative decimal integer") from exc
    if release < 0 or str(release) != str(raw_release).strip():
        raise ValueError("ASTRID_INSTALL_RELEASE must be a nonnegative decimal integer")
    managed_by = env.get("ASTRID_INSTALL_MANAGED_BY", "") or None
    if managed_by not in (None, "pinokio"):
        raise ValueError("ASTRID_INSTALL_MANAGED_BY must be empty or pinokio")
    return {"release": release, "managed_by": managed_by}
