"""Leaf entry point for a launcher-bound pack-host observation.

Invoke with the selected installation's interpreter in isolated mode:
``python -I -m astrid_runtime.pack_host_observer --json --data-root ...``.
The launcher must validate that interpreter and its installed Runtime first.
The process identifiers below are consistency evidence, never signal authority.
"""

from __future__ import annotations

import os
import sys


# Defence in depth for the trusted observer implementation: no process creation
# or interpreter replacement after this entry point starts.  The interpreter and
# package initialization are part of the installation the launcher validates.
_PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "os.fork", "os.forkpty", "os.posix_spawn",
    "os.spawn", "os.exec", "os.system", "pty.spawn",
})


def _deny_process_creation(event: str, args: tuple) -> None:
    if event in _PROCESS_EVENTS:
        raise RuntimeError("observer process creation refused")


def main(argv: list[str] | None = None) -> int:
    sys.addaudithook(_deny_process_creation)
    # This is the Runtime's fixed observer path, not a pack entry point.
    from . import cli

    try:
        args = cli.parser().parse_args(["observe-pack-host", *(sys.argv[1:] if argv is None else argv)])
        paths = cli._paths(args)
        observation = cli._observe_pack_host(
            paths, instance=args.runtime_instance_id, session=args.runtime_session_id,
            epoch=args.runtime_epoch, expected_endpoint=args.endpoint,
        )
        cli._emit({"observer_pid": os.getpid(), "observer_parent_pid": os.getppid(),
                   "observation": observation}, json_mode=True)
        return 0
    except Exception:
        cli._emit({"ok": False, "error": "pack host observation unavailable"}, json_mode=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
