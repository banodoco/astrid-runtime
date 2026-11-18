"""Prepare a disposable sandbox container and run its selected pytest command."""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


def run(
    command: list[str], *, env: dict[str, str] | None = None,
    preexec_fn=None,
    cwd: Path | None = None,
) -> None:
    subprocess.run(command, check=True, env=env, preexec_fn=preexec_fn, cwd=cwd)


def chown_tree(root: Path, uid: int, gid: int) -> None:
    for path in (root, *root.rglob("*")):
        os.chown(path, uid, gid, follow_symlinks=False)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("sandbox container entrypoint must start as root")

    run(["apt-get", "update", "-qq"])
    run(["apt-get", "install", "-y", "-qq", "ffmpeg", "nodejs", "npm"])
    run(["useradd", "-m", "ci"])
    ci = pwd.getpwnam("ci")

    def drop_privileges() -> None:
        os.setgroups([])
        os.setgid(ci.pw_gid)
        os.setuid(ci.pw_uid)

    workspace = Path("/home/ci/w")
    virtualenv = Path("/home/ci/v")
    agent_checkout = Path("/home/ci/astrid-agent")
    shutil.copytree("/src", workspace, symlinks=True)
    chown_tree(workspace, ci.pw_uid, ci.pw_gid)

    env = os.environ.copy()
    env.update(HOME=ci.pw_dir, USER=ci.pw_name, LOGNAME=ci.pw_name)
    if agent_mount := env.pop("ASTRID_AGENT_MOUNT", ""):
        source = Path(agent_mount)
        if not (source / ".git").is_dir() or not (source / "astrid/core/execution/generic_host.py").is_file():
            raise SystemExit(f"mounted Agent source is missing its checkout or .git history: {source}")
        shutil.copytree(source, agent_checkout, symlinks=True)
        chown_tree(agent_checkout, ci.pw_uid, ci.pw_gid)
        env["ASTRID_CHECKOUT"] = str(agent_checkout)

    run([sys.executable, "-m", "venv", str(virtualenv)], preexec_fn=drop_privileges)
    python = virtualenv / "bin/python"
    run(
        [str(python), "-m", "pip", "install", "-q", "-e", ".[test]", "-e", "packages/python"],
        env=env, preexec_fn=drop_privileges, cwd=workspace,
    )
    run(["npm", "ci"], env=env, preexec_fn=drop_privileges, cwd=workspace / "packages/typescript")
    if env.get("ASTRID_CHECKOUT"):
        run(
            [str(python), "-m", "pip", "install", "-q", env["ASTRID_CHECKOUT"]],
            env=env, preexec_fn=drop_privileges, cwd=workspace,
        )

    if Path("/test-results").is_dir():
        os.chown("/test-results", ci.pw_uid, ci.pw_gid)

    command = [
        str(python), "-m", "pytest", "-q", "-n", "2", "--process-control=sandbox",
        "-m", "not integration and not darwin_native and not live and not needs_real_pidfd",
        *sys.argv[1:],
    ]
    env["PATH"] = f"{workspace / 'packages/typescript/node_modules/.bin'}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(command, cwd=workspace, env=env, preexec_fn=drop_privileges, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
