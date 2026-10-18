"""Runs an external tool (Checkov, Bandit, zizmor, pip-audit, npm) for the agents.

The tool runs in its own process group (POSIX). On a timeout, or any other
error such as Ctrl-C, the whole group is killed and reaped, so no child
process is left running. The original exception (e.g. TimeoutExpired) is
re-raised; each agent turns it into its own error type.

Windows has no process groups here: only the tool itself is killed.
"""

import os
import signal
import subprocess

KILL_WAIT_SECONDS = 5


def run_tool(
    cmd: list[str], timeout: float, cwd: str | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    """Run a tool in its own process group. On a timeout (or any other error,
    e.g. Ctrl-C) the whole group is killed and reaped, so nothing is left running."""
    posix = os.name == "posix"
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=env,
        start_new_session=posix,  # new session: process group id == proc.pid
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException:
        _kill_group(proc, posix)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _kill_group(proc: subprocess.Popen, posix: bool) -> None:
    if posix:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # already gone
    else:
        proc.kill()  # Windows: no process groups here, only the tool itself
    try:
        proc.communicate(timeout=KILL_WAIT_SECONDS)  # reap it and drain the pipes
    except subprocess.TimeoutExpired:
        # Something outside the group still holds the pipes; the tool itself is dead.
        proc.wait()
