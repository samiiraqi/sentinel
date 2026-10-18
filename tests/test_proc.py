import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shared import proc as proc_module
from shared.proc import run_tool


class FakePopen:
    """Popen whose first communicate() fails with `first_error`."""

    instances = []

    def __init__(self, cmd, **kwargs):
        self.cmd, self.kwargs = cmd, kwargs
        self.pid = 4242
        self.returncode = -9
        self.communicate_calls = []
        self.first_error = FakePopen.next_error
        FakePopen.instances.append(self)

    def communicate(self, timeout=None):
        self.communicate_calls.append(timeout)
        if len(self.communicate_calls) == 1 and self.first_error:
            raise self.first_error
        return "", ""


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
@pytest.mark.parametrize(
    "error",
    [subprocess.TimeoutExpired(["tool"], 5), KeyboardInterrupt()],
    ids=["timeout", "ctrl-c"],
)
def test_run_tool_kills_whole_group_on_error(monkeypatch, error):
    killed = []
    FakePopen.instances, FakePopen.next_error = [], error
    monkeypatch.setattr(proc_module.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(proc_module.os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))

    with pytest.raises(type(error)):
        run_tool(["tool"], timeout=5)

    proc = FakePopen.instances[0]
    assert proc.kwargs["start_new_session"] is True
    assert killed == [(4242, signal.SIGKILL)]
    assert proc.communicate_calls == [5, proc_module.KILL_WAIT_SECONDS]  # reaped after the kill


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
def test_run_tool_tolerates_group_already_gone(monkeypatch):
    def gone(pgid, sig):
        raise ProcessLookupError

    FakePopen.instances, FakePopen.next_error = [], subprocess.TimeoutExpired(["tool"], 5)
    monkeypatch.setattr(proc_module.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(proc_module.os, "killpg", gone)
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool(["tool"], timeout=5)


def test_run_tool_returns_output():
    proc = run_tool([sys.executable, "-c", "print('hi')"], timeout=30)
    assert (proc.returncode, proc.stdout.strip()) == (0, "hi")


def test_run_tool_passes_cwd_and_env(tmp_path):
    code = "import os, sys; print(os.getcwd()); print(os.environ.get('SENTINEL_PROC_TEST')); sys.exit(3)"
    env = {"PATH": os.environ.get("PATH", ""), "SENTINEL_PROC_TEST": "yes"}
    proc = run_tool([sys.executable, "-c", code], timeout=30, cwd=str(tmp_path), env=env)
    assert proc.returncode == 3
    assert proc.stdout.split() == [str(tmp_path.resolve()), "yes"]


# A child that starts a grandchild, records both PIDs, then sleeps. The
# grandchild shares the output pipe, so killing only the child would hang.
CHILD = r"""
import os, subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(sys.argv[1], "w") as fh:
    fh.write(f"{os.getpid()} {grandchild.pid}")
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    """True if pid is running (a zombie waiting to be reaped counts as gone)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if not Path("/proc").is_dir():
        return True  # no /proc (macOS): os.kill says it exists
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0] != "Z"
    except (OSError, IndexError):
        return False  # vanished between the two checks


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only (skipped on Windows)")
def test_real_timeout_kills_child_and_grandchild(tmp_path):
    # The one test with real waiting (about 1.5 seconds).
    pid_file = tmp_path / "pids"
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool([sys.executable, "-c", CHILD, str(pid_file)], timeout=1.5)
    assert time.monotonic() - start < 10  # did not wait for the 60s sleeps

    pids = [int(p) for p in pid_file.read_text().split()]
    try:
        deadline = time.monotonic() + 5
        while any(_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not any(_alive(p) for p in pids), "child or grandchild still running"
    finally:
        for p in pids:  # never leave a stray process behind, even if the test fails
            try:
                os.kill(p, 9)
            except (ProcessLookupError, PermissionError):
                pass
