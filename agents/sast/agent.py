"""SAST agent: static analysis of Python source code with Bandit.

PYTHON ONLY: Bandit reads .py and .pyw files. TypeScript and other
languages are not scanned.

READ-ONLY and OFFLINE: Bandit parses each file without running it and
needs no network; this agent only lists files. Only the test id, test
name, CWE, confidence, severity, file and line are kept. Bandit's
"issue_text" and "code" fields are never copied into a finding: "code"
is source code, and for some tests (e.g. B105-B107, hard-coded
passwords) "issue_text" holds the matched string itself.

THE SCANNED FOLDER CANNOT CHANGE THE SCAN: Bandit runs with our own
empty config and ini file (so a .bandit file or pyproject.toml in the
folder cannot turn tests off) and with --ignore-nosec (so "# nosec"
comments cannot hide findings).

NEVER LOOKS CLEAN BY ACCIDENT: a missing bandit, a bad exit code, empty
or invalid output, or a timeout raises SastError. Files Bandit could not
parse (syntax errors, non-UTF-8), files it returned no result for, and
files this agent does not hand to Bandit (symlinks, files that are too
large) become low "sast-unscanned" findings.

TIME LIMIT: one whole scan never runs longer than TIMEOUT_SECONDS.
Files are passed to Bandit in batches; all batches share that deadline.

Usage: python -m agents.sast.agent <folder> [--exclude TEXT ...]
Exit code: 0 = no findings, 1 = findings, 2 = error.
"""

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

from shared.models import SEVERITIES, Finding
from shared.paths import is_excluded, relative_to_root

AGENT_NAME = "sast"
DEFAULT_SEVERITY = "medium"
UNSCANNED_RULE = "sast-unscanned"
UNSCANNED_SEVERITY = "low"
TIMEOUT_SECONDS = 300  # cap for a whole scan
MIN_RUN_SECONDS = 1.0  # do not start a batch with less time than this left
KILL_WAIT_SECONDS = 5
BATCH_SIZE = 200  # files per Bandit run, to keep the command line short
MAX_FILE_BYTES = 5 * 1024 * 1024
PY_SUFFIXES = (".py", ".pyw")
# Folders never walked (vendored code, environments, caches).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
INSTALL_HINT = "bandit is not installed. Run: pip install -r requirements-sast.txt"
# Our own empty settings: Bandit's defaults, nothing from the scanned folder.
EMPTY_CONFIG = "{}\n"
EMPTY_INI = "[bandit]\n"


class SastError(RuntimeError):
    """Bandit is missing, failed, timed out, or returned output we cannot read."""


def _severity(value) -> str:
    sev = str(value).lower() if value else ""
    return sev if sev in SEVERITIES else DEFAULT_SEVERITY


def _line(value) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _rel(name, root: str) -> str:
    """Path relative to root for a name Bandit reports (e.g. "././pkg/a.py").
    A name that is empty, not text, or outside root becomes "" (never shown)."""
    rel = relative_to_root(name, root) if isinstance(name, str) and name else None
    return rel or ""


def _unscanned(rel_path: str, reason: str) -> Finding:
    return Finding(
        agent=AGENT_NAME,
        rule_id=UNSCANNED_RULE,
        severity=UNSCANNED_SEVERITY,
        file=rel_path,
        line=0,
        message=f"not scanned: {reason}",
        redacted_match="",
    )


def _message(result: dict) -> str:
    """Built from safe fields only; Bandit's issue_text is never used."""
    name = str(result.get("test_name", ""))
    cwe = result.get("issue_cwe")
    cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
    confidence = str(result.get("issue_confidence", "")).lower() or "unknown"
    parts = [f"CWE-{cwe_id}"] if cwe_id else []
    parts.append(f"confidence {confidence}")
    return f"{name} ({', '.join(parts)})"


def parse_bandit_output(data: dict, root: str = "/") -> list[Finding]:
    """Turn Bandit JSON into Findings.

    Results become findings; entries in "errors" (files Bandit could not
    parse) become sast-unscanned findings. Paths are made relative to
    root. Bandit's "code" and "issue_text" fields are ignored.
    """
    findings = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        findings.append(
            Finding(
                agent=AGENT_NAME,
                rule_id=str(result.get("test_id", "")),
                severity=_severity(result.get("issue_severity")),
                file=_rel(result.get("filename"), root),
                line=_line(result.get("line_number")),
                message=_message(result),
                redacted_match=str(result.get("test_name", "")),
            )
        )
    for error in data.get("errors") or []:
        if not isinstance(error, dict):
            continue
        findings.append(_unscanned(_rel(error.get("filename"), root), "Bandit could not parse this file"))
    return findings


def scanned_files(data: dict, root: str = "/") -> set[str]:
    """Relative paths Bandit reported metrics for (every file it read)."""
    metrics = data.get("metrics") or {}
    return {_rel(name, root) for name in metrics if name != "_totals"}


def find_python_files(root: str, exclude: tuple[str, ...] = ()) -> tuple[list[str], list[Finding]]:
    """Read-only walk of root.

    Returns (relative paths of .py/.pyw files to give Bandit, sast-unscanned
    findings for files that are not given to it: symlinks and files over
    MAX_FILE_BYTES). Folder symlinks are not followed.
    """
    files, unscanned = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, d))
            and not is_excluded(os.path.relpath(os.path.join(dirpath, d), root), exclude)
        )
        for name in sorted(filenames):
            if not name.endswith(PY_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if is_excluded(rel, exclude):
                continue
            if os.path.islink(full):
                unscanned.append(_unscanned(rel, "symlink not followed"))
                continue
            try:
                too_large = os.path.getsize(full) > MAX_FILE_BYTES
            except OSError:
                unscanned.append(_unscanned(rel, "file could not be read"))
                continue
            if too_large:
                unscanned.append(_unscanned(rel, "file too large to scan"))
            else:
                files.append(rel)
    return files, unscanned


def _run_tool(cmd: list[str], timeout: float, cwd: str, env: dict) -> subprocess.CompletedProcess:
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
        proc.wait()


def run_bandit(root: str, files: list[str], config: str, ini: str, timeout: float) -> dict:
    """Run Bandit on files (relative to root) and return its parsed JSON. Raises SastError."""
    cmd = [
        sys.executable, "-m", "bandit",
        "-f", "json",
        "-q",
        "-c", config,
        "--ini", ini,
        "--ignore-nosec",
        # "./" so a file named like an option ("-x.py") is never read as one.
        *(f"./{rel}" for rel in files),
    ]
    try:
        proc = _run_tool(cmd, timeout, cwd=root, env=dict(os.environ))
    except subprocess.TimeoutExpired as exc:
        raise SastError(f"bandit timed out after {TIMEOUT_SECONDS}s") from exc

    # Bandit exits 0 (no issues) or 1 (issues found); anything else is an error.
    if proc.returncode not in (0, 1):
        raise SastError(f"bandit failed with exit code {proc.returncode}")
    out = (proc.stdout or "").strip()
    if not out:
        raise SastError("bandit returned no output")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise SastError("could not parse bandit JSON output") from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("results"), list)
        or not isinstance(data.get("errors"), list)
        or not isinstance(data.get("metrics"), dict)
    ):
        raise SastError("unexpected bandit JSON output")
    return data


def scan_directory(path: str, exclude: tuple[str, ...] = (), clock=time.monotonic) -> list[Finding]:
    """Run Bandit (Python only, offline) on every .py/.pyw file in a folder.

    Files whose path matches a value in `exclude` (by whole path
    components, see shared.paths.is_excluded) are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    if importlib.util.find_spec("bandit") is None:
        raise SastError(INSTALL_HINT)
    exclude = tuple(v for v in exclude if v)
    deadline = clock() + TIMEOUT_SECONDS

    files, findings = find_python_files(root, exclude)
    if not files:
        return findings

    with tempfile.TemporaryDirectory(prefix="sentinel-sast-") as tmp:
        config = os.path.join(tmp, "bandit.yml")
        ini = os.path.join(tmp, "bandit.ini")
        with open(config, "w", encoding="utf-8") as fh:
            fh.write(EMPTY_CONFIG)
        with open(ini, "w", encoding="utf-8") as fh:
            fh.write(EMPTY_INI)
        for start in range(0, len(files), BATCH_SIZE):
            batch = files[start:start + BATCH_SIZE]
            remaining = deadline - clock()
            if remaining < MIN_RUN_SECONDS:
                raise SastError(f"bandit timed out after {TIMEOUT_SECONDS}s")
            data = run_bandit(root, batch, config, ini, remaining)
            parsed = parse_bandit_output(data, root)
            findings.extend(parsed)
            reported = scanned_files(data, root) | {f.file for f in parsed if f.rule_id == UNSCANNED_RULE}
            findings.extend(
                _unscanned(rel, "Bandit returned no result for this file") for rel in batch if rel not in reported
            )
    return [f for f in findings if not is_excluded(f.file, exclude)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.sast.agent",
        description="Read-only static analysis of Python source code (via Bandit).",
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip files/folders named TEXT, or under path TEXT from FOLDER (repeatable)",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(args.folder, exclude=tuple(args.exclude))
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2
    except SastError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
