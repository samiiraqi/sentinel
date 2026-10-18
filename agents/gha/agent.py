"""GHA agent: finds insecure GitHub Actions workflows and action definitions
using zizmor.

WHICH FILES: .github/workflows/*.yml|yaml (at any depth) and action.yml|yaml
files (see shared.paths.is_gha_file). This agent alone owns them; the
config_yaml agent skips them, so a file never gets two sets of findings.

READ-ONLY and OFFLINE: zizmor runs with --offline (its five audits that need
a GitHub token are turned off) and never with --fix. GitHub tokens and every
ZIZMOR_* setting are removed from its environment. This agent only lists
files and checks their size and encoding. Only the audit id, description,
confidence, severity, file and line are kept; zizmor's "feature" and
"fragment" fields (raw workflow text) and "annotation" are never copied.

THE SCANNED FOLDER CANNOT CHANGE THE SCAN: --no-config (a zizmor.yml in the
folder is ignored), --no-ignores ("# zizmor: ignore" comments cannot hide
findings), and files are found by this agent, not by zizmor (so .gitignore
cannot hide a workflow and symlinks are never followed). zizmor runs at its
"regular" level: its pedantic and auditor findings are not reported.

NEVER LOOKS CLEAN BY ACCIDENT: a missing zizmor, a bad exit code, empty or
invalid output, or a timeout raises GhaError. Files zizmor could not parse
(invalid YAML, not a valid workflow or action), non-UTF-8 files, symlinks
and files that are too large become low "gha-unscanned" findings.

TIME LIMIT: zizmor runs once per file, so a file it cannot parse is known
exactly; all runs share one deadline of TIMEOUT_SECONDS.

Usage: python -m agents.gha.agent <folder> [--exclude TEXT ...]
Exit code: 0 = no findings, 1 = findings, 2 = error.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import sysconfig
import time

from shared.models import SEVERITIES, Finding
from shared.paths import is_excluded, is_gha_file

AGENT_NAME = "gha"
DEFAULT_SEVERITY = "medium"
UNSCANNED_RULE = "gha-unscanned"
UNSCANNED_SEVERITY = "low"
TIMEOUT_SECONDS = 300  # cap for a whole scan
MIN_RUN_SECONDS = 1.0  # do not start a run with less time than this left
KILL_WAIT_SECONDS = 5
MAX_FILE_BYTES = 5 * 1024 * 1024
# Folders never walked (vendored code, environments, caches); the same as the config_yaml agent.
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", ".serverless"}
# Removed from zizmor's environment, as well as every ZIZMOR_* setting.
SECRET_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "GH_HOST")
# zizmor's exit codes: 0 = no findings, 10-14 = findings (by highest severity),
# 3 = no auditable input (the one file we passed could not be parsed).
FINDINGS_EXIT_CODES = range(10, 15)
NO_INPUT_EXIT_CODE = 3
# zizmor severity -> ours. It has no "critical"; "informational" becomes low.
SEVERITY_MAP = {"informational": "low", "low": "low", "medium": "medium", "high": "high"}
INSTALL_HINT = "zizmor is not installed. Run: pip install -r requirements-gha.txt"


class GhaError(RuntimeError):
    """zizmor is missing, failed, timed out, or returned output we cannot read."""


def _severity(value) -> str:
    sev = SEVERITY_MAP.get(str(value).lower() if value else "", DEFAULT_SEVERITY)
    return sev if sev in SEVERITIES else DEFAULT_SEVERITY


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


def _line(locations) -> int:
    """1-based line of the primary location (zizmor counts rows from 0)."""
    if not isinstance(locations, list):
        return 0
    locs = [loc for loc in locations if isinstance(loc, dict)]
    primary = next(
        (loc for loc in locs if (loc.get("symbolic") or {}).get("kind") == "Primary"),
        locs[0] if locs else None,
    )
    try:
        return max(int(primary["concrete"]["location"]["start_point"]["row"]) + 1, 0)
    except (TypeError, KeyError, ValueError):
        return 0


def parse_zizmor_output(data: list, rel_path: str) -> list[Finding]:
    """Turn zizmor JSON (v1) for one file into Findings.

    The file is always rel_path (the file we passed in), never a path zizmor
    reports. Only ident, desc and determinations are read from each result,
    plus the line number; "feature", "fragment", "annotation" and "fixes"
    are ignored because they can hold raw workflow text.
    """
    findings = []
    for result in data:
        if not isinstance(result, dict):
            continue
        det = result.get("determinations")
        det = det if isinstance(det, dict) else {}
        ident = str(result.get("ident", ""))
        confidence = str(det.get("confidence", "")).lower() or "unknown"
        findings.append(
            Finding(
                agent=AGENT_NAME,
                rule_id=ident,
                severity=_severity(det.get("severity")),
                file=rel_path,
                line=_line(result.get("locations")),
                message=f"{result.get('desc', '')} (confidence {confidence})",
                redacted_match=ident,
            )
        )
    return findings


def find_gha_files(root: str, exclude: tuple[str, ...] = ()) -> tuple[list[str], list[Finding]]:
    """Read-only walk of root.

    Returns (relative paths of workflow/action files to give zizmor,
    gha-unscanned findings for files that are not given to it: symlinks,
    files over MAX_FILE_BYTES, and files that are not UTF-8 text). Folder
    symlinks are not followed.
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
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if not is_gha_file(rel) or is_excluded(rel, exclude):
                continue
            if os.path.islink(full):
                unscanned.append(_unscanned(rel, "symlink not followed"))
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    unscanned.append(_unscanned(rel, "file too large to scan"))
                    continue
                with open(full, "rb") as fh:
                    fh.read().decode("utf-8")
            except OSError:
                unscanned.append(_unscanned(rel, "file could not be read"))
                continue
            except UnicodeDecodeError:
                # zizmor would stop the whole scan on this file.
                unscanned.append(_unscanned(rel, "file could not be read as UTF-8 text"))
                continue
            files.append(rel)
    return files, unscanned


def zizmor_path() -> str | None:
    """The zizmor binary pip installed next to this Python, or None. PATH is not searched."""
    name = "zizmor.exe" if os.name == "nt" else "zizmor"
    path = os.path.join(sysconfig.get_path("scripts"), name)
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


def _env() -> dict:
    """zizmor's environment: no GitHub token or host, no ZIZMOR_* settings."""
    return {k: v for k, v in os.environ.items() if k not in SECRET_ENV and not k.startswith("ZIZMOR_")}


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


def run_zizmor(zizmor: str, root: str, rel_path: str, timeout: float) -> list | None:
    """Run zizmor offline on one file (relative to root).

    Returns its parsed JSON results, or None if zizmor could not parse the
    file. Raises GhaError.
    """
    cmd = [
        zizmor,
        "--offline",
        "--no-config",
        "--no-ignores",
        "--persona", "regular",
        "--format", "json-v1",
        "--no-progress",
        "--color", "never",
        # "--" and "./" so a file named like an option ("-x.yml") is never read as one.
        "--", f"./{rel_path}",
    ]
    try:
        proc = _run_tool(cmd, timeout, cwd=root, env=_env())
    except subprocess.TimeoutExpired as exc:
        raise GhaError(f"zizmor timed out after {TIMEOUT_SECONDS}s") from exc

    if proc.returncode == NO_INPUT_EXIT_CODE:
        return None
    if proc.returncode != 0 and proc.returncode not in FINDINGS_EXIT_CODES:
        raise GhaError(f"zizmor failed with exit code {proc.returncode}")
    out = (proc.stdout or "").strip()
    if not out:
        # zizmor prints "[]" when it found nothing, so empty output is an error.
        raise GhaError("zizmor returned no output")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise GhaError("could not parse zizmor JSON output") from exc
    if not isinstance(data, list):
        raise GhaError("unexpected zizmor JSON output")
    if proc.returncode in FINDINGS_EXIT_CODES and not data:
        raise GhaError(f"zizmor exit code {proc.returncode} means findings, but it returned none")
    return data


def scan_directory(path: str, exclude: tuple[str, ...] = (), clock=time.monotonic) -> list[Finding]:
    """Run zizmor (offline, regular level) on every workflow and action file in a folder.

    Files whose path matches a value in `exclude` (by whole path
    components, see shared.paths.is_excluded) are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    zizmor = zizmor_path()
    if zizmor is None:
        raise GhaError(INSTALL_HINT)
    exclude = tuple(v for v in exclude if v)
    deadline = clock() + TIMEOUT_SECONDS

    files, findings = find_gha_files(root, exclude)
    for rel in files:
        remaining = deadline - clock()
        if remaining < MIN_RUN_SECONDS:
            raise GhaError(f"zizmor timed out after {TIMEOUT_SECONDS}s")
        data = run_zizmor(zizmor, root, rel, remaining)
        if data is None:
            findings.append(_unscanned(rel, "zizmor could not parse this file (invalid YAML, or not a valid workflow or action)"))
        else:
            findings.extend(parse_zizmor_output(data, rel))
    return [f for f in findings if not is_excluded(f.file, exclude)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.gha.agent",
        description="Read-only scan of GitHub Actions workflows and action definitions (via zizmor, offline).",
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
    except GhaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
