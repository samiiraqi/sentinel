"""Config / YAML agent: finds insecure Kubernetes manifests, Dockerfiles and
GitHub Actions workflows using Checkov.

READ-ONLY: Checkov only reads the folder, and this agent only opens files
for reading. Checkov runs offline (--skip-download, no API key). Only the
check id, name, file, line, and resource id are kept; Checkov's raw values
(code_block, check_result) are dropped so no file content can leak.

NEVER LOOKS CLEAN BY ACCIDENT: a missing checkov, a bad exit code, empty
or invalid output, or a timeout raises ConfigYamlError. Checkov silently
skips invalid YAML and workflows it cannot read, so this agent also checks
coverage itself: such files become low "config-unscanned" findings.

Usage: python -m agents.config_yaml.agent <folder> [--exclude TEXT ...]
Exit code: 0 = no findings, 1 = findings, 2 = error.
"""

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys

from shared.models import SEVERITIES, Finding
from shared.paths import is_excluded

AGENT_NAME = "config_yaml"
FRAMEWORKS = ("kubernetes", "dockerfile", "github_actions")
DEFAULT_SEVERITY = "medium"
UNSCANNED_RULE = "config-unscanned"
UNSCANNED_SEVERITY = "low"
TIMEOUT_SECONDS = 300
KILL_WAIT_SECONDS = 5
MAX_FILE_BYTES = 5 * 1024 * 1024
YAML_SUFFIXES = (".yml", ".yaml")
# Folders never walked for the coverage check (Checkov skips these too, or they hold no config of ours).
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", ".serverless"}
SECRET_ENV = ("BC_API_KEY", "PRISMA_API_URL")
INSTALL_HINT = "checkov is not installed. Run: pip install -r requirements-terraform.txt"


class ConfigYamlError(RuntimeError):
    """Checkov is missing, failed, timed out, or returned output we cannot read."""


def _severity(value) -> str:
    sev = str(value).lower() if value else ""
    return sev if sev in SEVERITIES else DEFAULT_SEVERITY


def _first_line(line_range) -> int:
    if isinstance(line_range, list) and line_range:
        try:
            return max(int(line_range[0]), 0)
        except (TypeError, ValueError):
            pass
    return 0


def _unscanned(rel_path: str, reason: str, line: int = 0) -> Finding:
    return Finding(
        agent=AGENT_NAME,
        rule_id=UNSCANNED_RULE,
        severity=UNSCANNED_SEVERITY,
        file=rel_path,
        line=line,
        message=f"not scanned: {reason}",
        redacted_match="",
    )


def _reports(data) -> list[dict]:
    reports = data if isinstance(data, list) else [data]
    return [r for r in reports if isinstance(r, dict)]


def parse_checkov_output(data: dict | list) -> list[Finding]:
    """Turn Checkov JSON (one report or a list of reports) into Findings.

    Files Checkov lists under results.parsing_errors become config-unscanned.
    """
    findings = []
    for report in _reports(data):
        results = report.get("results") or {}
        for check in results.get("failed_checks") or []:
            # Only safe fields are copied; check_result/code_block are ignored.
            findings.append(
                Finding(
                    agent=AGENT_NAME,
                    rule_id=str(check.get("check_id", "")),
                    severity=_severity(check.get("severity")),
                    file=str(check.get("file_path", "")).lstrip("/"),
                    line=_first_line(check.get("file_line_range")),
                    message=str(check.get("check_name", "")),
                    redacted_match=str(check.get("resource", "")),
                )
            )
        for path in results.get("parsing_errors") or []:
            findings.append(_unscanned(str(path).lstrip("/"), "Checkov could not parse this file"))
    return findings


def scanned_files(data: dict | list, check_type: str) -> set[str]:
    """Relative paths Checkov reported any passed or failed check for, in one framework."""
    files = set()
    for report in _reports(data):
        if report.get("check_type") != check_type:
            continue
        results = report.get("results") or {}
        for key in ("passed_checks", "failed_checks"):
            for check in results.get(key) or []:
                files.add(str(check.get("file_path", "")).lstrip("/"))
    return files


def _is_workflow(rel_path: str) -> bool:
    parts = rel_path.split("/")
    return (
        rel_path.endswith(YAML_SUFFIXES)
        and len(parts) >= 3
        and parts[-3:-1] == [".github", "workflows"]
    )


def check_yaml_files(root: str, exclude: tuple[str, ...] = ()) -> tuple[list[Finding], list[str]]:
    """Read-only coverage check of every .yml/.yaml file under root.

    Returns (config-unscanned findings for invalid or unreadable YAML,
    relative paths of valid workflow files that Checkov must have scanned).
    """
    try:
        import yaml  # installed with checkov
    except ImportError as exc:
        raise ConfigYamlError(INSTALL_HINT) from exc

    unscanned, workflows = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, d))
            and not is_excluded(os.path.relpath(os.path.join(dirpath, d), root), exclude)
        )
        for name in sorted(filenames):
            if not name.endswith(YAML_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full) or is_excluded(rel, exclude):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    unscanned.append(_unscanned(rel, "file too large to verify"))
                    continue
                with open(full, encoding="utf-8") as fh:
                    for _ in yaml.safe_load_all(fh):
                        pass
            except yaml.YAMLError as exc:
                mark = getattr(exc, "problem_mark", None)
                line = mark.line + 1 if mark is not None else 0
                unscanned.append(_unscanned(rel, "invalid YAML (Checkov skips it silently)", line))
                continue
            except (OSError, UnicodeDecodeError):
                unscanned.append(_unscanned(rel, "file could not be read as UTF-8 text"))
                continue
            if _is_workflow(rel):
                workflows.append(rel)
    return unscanned, workflows


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


def run_checkov(root: str) -> dict | list:
    """Run Checkov offline on root and return its parsed JSON. Raises ConfigYamlError."""
    cmd = [
        sys.executable, "-m", "checkov.main",
        "-d", ".",  # run from root, so every file_path is relative to it
        "--framework", *FRAMEWORKS,
        "-o", "json",
        "--compact",
        "--skip-download",
    ]
    # Never pass an API key to Checkov, even if one is set in the environment.
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
    try:
        proc = _run_tool(cmd, TIMEOUT_SECONDS, cwd=root, env=env)
    except subprocess.TimeoutExpired as exc:
        raise ConfigYamlError(f"checkov timed out after {TIMEOUT_SECONDS}s") from exc

    # Checkov exits 0 (passed) or 1 (failed checks); anything else is an error.
    if proc.returncode not in (0, 1):
        raise ConfigYamlError(f"checkov failed with exit code {proc.returncode}")
    out = (proc.stdout or "").strip()
    if not out:
        # Checkov always prints at least a summary, so empty output is an error.
        raise ConfigYamlError("checkov returned no output")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ConfigYamlError("could not parse checkov JSON output") from exc
    if not isinstance(data, (dict, list)):
        raise ConfigYamlError("unexpected checkov JSON output")
    return data


def scan_directory(path: str, exclude: tuple[str, ...] = ()) -> list[Finding]:
    """Run Checkov (Kubernetes, Dockerfile, GitHub Actions; offline) on a folder.

    Findings whose file path matches a value in `exclude` (by whole path
    components, see shared.paths.is_excluded) are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    if importlib.util.find_spec("checkov") is None:
        raise ConfigYamlError(INSTALL_HINT)
    exclude = tuple(v for v in exclude if v)

    data = run_checkov(root)
    findings = parse_checkov_output(data)

    unscanned, workflows = check_yaml_files(root, exclude)
    reported = {f.file for f in findings}
    findings.extend(f for f in unscanned if f.file not in reported)
    seen = scanned_files(data, "github_actions")
    findings.extend(
        _unscanned(rel, "Checkov returned no result for this workflow")
        for rel in workflows
        if rel not in seen
    )
    return [f for f in findings if not is_excluded(f.file, exclude)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.config_yaml.agent",
        description=(
            "Read-only scan of a folder for insecure Kubernetes manifests, "
            "Dockerfiles and GitHub Actions workflows (via Checkov)."
        ),
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip findings in files/folders named TEXT, or under path TEXT from FOLDER (repeatable)",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(args.folder, exclude=tuple(args.exclude))
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2
    except ConfigYamlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
