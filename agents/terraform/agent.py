"""Terraform agent: finds insecure Terraform using Checkov.

READ-ONLY: Checkov only reads the folder. Terraform itself is never run
(no init, plan, or apply). Checkov runs offline (--skip-download, no API
key). Only the check id, name, file, line, and resource id are kept;
Checkov's raw resource values are dropped so no secret can leak.

Usage: python -m agents.terraform.agent <folder> [--exclude TEXT ...]
Exit code: 0 = no findings, 1 = findings, 2 = error.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys

from shared.models import SEVERITIES, Finding
from shared.paths import is_excluded

AGENT_NAME = "terraform"
DEFAULT_SEVERITY = "medium"
TIMEOUT_SECONDS = 300
INSTALL_HINT = "checkov is not installed. Run: pip install -r requirements-terraform.txt"


class CheckovError(RuntimeError):
    """Checkov is missing, failed, or returned output we cannot read."""


def _severity(value) -> str:
    sev = str(value).lower() if value else ""
    return sev if sev in SEVERITIES else DEFAULT_SEVERITY


def _first_line(line_range) -> int:
    if isinstance(line_range, list) and line_range:
        try:
            return int(line_range[0])
        except (TypeError, ValueError):
            pass
    return 0


def parse_checkov_output(data: dict | list) -> list[Finding]:
    """Turn Checkov JSON (one report or a list of reports) into Findings."""
    reports = data if isinstance(data, list) else [data]
    findings = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        for check in (report.get("results") or {}).get("failed_checks") or []:
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
    return findings


def scan_directory(path: str, exclude: tuple[str, ...] = ()) -> list[Finding]:
    """Run Checkov (Terraform only, offline) on a folder and return Findings.

    Findings whose file path matches a value in `exclude` (by whole path
    components, see shared.paths.is_excluded) are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    if importlib.util.find_spec("checkov") is None:
        raise CheckovError(INSTALL_HINT)
    exclude = tuple(v for v in exclude if v)

    cmd = [
        sys.executable, "-m", "checkov.main",
        "-d", root,
        "--framework", "terraform",
        "-o", "json",
        "--quiet",
        "--compact",
        "--skip-download",
    ]
    # Never pass an API key to Checkov, even if one is set in the environment.
    env = {k: v for k, v in os.environ.items() if k not in ("BC_API_KEY", "PRISMA_API_URL")}
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=env, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckovError(f"checkov timed out after {TIMEOUT_SECONDS}s") from exc

    # Checkov exits 0 (passed) or 1 (failed checks); anything else is an error.
    if proc.returncode not in (0, 1):
        raise CheckovError(f"checkov failed with exit code {proc.returncode}")
    out = proc.stdout.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise CheckovError("could not parse checkov JSON output") from exc

    return [f for f in parse_checkov_output(data) if not is_excluded(f.file, exclude)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.terraform.agent",
        description="Read-only scan of a folder for insecure Terraform (via Checkov).",
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
    except CheckovError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
