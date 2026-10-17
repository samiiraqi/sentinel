"""Terraform agent: finds insecure Terraform using Checkov.

READ-ONLY: Checkov only reads the folder. Terraform itself is never run
(no init, plan, or apply). Checkov runs offline (--skip-download, no API
key). Only the check id, name, file, line, and resource id are kept;
Checkov's raw resource values are dropped so no secret can leak.

NEVER LOOKS CLEAN BY ACCIDENT: a missing checkov, a bad exit code, empty
or invalid output, or a timeout raises CheckovError. Checkov skips .tf
files it cannot parse, so each one becomes a low "terraform-unscanned"
finding (and one more if Checkov counts parse errors it gives no name for).

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
from shared.paths import is_excluded, relative_to_root

AGENT_NAME = "terraform"
DEFAULT_SEVERITY = "medium"
UNSCANNED_RULE = "terraform-unscanned"
UNSCANNED_SEVERITY = "low"
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


def _parse_error_count(report: dict) -> int:
    count = (report.get("summary") or {}).get("parsing_errors", 0)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise CheckovError("unexpected checkov parsing_errors count")
    return count


def parse_checkov_output(data: dict | list, root: str = "/") -> list[Finding]:
    """Turn Checkov JSON (one report or a list of reports) into Findings.

    Files Checkov lists under results.parsing_errors (absolute paths) become
    terraform-unscanned findings, relative to root. If summary.parsing_errors
    counts more files than were named inside root, one extra finding with an
    empty file says so, so a scan with parse errors never looks clean.
    """
    reports = data if isinstance(data, list) else [data]
    findings = []
    for report in reports:
        if not isinstance(report, dict):
            continue
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

        errors = results.get("parsing_errors") or []
        if not isinstance(errors, list):
            raise CheckovError("unexpected checkov parsing_errors list")
        named = []
        for path in errors:
            rel = relative_to_root(path, root) if isinstance(path, str) and path else None
            if rel is not None and rel not in named:
                named.append(rel)
        # Only the path is kept; Checkov's error text is never copied.
        findings.extend(_unscanned(rel, "Checkov could not parse this file") for rel in named)
        missing = _parse_error_count(report) - len(named)
        if missing > 0:
            findings.append(
                _unscanned("", f"Checkov could not parse {missing} file(s) and gave no file name inside the scanned folder")
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
        # No --quiet: with it, Checkov drops results.parsing_errors (the file names).
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
    out = (proc.stdout or "").strip()
    if not out:
        # Checkov always prints at least a summary, so empty output is an error.
        raise CheckovError("checkov returned no output")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise CheckovError("could not parse checkov JSON output") from exc
    if not isinstance(data, (dict, list)):
        raise CheckovError("unexpected checkov JSON output")

    return [f for f in parse_checkov_output(data, root) if not is_excluded(f.file, exclude)]


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
