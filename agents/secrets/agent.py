"""Secrets agent: finds hard-coded secrets in a folder.

READ-ONLY: files are only ever opened for reading. Nothing is written,
deleted, or modified. Full secrets are redacted before a Finding is built,
so they never appear in the output.

Usage: python -m agents.secrets.agent <folder> [--exclude TEXT ...] [--exclude-file PATH ...]
Exit code: 0 = no findings, 1 = findings, 2 = invalid folder.
"""

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass

from shared.models import Finding
from shared.paths import is_excluded

AGENT_NAME = "secrets"
SKIP_DIRS = {".git", ".venv", "node_modules"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # skip very large files
BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: re.Pattern
    group: int = 0  # regex group that holds the secret value
    # Captured values (compared lowercased, whole value only) that are never a secret.
    ignore_values: frozenset[str] = frozenset()


# Boolean/null literals, e.g. "automountServiceAccountToken: false" in a
# Kubernetes manifest. Matched against the whole captured value (quotes are
# outside the group), so "falsehood123" or "true_secret_key" are still found.
# Trade-off: a password that is literally "true", "false" or "null" is missed.
BOOLEAN_NULL_LITERALS = frozenset({"true", "false", "null"})

RULES = [
    Rule(
        rule_id="aws-access-key-id",
        severity="high",
        message="Possible AWS access key ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Rule(
        rule_id="private-key",
        severity="critical",
        message="Private key header found",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    ),
    Rule(
        rule_id="anthropic-api-key",
        severity="critical",
        message="Possible Anthropic API key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}"),
    ),
    Rule(
        rule_id="generic-secret-assignment",
        severity="medium",
        message="Possible hard-coded password/secret/token/API key",
        pattern=re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key)[A-Za-z0-9_]*"
            r"[\"']?\s*[:=]\s*[\"']?([^\s\"'#,;]{4,})"
        ),
        group=1,
        ignore_values=BOOLEAN_NULL_LITERALS,
    ),
]


def redact(value: str) -> str:
    """Show at most the first 4 characters (fewer for short values), then ****."""
    visible = min(4, len(value) // 2)
    return value[:visible] + "****"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:BINARY_SNIFF_BYTES]


def _read_text(path: str) -> str | None:
    """Read a regular file as text. Returns None for symlinks, binaries, etc."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    # Only plain files: no symlinks, FIFOs, devices, or sockets.
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
        return None
    try:
        with open(path, "rb") as fh:  # read-only
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if _is_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def iter_matches(text: str):
    """Yield (rule, line_no, raw value) for every match in text.

    The raw value must never be stored or printed: callers redact it (or
    only hash it) right away. Shared with the git_history agent.
    """
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(rule.group)
                if value.lower() in rule.ignore_values:
                    continue
                yield rule, line_no, value


def scan_text(text: str, rel_path: str) -> list[Finding]:
    # Redact first; the raw value is never stored.
    return [
        Finding(
            agent=AGENT_NAME,
            rule_id=rule.rule_id,
            severity=rule.severity,
            file=rel_path,
            line=line_no,
            message=rule.message,
            redacted_match=redact(value),
        )
        for rule, line_no, value in iter_matches(text)
    ]


def _rel(full: str, root: str) -> str:
    """Path relative to the scan root, always with / separators."""
    return os.path.relpath(full, root).replace(os.sep, "/")


def scan_directory(
    path: str, exclude: tuple[str, ...] = (), exclude_files: tuple[str, ...] = ()
) -> list[Finding]:
    """Recursively scan a folder for secrets. Never follows symlinks.

    Folders or files matching a value in `exclude` are skipped, by whole
    path components (see shared.paths.is_excluded), never by substring.
    Files whose relative path (with / separators) is exactly equal to a
    value in `exclude_files` are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    exclude = tuple(v for v in exclude if v)
    exclude_files = frozenset(v for v in exclude_files if v)

    findings = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune skipped, excluded, and symlinked directories in place.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, d))
            and not is_excluded(_rel(os.path.join(dirpath, d), root), exclude)
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel_path = _rel(full, root)
            if is_excluded(rel_path, exclude) or rel_path in exclude_files:
                continue
            text = _read_text(full)
            if text is None:
                continue
            findings.extend(scan_text(text, rel_path))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.secrets.agent",
        description="Read-only scan of a folder for hard-coded secrets.",
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip folders/files named TEXT, or under path TEXT from FOLDER (repeatable)",
    )
    parser.add_argument(
        "--exclude-file",
        action="append",
        default=[],
        metavar="PATH",
        help="skip the one file whose path relative to FOLDER is exactly PATH (repeatable)",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(
            args.folder, exclude=tuple(args.exclude), exclude_files=tuple(args.exclude_file)
        )
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
