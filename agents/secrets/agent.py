"""Secrets agent: finds hard-coded secrets in a folder.

READ-ONLY: files are only ever opened for reading. Nothing is written,
deleted, or modified. Full secrets are redacted before a Finding is built,
so they never appear in the output.

Usage: python -m agents.secrets.agent <folder>
"""

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass

from shared.models import Finding

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


def scan_text(text: str, rel_path: str) -> list[Finding]:
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                # Redact first; the raw value is never stored.
                findings.append(
                    Finding(
                        agent=AGENT_NAME,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        file=rel_path,
                        line=line_no,
                        message=rule.message,
                        redacted_match=redact(match.group(rule.group)),
                    )
                )
    return findings


def scan_directory(path: str) -> list[Finding]:
    """Recursively scan a folder for secrets. Never follows symlinks."""
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)

    findings = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune skipped and symlinked directories in place.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            text = _read_text(full)
            if text is None:
                continue
            findings.extend(scan_text(text, os.path.relpath(full, root)))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.secrets.agent",
        description="Read-only scan of a folder for hard-coded secrets.",
    )
    parser.add_argument("folder", help="folder to scan")
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(args.folder)
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
