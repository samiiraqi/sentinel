"""Interactive approval CLI. Records decisions only; never runs any action.

Usage: python -m approval <folder> [--exclude TEXT ...] [--log audit/decisions.jsonl]
"""

import argparse
import getpass
import sys

from approval.decisions import fingerprint, pending_findings, record_decision
from orchestrator.orchestrator import run_all

CHOICES = {"a": "approve", "r": "reject", "d": "defer", "s": "skip", "q": "quit"}
PROMPT = "[a]pprove / [r]eject / [d]efer / [s]kip / [q]uit: "


def _ask(prompt: str) -> str | None:
    """input() that returns None on Ctrl-D / end of input."""
    try:
        return input(prompt).strip()
    except EOFError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m approval",
        description="Review findings and record approve/reject/defer decisions in the audit log.",
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip folders/files whose path contains TEXT (repeatable)",
    )
    parser.add_argument("--log", default="audit/decisions.jsonl", help="audit log file (JSON Lines)")
    args = parser.parse_args(argv)

    try:
        report = run_all(args.folder, exclude=tuple(args.exclude))
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2
    for name, info in report["agents"].items():
        if info["status"] == "failed":
            print(f"warning: agent {name} failed: {info['error']}", file=sys.stderr)

    approver = getpass.getuser()
    pending = pending_findings(report, args.log)
    counts = {name: 0 for name in CHOICES.values()}
    seen = set()  # findings decided in this session
    print(f"{len(pending)} pending finding(s). Approver: {approver}")

    for i, f in enumerate(pending, start=1):
        if fingerprint(f) in seen:
            continue
        print()
        print(f"[{i}/{len(pending)}] {f['agent']}  {f['rule_id']}  {f['severity']}")
        print(f"  {f['file']}:{f['line']}  {f['redacted_match']}")
        print(f"  {f['message']}")

        choice = None
        while choice is None:
            answer = _ask(PROMPT)
            if answer is None:
                choice = "quit"
            else:
                choice = CHOICES.get(answer[:1].lower())
        if choice == "quit":
            counts["quit"] += 1
            break
        if choice == "skip":
            counts["skip"] += 1
            continue

        note = _ask("Optional note (Enter for none): ") or ""
        record_decision(args.log, f, choice, approver, note)
        if choice != "defer":
            seen.add(fingerprint(f))
        counts[choice] += 1

    print()
    print("Summary: " + ", ".join(f"{k}={counts[k]}" for k in ("approve", "reject", "defer", "skip")))
    print(f"Audit log: {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
