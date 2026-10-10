"""Human approval decisions, stored in an append-only audit log.

A decision is a RECORD ONLY: it never changes scanned files or
infrastructure and never runs any action. The log is opened in append
mode only; earlier lines are never rewritten, truncated, or deleted.
Only fields from the (already redacted) Finding are stored.

Log format: one JSON object per line (JSON Lines).
"""

import hashlib
import json
import os
from datetime import datetime, timezone

VALID_DECISIONS = ("approve", "reject", "defer")
FINAL_DECISIONS = ("approve", "reject")  # defer comes back next time

# Finding fields copied into each record. Nothing else from the finding is kept.
FINDING_FIELDS = ("agent", "rule_id", "severity", "file", "line", "redacted_match")


def fingerprint(finding: dict) -> str:
    """Stable id for a finding: sha256 of agent|rule_id|file|line, first 16 hex chars."""
    raw = "|".join(str(finding[k]) for k in ("agent", "rule_id", "file", "line"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def record_decision(log_path: str, finding: dict, decision: str, approver: str, note: str = "") -> dict:
    """Append ONE decision line to the log and return the record."""
    if decision not in VALID_DECISIONS:
        raise ValueError(f"invalid decision: {decision!r} (use one of {VALID_DECISIONS})")
    if not approver:
        raise ValueError("approver is required")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint(finding),
        "decision": decision,
        "approver": approver,
        "note": note,
    }
    record.update({k: finding.get(k) for k in FINDING_FIELDS})

    folder = os.path.dirname(os.path.abspath(log_path))
    os.makedirs(folder, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as fh:  # append-only
        fh.write(json.dumps(record) + "\n")
    return record


def load_decided(log_path: str) -> set[str]:
    """Fingerprints that already have an approve or reject decision."""
    decided = set()
    try:
        fh = open(log_path, encoding="utf-8")
    except FileNotFoundError:
        return decided
    with fh:
        for line in fh:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # never fix the log; just skip a bad line
            if isinstance(record, dict) and record.get("decision") in FINAL_DECISIONS:
                decided.add(record.get("fingerprint"))
    return decided


def pending_findings(report: dict, log_path: str) -> list[dict]:
    """Findings from an orchestrator report that are not yet approved or rejected."""
    decided = load_decided(log_path)
    return [f for f in report.get("findings", []) if fingerprint(f) not in decided]
