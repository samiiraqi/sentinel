# Audit log

- `decisions.jsonl` is written by `python -m approval`. It holds one JSON object per line, and lines are only ever appended, never changed or deleted.
- Each line contains: `timestamp` (UTC, ISO 8601), `fingerprint`, `decision` (approve/reject/defer), `approver`, `note`, and the finding's `agent`, `rule_id`, `severity`, `file`, `line` and `redacted_match`.
- `fingerprint` is the first 16 hex characters of sha256("agent|rule_id|file|line"), so the same finding gets the same id across runs.
- A decision is a record only. Nothing is changed or run because of it. A deferred finding shows up again next time; approved and rejected ones do not.
- Log files (`*.jsonl`) are git-ignored and stay on this machine; only this README is committed.
