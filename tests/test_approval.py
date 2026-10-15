import hashlib
import json
from pathlib import Path

import pytest

from approval.decisions import (
    fingerprint,
    load_decided,
    pending_findings,
    record_decision,
)
from orchestrator.orchestrator import run_all

FIXTURES = Path(__file__).parent / "fixtures"

# FAKE values from the fixtures, split so this file does not trip the
# secrets scan in CI. None may appear in the log.
FAKE_SECRETS = [
    "AKIA" + "IOSFODNN7EXAMPLE",
    "FAKEKEYDATAFORTESTSONLY" + "NOTAREALKEY000000",
    "FakePassw0rd" + "ForTests",
    "sk-" + "ant-FAKE-KEY-FOR-TESTS-ONLY-000000",
]


def _finding(rule_id="private-key", file="k.pem", line=1, agent="secrets"):
    return {
        "agent": agent,
        "rule_id": rule_id,
        "severity": "critical",
        "file": file,
        "line": line,
        "message": "test",
        "redacted_match": "ab****",
    }


def _lines(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove nothing changes."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


def test_fingerprint_is_stable_and_specific():
    fp = fingerprint(_finding())
    assert fp == fingerprint(_finding())
    assert len(fp) == 16
    assert fp == hashlib.sha256(b"secrets|private-key|k.pem|1").hexdigest()[:16]
    assert fp != fingerprint(_finding(file="other.pem"))
    assert fp != fingerprint(_finding(line=2))


def test_record_appends_and_never_overwrites(tmp_path):
    log = tmp_path / "audit" / "decisions.jsonl"  # folder does not exist yet
    first = record_decision(str(log), _finding(line=1), "approve", "alice", "known test key")
    second = record_decision(str(log), _finding(line=2), "reject", "bob")

    lines = _lines(log)
    assert lines == [first, second]
    assert lines[0]["decision"] == "approve" and lines[0]["note"] == "known test key"
    assert lines[1]["decision"] == "reject" and lines[1]["approver"] == "bob"
    assert set(lines[0]) == {
        "timestamp", "fingerprint", "decision", "approver", "note",
        "agent", "rule_id", "severity", "file", "line", "redacted_match",
    }
    assert "message" not in lines[0]


@pytest.mark.parametrize("decision", ["delete", "APPROVE", "", "apply"])
def test_invalid_decision_raises(tmp_path, decision):
    log = tmp_path / "decisions.jsonl"
    with pytest.raises(ValueError):
        record_decision(str(log), _finding(), decision, "alice")
    assert not log.exists()


def test_missing_log_is_empty(tmp_path):
    assert load_decided(str(tmp_path / "nope.jsonl")) == set()


def test_load_decided_counts_approve_and_reject_not_defer(tmp_path):
    log = str(tmp_path / "decisions.jsonl")
    a, r, d = _finding(line=1), _finding(line=2), _finding(line=3)
    record_decision(log, a, "approve", "alice")
    record_decision(log, r, "reject", "alice")
    record_decision(log, d, "defer", "alice")
    assert load_decided(log) == {fingerprint(a), fingerprint(r)}


def test_pending_excludes_decided(tmp_path):
    log = str(tmp_path / "decisions.jsonl")
    a, r, d, new = (_finding(line=n) for n in (1, 2, 3, 4))
    report = {"findings": [a, r, d, new]}
    assert pending_findings(report, log) == [a, r, d, new]

    record_decision(log, a, "approve", "alice")
    record_decision(log, r, "reject", "alice")
    record_decision(log, d, "defer", "alice")
    assert pending_findings(report, log) == [d, new]


def test_decisions_do_not_modify_scanned_files(tmp_path):
    before = _snapshot(FIXTURES)
    report = run_all(str(FIXTURES))
    log = str(tmp_path / "decisions.jsonl")
    for finding, decision in zip(report["findings"], ["approve", "reject", "defer"]):
        record_decision(log, finding, decision, "alice")
    assert _snapshot(FIXTURES) == before


def test_log_never_contains_full_fake_secret(tmp_path):
    report = run_all(str(FIXTURES))
    assert report["findings"]
    log = tmp_path / "decisions.jsonl"
    for finding in report["findings"]:
        record_decision(str(log), finding, "defer", "alice")
    text = log.read_text()
    assert len(text.splitlines()) == len(report["findings"])
    for value in FAKE_SECRETS:
        assert value not in text


def test_cli_offline_is_passed_to_orchestrator(tmp_path, monkeypatch, capsys):
    import approval.__main__ as approval_main

    calls = []

    def fake_run_all(path, exclude=(), offline=False):
        calls.append(offline)
        return {"agents": {"dependencies": {"status": "failed", "error": "offline mode", "count": 0}}, "findings": []}

    monkeypatch.setattr(approval_main, "run_all", fake_run_all)
    assert approval_main.main([str(tmp_path), "--offline", "--log", str(tmp_path / "d.jsonl")]) == 0
    assert approval_main.main([str(tmp_path), "--log", str(tmp_path / "d.jsonl")]) == 0
    assert calls == [True, False]
    assert "warning: agent dependencies failed: offline mode" in capsys.readouterr().err
