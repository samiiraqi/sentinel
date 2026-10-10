import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from orchestrator import orchestrator
from orchestrator.orchestrator import apply_severity, main, run_all, sort_findings
from shared.models import Finding

FIXTURES = Path(__file__).parent / "fixtures"

needs_checkov = pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="checkov not installed (pip install -r requirements-terraform.txt)",
)

# FAKE values from the fixtures, split so this file does not trip the
# secrets scan in CI. None may appear in any report.
FAKE_SECRETS = [
    "AKIA" + "IOSFODNN7EXAMPLE",
    "FAKEKEYDATAFORTESTSONLY" + "NOTAREALKEY000000",
    "FakePassw0rd" + "ForTests",
    "sk-" + "ant-FAKE-KEY-FOR-TESTS-ONLY-000000",
]


def _finding(rule_id="x", severity="low", file="a.txt", line=1, agent="secrets"):
    return Finding(
        agent=agent,
        rule_id=rule_id,
        severity=severity,
        file=file,
        line=line,
        message="test",
        redacted_match="ab****",
    )


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the run changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


@pytest.mark.parametrize(
    "rule_id, agent_severity, expected",
    [
        ("private-key", "low", "critical"),
        ("aws-access-key-id", "high", "critical"),
        ("anthropic-api-key", "medium", "critical"),
        ("generic-secret-assignment", "medium", "high"),
        ("CKV_AWS_24", "medium", "high"),
        ("CKV_AWS_20", "medium", "high"),
        ("CKV_AWS_3", "low", "medium"),
        ("CKV_AZURE_3", "high", "medium"),
        ("CKV_UNKNOWN_1", "low", "low"),
        ("some-other-rule", "critical", "critical"),
    ],
)
def test_severity_override(rule_id, agent_severity, expected):
    assert apply_severity(_finding(rule_id, agent_severity)).severity == expected


def test_sort_order():
    findings = [
        _finding(severity="low", file="a.txt", line=1),
        _finding(severity="medium", file="b.txt", line=9),
        _finding(severity="critical", file="z.txt", line=5),
        _finding(severity="medium", file="b.txt", line=2),
        _finding(severity="high", file="c.txt", line=1),
        _finding(severity="critical", file="a.txt", line=7),
        _finding(severity="medium", file="a.txt", line=30),
    ]
    got = [(f.severity, f.file, f.line) for f in sort_findings(findings)]
    assert got == [
        ("critical", "a.txt", 7),
        ("critical", "z.txt", 5),
        ("high", "c.txt", 1),
        ("medium", "a.txt", 30),
        ("medium", "b.txt", 2),
        ("medium", "b.txt", 9),
        ("low", "a.txt", 1),
    ]


def test_one_failing_agent_does_not_stop_the_others(tmp_path, monkeypatch, capsys):
    def broken(path, exclude=()):
        raise RuntimeError("checkov is not installed")

    def fake_secrets(path, exclude=()):
        return [_finding("private-key", "low", file="k.pem")]

    monkeypatch.setitem(orchestrator.AGENTS, "secrets", fake_secrets)
    monkeypatch.setitem(orchestrator.AGENTS, "terraform", broken)

    report = run_all(str(tmp_path))
    assert report["agents"]["terraform"] == {
        "status": "failed",
        "error": "RuntimeError: checkov is not installed",
        "count": 0,
    }
    assert report["agents"]["secrets"] == {"status": "ok", "error": None, "count": 1}
    assert report["summary"]["total"] == 1
    assert report["summary"]["by_severity"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert report["findings"][0]["rule_id"] == "private-key"

    assert main([str(tmp_path)]) == 1
    capsys.readouterr()


def test_exit_code_2_when_all_agents_fail(tmp_path, monkeypatch, capsys):
    def broken(path, exclude=()):
        raise RuntimeError("boom")

    for name in orchestrator.AGENTS:
        monkeypatch.setitem(orchestrator.AGENTS, name, broken)
    assert main([str(tmp_path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert all(a["status"] == "failed" for a in report["agents"].values())


def test_exit_code_2_for_missing_folder(tmp_path, capsys):
    assert main([str(tmp_path / "does-not-exist")]) == 2
    capsys.readouterr()


def test_integration_finds_from_both_agents():
    report = run_all(str(FIXTURES))
    agents = {f["agent"] for f in report["findings"]}
    assert report["agents"]["secrets"]["status"] == "ok"
    assert "secrets" in agents
    assert {"aws-access-key-id", "private-key"} <= {f["rule_id"] for f in report["findings"]}
    assert report["summary"]["total"] == len(report["findings"])


@needs_checkov
def test_integration_includes_terraform_findings():
    report = run_all(str(FIXTURES))
    assert report["agents"]["terraform"]["status"] == "ok"
    tf = [f for f in report["findings"] if f["agent"] == "terraform"]
    assert {"CKV_AWS_20", "CKV_AWS_24"} <= {f["rule_id"] for f in tf}
    assert all(f["file"].startswith("terraform/bad/") for f in tf)


def test_run_does_not_modify_files():
    before = _snapshot(FIXTURES)
    run_all(str(FIXTURES))
    assert _snapshot(FIXTURES) == before


def test_full_secret_never_in_report(capsys):
    assert main([str(FIXTURES)]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)["findings"]
    for secret in FAKE_SECRETS:
        assert secret not in out
