import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from agents.dependencies import agent as dependencies_agent
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

    # Any failed agent -> exit 2, but the findings are still printed.
    assert main([str(tmp_path)]) == 2
    printed = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in printed["findings"]] == ["private-key"]
    assert printed["agents"]["terraform"]["status"] == "failed"


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
    # Without checkov the terraform agent fails, and any failed agent means exit 2.
    expected = 1 if importlib.util.find_spec("checkov") else 2
    assert main([str(FIXTURES)]) == expected
    out = capsys.readouterr().out
    assert json.loads(out)["findings"]
    for secret in FAKE_SECRETS:
        assert secret not in out


# ---------------------------------------------------------------- dependencies agent


def _no_tools(monkeypatch):
    """Fail the test if any external tool (pip-audit, npm) would be started."""

    def fail(*args, **kwargs):
        raise AssertionError("no tool or network call expected")

    monkeypatch.setattr(dependencies_agent, "_run_tool", fail)


def _all_agents_return(monkeypatch, results):
    for name in orchestrator.AGENTS:
        found = results.get(name, [])
        monkeypatch.setitem(orchestrator.AGENTS, name, lambda path, exclude=(), offline=False, found=found: found)


def test_dependencies_agent_is_registered():
    assert orchestrator.AGENTS["dependencies"] is dependencies_agent.scan_directory
    assert orchestrator.NETWORK_AGENTS == {"dependencies"}


def test_dependencies_findings_are_merged_and_sorted(tmp_path, monkeypatch, capsys):
    _all_agents_return(
        monkeypatch,
        {
            # One item per line, or our own secrets scan reports this key as a hard-coded secret.
            "secrets": [
                _finding("private-key", "low", file="k.pem"),
            ],
            "dependencies": [
                _finding("unpinned-dependency", "medium", file="requirements.txt", line=2, agent="dependencies"),
                _finding("CVE-2018-18074", "high", file="requirements.txt", line=1, agent="dependencies"),
            ],
        },
    )
    report = run_all(str(tmp_path))
    assert [(f["agent"], f["rule_id"]) for f in report["findings"]] == [
        ("secrets", "private-key"),  # raised to critical by SEVERITY_RULES
        ("dependencies", "CVE-2018-18074"),
        ("dependencies", "unpinned-dependency"),
    ]
    assert report["agents"]["dependencies"] == {"status": "ok", "error": None, "count": 2}
    assert report["summary"]["by_agent"]["dependencies"] == 2
    assert main([str(tmp_path)]) == 1
    capsys.readouterr()


def test_failed_dependencies_agent_is_never_clean(tmp_path, monkeypatch, capsys):
    # The case that used to exit 0: other agents found nothing, dependencies failed.
    _all_agents_return(monkeypatch, {})

    def broken(path, exclude=(), offline=False):
        raise dependencies_agent.DependenciesError(dependencies_agent.PIP_AUDIT_HINT)

    monkeypatch.setitem(orchestrator.AGENTS, "dependencies", broken)
    assert main([str(tmp_path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["agents"]["dependencies"]["status"] == "failed"
    assert "pip-audit is not installed" in report["agents"]["dependencies"]["error"]
    assert report["agents"]["secrets"]["status"] == "ok"


def test_real_dependencies_agent_missing_tool_shows_failed(tmp_path, monkeypatch):
    _no_tools(monkeypatch)
    monkeypatch.setattr(dependencies_agent, "_pip_audit_installed", lambda: False)
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    report = run_all(str(tmp_path))
    assert report["agents"]["dependencies"]["status"] == "failed"
    assert "pip-audit is not installed" in report["agents"]["dependencies"]["error"]
    assert report["agents"]["secrets"]["status"] == "ok"


def test_exit_code_0_only_when_every_agent_ran_clean(tmp_path, monkeypatch, capsys):
    _all_agents_return(monkeypatch, {})
    assert main([str(tmp_path)]) == 0
    capsys.readouterr()


def test_offline_only_reaches_network_agents(tmp_path, monkeypatch):
    _no_tools(monkeypatch)
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    calls = []

    # No `offline` parameter: a TypeError here would mean it was passed to a non-network agent.
    def plain(path, exclude=()):
        calls.append(path)
        return []

    monkeypatch.setitem(orchestrator.AGENTS, "secrets", plain)
    monkeypatch.setitem(orchestrator.AGENTS, "terraform", plain)

    report = run_all(str(tmp_path), offline=True)
    assert report["agents"]["dependencies"]["status"] == "failed"
    assert "offline mode" in report["agents"]["dependencies"]["error"]
    assert report["agents"]["secrets"]["status"] == "ok"
    assert report["agents"]["terraform"]["status"] == "ok"
    assert len(calls) == 2


def test_cli_offline_flag(tmp_path, monkeypatch, capsys):
    _no_tools(monkeypatch)
    (tmp_path / "k.pem").write_text("-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n")
    assert main([str(tmp_path), "--offline"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert "offline mode" in report["agents"]["dependencies"]["error"]
    assert report["findings"]  # findings from the other agents are still printed


def test_fixtures_need_no_dependency_tools():
    # Integration tests scan tests/fixtures; with no dependency files there,
    # they never start pip-audit or npm, so CI makes no network calls.
    assert dependencies_agent.find_manifests(str(FIXTURES)) == ([], [])


def test_dependencies_budget_exceeded_shows_failed(tmp_path, monkeypatch, capsys):
    _no_tools(monkeypatch)  # a 0.5s budget is too little to start any tool
    monkeypatch.setattr(dependencies_agent, "_pip_audit_installed", lambda: True)
    monkeypatch.setenv(dependencies_agent.BUDGET_ENV, "0.5")
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    assert main([str(tmp_path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["agents"]["dependencies"]["status"] == "failed"
    assert "TimeBudgetExceeded: time budget of 0.5s ran out" in report["agents"]["dependencies"]["error"]
    assert "not audited: requirements.txt (in progress)" in report["agents"]["dependencies"]["error"]
