import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from agents.terraform import agent
from agents.terraform.agent import main, parse_checkov_output, scan_directory

FIXTURES = Path(__file__).parent / "fixtures" / "terraform"
BAD = FIXTURES / "bad"
GOOD = FIXTURES / "good"

needs_checkov = pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="checkov not installed (pip install -r requirements-terraform.txt)",
)

SAMPLE = {
    "check_type": "terraform",
    "results": {
        "passed_checks": [
            {"check_id": "CKV_AWS_3", "file_path": "/ok.tf", "file_line_range": [1, 4]},
        ],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                "file_path": "/main.tf",
                "file_line_range": [8, 19],
                "resource": "aws_security_group.open_ssh",
                "severity": "HIGH",
                # Raw values Checkov includes; these must never reach a Finding.
                "check_result": {"result": "FAILED", "entity": {"user_data": "FAKE-VALUE"}},
            },
            {
                "check_id": "CKV_AWS_3",
                "check_name": "Ensure all data stored in the EBS is securely encrypted",
                "file_path": "/modules/disk.tf",
                "file_line_range": [21, 25],
                "resource": "aws_ebs_volume.unencrypted",
                "severity": None,
            },
        ],
    },
}


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


def test_parse_sample_maps_failed_checks():
    findings = parse_checkov_output(SAMPLE)
    assert [f.to_dict() for f in findings] == [
        {
            "agent": "terraform",
            "rule_id": "CKV_AWS_24",
            "severity": "high",
            "file": "main.tf",
            "line": 8,
            "message": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
            "redacted_match": "aws_security_group.open_ssh",
        },
        {
            "agent": "terraform",
            "rule_id": "CKV_AWS_3",
            "severity": "medium",
            "file": "modules/disk.tf",
            "line": 21,
            "message": "Ensure all data stored in the EBS is securely encrypted",
            "redacted_match": "aws_ebs_volume.unencrypted",
        },
    ]
    assert "FAKE-VALUE" not in json.dumps([f.to_dict() for f in findings])


def test_parse_list_input():
    other = {"check_type": "secrets", "results": {"failed_checks": []}}
    findings = parse_checkov_output([SAMPLE, other, SAMPLE])
    assert len(findings) == 4


@pytest.mark.parametrize("data", [{}, [], {"results": {}}, {"results": {"failed_checks": []}}])
def test_parse_empty_input(data):
    assert parse_checkov_output(data) == []


def test_cli_exit_code_2_for_missing_folder(tmp_path, capsys):
    assert main([str(tmp_path / "does-not-exist")]) == 2
    capsys.readouterr()


@needs_checkov
def test_bad_fixtures_have_findings(capsys):
    findings = scan_directory(str(BAD))
    assert len(findings) >= 3
    rule_ids = {f.rule_id for f in findings}
    # S3 public ACL, SSH open to the world, unencrypted EBS, HTTP-only storage.
    assert {"CKV_AWS_20", "CKV_AWS_24", "CKV_AWS_3", "CKV_AZURE_3"} <= rule_ids
    assert all(f.agent == "terraform" and f.file == "main.tf" for f in findings)

    assert main([str(BAD)]) == 1
    assert len(json.loads(capsys.readouterr().out)) == len(findings)


@needs_checkov
def test_good_fixtures_have_no_findings(capsys):
    assert main([str(GOOD)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_checkov
def test_exclude_skips_matching_files(capsys):
    assert main([str(BAD), "--exclude", "main.tf"]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_checkov
def test_scan_does_not_modify_files():
    before = _snapshot(FIXTURES)
    scan_directory(str(BAD))
    scan_directory(str(GOOD))
    assert _snapshot(FIXTURES) == before


def test_exclude_does_not_drop_lookalike_files(tmp_path, monkeypatch):
    # Offline: Checkov is faked, only the exclude filter is under test.
    files = ("main.tf", "infra/main.tf", "xmain.tf", "main.tf.bak", "tests/fixtures/a.tf", "other/tests/fixtures/a.tf")
    output = {"results": {"failed_checks": [
        {"check_id": "CKV_AWS_24", "check_name": "x", "file_path": "/" + f, "file_line_range": [1, 2]}
        for f in files
    ]}}
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(agent.importlib.util, "find_spec",
                        lambda name, *a: object() if name == "checkov" else real_find_spec(name, *a))
    monkeypatch.setattr(agent.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, json.dumps(output), ""))

    found = scan_directory(str(tmp_path), exclude=("main.tf", "tests/fixtures"))
    assert {f.file for f in found} == {"xmain.tf", "main.tf.bak", "other/tests/fixtures/a.tf"}


# Offline: Checkov is faked, so these run without checkov installed.
# What checkov 3.3.26 prints for a folder with no Terraform files.
NO_TERRAFORM_SUMMARY = {
    "passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
    "resource_count": 0, "checkov_version": "3.3.26",
}


def _fake_checkov(monkeypatch, returncode=0, stdout="", installed=True, raises=None):
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        agent.importlib.util, "find_spec",
        lambda name, *a: (object() if installed else None) if name == "checkov" else real_find_spec(name, *a),
    )

    def fake_run(cmd, **kw):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout, "")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)


@pytest.mark.parametrize("stdout", ["", "  \n", None], ids=["empty", "whitespace", "none"])
def test_empty_output_is_an_error_not_clean(tmp_path, monkeypatch, capsys, stdout):
    _fake_checkov(monkeypatch, stdout=stdout)
    with pytest.raises(agent.CheckovError, match="no output"):
        scan_directory(str(tmp_path))
    assert main([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error: checkov returned no output" in captured.err


def test_invalid_json_is_an_error(tmp_path, monkeypatch):
    _fake_checkov(monkeypatch, stdout="not json {")
    with pytest.raises(agent.CheckovError, match="could not parse"):
        scan_directory(str(tmp_path))


@pytest.mark.parametrize("stdout", ["null", "5", '"x"', "true"])
def test_json_that_is_not_an_object_or_list_is_an_error(tmp_path, monkeypatch, stdout):
    _fake_checkov(monkeypatch, stdout=stdout)
    with pytest.raises(agent.CheckovError, match="unexpected"):
        scan_directory(str(tmp_path))


@pytest.mark.parametrize("returncode", [2, -9])
def test_bad_exit_code_is_an_error(tmp_path, monkeypatch, returncode):
    _fake_checkov(monkeypatch, returncode=returncode, stdout=json.dumps(SAMPLE))
    with pytest.raises(agent.CheckovError, match=f"exit code {returncode}"):
        scan_directory(str(tmp_path))


def test_timeout_is_an_error(tmp_path, monkeypatch):
    _fake_checkov(monkeypatch, raises=subprocess.TimeoutExpired("checkov", agent.TIMEOUT_SECONDS))
    with pytest.raises(agent.CheckovError, match="timed out"):
        scan_directory(str(tmp_path))


def test_missing_checkov_is_an_error(tmp_path, monkeypatch, capsys):
    _fake_checkov(monkeypatch, installed=False)
    with pytest.raises(agent.CheckovError, match="not installed"):
        scan_directory(str(tmp_path))
    assert main([str(tmp_path)]) == 2
    assert agent.INSTALL_HINT in capsys.readouterr().err


def test_folder_without_terraform_is_clean(tmp_path, monkeypatch, capsys):
    _fake_checkov(monkeypatch, stdout=json.dumps(NO_TERRAFORM_SUMMARY, indent=4))
    assert scan_directory(str(tmp_path)) == []
    assert main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []
