import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

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
