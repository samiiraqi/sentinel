import hashlib
import json
import os
from pathlib import Path

import pytest

from agents.secrets.agent import main, redact, scan_directory

FIXTURES = Path(__file__).parent / "fixtures"

# FAKE values, split into pieces so this file does not itself trip the
# scanner when CI scans the repo.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_ANTHROPIC_KEY = "sk-" + "ant-FAKE-KEY-FOR-TESTS-ONLY-000000"

# Every FAKE secret value in the fixtures. None may appear in any output.
FAKE_SECRETS = [
    FAKE_AWS_KEY,
    "FAKEKEYDATAFORTESTSONLYNOTAREALKEY000000",
    "FakePassw0rdForTests",
    FAKE_ANTHROPIC_KEY,
]


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


@pytest.fixture(scope="module")
def findings():
    return scan_directory(str(FIXTURES))


@pytest.mark.parametrize(
    "file, rule_id",
    [
        ("aws_config.ini", "aws-access-key-id"),
        ("fake_key.pem", "private-key"),
        ("settings.py", "generic-secret-assignment"),
        ("settings.py", "anthropic-api-key"),
    ],
)
def test_each_fake_secret_is_found(findings, file, rule_id):
    assert any(f.file == file and f.rule_id == rule_id for f in findings)


def test_clean_file_has_no_findings(findings):
    assert [f for f in findings if f.file == "clean.py"] == []


def test_full_secret_never_in_findings(findings):
    output = json.dumps([f.to_dict() for f in findings])
    for secret in FAKE_SECRETS:
        assert secret not in output
    for f in findings:
        assert f.redacted_match.endswith("****")
        assert len(f.redacted_match) <= 8


def test_full_secret_never_in_cli_output(capsys):
    assert main([str(FIXTURES)]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)  # valid, non-empty JSON
    for secret in FAKE_SECRETS:
        assert secret not in out


def test_scan_does_not_modify_files():
    before = _snapshot(FIXTURES)
    scan_directory(str(FIXTURES))
    assert _snapshot(FIXTURES) == before


def test_redact_short_values_are_not_fully_shown():
    assert redact("abcd") == "ab****"
    assert redact(FAKE_AWS_KEY) == "AKIA****"


def test_skips_binary_symlinks_and_ignored_dirs(tmp_path):
    secret_line = f"aws_access_key_id = {FAKE_AWS_KEY}\n".encode()
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01" + secret_line)
    for skipped in (".git", ".venv", "node_modules"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "config").write_bytes(secret_line)

    outside = tmp_path.parent / f"{tmp_path.name}_outside"
    outside.mkdir()
    (outside / "leak.txt").write_bytes(secret_line)
    os.symlink(outside, tmp_path / "linked_dir")
    os.symlink(outside / "leak.txt", tmp_path / "linked_file.txt")

    assert scan_directory(str(tmp_path)) == []


def test_exclude_skips_matching_folders_and_files(tmp_path):
    secret_line = f"aws_access_key_id = {FAKE_AWS_KEY}\n"
    (tmp_path / "keep").mkdir()
    (tmp_path / "keep" / "a.txt").write_text(secret_line)
    (tmp_path / "skip_me").mkdir()
    (tmp_path / "skip_me" / "b.txt").write_text(secret_line)
    (tmp_path / "keep" / "skip_me.txt").write_text(secret_line)

    assert {f.file for f in scan_directory(str(tmp_path))} == {
        "keep/a.txt",
        "keep/skip_me.txt",
        "skip_me/b.txt",
    }
    found = scan_directory(str(tmp_path), exclude=("skip_me",))
    # Whole-component match: the folder skip_me/ is skipped, the file
    # keep/skip_me.txt is not (its name only contains "skip_me").
    assert {f.file for f in found} == {"keep/a.txt", "keep/skip_me.txt"}
    found = scan_directory(str(tmp_path), exclude=("skip_me", "skip_me.txt"))
    assert {f.file for f in found} == {"keep/a.txt"}


def test_exclude_does_not_hide_lookalike_paths(tmp_path):
    secret_line = f"aws_access_key_id = {FAKE_AWS_KEY}\n"
    hidden = (".venv/x.txt", "app/.venv/x.txt", "tests/fixtures/x.txt")
    visible = ("prod.venv-config", ".venv-old/x.txt", "tests/fixtures_old/a.txt", "other/tests/fixtures/a.txt")
    for rel in hidden + visible:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(secret_line)

    found = scan_directory(str(tmp_path), exclude=(".venv", "tests/fixtures"))
    assert {f.file for f in found} == set(visible)


def test_cli_exclude_option_is_repeatable(tmp_path, capsys):
    (tmp_path / "one").mkdir()
    (tmp_path / "one" / "a.txt").write_text(f"key = {FAKE_AWS_KEY}\n")
    (tmp_path / "two").mkdir()
    (tmp_path / "two" / "b.txt").write_text(f"key = {FAKE_AWS_KEY}\n")

    assert main([str(tmp_path), "--exclude", "one"]) == 1
    assert {f["file"] for f in json.loads(capsys.readouterr().out)} == {"two/b.txt"}
    assert main([str(tmp_path), "--exclude", "one", "--exclude", "two"]) == 0
    assert json.loads(capsys.readouterr().out) == []


LOOKALIKES = ("old-constraints-ci.txt", "docs/constraints-ci.txt", "constraints-ci.txt.bak")


def _write_constraints_lookalikes(root):
    secret_line = f"aws_access_key_id = {FAKE_AWS_KEY}\n"
    (root / "docs").mkdir()
    for rel in ("constraints-ci.txt", *LOOKALIKES):
        (root / rel).write_text(secret_line)


def test_exclude_file_skips_only_the_exact_path(tmp_path):
    _write_constraints_lookalikes(tmp_path)

    found = scan_directory(str(tmp_path), exclude_files=("constraints-ci.txt",))
    assert {f.file for f in found} == set(LOOKALIKES)
    assert all(f.rule_id == "aws-access-key-id" for f in found)


def test_exclude_file_does_not_match_folders(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text(f"aws_access_key_id = {FAKE_AWS_KEY}\n")

    found = scan_directory(str(tmp_path), exclude_files=("docs",))
    assert {f.file for f in found} == {"docs/a.txt"}


def test_cli_exclude_file_option(tmp_path, capsys):
    _write_constraints_lookalikes(tmp_path)

    assert main([str(tmp_path), "--exclude-file", "constraints-ci.txt"]) == 1
    assert {f["file"] for f in json.loads(capsys.readouterr().out)} == set(LOOKALIKES)
    args = [str(tmp_path)]
    for rel in ("constraints-ci.txt", *LOOKALIKES):
        args += ["--exclude-file", rel]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_exit_code_1_with_findings_0_when_clean(capsys):
    assert main([str(FIXTURES)]) == 1
    # config_yaml/good/k8s/deployment.yaml sets automountServiceAccountToken to false,
    # a known false positive of generic-secret-assignment; this test is about the 3 secret fixtures.
    assert main([str(FIXTURES), "--exclude", "aws_config.ini", "--exclude", "fake_key.pem",
                 "--exclude", "settings.py", "--exclude", "config_yaml"]) == 0
    capsys.readouterr()
