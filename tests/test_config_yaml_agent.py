import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.config_yaml import agent
from agents.gha import agent as gha_agent
from agents.config_yaml.agent import (
    ConfigYamlError,
    check_yaml_files,
    find_dockerfiles,
    main,
    parse_checkov_output,
    scan_directory,
    scanned_files,
)
from shared import proc as shared_proc

FIXTURES = Path(__file__).parent / "fixtures" / "config_yaml"
BAD = FIXTURES / "bad"
GOOD = FIXTURES / "good"

needs_checkov = pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="checkov not installed (pip install -r requirements-terraform.txt)",
)
# The coverage check uses PyYAML, which is installed with checkov.
needs_yaml = pytest.mark.skipif(
    importlib.util.find_spec("yaml") is None,
    reason="PyYAML not installed (comes with checkov: pip install -r requirements-terraform.txt)",
)

# Trimmed from real `checkov --framework kubernetes dockerfile github_actions -o json --compact` output (3.3.29).
# The agent no longer runs github_actions; that report stays to test the parser on any report.
SAMPLE = [
    {
        "check_type": "kubernetes",
        "results": {
            "passed_checks": [
                {"check_id": "CKV_K8S_1", "file_path": "/k8s/ok.yaml", "file_line_range": [1, 9]},
            ],
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_16",
                    "check_name": "Container should not be privileged",
                    "file_path": "/k8s/deployment.yaml",
                    "file_line_range": [2, 21],
                    "resource": "Deployment.default.web",
                    "severity": None,
                    # Raw values Checkov includes; these must never reach a Finding.
                    "code_block": [[1, "FAKE-RAW-CONTENT"]],
                    "check_result": {"result": "FAILED", "results_configuration": {"value": "FAKE-VALUE"}},
                },
            ],
            "parsing_errors": ["/k8s/broken.yaml"],
        },
        "summary": {"passed": 1, "failed": 1, "parsing_errors": 1},
    },
    {
        "check_type": "github_actions",
        "results": {
            "passed_checks": [
                {"check_id": "CKV_GHA_1", "file_path": "/.github/workflows/ci.yml", "file_line_range": [0, 1]},
            ],
            "failed_checks": [
                {
                    "check_id": "CKV_GHA_2",
                    "check_name": "Ensure run commands are not vulnerable to shell injection",
                    "file_path": "/.github/workflows/bad.yml",
                    "file_line_range": [10, 13],
                    "resource": "jobs(greet).steps[1]",
                    "severity": "HIGH",
                },
            ],
        },
        "summary": {"passed": 1, "failed": 1, "parsing_errors": 0},
    },
]

# What Checkov prints when it found nothing to check.
EMPTY_SUMMARY = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0}


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


class FakeCheckov:
    """Stands in for the checkov process: records the call, returns fixed output."""

    def __init__(self, stdout="", code=0, raises=None):
        self.stdout = stdout if isinstance(stdout, str) else json.dumps(stdout)
        self.code, self.raises = code, raises
        self.calls = []

    def run(self, cmd, timeout, cwd, env):
        self.calls.append({"cmd": list(cmd), "timeout": timeout, "cwd": cwd, "env": dict(env)})
        if self.raises:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.code, self.stdout, "")


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        checkov = FakeCheckov(**kwargs)
        monkeypatch.setattr(agent, "_run_tool", checkov.run)
        real_find_spec = importlib.util.find_spec
        monkeypatch.setattr(agent.importlib.util, "find_spec",
                            lambda name, *a: object() if name == "checkov" else real_find_spec(name, *a))
        return checkov
    return install


# ---------------------------------------------------------------- parser


def test_parse_maps_fields_and_drops_raw_values():
    findings = parse_checkov_output(SAMPLE)
    k8s = next(f for f in findings if f.rule_id == "CKV_K8S_16")
    assert k8s.to_dict() == {
        "agent": "config_yaml",
        "rule_id": "CKV_K8S_16",
        "severity": "medium",  # Checkov gives none: default
        "file": "k8s/deployment.yaml",
        "line": 2,
        "message": "Container should not be privileged",
        "redacted_match": "Deployment.default.web",
    }
    assert "FAKE" not in json.dumps([f.to_dict() for f in findings])
    gha = next(f for f in findings if f.rule_id == "CKV_GHA_2")
    assert (gha.severity, gha.file, gha.line) == ("high", ".github/workflows/bad.yml", 10)


def test_parse_errors_become_unscanned_findings():
    unscanned = [f for f in parse_checkov_output(SAMPLE) if f.rule_id == "config-unscanned"]
    assert [(f.file, f.severity) for f in unscanned] == [("k8s/broken.yaml", "low")]


def test_parse_single_report_dict_and_empty_summary():
    assert [f.rule_id for f in parse_checkov_output(SAMPLE[1])] == ["CKV_GHA_2"]
    assert parse_checkov_output(EMPTY_SUMMARY) == []
    assert parse_checkov_output([None, "x", {}]) == []


def test_scanned_files_counts_passed_and_failed_per_framework():
    assert scanned_files(SAMPLE, "github_actions") == {".github/workflows/ci.yml", ".github/workflows/bad.yml"}
    assert scanned_files(SAMPLE, "kubernetes") == {"k8s/ok.yaml", "k8s/deployment.yaml"}
    assert scanned_files(EMPTY_SUMMARY, "github_actions") == set()


# ---------------------------------------------------------------- failures never look clean


def test_missing_checkov_is_an_error(tmp_path, monkeypatch):
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(agent.importlib.util, "find_spec",
                        lambda name, *a: None if name == "checkov" else real_find_spec(name, *a))
    with pytest.raises(ConfigYamlError, match="checkov is not installed"):
        scan_directory(str(tmp_path))


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"code": 2, "stdout": SAMPLE}, "exit code 2"),
        ({"code": 1, "stdout": "not json"}, "could not parse"),
        ({"code": 0, "stdout": "   \n"}, "no output"),
        ({"code": 0, "stdout": "42"}, "unexpected"),
        ({"raises": subprocess.TimeoutExpired(["checkov"], 300)}, "timed out"),
    ],
)
def test_tool_failures_raise_never_return_empty(tmp_path, fake, kwargs, message):
    fake(**kwargs)
    with pytest.raises(ConfigYamlError, match=message):
        scan_directory(str(tmp_path))


def test_cli_error_exit_code_2(tmp_path, fake, capsys):
    fake(code=2, stdout="")
    assert main([str(tmp_path)]) == 2
    assert "exit code 2" in capsys.readouterr().err


def test_missing_yaml_is_an_error(tmp_path, fake, monkeypatch):
    fake(stdout=EMPTY_SUMMARY)
    monkeypatch.setitem(sys.modules, "yaml", None)  # makes `import yaml` fail
    with pytest.raises(ConfigYamlError, match="checkov is not installed"):
        scan_directory(str(tmp_path))


def test_cli_not_a_directory(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


# ---------------------------------------------------------------- how checkov is run


@needs_yaml
def test_checkov_runs_offline_without_api_keys(tmp_path, fake, monkeypatch):
    monkeypatch.setenv("BC_API_KEY", "FAKE-KEY-FOR-TESTS")
    monkeypatch.setenv("PRISMA_API_URL", "https://example.invalid")
    checkov = fake(stdout=EMPTY_SUMMARY)
    assert scan_directory(str(tmp_path)) == []

    (call,) = checkov.calls
    assert "--skip-download" in call["cmd"]
    assert call["cmd"][call["cmd"].index("--framework") + 1:][:3] == ["kubernetes", "dockerfile", "-o"]
    assert "github_actions" not in call["cmd"]  # the gha agent owns workflows
    assert call["cwd"] == str(tmp_path)
    assert call["timeout"] == agent.TIMEOUT_SECONDS
    assert "BC_API_KEY" not in call["env"] and "PRISMA_API_URL" not in call["env"]


def test_uses_the_shared_process_runner():
    # Kill-on-timeout (child and grandchild) is tested once, in tests/test_proc.py.
    assert agent._run_tool is shared_proc.run_tool


# ---------------------------------------------------------------- coverage check


@needs_yaml
def test_invalid_yaml_is_reported_unscanned(tmp_path, fake):
    (tmp_path / "pod.yaml").write_text("apiVersion: v1\nkind: Pod\nspec: [\n")
    (tmp_path / "ok.yml").write_text("a: 1\n---\nb: 2\n")
    (tmp_path / "notes.txt").write_text("not: [yaml\n")
    fake(stdout=EMPTY_SUMMARY)

    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file, f.severity) for f in found] == [("config-unscanned", "pod.yaml", "low")]
    assert found[0].line == 4


@needs_yaml
def test_gha_files_are_never_reported(tmp_path, fake):
    # Workflows and action.yml files belong to the gha agent: no rule findings,
    # no config-unscanned findings, even if invalid or if Checkov reports one.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "missed.yaml").write_text("name: b\non: push\njobs: {}\n")
    (wf / "invalid.yml").write_text("jobs: [\n")
    (tmp_path / "action.yml").write_text("runs: [\n")
    (tmp_path / "k8s.yaml").write_text("a: [\n")
    fake(stdout=[
        {"check_type": "kubernetes", "results": {"parsing_errors": [str(wf / "invalid.yml")]}},
        {"check_type": "github_actions", "results": {"failed_checks": [
            {"check_id": "CKV_GHA_2", "check_name": "x", "file_path": "/.github/workflows/missed.yaml"},
        ]}},
    ])

    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file) for f in found] == [("config-unscanned", "k8s.yaml")]


@needs_yaml
def test_checkov_parse_error_and_own_check_are_not_duplicated(tmp_path, fake):
    (tmp_path / "broken.yaml").write_text("a: [\n")
    # Checkov lists parsing_errors as absolute paths.
    fake(stdout={"check_type": "kubernetes", "results": {"parsing_errors": [str(tmp_path / "broken.yaml")]}})
    assert [f.file for f in scan_directory(str(tmp_path))] == ["broken.yaml"]


@needs_yaml
def test_coverage_check_skips_vendored_dirs_and_symlinks(tmp_path):
    for folder in ("node_modules", ".venv", ".git"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "x.yaml").write_text("a: [\n")
    (tmp_path / "outside.yaml").write_text("a: [\n")
    (tmp_path / "link.yaml").symlink_to(tmp_path / "outside.yaml")

    unscanned = check_yaml_files(str(tmp_path))
    assert [f.file for f in unscanned] == ["outside.yaml"]


@needs_yaml
def test_exclude_uses_component_matching(tmp_path, fake):
    output = {"check_type": "kubernetes", "results": {"failed_checks": [
        {"check_id": "CKV_K8S_16", "check_name": "x", "file_path": "/" + f, "file_line_range": [1, 2]}
        for f in ("k8s/a.yaml", "k8s-old/a.yaml", "tests/fixtures/a.yaml", "other/tests/fixtures/a.yaml")
    ]}}
    fake(stdout=output)
    found = scan_directory(str(tmp_path), exclude=("k8s", "tests/fixtures"))
    assert {f.file for f in found} == {"k8s-old/a.yaml", "other/tests/fixtures/a.yaml"}


# ---------------------------------------------------------------- parsing_errors paths
# Checkov lists parsing_errors as absolute paths; they must become relative
# to the scanned folder, and a path outside it must never be shown.
ROOT = "/scan/root"
OUTSIDE_MESSAGE = "not scanned: Checkov could not parse a file outside the scanned folder"


def _parse_errors(*paths, check_type="kubernetes"):
    return {"check_type": check_type, "results": {"parsing_errors": list(paths)}}


def test_absolute_parse_error_paths_become_relative():
    findings = parse_checkov_output(_parse_errors(ROOT + "/k8s/broken.yaml", ROOT + "/a/b/c.yml"), ROOT)
    assert [(f.rule_id, f.severity, f.file, f.line) for f in findings] == [
        ("config-unscanned", "low", "k8s/broken.yaml", 0),
        ("config-unscanned", "low", "a/b/c.yml", 0),
    ]
    assert all(f.message == "not scanned: Checkov could not parse this file" for f in findings)


@pytest.mark.parametrize(
    "path",
    ["/elsewhere/deploy.yaml", ROOT + "/../deploy.yaml", ROOT, "", 5, None],
    ids=["other-folder", "dot-dot", "root-itself", "empty", "int", "none"],
)
def test_parse_error_outside_root_is_one_unnamed_finding(path):
    findings = parse_checkov_output(_parse_errors(path), ROOT)
    assert [(f.rule_id, f.severity, f.file, f.message) for f in findings] == [
        ("config-unscanned", "low", "", OUTSIDE_MESSAGE),
    ]
    assert "elsewhere" not in json.dumps([f.to_dict() for f in findings])


def test_many_outside_paths_across_reports_give_one_unnamed_finding():
    data = [
        _parse_errors("/elsewhere/a.yaml", ROOT + "/k8s/in.yaml"),
        _parse_errors("/elsewhere/b.yml", "", check_type="github_actions"),
    ]
    assert [f.file for f in parse_checkov_output(data, ROOT)] == ["k8s/in.yaml", ""]


@needs_yaml
def test_nested_absolute_parse_error_is_relative_and_not_duplicated(tmp_path, fake):
    nested = tmp_path / "k8s" / "apps" / "broken.yaml"
    nested.parent.mkdir(parents=True)
    nested.write_text("a: [\n")
    fake(stdout=_parse_errors(str(nested)))
    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file) for f in found] == [("config-unscanned", "k8s/apps/broken.yaml")]


@needs_yaml
def test_exclude_hides_named_parse_error_but_not_outside_one(tmp_path, fake):
    fake(stdout=_parse_errors(str(tmp_path / "k8s" / "a.yaml"), "/elsewhere/b.yaml"))
    assert [f.file for f in scan_directory(str(tmp_path))] == ["k8s/a.yaml", ""]
    found = scan_directory(str(tmp_path), exclude=("k8s", "elsewhere", "b.yaml"))
    assert [(f.file, f.message) for f in found] == [("", OUTSIDE_MESSAGE)]


# ---------------------------------------------------------------- real checkov


@needs_checkov
def test_bad_fixtures_have_expected_findings():
    found = scan_directory(str(BAD))
    by_file = {}
    for f in found:
        by_file.setdefault(f.file, set()).add(f.rule_id)
    assert {"CKV_K8S_16", "CKV_K8S_19"} <= by_file["k8s/deployment.yaml"]
    assert {"CKV_DOCKER_2", "CKV_DOCKER_3", "CKV_DOCKER_7"} <= by_file["Dockerfile"]
    assert ".github/workflows/bad.yml" not in by_file  # owned by the gha agent
    assert all(f.agent == "config_yaml" and f.rule_id != "config-unscanned" for f in found)


@needs_checkov
def test_good_fixtures_have_no_findings(capsys):
    assert main([str(GOOD)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_checkov
@pytest.mark.skipif(gha_agent.zizmor_path() is None, reason="zizmor not installed (pip install -r requirements-gha.txt)")
def test_real_silent_skip_workflow_is_reported_by_gha_only(tmp_path):
    # A workflow Checkov used to skip silently: config_yaml now leaves it to
    # the gha agent, which must report it, never return it as clean.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "broken.yml").write_text('jobs:\n  a:\n    steps:\n      - run: echo "a: b"\n')
    assert scan_directory(str(tmp_path)) == []
    found = gha_agent.scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file) for f in found] == [("gha-unscanned", ".github/workflows/broken.yml")]


@needs_checkov
def test_scan_does_not_modify_files():
    before = _snapshot(FIXTURES)
    scan_directory(str(BAD))
    scan_directory(str(GOOD))
    assert _snapshot(FIXTURES) == before



@needs_checkov
def test_real_checkov_paths_are_relative_to_scanned_folder(tmp_path):
    # Broken file written at test time; nothing broken is committed.
    deploy = tmp_path / "k8s" / "apps" / "web" / "deployment.yaml"
    dockerfile = tmp_path / "docker" / "api" / "Dockerfile"
    broken = tmp_path / "configs" / "broken" / "bad.yaml"
    for target, source in ((deploy, BAD / "k8s" / "deployment.yaml"), (dockerfile, BAD / "Dockerfile")):
        target.parent.mkdir(parents=True)
        target.write_text(source.read_text())
    broken.parent.mkdir(parents=True)
    broken.write_text("apiVersion: v1\nkind: Pod\nspec: [\n")

    found = scan_directory(str(tmp_path))
    files = {f.file for f in found}
    assert files == {"k8s/apps/web/deployment.yaml", "docker/api/Dockerfile", "configs/broken/bad.yaml"}
    for f in found:
        assert not f.file.startswith("/") and tmp_path.name not in f.file
        assert (tmp_path / f.file).is_file()
    assert [f.file for f in found if f.rule_id == "config-unscanned"] == ["configs/broken/bad.yaml"]
    assert "CKV_K8S_16" in {f.rule_id for f in found if f.file == "k8s/apps/web/deployment.yaml"}


# ---------------------------------------------------------------- Dockerfile coverage
# Checkov silently skips Dockerfiles it cannot read (binary, non-UTF-8).
# Every such file is written to tmp_path at test time; none is committed.
VALID_DOCKERFILE = "FROM alpine:3.19\nUSER app\n"
BINARY = bytes(range(256))  # not valid UTF-8
NON_UTF8 = b"FROM alpine:3.19\n# SECRET-MARKER caf\xe9\nUSER app\n"
UTF8_MESSAGE = "not scanned: file could not be read as UTF-8 text (Checkov skips it silently)"
NO_RESULT_MESSAGE = "not scanned: Checkov returned no result for this Dockerfile"

# File names (and folders) Checkov 3.3.x scans as Dockerfiles, and ones it does not.
CHECKOV_SCANS = [
    "Dockerfile", "Dockerfile.prod", "api.Dockerfile", "dockerfile", "prod.dockerfile.bak",
    "sub/Dockerfile", "venv/Dockerfile", "__pycache__/Dockerfile",
]
CHECKOV_IGNORES = [
    "Containerfile", "DOCKERFILE", "Dockerfile-dev", "Dockerfile.dockerignore", ".Dockerfile",
    ".x.Dockerfile", ".hidden/Dockerfile", ".venv/Dockerfile", "node_modules/Dockerfile",
    "a/node_modules/b/Dockerfile", ".terraform/Dockerfile", ".serverless/Dockerfile",
]


def _write(root: Path, rel: str, content: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    return path


def _docker_output(passed=(), skipped=()):
    return {"check_type": "dockerfile", "results": {
        "passed_checks": [{"check_id": "CKV_DOCKER_1", "file_path": "/" + f} for f in passed],
        "skipped_checks": [{"check_id": "CKV_DOCKER_2", "file_path": "/" + f} for f in skipped],
    }}


def _no_reads(*args, **kwargs):
    raise AssertionError("file content must not be read")


@needs_checkov
def test_dockerfile_without_checkov_result_is_unscanned(tmp_path, fake):
    _write(tmp_path, "covered/Dockerfile", VALID_DOCKERFILE)
    _write(tmp_path, "suppressed/Dockerfile", VALID_DOCKERFILE)
    _write(tmp_path, "text/Dockerfile", VALID_DOCKERFILE)
    _write(tmp_path, "nonutf8/Dockerfile", NON_UTF8)
    _write(tmp_path, "binary/Dockerfile", BINARY)
    _write(tmp_path, "empty/Dockerfile", "")
    _write(tmp_path, "blank/Dockerfile", "\n   \n\t\n")
    _write(tmp_path, "bom-only/Dockerfile", b"\xef\xbb\xbf\n")
    fake(stdout=_docker_output(passed=["covered/Dockerfile"], skipped=["suppressed/Dockerfile"]))

    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.severity, f.file, f.line, f.message, f.redacted_match) for f in found] == [
        ("config-unscanned", "low", "binary/Dockerfile", 0, UTF8_MESSAGE, ""),
        ("config-unscanned", "low", "nonutf8/Dockerfile", 0, UTF8_MESSAGE, ""),
        ("config-unscanned", "low", "text/Dockerfile", 0, NO_RESULT_MESSAGE, ""),
    ]
    dumped = json.dumps([f.to_dict() for f in found])
    assert "SECRET-MARKER" not in dumped and "alpine" not in dumped


@needs_checkov
def test_find_dockerfiles_uses_checkov_names_and_folder_rules(tmp_path):
    for rel in CHECKOV_SCANS + CHECKOV_IGNORES:
        _write(tmp_path, rel, VALID_DOCKERFILE)
    (tmp_path / "linked-dir").symlink_to(tmp_path / "sub")  # folder symlinks are not followed
    assert set(find_dockerfiles(str(tmp_path))) == set(CHECKOV_SCANS)


@needs_checkov
def test_symlinked_dockerfile_is_never_read(tmp_path, fake, monkeypatch):
    outside = tmp_path / "outside"
    _write(outside, "real", VALID_DOCKERFILE)
    _write(outside, "empty", "")
    root = tmp_path / "root"
    root.mkdir()
    (root / "covered.Dockerfile").symlink_to(outside / "real")
    (root / "missed.Dockerfile").symlink_to(outside / "real")
    (root / "empty.Dockerfile").symlink_to(outside / "empty")
    fake(stdout=_docker_output(passed=["covered.Dockerfile"]))
    monkeypatch.setattr(agent, "open", _no_reads, raising=False)

    found = scan_directory(str(root))
    # Not read, so an empty target cannot be told apart: both get the generic finding.
    assert [(f.file, f.message) for f in found] == [
        ("empty.Dockerfile", NO_RESULT_MESSAGE),
        ("missed.Dockerfile", NO_RESULT_MESSAGE),
    ]


@needs_checkov
def test_oversized_dockerfile_is_not_read(tmp_path, fake, monkeypatch):
    _write(tmp_path, "Dockerfile", VALID_DOCKERFILE)
    fake(stdout=EMPTY_SUMMARY)
    monkeypatch.setattr(agent, "MAX_FILE_BYTES", 4)
    monkeypatch.setattr(agent, "open", _no_reads, raising=False)
    assert [(f.file, f.message) for f in scan_directory(str(tmp_path))] == [("Dockerfile", NO_RESULT_MESSAGE)]


@needs_checkov
def test_exclude_applies_to_dockerfile_check(tmp_path, fake):
    for rel in ("docker/Dockerfile", "api.Dockerfile", "app/Dockerfile"):
        _write(tmp_path, rel, BINARY)
    fake(stdout=EMPTY_SUMMARY)
    found = scan_directory(str(tmp_path), exclude=("docker", "api.Dockerfile"))
    assert [f.file for f in found] == ["app/Dockerfile"]


@needs_checkov
def test_checkov_walk_settings_are_not_passed_to_checkov(tmp_path, fake, monkeypatch):
    monkeypatch.setenv("CKV_IGNORED_DIRECTORIES", "sub")
    monkeypatch.setenv("CKV_IGNORE_HIDDEN_DIRECTORIES", "False")
    checkov = fake(stdout=EMPTY_SUMMARY)
    scan_directory(str(tmp_path))
    (call,) = checkov.calls
    assert "CKV_IGNORED_DIRECTORIES" not in call["env"]
    assert "CKV_IGNORE_HIDDEN_DIRECTORIES" not in call["env"]


@needs_yaml
def test_missing_is_dockerfile_is_an_error_not_clean(tmp_path, fake, monkeypatch, capsys):
    fake(stdout=EMPTY_SUMMARY)
    monkeypatch.setitem(sys.modules, "checkov.common.util.dockerfile", None)  # makes the import fail
    with pytest.raises(ConfigYamlError, match="is_dockerfile could not be imported"):
        scan_directory(str(tmp_path))
    assert main([str(tmp_path)]) == 2
    assert "is_dockerfile" in capsys.readouterr().err


@needs_checkov
def test_real_checkov_unscanned_dockerfiles(tmp_path):
    _write(tmp_path, "good/Dockerfile", (GOOD / "Dockerfile").read_text())
    _write(tmp_path, "binary/Dockerfile", BINARY)
    _write(tmp_path, "nonutf8/Dockerfile", NON_UTF8)
    _write(tmp_path, "empty/Dockerfile", "")
    _write(tmp_path, "comments/Dockerfile", "# only a comment\n# and another\n")

    unscanned = [f for f in scan_directory(str(tmp_path)) if f.rule_id == "config-unscanned"]
    assert [(f.file, f.message) for f in unscanned] == [
        ("binary/Dockerfile", UTF8_MESSAGE),
        ("nonutf8/Dockerfile", UTF8_MESSAGE),
    ]
    assert "SECRET-MARKER" not in json.dumps([f.to_dict() for f in unscanned])


@needs_checkov
def test_real_checkov_dockerfile_rules_have_not_drifted(tmp_path):
    # If a Checkov upgrade changes which files it scans as Dockerfiles, this fails.
    valid, broken = tmp_path / "valid", tmp_path / "broken"
    for rel in CHECKOV_SCANS + CHECKOV_IGNORES:
        _write(valid, rel, VALID_DOCKERFILE)
        _write(broken, rel, BINARY)

    # Valid content: exactly the files the agent walks are the files Checkov scans.
    scanned = scanned_files(agent.run_checkov(str(valid)), "dockerfile")
    assert scanned == set(CHECKOV_SCANS) == set(find_dockerfiles(str(valid)))
    # Binary content: every one of them is reported, and nothing Checkov ignores.
    found = scan_directory(str(broken))
    assert {f.file for f in found if f.rule_id == "config-unscanned"} == set(CHECKOV_SCANS)
