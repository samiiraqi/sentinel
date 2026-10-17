import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.config_yaml import agent
from agents.config_yaml.agent import (
    ConfigYamlError,
    check_yaml_files,
    main,
    parse_checkov_output,
    scan_directory,
    scanned_files,
)

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
    assert call["cmd"][call["cmd"].index("--framework") + 1:][:3] == ["kubernetes", "dockerfile", "github_actions"]
    assert call["cwd"] == str(tmp_path)
    assert call["timeout"] == agent.TIMEOUT_SECONDS
    assert "BC_API_KEY" not in call["env"] and "PRISMA_API_URL" not in call["env"]


def test_run_tool_kills_on_timeout():
    with pytest.raises(subprocess.TimeoutExpired):
        agent._run_tool(["sleep", "30"], timeout=0.2, cwd=".", env={"PATH": "/usr/bin:/bin"})


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
def test_workflow_without_checkov_result_is_unscanned(tmp_path, fake):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "seen.yml").write_text("name: a\non: push\njobs: {}\n")
    (wf / "missed.yaml").write_text("name: b\non: push\njobs: {}\n")
    fake(stdout={"check_type": "github_actions", "results": {"passed_checks": [
        {"check_id": "CKV_GHA_1", "file_path": "/.github/workflows/seen.yml"},
    ]}})

    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file) for f in found] == [("config-unscanned", ".github/workflows/missed.yaml")]
    assert "no result" in found[0].message


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

    unscanned, workflows = check_yaml_files(str(tmp_path))
    assert [f.file for f in unscanned] == ["outside.yaml"]
    assert workflows == []


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
    assert "CKV_GHA_2" in by_file[".github/workflows/bad.yml"]
    assert all(f.agent == "config_yaml" and f.rule_id != "config-unscanned" for f in found)


@needs_checkov
def test_good_fixtures_have_no_findings(capsys):
    assert main([str(GOOD)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_checkov
def test_real_checkov_silent_skip_is_caught(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "broken.yml").write_text('jobs:\n  a:\n    steps:\n      - run: echo "a: b"\n')
    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file) for f in found] == [("config-unscanned", ".github/workflows/broken.yml")]


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
