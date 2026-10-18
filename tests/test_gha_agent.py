import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from agents.gha import agent
from agents.gha.agent import (
    GhaError,
    find_gha_files,
    main,
    parse_zizmor_output,
    scan_directory,
    zizmor_path,
)

REPO = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

needs_zizmor = pytest.mark.skipif(
    zizmor_path() is None,
    reason="zizmor not installed (pip install -r requirements-gha.txt)",
)

# Bad workflows and actions, written into tmp_path at test time only (never committed).
# MARKER-* strings are workflow content that must never reach a finding.
INJECTION_WF = (
    "on: issues\n"
    "jobs:\n"
    "  greet:\n"
    "    runs-on: ubuntu-24.04\n"
    "    steps:\n"
    "      - run: |\n"
    '          echo "MARKER-RUN ${{ github.event.issue.title }}"\n'
)
CLEAN_WF = (
    "name: clean\n"
    "on: push\n"
    "permissions: {}\n"
    "jobs:\n"
    "  a:\n"
    "    name: a\n"
    "    runs-on: ubuntu-24.04\n"
    "    steps:\n"
    "      - run: echo MARKER-CLEAN\n"
)
INJECTION_ACTION = (
    "name: x\n"
    "description: y\n"
    "runs:\n"
    "  using: composite\n"
    "  steps:\n"
    "    - run: echo ${{ github.event.issue.title }}\n"
    "      shell: bash\n"
)
INVALID_YAML = "on: push\njobs:\n  a:\n    steps: [\n"
NOT_A_WORKFLOW = "on: push\njobs:\n  a:\n    runs-on: x\n    steps: 5\n"
NON_UTF8 = b"on: push\n# MARKER-BYTES caf\xe9\njobs: {}\n"
PARSE_MESSAGE = "not scanned: zizmor could not parse this file (invalid YAML, or not a valid workflow or action)"

# Trimmed from real `zizmor --offline --format json-v1` output (1.31.1).
SAMPLE = [
    {
        "ident": "template-injection",
        "desc": "code injection via template expansion",
        "url": "https://docs.zizmor.sh/audits/#template-injection",
        "determinations": {"confidence": "High", "severity": "High", "persona": "Regular"},
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": "/elsewhere/FAKE-PATH.yml"}},
                    "annotation": "this step FAKE-ANNOTATION",
                    "kind": "Hidden",
                },
                "concrete": {
                    "location": {"start_point": {"row": 9, "column": 8}},
                    "feature": "run: FAKE-RAW-FEATURE",
                },
            },
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": "/elsewhere/FAKE-PATH.yml"}},
                    "annotation": "may expand into attacker-controllable code",
                    "feature_kind": {"Subfeature": {"after": 19, "fragment": {"Raw": "FAKE-RAW-FRAGMENT"}}},
                    "kind": "Primary",
                },
                "concrete": {
                    "location": {"start_point": {"row": 10, "column": 32}},
                    "feature": "FAKE-RAW-FEATURE",
                },
            },
        ],
        "ignored": False,
        "fixes": [{"title": "FAKE-FIX-TITLE", "disposition": "unsafe"}],
    },
    {
        "ident": "excessive-permissions",
        "desc": "overly broad permissions",
        "determinations": {"confidence": "Medium", "severity": "Medium", "persona": "Regular"},
        "locations": [{"symbolic": {"kind": "Primary"}, "concrete": {"location": {"start_point": {"row": 6}}}}],
    },
]


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


def _write(root: Path, rel: str, content: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    return path


def _workflow(root: Path, name: str = "ci.yml", content: str | bytes = CLEAN_WF) -> Path:
    return _write(root, f".github/workflows/{name}", content)


def _dump(findings) -> str:
    return json.dumps([f.to_dict() for f in findings])


class FakeZizmor:
    """Stands in for the zizmor process: records each call, returns fixed output."""

    def __init__(self, stdout="[]", code=0, raises=None):
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
        zizmor = FakeZizmor(**kwargs)
        monkeypatch.setattr(agent, "_run_tool", zizmor.run)
        monkeypatch.setattr(agent, "zizmor_path", lambda: "/fake/bin/zizmor")
        return zizmor
    return install


# ---------------------------------------------------------------- parser


def test_parse_maps_fields_and_drops_raw_values():
    findings = parse_zizmor_output(SAMPLE, ".github/workflows/bad.yml")
    assert [f.to_dict() for f in findings] == [
        {
            "agent": "gha",
            "rule_id": "template-injection",
            "severity": "high",
            "file": ".github/workflows/bad.yml",  # the file we passed, not zizmor's path
            "line": 11,  # primary location, 0-based row + 1
            "message": "code injection via template expansion (confidence high)",
            "redacted_match": "template-injection",
        },
        {
            "agent": "gha",
            "rule_id": "excessive-permissions",
            "severity": "medium",
            "file": ".github/workflows/bad.yml",
            "line": 7,
            "message": "overly broad permissions (confidence medium)",
            "redacted_match": "excessive-permissions",
        },
    ]
    assert "FAKE" not in _dump(findings) and "elsewhere" not in _dump(findings)


@pytest.mark.parametrize(
    "value, expected",
    [("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Informational", "low"),
     ("Unknown", "medium"), ("critical", "medium"), (None, "medium"), (5, "medium")],
)
def test_severity_mapping(value, expected):
    (finding,) = parse_zizmor_output([{"ident": "x", "determinations": {"severity": value}}], "a.yml")
    assert finding.severity == expected


@pytest.mark.parametrize(
    "locations, line",
    [
        ([{"concrete": {"location": {"start_point": {"row": 4}}}}], 5),  # no Primary: first one
        ([], 0),
        (None, 0),
        ([{"concrete": {"location": {"start_point": {"row": "x"}}}}], 0),
        ([{"symbolic": {"kind": "Primary"}}], 0),
    ],
)
def test_line_falls_back_safely(locations, line):
    (finding,) = parse_zizmor_output([{"ident": "x", "locations": locations}], "a.yml")
    assert finding.line == line


def test_parse_skips_non_dict_results():
    assert parse_zizmor_output([None, "x", 5], "a.yml") == []


# ---------------------------------------------------------------- failures never look clean


def test_missing_zizmor_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(agent, "zizmor_path", lambda: None)
    with pytest.raises(GhaError, match="zizmor is not installed"):
        scan_directory(str(tmp_path))  # even with no workflows to scan
    assert main([str(tmp_path)]) == 2
    assert "zizmor is not installed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"code": 1, "stdout": "[]"}, "exit code 1"),
        ({"code": 2, "stdout": "[]"}, "exit code 2"),
        ({"code": 99, "stdout": "[]"}, "exit code 99"),
        ({"code": 0, "stdout": "   \n"}, "no output"),
        ({"code": 14, "stdout": "not json"}, "could not parse"),
        ({"code": 0, "stdout": {"results": []}}, "unexpected"),
        ({"code": 14, "stdout": []}, "means findings, but it returned none"),
        ({"raises": subprocess.TimeoutExpired(["zizmor"], 300)}, "timed out"),
    ],
)
def test_tool_failures_raise_never_return_empty(tmp_path, fake, kwargs, message):
    _workflow(tmp_path)
    fake(**kwargs)
    with pytest.raises(GhaError, match=message):
        scan_directory(str(tmp_path))


def test_unparsed_file_is_unscanned_not_clean(tmp_path, fake):
    _workflow(tmp_path, "broken.yml")
    fake(code=3, stdout="")
    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.severity, f.file, f.line, f.message) for f in found] == [
        ("gha-unscanned", "low", ".github/workflows/broken.yml", 0, PARSE_MESSAGE),
    ]


def test_cli_error_exit_code_2(tmp_path, fake, capsys):
    _workflow(tmp_path)
    fake(code=1, stdout="")
    assert main([str(tmp_path)]) == 2
    assert "exit code 1" in capsys.readouterr().err


def test_cli_not_a_directory(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_one_deadline_for_the_whole_scan(tmp_path, fake):
    for name in ("a.yml", "b.yml", "c.yml"):
        _workflow(tmp_path, name)
    zizmor = fake()
    now = [0.0]

    def clock():
        now[0] += 100.0  # every check costs 100s
        return now[0]

    with pytest.raises(GhaError, match="timed out"):
        scan_directory(str(tmp_path), clock=clock)
    # Deadline 300s: runs start with 200s and 100s left, then no time is left.
    assert [c["timeout"] for c in zizmor.calls] == [200.0, 100.0]


def test_run_tool_kills_on_timeout():
    with pytest.raises(subprocess.TimeoutExpired):
        agent._run_tool(["sleep", "30"], timeout=0.2, cwd=".", env={"PATH": "/usr/bin:/bin"})


# ---------------------------------------------------------------- how zizmor is run


def test_zizmor_runs_offline_per_file_without_tokens(tmp_path, fake, monkeypatch):
    _workflow(tmp_path, "a.yml")
    _write(tmp_path, "act/action.yml", INJECTION_ACTION)
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "ZIZMOR_CONFIG", "ZIZMOR_GITHUB_TOKEN"):
        monkeypatch.setenv(name, "FAKE-VALUE-FOR-TESTS")
    zizmor = fake()
    assert scan_directory(str(tmp_path)) == []

    assert [c["cmd"][-2:] for c in zizmor.calls] == [["--", "./.github/workflows/a.yml"], ["--", "./act/action.yml"]]
    for call in zizmor.calls:
        cmd = call["cmd"]
        assert cmd[0] == "/fake/bin/zizmor"
        assert {"--offline", "--no-config", "--no-ignores"} <= set(cmd)
        assert cmd[cmd.index("--persona") + 1] == "regular"
        assert cmd[cmd.index("--format") + 1] == "json-v1"
        assert not any(c.startswith("--fix") for c in cmd)  # zizmor never writes files
        assert call["cwd"] == str(tmp_path)
        assert "FAKE-VALUE-FOR-TESTS" not in call["env"].values()
        assert "PATH" in call["env"]


def test_zizmor_is_not_taken_from_path(tmp_path, monkeypatch):
    on_path = tmp_path / "path"
    _write(on_path, "zizmor", "#!/bin/sh\n").chmod(0o755)
    monkeypatch.setenv("PATH", str(on_path))
    monkeypatch.setattr(agent.sysconfig, "get_path", lambda name: str(tmp_path / "scripts"))
    assert zizmor_path() is None


# ---------------------------------------------------------------- which files are scanned


def test_find_gha_files_owns_workflows_and_actions_only(tmp_path):
    for rel in (
        ".github/workflows/a.yml", ".github/workflows/b.yaml", "sub/.github/workflows/c.yml",
        "act/action.yml", "action.yaml",
        ".github/workflows/notes.txt", ".github/workflows/deep/d.yml", ".github/dependabot.yml",
        "k8s/deploy.yaml", "workflows/e.yml", "node_modules/x/action.yml", ".venv/.github/workflows/f.yml",
    ):
        _write(tmp_path, rel, CLEAN_WF)
    files, unscanned = find_gha_files(str(tmp_path))
    assert files == ["action.yaml", ".github/workflows/a.yml", ".github/workflows/b.yaml",
                     "act/action.yml", "sub/.github/workflows/c.yml"]
    assert unscanned == []


def test_symlinks_are_never_followed(tmp_path, fake):
    outside = _write(tmp_path / "outside", "real.yml", CLEAN_WF)
    root = tmp_path / "root"
    _workflow(root, "ok.yml")
    (root / ".github" / "workflows" / "link.yml").symlink_to(outside)
    (root / "linked-dir").mkdir()
    (root / "linked-dir" / ".github").symlink_to(root / ".github", target_is_directory=True)
    zizmor = fake()
    found = scan_directory(str(root))
    assert [(f.file, f.message) for f in found] == [(".github/workflows/link.yml", "not scanned: symlink not followed")]
    assert [c["cmd"][-1] for c in zizmor.calls] == ["./.github/workflows/ok.yml"]


def test_oversized_and_non_utf8_files_are_unscanned_and_not_given_to_zizmor(tmp_path, fake, monkeypatch):
    _workflow(tmp_path, "big.yml", CLEAN_WF)
    _workflow(tmp_path, "bytes.yml", NON_UTF8)
    _workflow(tmp_path, "ok.yml", "on: push\n")
    monkeypatch.setattr(agent, "MAX_FILE_BYTES", len(CLEAN_WF) - 1)
    zizmor = fake()
    found = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.file, f.message) for f in found] == [
        ("gha-unscanned", ".github/workflows/big.yml", "not scanned: file too large to scan"),
        ("gha-unscanned", ".github/workflows/bytes.yml", "not scanned: file could not be read as UTF-8 text"),
    ]
    assert [c["cmd"][-1] for c in zizmor.calls] == ["./.github/workflows/ok.yml"]
    assert "MARKER" not in _dump(found)


def test_exclude_uses_component_matching(tmp_path, fake):
    for rel in ("legacy/.github/workflows/a.yml", "legacy-new/.github/workflows/a.yml",
                "tests/fixtures/.github/workflows/a.yml", "other/tests/fixtures/.github/workflows/a.yml"):
        _write(tmp_path, rel, CLEAN_WF)
    zizmor = fake()
    scan_directory(str(tmp_path), exclude=("legacy", "tests/fixtures"))
    assert sorted(c["cmd"][-1] for c in zizmor.calls) == [
        "./legacy-new/.github/workflows/a.yml",
        "./other/tests/fixtures/.github/workflows/a.yml",
    ]


def test_no_files_means_no_zizmor_run(tmp_path, fake):
    _write(tmp_path, "k8s/deploy.yaml", "a: 1\n")
    zizmor = fake()
    assert scan_directory(str(tmp_path)) == []
    assert zizmor.calls == []


# ---------------------------------------------------------------- real zizmor


@needs_zizmor
def test_real_zizmor_finds_injection_without_raw_content(tmp_path):
    _workflow(tmp_path, "bad.yml", INJECTION_WF)
    found = scan_directory(str(tmp_path))
    by_rule = {f.rule_id: f for f in found}
    assert {"template-injection", "excessive-permissions"} <= set(by_rule)
    injection = by_rule["template-injection"]
    assert (injection.severity, injection.file, injection.line) == ("high", ".github/workflows/bad.yml", 7)
    dumped = _dump(found)
    assert "MARKER" not in dumped and "github.event" not in dumped and str(tmp_path) not in dumped


@needs_zizmor
def test_real_zizmor_clean_workflow(tmp_path, capsys):
    _workflow(tmp_path, "clean.yml", CLEAN_WF)
    assert main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_zizmor
def test_real_zizmor_scans_composite_actions(tmp_path):
    _write(tmp_path, "act/action.yml", INJECTION_ACTION)
    assert ("template-injection", "act/action.yml") in {(f.rule_id, f.file) for f in scan_directory(str(tmp_path))}


@needs_zizmor
def test_real_zizmor_unparsed_files_are_unscanned_and_the_rest_still_scanned(tmp_path, monkeypatch):
    _workflow(tmp_path, "invalid.yml", INVALID_YAML)
    _workflow(tmp_path, "schema.yml", NOT_A_WORKFLOW)
    _workflow(tmp_path, "bom.yml", "\ufeff" + CLEAN_WF)
    _workflow(tmp_path, "bytes.yml", NON_UTF8)
    _workflow(tmp_path, "big.yml", CLEAN_WF + "#" * 100)
    _workflow(tmp_path, "bad.yml", INJECTION_WF)
    (tmp_path / ".github" / "workflows" / "link.yml").symlink_to(tmp_path / ".github" / "workflows" / "bad.yml")
    monkeypatch.setattr(agent, "MAX_FILE_BYTES", len(CLEAN_WF) + 50)

    found = scan_directory(str(tmp_path))
    unscanned = {f.file: f.message for f in found if f.rule_id == "gha-unscanned"}
    assert unscanned == {
        ".github/workflows/invalid.yml": PARSE_MESSAGE,
        ".github/workflows/schema.yml": PARSE_MESSAGE,
        ".github/workflows/bom.yml": PARSE_MESSAGE,
        ".github/workflows/bytes.yml": "not scanned: file could not be read as UTF-8 text",
        ".github/workflows/big.yml": "not scanned: file too large to scan",
        ".github/workflows/link.yml": "not scanned: symlink not followed",
    }
    assert ("template-injection", ".github/workflows/bad.yml") in {(f.rule_id, f.file) for f in found}
    assert "MARKER" not in _dump(found)


@needs_zizmor
def test_real_zizmor_folder_cannot_hide_findings(tmp_path):
    # A gitignored workflow, a zizmor.yml that turns the audit off, and an ignore comment.
    (tmp_path / ".git").mkdir()
    _write(tmp_path, ".gitignore", ".github/\n")
    _write(tmp_path, "zizmor.yml", "rules:\n  template-injection:\n    disable: true\n")
    _write(tmp_path, ".github/zizmor.yml", "rules:\n  template-injection:\n    disable: true\n")
    # Without --no-ignores this comment hides the finding (checked with zizmor 1.31.1).
    hidden = INJECTION_WF.replace("- run: |\n", "- run: | # zizmor: ignore[template-injection]\n")
    assert hidden != INJECTION_WF
    _workflow(tmp_path, "bad.yml", hidden)
    assert "template-injection" in {f.rule_id for f in scan_directory(str(tmp_path))}


@needs_zizmor
def test_real_zizmor_fixtures():
    bad = scan_directory(str(FIXTURES / "config_yaml" / "bad"))
    assert sorted((f.rule_id, f.severity, f.file) for f in bad) == [
        ("excessive-permissions", "medium", ".github/workflows/bad.yml"),
        ("template-injection", "high", ".github/workflows/bad.yml"),
    ]
    for folder in ("config_yaml/good", "terraform/bad", "terraform/good"):
        assert scan_directory(str(FIXTURES / folder)) == []


@needs_zizmor
def test_our_own_ci_workflow_passes():
    assert scan_directory(str(REPO), exclude=("tests/fixtures", ".venv")) == []


@needs_zizmor
def test_scan_does_not_modify_files(tmp_path):
    _workflow(tmp_path, "bad.yml", INJECTION_WF)
    _write(tmp_path, "act/action.yml", INJECTION_ACTION)
    before = _snapshot(tmp_path) | _snapshot(FIXTURES)
    scan_directory(str(tmp_path))
    scan_directory(str(FIXTURES))
    assert _snapshot(tmp_path) | _snapshot(FIXTURES) == before
    assert not any(name.endswith(".orig") for _, _, names in os.walk(tmp_path) for name in names)
