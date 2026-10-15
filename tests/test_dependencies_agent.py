import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agents.dependencies import agent
from agents.dependencies.agent import (
    DependenciesError,
    main,
    parse_npm_audit_output,
    parse_pip_audit_output,
    parse_requirements,
    scan_directory,
)

# Live tests contact PyPI and the npm registry, so they only run on request.
LIVE = os.environ.get("SENTINEL_LIVE_TESTS") == "1"

# Trimmed from real `pip-audit -f json` output (pip-audit 2.10).
PIP_SAMPLE = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.19.0",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "aliases": ["GHSA-x84v-xcm2-53pg", "CVE-2018-18074"],
                    "description": "FAKE-DESCRIPTION must not be copied",
                },
                # pip-audit can list the same advisory twice.
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "aliases": ["GHSA-x84v-xcm2-53pg", "CVE-2018-18074"],
                    "description": "second copy",
                },
            ],
        },
        {
            "name": "jinja2",
            "version": "3.1.4",
            "vulns": [{"id": "GHSA-q2x7-8rv6-6q7h", "fix_versions": [], "aliases": [], "description": ""}],
        },
        {"name": "six", "version": "1.17.0", "vulns": []},
        {"name": "private-pkg", "skip_reason": "Dependency not found on PyPI and could not be audited"},
    ],
    "fixes": [],
}

# Trimmed from real `npm audit --json --package-lock-only` output (npm 10).
NPM_SAMPLE = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "isDirect": True,
            "via": [
                {
                    "source": 1106913,
                    "name": "lodash",
                    "title": "Command Injection in lodash",
                    "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                    "severity": "high",
                },
                {
                    "source": 1108258,
                    "name": "lodash",
                    "title": "ReDoS in lodash",
                    "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
                    "severity": "moderate",
                },
                {
                    "source": 1108258,
                    "name": "lodash",
                    "title": "ReDoS in lodash (duplicate)",
                    "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
                    "severity": "moderate",
                },
            ],
            "effects": ["wrapper"],
            "range": "<=4.17.23",
            "nodes": ["node_modules/lodash"],
            "fixAvailable": {"name": "lodash", "version": "4.18.1", "isSemVerMajor": False},
        },
        # Only vulnerable through lodash: a plain-string "via", no own advisory.
        "wrapper": {
            "name": "wrapper",
            "severity": "high",
            "isDirect": True,
            "via": ["lodash"],
            "effects": [],
            "range": "1.0.0",
            "nodes": ["node_modules/wrapper"],
            "fixAvailable": False,
        },
        "tiny": {
            "name": "tiny",
            "severity": "low",
            "isDirect": False,
            "via": [{"source": 42, "name": "tiny", "title": "Info only", "severity": "info"}],
            "effects": [],
            "range": "*",
            "nodes": ["node_modules/tiny"],
            "fixAvailable": False,
        },
    },
    "metadata": {"vulnerabilities": {"total": 3}},
}

NPM_CLEAN = {"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}

LOCKFILE = json.dumps(
    {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"lodash": "4.17.15", "wrapper": "1.0.0"}},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/tiny": {"version": "0.1.0"},
            "node_modules/wrapper": {"version": "1.0.0"},
        },
    },
    indent=2,
)

REQUIREMENTS = """\
# comment line
requests==2.19.0  # inline comment
Jinja2[i18n] == 3.1.4 ; python_version >= "3.8"
six==1.17.0 \\
    --hash=sha256:aaaa
private_pkg==1.0.0
-r other.txt
--index-url https://example.invalid/simple
fastapi
uvicorn>=0.30
pkg===1.0
wild==1.*
tool @ https://example.invalid/tool.zip
"""


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


class FakeTools:
    """Stands in for pip-audit and npm: records calls, returns fixed output."""

    def __init__(self, pip=PIP_SAMPLE, npm=NPM_SAMPLE, pip_code=1, npm_code=1):
        self.pip_out = pip if isinstance(pip, str) else json.dumps(pip)
        self.npm_out = npm if isinstance(npm, str) else json.dumps(npm)
        self.pip_code, self.npm_code = pip_code, npm_code
        self.calls = []

    def run(self, cmd, **kwargs):
        call = {"cmd": list(cmd), **kwargs}
        if "pip_audit" in cmd:
            req = cmd[cmd.index("-r") + 1]
            call["requirements"] = Path(req).read_text()
            self.calls.append(call)
            return subprocess.CompletedProcess(cmd, self.pip_code, self.pip_out, "")
        self.calls.append(call)
        return subprocess.CompletedProcess(cmd, self.npm_code, self.npm_out, "")


@pytest.fixture
def tools(monkeypatch):
    fake = FakeTools()
    monkeypatch.setattr(agent, "_run_tool", fake.run)
    monkeypatch.setattr(agent, "_pip_audit_installed", lambda: True)
    monkeypatch.setattr(agent, "_npm_path", lambda: "/usr/bin/npm")
    return fake


@pytest.fixture
def project(tmp_path):
    (tmp_path / "requirements.txt").write_text(REQUIREMENTS)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text(LOCKFILE)
    return tmp_path


# ---------------------------------------------------------------- parsers


def test_parse_requirements_splits_pinned_and_unpinned():
    pinned, unpinned, options = parse_requirements(REQUIREMENTS)
    assert pinned == [
        (2, "requests", "2.19.0"),
        (3, "Jinja2", "3.1.4"),
        (4, "six", "1.17.0"),
        (6, "private_pkg", "1.0.0"),
    ]
    assert unpinned == [
        (9, "fastapi"),
        (10, "uvicorn>=0.30"),
        (11, "pkg===1.0"),
        (12, "wild==1.*"),
        (13, "tool @ https://example.invalid/tool.zip"),
    ]
    assert options == [
        (7, "requirement", "other.txt", "-r other.txt"),
        (8, "index-url", "https://example.invalid/simple", "--index-url https://example.invalid/simple"),
    ]


@pytest.mark.parametrize(
    "line, expected",
    [
        ("-r base.txt", ("requirement", "base.txt")),
        ("-rbase.txt", ("requirement", "base.txt")),
        ("--requirement=base.txt", ("requirement", "base.txt")),
        ("--requirement base.txt", ("requirement", "base.txt")),
        ("-c constraints.txt", ("constraint", "constraints.txt")),
        ("--constraint=constraints.txt", ("constraint", "constraints.txt")),
        ("-e .", ("editable", ".")),
        ("--editable git+https://example.invalid/x.git", ("editable", "git+https://example.invalid/x.git")),
        ("-i https://example.invalid/simple", ("index-url", "https://example.invalid/simple")),
        ("--extra-index-url https://example.invalid/simple", ("extra-index-url", "https://example.invalid/simple")),
    ],
)
def test_parse_requirements_option_forms(line, expected):
    _, _, options = parse_requirements(line + "\n")
    assert [(kind, value) for _, kind, value, _ in options] == [expected]


def test_parse_requirements_ignores_other_options():
    assert parse_requirements("--pre\n--no-binary :all:\n") == ([], [], [])


def test_url_credentials_are_redacted():
    text = (
        "--index-url https://user:TOKEN123@example.invalid/simple\n"
        "pkg @ https://TOKEN456@example.invalid/pkg.zip\n"
    )
    _, unpinned, options = parse_requirements(text)
    dumped = json.dumps([unpinned, options])
    assert "TOKEN123" not in dumped and "TOKEN456" not in dumped
    assert options[0][3] == "--index-url https://***@example.invalid/simple"


def test_parse_pip_audit_maps_vulns():
    lines = {("requests", "2.19.0"): 2, ("jinja2", "3.1.4"): 3, ("six", "1.17.0"): 4, ("private-pkg", "1.0.0"): 6}
    findings = parse_pip_audit_output(PIP_SAMPLE, "requirements.txt", lines)
    assert [f.to_dict() for f in findings] == [
        {
            "agent": "dependencies",
            "rule_id": "CVE-2018-18074",
            "severity": "high",
            "file": "requirements.txt",
            "line": 2,
            "message": "requests 2.19.0: CVE-2018-18074 (also GHSA-x84v-xcm2-53pg, PYSEC-2018-28); fixed in: 2.20.0",
            "redacted_match": "requests==2.19.0",
        },
        {
            "agent": "dependencies",
            "rule_id": "GHSA-q2x7-8rv6-6q7h",
            "severity": "high",
            "file": "requirements.txt",
            "line": 3,
            "message": "jinja2 3.1.4: GHSA-q2x7-8rv6-6q7h; fixed in: none",
            "redacted_match": "jinja2==3.1.4",
        },
        {
            "agent": "dependencies",
            "rule_id": "unaudited-dependency",
            "severity": "low",
            "file": "requirements.txt",
            "line": 6,
            "message": "private-pkg: could not be audited (Dependency not found on PyPI and could not be audited)",
            "redacted_match": "private-pkg",
        },
    ]
    assert "FAKE-DESCRIPTION" not in json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize("data", [{}, {"dependencies": []}, {"dependencies": [None, "x"]}])
def test_parse_pip_audit_empty_input(data):
    assert parse_pip_audit_output(data, "requirements.txt", {}) == []


def test_parse_npm_audit_maps_advisories():
    findings = parse_npm_audit_output(NPM_SAMPLE, "web/package-lock.json", LOCKFILE)
    lodash_line = LOCKFILE.splitlines().index('    "node_modules/lodash": {') + 1
    tiny_line = LOCKFILE.splitlines().index('    "node_modules/tiny": {') + 1
    assert [f.to_dict() for f in findings] == [
        {
            "agent": "dependencies",
            "rule_id": "GHSA-35jh-r3h4-6jhm",
            "severity": "high",
            "file": "web/package-lock.json",
            "line": lodash_line,
            "message": "lodash@4.17.15: Command Injection in lodash; fix available: yes",
            "redacted_match": "lodash@4.17.15",
        },
        {
            "agent": "dependencies",
            "rule_id": "GHSA-29mw-wpgm-hmr9",
            "severity": "medium",
            "file": "web/package-lock.json",
            "line": lodash_line,
            "message": "lodash@4.17.15: ReDoS in lodash; fix available: yes",
            "redacted_match": "lodash@4.17.15",
        },
        {
            "agent": "dependencies",
            "rule_id": "npm-advisory-42",
            "severity": "low",
            "file": "web/package-lock.json",
            "line": tiny_line,
            "message": "tiny@0.1.0: Info only; fix available: no",
            "redacted_match": "tiny@0.1.0",
        },
    ]


def test_parse_npm_audit_without_lockfile_uses_range():
    findings = parse_npm_audit_output(NPM_SAMPLE, "package-lock.json")
    assert findings[0].line == 0
    assert findings[0].redacted_match == "lodash@<=4.17.23"


@pytest.mark.parametrize("data", [{}, NPM_CLEAN, {"vulnerabilities": {"x": None}}])
def test_parse_npm_audit_empty_input(data):
    assert parse_npm_audit_output(data, "package-lock.json") == []


# ---------------------------------------------------------------- scan


def test_scan_runs_both_tools_read_only(project, tools, monkeypatch):
    monkeypatch.setenv("PIP_AUDIT_VULNERABILITY_SERVICE", "osv")
    findings = scan_directory(str(project))

    pip_call, npm_call = tools.calls
    # pip-audit: never uses pip, only sees the pinned lines (normalized), no options.
    assert {"--disable-pip", "--no-deps"} <= set(pip_call["cmd"])
    assert "--fix" not in pip_call["cmd"]
    assert pip_call["requirements"] == "jinja2==3.1.4\nprivate-pkg==1.0.0\nrequests==2.19.0\nsix==1.17.0\n"
    assert "PIP_AUDIT_VULNERABILITY_SERVICE" not in pip_call["env"]
    assert not Path(pip_call["cmd"][pip_call["cmd"].index("-r") + 1]).exists()  # temp file removed

    # npm: lockfile only, fixed registry, pinned to the lockfile's folder, never "fix".
    web = str(project / "web")
    assert npm_call["cmd"][:2] == ["/usr/bin/npm", "audit"]
    assert "--package-lock-only" in npm_call["cmd"]
    assert npm_call["cmd"][npm_call["cmd"].index("--registry") + 1] == "https://registry.npmjs.org/"
    assert npm_call["cmd"][npm_call["cmd"].index("--prefix") + 1] == web
    assert npm_call["cwd"] == web
    assert "fix" not in npm_call["cmd"]

    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert [f.line for f in by_rule["unpinned-dependency"]] == [9, 10, 11, 12, 13]
    assert all(f.severity == "medium" for f in by_rule["unpinned-dependency"])
    assert by_rule["CVE-2018-18074"][0].line == 2
    assert by_rule["GHSA-q2x7-8rv6-6q7h"][0].line == 3  # Jinja2 matched to jinja2
    assert by_rule["GHSA-35jh-r3h4-6jhm"][0].file == "web/package-lock.json"


def test_scan_does_not_modify_files(project, tools):
    before = _snapshot(project)
    scan_directory(str(project))
    assert _snapshot(project) == before


def test_only_unpinned_lines_skips_pip_audit(tmp_path, tools):
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    findings = scan_directory(str(tmp_path))
    assert tools.calls == []
    assert [(f.rule_id, f.file, f.line) for f in findings] == [("unpinned-dependency", "requirements-dev.txt", 1)]


def test_no_manifests_needs_no_tools(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("no tool should run")

    monkeypatch.setattr(agent, "_run_tool", fail)
    monkeypatch.setattr(agent, "_pip_audit_installed", lambda: False)
    monkeypatch.setattr(agent, "_npm_path", lambda: None)
    (tmp_path / "README.md").write_text("hi")
    assert scan_directory(str(tmp_path)) == []


def test_skips_vendored_and_excluded_folders(tmp_path, tools):
    for folder in ("node_modules/dep", ".venv/lib", "vendor"):
        (tmp_path / folder).mkdir(parents=True)
        (tmp_path / folder / "requirements.txt").write_text("fastapi\n")
        (tmp_path / folder / "package-lock.json").write_text(LOCKFILE)
    assert scan_directory(str(tmp_path), exclude=("vendor",)) == []
    assert tools.calls == []


def test_missing_pip_audit_is_an_error(project, tools, monkeypatch):
    monkeypatch.setattr(agent, "_pip_audit_installed", lambda: False)
    with pytest.raises(DependenciesError, match="pip install -r requirements-dependencies.txt"):
        scan_directory(str(project))
    assert tools.calls == []


def test_missing_npm_is_an_error(project, tools, monkeypatch):
    monkeypatch.setattr(agent, "_npm_path", lambda: None)
    with pytest.raises(DependenciesError, match="npm is not installed"):
        scan_directory(str(project))
    assert tools.calls == []


def test_missing_npm_is_fine_without_lockfiles(tmp_path, tools, monkeypatch):
    monkeypatch.setattr(agent, "_npm_path", lambda: None)
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    assert scan_directory(str(tmp_path))


@pytest.mark.parametrize(
    "fake, message",
    [
        (FakeTools(pip="", pip_code=1), "pip-audit failed"),  # e.g. the "not pinned" error
        (FakeTools(pip="not json", pip_code=1), "pip-audit failed"),
        (FakeTools(pip=PIP_SAMPLE, pip_code=2), "pip-audit failed"),
        (FakeTools(pip={"oops": 1}, pip_code=0), "pip-audit failed"),
        (FakeTools(npm="not json"), "could not parse npm audit JSON"),
        (FakeTools(npm={"error": {"code": "ENOLOCK", "summary": "needs a lockfile"}}), "ENOLOCK"),
        (FakeTools(npm={"error": {"code": "ENOTFOUND", "summary": "no network"}}), "ENOTFOUND"),
        (FakeTools(npm={"advisories": {}, "metadata": {}}), "need npm 7 or newer"),
        (FakeTools(npm=[]), "unexpected npm audit output"),
    ],
)
def test_tool_failures_are_errors_not_clean_results(project, monkeypatch, fake, message):
    monkeypatch.setattr(agent, "_run_tool", fake.run)
    monkeypatch.setattr(agent, "_pip_audit_installed", lambda: True)
    monkeypatch.setattr(agent, "_npm_path", lambda: "/usr/bin/npm")
    with pytest.raises(DependenciesError, match=message):
        scan_directory(str(project))


@pytest.mark.parametrize("tool", ["pip_audit", "npm"])
def test_timeouts_are_errors(project, tools, monkeypatch, tool):
    def slow(cmd, **kwargs):
        if tool in " ".join(cmd):
            raise subprocess.TimeoutExpired(cmd, 1)
        return tools.run(cmd, **kwargs)

    monkeypatch.setattr(agent, "_run_tool", slow)
    with pytest.raises(DependenciesError, match="timed out"):
        scan_directory(str(project))


def test_offline_refuses_to_run(project, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("no tool should run")

    monkeypatch.setattr(agent, "_run_tool", fail)
    with pytest.raises(DependenciesError, match="offline mode"):
        scan_directory(str(project), offline=True)


# ---------------------------------------------------------------- includes and options


def _unaudited(findings):
    return [(f.file, f.line, f.message) for f in findings if f.rule_id == "unaudited-dependency"]


def test_include_base_txt_is_scanned_not_clean(tmp_path, tools, capsys):
    # The exact case that used to return [] with exit code 0.
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("fastapi\nrequests==2.19.0\n")
    (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\n")
    tools.pip_out = json.dumps({"dependencies": [PIP_SAMPLE["dependencies"][0]], "fixes": []})

    findings = scan_directory(str(tmp_path))

    assert [c["requirements"] for c in tools.calls] == ["requests==2.19.0\n"]
    assert [(f.rule_id, f.file, f.line) for f in findings] == [
        ("unpinned-dependency", "requirements/base.txt", 1),
        ("CVE-2018-18074", "requirements/base.txt", 2),
    ]
    assert main([str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out) != []


def test_nested_includes_and_no_double_scan(tmp_path, tools):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("requests==2.19.0\n")
    (tmp_path / "requirements" / "web.txt").write_text("-r base.txt\nsix==1.17.0\n")  # relative to web.txt
    (tmp_path / "requirements.txt").write_text("-r requirements/web.txt\n-r requirements/base.txt\n")
    (tmp_path / "requirements-dev.txt").write_text("-r requirements.txt\n")
    tools.pip_out = json.dumps({"dependencies": [], "fixes": []})
    tools.pip_code = 0

    assert scan_directory(str(tmp_path)) == []
    assert sorted(c["requirements"] for c in tools.calls) == ["requests==2.19.0\n", "six==1.17.0\n"]


def test_missing_include_is_reported(tmp_path, tools):
    (tmp_path / "requirements.txt").write_text("# deps\n-r requirements/missing.txt\n")
    assert _unaudited(scan_directory(str(tmp_path))) == [
        ("requirements.txt", 2, "not audited: include file not found"),
    ]


def test_include_outside_folder_is_reported_and_not_read(tmp_path, tools):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "outside.txt").write_text("requests==2.19.0\n")
    (project / "requirements.txt").write_text("-r ../outside.txt\n")
    assert _unaudited(scan_directory(str(project))) == [
        ("requirements.txt", 1, "not audited: include resolves outside the scanned folder"),
    ]
    assert tools.calls == []


def test_symlinked_include_outside_folder_is_reported(tmp_path, tools):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "outside.txt").write_text("requests==2.19.0\n")
    (project / "base.txt").symlink_to(tmp_path / "outside.txt")
    (project / "requirements.txt").write_text("-r base.txt\n")
    assert _unaudited(scan_directory(str(project))) == [
        ("requirements.txt", 1, "not audited: include resolves outside the scanned folder"),
    ]
    assert tools.calls == []


def test_symlinked_requirements_file_outside_folder_is_reported(tmp_path, tools):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "outside.txt").write_text("requests==2.19.0\n")
    (project / "requirements.txt").symlink_to(tmp_path / "outside.txt")
    assert _unaudited(scan_directory(str(project))) == [
        ("requirements.txt", 0, "not audited: file is a link to outside the scanned folder"),
    ]
    assert tools.calls == []


def test_include_cycle_is_reported_and_stops(tmp_path, tools):
    (tmp_path / "requirements.txt").write_text("-r b.txt\n")
    (tmp_path / "b.txt").write_text("fastapi\n-r requirements.txt\n")
    findings = scan_directory(str(tmp_path))
    assert _unaudited(findings) == [("b.txt", 2, "not audited: include cycle")]
    assert [(f.rule_id, f.file) for f in findings if f.rule_id == "unpinned-dependency"] == [
        ("unpinned-dependency", "b.txt"),
    ]


def test_self_include_is_a_cycle(tmp_path, tools):
    (tmp_path / "requirements.txt").write_text("-r requirements.txt\n")
    assert _unaudited(scan_directory(str(tmp_path))) == [("requirements.txt", 1, "not audited: include cycle")]


def test_remote_include_is_reported(tmp_path, tools):
    (tmp_path / "requirements.txt").write_text("-r https://example.invalid/reqs.txt\n")
    assert _unaudited(scan_directory(str(tmp_path))) == [
        ("requirements.txt", 1, "not audited: remote include (URL) cannot be followed"),
    ]


@pytest.mark.parametrize(
    "line, reason",
    [
        ("-c constraints.txt", "constraints file skipped"),
        ("--index-url https://example.invalid/simple", "custom package index"),
        ("--extra-index-url https://example.invalid/simple", "extra package index"),
        ("-e .", "editable requirement"),
        ("-e git+https://example.invalid/x.git#egg=x", "editable requirement"),
    ],
)
def test_options_are_reported_as_unaudited(tmp_path, tools, line, reason):
    (tmp_path / "constraints.txt").write_text("requests==2.19.0\n")
    (tmp_path / "requirements.txt").write_text(line + "\n")
    findings = scan_directory(str(tmp_path))
    assert [(f.rule_id, f.severity, f.file, f.line, f.redacted_match) for f in findings] == [
        ("unaudited-dependency", "low", "requirements.txt", 1, line),
    ]
    assert reason in findings[0].message
    assert tools.calls == []  # a constraints file is never audited as a dependency list


def test_index_url_credentials_never_reach_findings(tmp_path, tools, capsys):
    (tmp_path / "requirements.txt").write_text("--extra-index-url https://ci:SECRET789@example.invalid/simple\n")
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "SECRET789" not in out and "https://***@example.invalid/simple" in out


# ---------------------------------------------------------------- CLI


def test_cli_offline_exit_code_2(project, capsys):
    assert main([str(project), "--offline"]) == 2
    err = capsys.readouterr().err
    assert "offline mode" in err and "online vulnerability databases" in err


def test_cli_exit_code_2_for_missing_folder(tmp_path, capsys):
    assert main([str(tmp_path / "does-not-exist")]) == 2
    capsys.readouterr()


def test_cli_exit_code_1_with_findings(project, tools, capsys):
    assert main([str(project)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out and all(f["agent"] == "dependencies" for f in out)


def test_cli_exit_code_0_when_clean(tmp_path, monkeypatch, capsys):
    fake = FakeTools(npm=NPM_CLEAN, npm_code=0)
    monkeypatch.setattr(agent, "_run_tool", fake.run)
    monkeypatch.setattr(agent, "_npm_path", lambda: "/usr/bin/npm")
    (tmp_path / "package-lock.json").write_text(LOCKFILE)
    assert main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_tool_error_exit_code_2(project, tools, monkeypatch, capsys):
    monkeypatch.setattr(agent, "_npm_path", lambda: None)
    assert main([str(project)]) == 2
    assert "npm is not installed" in capsys.readouterr().err


# ---------------------------------------------------------------- live (opt-in, network)


@pytest.mark.skipif(
    not LIVE or importlib.util.find_spec("pip_audit") is None,
    reason="live test: set SENTINEL_LIVE_TESTS=1 and pip install -r requirements-dependencies.txt",
)
def test_live_pip_audit(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    rule_ids = {f.rule_id for f in scan_directory(str(tmp_path))}
    assert "CVE-2018-18074" in rule_ids


@pytest.mark.skipif(
    not LIVE or shutil.which("npm") is None,
    reason="live test: set SENTINEL_LIVE_TESTS=1 and install npm",
)
def test_live_npm_audit_on_dashboard():
    dashboard = Path(__file__).parent.parent / "dashboard"
    before = _snapshot(dashboard / "src") | {"lock": _snapshot(dashboard).get(str(dashboard / "package-lock.json"))}
    scan_directory(str(dashboard))  # must not raise; findings depend on the live database
    after = _snapshot(dashboard / "src") | {"lock": _snapshot(dashboard).get(str(dashboard / "package-lock.json"))}
    assert after == before


# ---------------------------------------------------------------- time budget


@pytest.fixture(autouse=True)
def _no_budget_env(monkeypatch):
    # A value set in the developer's shell must not change test results.
    monkeypatch.delenv(agent.BUDGET_ENV, raising=False)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class TimedTools(FakeTools):
    """Each tool run "takes" the next duration on the fake clock; no real waiting.

    A run longer than its timeout uses up the timeout, then times out."""

    def __init__(self, clock, durations):
        super().__init__(pip={"dependencies": [], "fixes": []}, npm=NPM_CLEAN, pip_code=0, npm_code=0)
        self.clock = clock
        self.durations = list(durations)
        self.timeouts = []

    def run(self, cmd, **kwargs):
        timeout = kwargs["timeout"]
        self.timeouts.append(timeout)
        took = self.durations.pop(0)
        if took > timeout:
            self.clock.now += timeout
            raise subprocess.TimeoutExpired(cmd, timeout)
        self.clock.now += took
        return super().run(cmd, **kwargs)


@pytest.fixture
def timed(monkeypatch):
    def make(durations):
        clock = Clock()
        fake = TimedTools(clock, durations)
        monkeypatch.setattr(agent, "_run_tool", fake.run)
        monkeypatch.setattr(agent, "_pip_audit_installed", lambda: True)
        monkeypatch.setattr(agent, "_npm_path", lambda: "/usr/bin/npm")
        return clock, fake

    return make


@pytest.fixture
def three_files(tmp_path):
    # Scan order: requirements-dev.txt, requirements.txt, web/package-lock.json
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    (tmp_path / "requirements-dev.txt").write_text("six==1.17.0\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text(LOCKFILE)
    return tmp_path


def test_runs_are_capped_and_get_what_is_left(three_files, timed):
    clock, fake = timed([250, 200, 10])
    assert scan_directory(str(three_files), budget_seconds=600, clock=clock) == []
    assert fake.timeouts == [300, 300, 150]  # 600 - 250 = 350, capped at 300; then 600 - 450


def test_budget_runs_out_during_a_run(three_files, timed):
    clock, fake = timed([200, 150])
    with pytest.raises(agent.TimeBudgetExceeded) as exc:
        scan_directory(str(three_files), budget_seconds=300, clock=clock)
    assert fake.timeouts == [300, 100]  # exactly 2 runs started: npm audit never did
    assert str(exc.value) == (
        "time budget of 300s ran out: audited 1 file(s) (requirements-dev.txt); "
        "not audited: requirements.txt (in progress), web/package-lock.json, and any files they include"
    )


def test_budget_spent_before_next_tool_starts(three_files, timed):
    clock, fake = timed([299.5])  # 0.5s left: too little to start another tool
    with pytest.raises(agent.TimeBudgetExceeded, match="audited 1 file\\(s\\) \\(requirements-dev.txt\\)"):
        scan_directory(str(three_files), budget_seconds=300, clock=clock)
    assert len(fake.calls) == 1


def test_budget_runs_out_inside_an_include(tmp_path, timed):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("requests==2.19.0\n")
    (tmp_path / "requirements.txt").write_text("-r requirements/base.txt\nsix==1.17.0\n")
    clock, fake = timed([100, 250])
    with pytest.raises(agent.TimeBudgetExceeded) as exc:
        scan_directory(str(tmp_path), budget_seconds=300, clock=clock)
    assert fake.timeouts == [300, 200]
    assert str(exc.value) == (
        "time budget of 300s ran out: audited 1 file(s) (requirements.txt); "
        "not audited: requirements/base.txt (in progress), and any files they include"
    )


def test_budget_runs_out_on_the_lockfile(three_files, timed):
    clock, fake = timed([10, 10, 500])
    with pytest.raises(agent.TimeBudgetExceeded) as exc:
        scan_directory(str(three_files), budget_seconds=300, clock=clock)
    assert fake.timeouts == [300, 290, 280]
    assert "audited 2 file(s) (requirements-dev.txt, requirements.txt)" in str(exc.value)
    assert "not audited: web/package-lock.json (in progress)" in str(exc.value)


def test_per_run_cap_is_not_reported_as_budget(three_files, timed):
    clock, fake = timed([400])
    with pytest.raises(DependenciesError) as exc:
        scan_directory(str(three_files), budget_seconds=3600, clock=clock)
    assert not isinstance(exc.value, agent.TimeBudgetExceeded)
    assert str(exc.value) == "pip-audit timed out after 300s on requirements-dev.txt"


def test_cli_budget_exceeded_exit_2_never_clean(three_files, timed, capsys):
    timed([])  # 0.5s budget: no tool may even start, so nothing is waited for
    assert main([str(three_files), "--time-budget", "0.5"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""  # no findings list, so nothing that looks like a clean result
    assert "time budget of 0.5s ran out: audited 0 file(s); not audited: requirements-dev.txt (in progress)" in captured.err


def test_budget_default_env_and_parameter(monkeypatch):
    assert agent.resolve_budget() == agent.DEFAULT_BUDGET_SECONDS == 300
    monkeypatch.setenv(agent.BUDGET_ENV, "120")
    assert agent.resolve_budget() == 120
    assert agent.resolve_budget(45) == 45  # parameter / --time-budget beats the env var
    assert agent.resolve_budget("3600") == 3600


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "99999", "nan", "inf", ""])
def test_bad_budget_values_are_errors(monkeypatch, tmp_path, capsys, bad):
    with pytest.raises(DependenciesError, match="invalid time budget from --time-budget"):
        agent.resolve_budget(bad)
    monkeypatch.setenv(agent.BUDGET_ENV, bad)
    with pytest.raises(DependenciesError, match=f"invalid time budget from {agent.BUDGET_ENV}"):
        agent.resolve_budget()
    assert main([str(tmp_path)]) == 2  # even with nothing to scan, a bad setting is reported
    assert "invalid time budget" in capsys.readouterr().err


def test_cli_flag_beats_bad_env(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(agent.BUDGET_ENV, "abc")
    assert main([str(tmp_path), "--time-budget", "60"]) == 0
    capsys.readouterr()


# ---------------------------------------------------------------- process cleanup


class FakePopen:
    """Popen whose first communicate() fails with `first_error`."""

    instances = []

    def __init__(self, cmd, **kwargs):
        self.cmd, self.kwargs = cmd, kwargs
        self.pid = 4242
        self.returncode = -9
        self.communicate_calls = []
        self.first_error = FakePopen.next_error
        FakePopen.instances.append(self)

    def communicate(self, timeout=None):
        self.communicate_calls.append(timeout)
        if len(self.communicate_calls) == 1 and self.first_error:
            raise self.first_error
        return "", ""


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
@pytest.mark.parametrize(
    "error",
    [subprocess.TimeoutExpired(["tool"], 5), KeyboardInterrupt()],
    ids=["timeout", "ctrl-c"],
)
def test_run_tool_kills_whole_group_on_error(monkeypatch, error):
    import signal

    killed = []
    FakePopen.instances, FakePopen.next_error = [], error
    monkeypatch.setattr(agent.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(agent.os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))

    with pytest.raises(type(error)):
        agent._run_tool(["tool"], timeout=5)

    proc = FakePopen.instances[0]
    assert proc.kwargs["start_new_session"] is True
    assert killed == [(4242, signal.SIGKILL)]
    assert proc.communicate_calls == [5, agent.KILL_WAIT_SECONDS]  # reaped after the kill


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only")
def test_run_tool_tolerates_group_already_gone(monkeypatch):
    def gone(pgid, sig):
        raise ProcessLookupError

    FakePopen.instances, FakePopen.next_error = [], subprocess.TimeoutExpired(["tool"], 5)
    monkeypatch.setattr(agent.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(agent.os, "killpg", gone)
    with pytest.raises(subprocess.TimeoutExpired):
        agent._run_tool(["tool"], timeout=5)


def test_run_tool_returns_output():
    import sys

    proc = agent._run_tool([sys.executable, "-c", "print('hi')"], timeout=30)
    assert (proc.returncode, proc.stdout.strip()) == (0, "hi")


# A child that starts a grandchild, records both PIDs, then sleeps. The
# grandchild shares the output pipe, so killing only the child would hang.
CHILD = r"""
import os, subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(sys.argv[1], "w") as fh:
    fh.write(f"{os.getpid()} {grandchild.pid}")
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    """True if pid is running (a zombie waiting to be reaped counts as gone)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if not Path("/proc").is_dir():
        return True  # no /proc (macOS): os.kill says it exists
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0] != "Z"
    except (OSError, IndexError):
        return False  # vanished between the two checks


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX only (skipped on Windows)")
def test_real_timeout_kills_child_and_grandchild(tmp_path):
    # The one test with real waiting (about 1.5 seconds).
    import sys
    import time

    pid_file = tmp_path / "pids"
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        agent._run_tool([sys.executable, "-c", CHILD, str(pid_file)], timeout=1.5)
    assert time.monotonic() - start < 10  # did not wait for the 60s sleeps

    pids = [int(p) for p in pid_file.read_text().split()]
    try:
        deadline = time.monotonic() + 5
        while any(_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not any(_alive(p) for p in pids), "child or grandchild still running"
    finally:
        for p in pids:  # never leave a stray process behind, even if the test fails
            try:
                os.kill(p, 9)
            except (ProcessLookupError, PermissionError):
                pass
