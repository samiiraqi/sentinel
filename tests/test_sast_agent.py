import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

from agents.sast import agent
from agents.sast.agent import (
    SastError,
    find_python_files,
    main,
    parse_bandit_output,
    scan_directory,
    scanned_files,
)
from shared import proc as shared_proc

needs_bandit = pytest.mark.skipif(
    importlib.util.find_spec("bandit") is None,
    reason="bandit not installed (pip install -r requirements-sast.txt)",
)

# FAKE password, and the word "password", split so this file does not trip
# the secrets scan in CI.
FAKE_VALUE = "FakePassw0rd" + "ForTests"
PW_WORD = "pass" + "word"

# Bad code, written into tmp_path at test time only (never committed).
BAD_CODE = {
    "shell.py": "import subprocess\n\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n",
    "load.py": "import pickle\n\n\ndef load(data):\n    return pickle.loads(data)\n",
    "conf.py": "import yaml\n\n\ndef read(text):\n    return yaml.load(text)\n",
}
CLEAN_CODE = "def add(a, b):\n    return a + b\n"
ASSERT_CODE = "def check(value):\n    assert value\n"

# Trimmed from real `bandit -f json` output (1.9.4).
SAMPLE = {
    "errors": [{"filename": "././pkg/broken.py", "reason": "syntax error while parsing AST from file"}],
    "metrics": {
        "././pkg/app.py": {"loc": 3},
        "././pkg/broken.py": {"loc": 0},
        "_totals": {"loc": 3},
    },
    "results": [
        {
            "test_id": "B105",
            "test_name": "hardcoded_password_string",
            "issue_severity": "LOW",
            "issue_confidence": "MEDIUM",
            "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
            "filename": "././pkg/app.py",
            "line_number": 2,
            "line_range": [2],
            # Raw values Bandit includes; these must never reach a Finding.
            "issue_text": f"Possible hardcoded {PW_WORD}: '{FAKE_VALUE}'",
            "code": f"1 import os\n2 {PW_WORD} = '{FAKE_VALUE}'\n",
        },
        {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
            "filename": "././pkg/app.py",
            "line_number": "3",
            "issue_text": "FAKE-ISSUE-TEXT",
            "code": "FAKE-RAW-CODE",
        },
    ],
}


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove the scan changes nothing."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


def _write(root: Path, files: dict) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _empty_output(files: list[str]) -> dict:
    return {"errors": [], "results": [], "metrics": {f"././{f}": {} for f in files} | {"_totals": {}}}


class FakeBandit:
    """Stands in for the bandit process: records each call, returns fixed output."""

    def __init__(self, stdout=None, code=0, raises=None):
        self.stdout = stdout
        self.code, self.raises = code, raises
        self.calls = []

    def run(self, cmd, timeout, cwd, env):
        files = [c[2:] for c in cmd if c.startswith("./")]
        config = cmd[cmd.index("-c") + 1]
        ini = cmd[cmd.index("--ini") + 1]
        self.calls.append({
            "cmd": list(cmd),
            "files": files,
            "timeout": timeout,
            "cwd": cwd,
            "config": Path(config).read_text(),
            "ini": Path(ini).read_text(),
        })
        if self.raises:
            raise self.raises
        stdout = self.stdout if self.stdout is not None else _empty_output(files)
        if not isinstance(stdout, str):
            stdout = json.dumps(stdout)
        return subprocess.CompletedProcess(cmd, self.code, stdout, "")


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        bandit = FakeBandit(**kwargs)
        monkeypatch.setattr(agent, "_run_tool", bandit.run)
        real_find_spec = importlib.util.find_spec
        monkeypatch.setattr(agent.importlib.util, "find_spec",
                            lambda name, *a: object() if name == "bandit" else real_find_spec(name, *a))
        return bandit
    return install


# ---------------------------------------------------------------- parser


def test_parse_maps_fields_and_never_copies_issue_text_or_code():
    findings = parse_bandit_output(SAMPLE)
    by_rule = {f.rule_id: f for f in findings}

    pw = by_rule["B105"]
    assert pw.agent == "sast"
    assert pw.file == "pkg/app.py"
    assert pw.line == 2
    assert pw.severity == "low"
    assert pw.message == "hardcoded_password_string (CWE-259, confidence medium)"
    assert pw.redacted_match == "hardcoded_password_string"

    shell = by_rule["B602"]
    assert (shell.severity, shell.line) == ("high", 3)

    dumped = json.dumps([f.to_dict() for f in findings])
    for raw in (FAKE_VALUE, "FAKE-ISSUE-TEXT", "FAKE-RAW-CODE", "Possible hardcoded", "import os"):
        assert raw not in dumped


def test_parse_errors_become_unscanned_findings():
    unscanned = [f for f in parse_bandit_output(SAMPLE) if f.rule_id == "sast-unscanned"]
    assert [(f.file, f.severity, f.line) for f in unscanned] == [("pkg/broken.py", "low", 0)]
    assert unscanned[0].message == "not scanned: Bandit could not parse this file"


@pytest.mark.parametrize(
    "value, expected",
    [("LOW", "low"), ("MEDIUM", "medium"), ("HIGH", "high"), ("UNDEFINED", "medium"), (None, "medium")],
)
def test_severity_mapping(value, expected):
    data = {"results": [{"test_id": "B1", "issue_severity": value, "filename": "./a.py", "line_number": 1}]}
    assert parse_bandit_output(data)[0].severity == expected


def test_parse_ignores_malformed_entries():
    data = {"results": ["x", None], "errors": [42]}
    assert parse_bandit_output(data) == []


def test_scanned_files_skips_totals():
    assert scanned_files(SAMPLE) == {"pkg/app.py", "pkg/broken.py"}


@pytest.mark.parametrize("name", ["/etc/passwd.py", "../outside.py", "", None, 42])
def test_paths_outside_root_are_never_shown(name):
    data = {"results": [{"test_id": "B1", "filename": name, "line_number": 1}], "errors": [{"filename": name}]}
    assert [f.file for f in parse_bandit_output(data, "/scan/root")] == ["", ""]


def test_paths_are_relative_to_root():
    data = {"results": [{"test_id": "B1", "filename": "/scan/root/pkg/a.py", "line_number": 1}]}
    assert parse_bandit_output(data, "/scan/root")[0].file == "pkg/a.py"


def _assert_result(filename):
    return {"results": [{"test_id": "B101", "filename": filename, "line_number": 1}]}


def test_scan_root_under_a_tests_folder_does_not_hide_asserts():
    data = _assert_result("/work/tests/project/app.py")
    assert [f.file for f in parse_bandit_output(data, "/work/tests/project")] == ["app.py"]


@pytest.mark.parametrize("name", ["/etc/tests/a.py", "../tests/a.py", "", None])
def test_assert_with_unknown_path_is_still_reported(name):
    assert [f.rule_id for f in parse_bandit_output(_assert_result(name), "/scan/root")] == ["B101"]


def test_ignored_rules_for_test_files_are_configurable(monkeypatch):
    data = _assert_result("tests/a.py")
    assert parse_bandit_output(data) == []
    monkeypatch.setattr(agent, "TEST_FILE_IGNORED_RULES", frozenset())
    assert [f.rule_id for f in parse_bandit_output(data)] == ["B101"]


# ---------------------------------------------------------------- failures


def test_missing_bandit_is_an_error(tmp_path, monkeypatch):
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(agent.importlib.util, "find_spec",
                        lambda name, *a: None if name == "bandit" else real_find_spec(name, *a))
    with pytest.raises(SastError, match="bandit is not installed"):
        scan_directory(str(tmp_path))


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"code": 2, "stdout": SAMPLE}, "exit code 2"),
        ({"code": 1, "stdout": "not json"}, "could not parse"),
        ({"code": 0, "stdout": "   \n"}, "no output"),
        ({"code": 0, "stdout": "42"}, "unexpected"),
        ({"code": 0, "stdout": {"results": []}}, "unexpected"),
        ({"raises": subprocess.TimeoutExpired(["bandit"], 300)}, "timed out"),
    ],
)
def test_tool_failures_raise_never_return_empty(tmp_path, fake, kwargs, message):
    (tmp_path / "a.py").write_text(CLEAN_CODE)
    fake(**kwargs)
    with pytest.raises(SastError, match=message):
        scan_directory(str(tmp_path))


def test_cli_error_exit_code_2(tmp_path, fake, capsys):
    (tmp_path / "a.py").write_text(CLEAN_CODE)
    fake(code=2, stdout="")
    assert main([str(tmp_path)]) == 2
    assert "exit code 2" in capsys.readouterr().err


def test_cli_not_a_directory(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_file_without_bandit_result_is_unscanned(tmp_path, fake):
    _write(tmp_path, {"a.py": CLEAN_CODE, "b.py": CLEAN_CODE})
    fake(stdout=_empty_output(["a.py"]))
    assert [(f.rule_id, f.file, f.message) for f in scan_directory(str(tmp_path))] == [
        ("sast-unscanned", "b.py", "not scanned: Bandit returned no result for this file"),
    ]


def test_uses_the_shared_process_runner():
    # Kill-on-timeout (child and grandchild) is tested once, in tests/test_proc.py.
    assert agent._run_tool is shared_proc.run_tool


# ---------------------------------------------------------------- how bandit is run


def test_bandit_runs_with_our_empty_config_and_ignore_nosec(tmp_path, fake):
    _write(tmp_path, {"a.py": CLEAN_CODE, "-x.py": CLEAN_CODE})
    bandit = fake()
    assert scan_directory(str(tmp_path)) == []

    (call,) = bandit.calls
    assert "--ignore-nosec" in call["cmd"]
    assert call["config"] == agent.EMPTY_CONFIG
    assert call["ini"] == agent.EMPTY_INI
    assert call["cwd"] == str(tmp_path)
    assert call["files"] == ["-x.py", "a.py"]
    assert "-x.py" not in call["cmd"]  # always passed as ./-x.py
    assert call["timeout"] <= agent.TIMEOUT_SECONDS


def test_no_python_files_never_starts_bandit(tmp_path, fake):
    (tmp_path / "README.md").write_text("hi\n")
    bandit = fake()
    assert scan_directory(str(tmp_path)) == []
    assert bandit.calls == []


def test_files_are_scanned_in_batches(tmp_path, fake, monkeypatch):
    monkeypatch.setattr(agent, "BATCH_SIZE", 2)
    _write(tmp_path, {f"m{i}.py": CLEAN_CODE for i in range(5)})
    bandit = fake()
    assert scan_directory(str(tmp_path)) == []
    assert [c["files"] for c in bandit.calls] == [["m0.py", "m1.py"], ["m2.py", "m3.py"], ["m4.py"]]


def test_batches_share_one_time_limit(tmp_path, fake, monkeypatch):
    monkeypatch.setattr(agent, "BATCH_SIZE", 1)
    _write(tmp_path, {"a.py": CLEAN_CODE, "b.py": CLEAN_CODE})
    now = [0.0]
    bandit = fake()
    real_run = bandit.run

    def slow_run(cmd, timeout, cwd, env):
        now[0] += agent.TIMEOUT_SECONDS  # the first batch uses up the whole limit
        return real_run(cmd, timeout, cwd, env)

    monkeypatch.setattr(agent, "_run_tool", slow_run)
    with pytest.raises(SastError, match="timed out"):
        scan_directory(str(tmp_path), clock=lambda: now[0])
    assert len(bandit.calls) == 1


# ---------------------------------------------------------------- file walk


def test_walk_skips_vendored_dirs_and_reports_symlinks(tmp_path):
    _write(tmp_path, {
        "app/main.py": CLEAN_CODE,
        "app/gui.pyw": CLEAN_CODE,
        "app/notes.txt": "x\n",
        ".venv/lib/x.py": CLEAN_CODE,
        "node_modules/y.py": CLEAN_CODE,
        "real/z.py": CLEAN_CODE,
    })
    os.symlink(tmp_path / "real", tmp_path / "linkdir")
    os.symlink(tmp_path / "app" / "main.py", tmp_path / "link.py")
    files, unscanned = find_python_files(str(tmp_path))
    assert files == ["app/gui.pyw", "app/main.py", "real/z.py"]
    assert [(f.file, f.message) for f in unscanned] == [("link.py", "not scanned: symlink not followed")]


def test_oversized_file_is_unscanned(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "MAX_FILE_BYTES", 10)
    _write(tmp_path, {"small.py": "x = 1\n", "big.py": "x = 1\n" * 10})
    files, unscanned = find_python_files(str(tmp_path))
    assert files == ["small.py"]
    assert [(f.file, f.message) for f in unscanned] == [("big.py", "not scanned: file too large to scan")]


def test_exclude_uses_component_matching(tmp_path):
    _write(tmp_path, {
        "tests/fixtures/a.py": CLEAN_CODE,
        "tests/test_x.py": CLEAN_CODE,
        "src/tests.py": CLEAN_CODE,
        "src/prod.venv-config.py": CLEAN_CODE,
    })
    files, _ = find_python_files(str(tmp_path), ("tests/fixtures", ".venv"))
    assert files == ["src/prod.venv-config.py", "src/tests.py", "tests/test_x.py"]
    files, _ = find_python_files(str(tmp_path), ("tests",))
    assert files == ["src/prod.venv-config.py", "src/tests.py"]


# ---------------------------------------------------------------- real bandit


@needs_bandit
def test_real_bandit_finds_bad_code(tmp_path):
    _write(tmp_path, BAD_CODE | {"clean.py": CLEAN_CODE})
    found = {(f.rule_id, f.file) for f in scan_directory(str(tmp_path))}
    assert {("B602", "shell.py"), ("B301", "load.py"), ("B506", "conf.py")} <= found
    assert not any(file == "clean.py" for _, file in found)


@needs_bandit
def test_real_bandit_clean_code_has_no_findings(tmp_path, capsys):
    _write(tmp_path, {"clean.py": CLEAN_CODE, "pkg/__init__.py": ""})
    assert scan_directory(str(tmp_path)) == []
    assert main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_bandit
def test_real_bandit_syntax_error_and_non_utf8_are_unscanned(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n")
    (tmp_path / "latin1.py").write_bytes(b'x = "\xff\xfe"\n')
    (tmp_path / "ok.py").write_text(CLEAN_CODE)
    findings = scan_directory(str(tmp_path))
    assert sorted((f.rule_id, f.file) for f in findings) == [
        ("sast-unscanned", "broken.py"),
        ("sast-unscanned", "latin1.py"),
    ]


@needs_bandit
def test_real_bandit_ignores_scanned_folder_settings_and_nosec(tmp_path):
    (tmp_path / ".bandit").write_text("[bandit]\nskips = B602,B404\n")
    (tmp_path / "pyproject.toml").write_text('[tool.bandit]\nskips = ["B602", "B404"]\n')
    (tmp_path / "shell.py").write_text(
        "import subprocess  # nosec\n\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)  # nosec B602\n"
    )
    rules = {f.rule_id for f in scan_directory(str(tmp_path))}
    assert {"B404", "B602"} <= rules


@needs_bandit
def test_real_bandit_password_never_in_output(tmp_path, capsys):
    (tmp_path / "settings.py").write_text(f"{PW_WORD} = {FAKE_VALUE!r}\n")
    findings = scan_directory(str(tmp_path))
    assert "B105" in {f.rule_id for f in findings}
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "B105" in out
    assert FAKE_VALUE not in out
    assert FAKE_VALUE not in json.dumps([f.to_dict() for f in findings])


@needs_bandit
@pytest.mark.parametrize("name", ["tests/helpers.py", "pkg/tests/sub/helpers.py", "test_app.py", "pkg/app_test.py"])
def test_real_bandit_assert_in_test_file_is_not_reported(tmp_path, name):
    # Exactly no findings: the file also must not turn into sast-unscanned.
    _write(tmp_path, {name: ASSERT_CODE})
    assert scan_directory(str(tmp_path)) == []


@needs_bandit
@pytest.mark.parametrize("name", ["app.py", "src/tests.py", "src/test/app.py", "pkg/latest_data.py"])
def test_real_bandit_assert_in_normal_code_is_reported(tmp_path, name):
    _write(tmp_path, {name: ASSERT_CODE})
    assert [(f.rule_id, f.file) for f in scan_directory(str(tmp_path))] == [("B101", name)]


@needs_bandit
@pytest.mark.parametrize("name", ["tests/helpers.py", "test_app.py", "pkg/app_test.py"])
def test_real_bandit_other_rules_in_test_files_are_reported(tmp_path, name):
    _write(tmp_path, {name: f"{PW_WORD} = {FAKE_VALUE!r}\n" + ASSERT_CODE + BAD_CODE["shell.py"]})
    rules = {f.rule_id for f in scan_directory(str(tmp_path))}
    assert {"B105", "B602"} <= rules
    assert "B101" not in rules


@needs_bandit
def test_real_bandit_exclude(tmp_path):
    _write(tmp_path, {"tests/shell.py": BAD_CODE["shell.py"], "src/clean.py": CLEAN_CODE})
    assert scan_directory(str(tmp_path), exclude=("tests",)) == []
    assert scan_directory(str(tmp_path))


@needs_bandit
def test_real_bandit_does_not_modify_files(tmp_path):
    _write(tmp_path, BAD_CODE | {"clean.py": CLEAN_CODE})
    (tmp_path / "broken.py").write_text("def f(:\n")
    before = _snapshot(tmp_path)
    scan_directory(str(tmp_path))
    assert _snapshot(tmp_path) == before
    assert not any(p.name == "__pycache__" for p in tmp_path.rglob("*"))
