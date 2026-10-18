import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from agents.git_history import agent
from agents.git_history.agent import GitHistoryError, main, parse_log, scan_directory
from approval.decisions import fingerprint
from shared import proc as shared_proc

REPO = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

# FAKE values, split into pieces so this file does not trip the secrets scan in CI.
FAKE_AWS = "AKIA" + "TESTONLYFAKE0000"
FAKE_AWS_2 = "AKIA" + "TESTONLYFAKE1111"
PW_WORD = "pass" + "word"
FAKE_PW = "Fake" + "HistoryValue42"
FAKE_PW_2 = "Fake" + "HistoryValue43"
FAKE_VALUES = [FAKE_AWS, FAKE_AWS_2, FAKE_PW, FAKE_PW_2]
UNSCANNED = "git-history-unscanned"

# Safe git settings for building test repos: no system/global config, fixed identity, no signing.
SAFE_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
}
SAFE_CONFIG = [
    "-c", "user.name=Sentinel Test",
    "-c", "user.email=test@example.invalid",
    "-c", "commit.gpgsign=false",
    "-c", "init.defaultBranch=main",
    "-c", "protocol.file.allow=always",
]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *SAFE_CONFIG, "-C", str(repo), *args], check=True, capture_output=True, text=True, env=SAFE_ENV
    ).stdout


def _init(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    return path


def _commit(repo: Path, files: dict, message: str = "change") -> str:
    """Write (str/bytes) or delete (None) files, commit everything, return the commit id."""
    for rel, content in files.items():
        target = repo / rel
        if content is None:
            target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _aws_line(value: str = FAKE_AWS) -> str:
    return f"aws_key_id = {value}\n"


def _pw_line(value: str = FAKE_PW) -> str:
    return f'{PW_WORD} = "{value}"\n'


def _rows(found):
    return [(f.rule_id, f.file, f.line) for f in found]


def _dump(found) -> str:
    return json.dumps([f.to_dict() for f in found])


def _snapshot(root: Path) -> dict:
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


# ---------------------------------------------------------------- parser


def test_parse_log_counts_hunk_lines():
    sha = "a" * 40
    text = "\n".join([
        f"commit {sha}",
        "",
        "diff --git a/x.txt b/x.txt",
        "--- a/x.txt",
        "+++ b/x.txt",
        "@@ -3,2 +3,3 @@",
        "-old",
        "-old",
        "+++ b/not-a-header.txt",  # content line that looks like a header
        "+commit " + "b" * 40,  # content line that looks like a commit
        "+third",
        "\\ No newline at end of file",
        "diff --git a/two words.txt b/two words.txt",
        "--- /dev/null",
        "+++ b/two words.txt\t",
        "@@ -0,0 +1 @@",
        "+spaced",
        "diff --git a/gone.txt b/gone.txt",
        "--- a/gone.txt",
        "+++ /dev/null",
        "@@ -1 +0,0 @@",
        "-was here",
        "@@ -9,0 +10 @@",
        "+after a zero-length hunk",
    ])
    assert list(parse_log(text)) == [
        (sha, "x.txt", 3, "++ b/not-a-header.txt"),
        (sha, "x.txt", 4, "commit " + "b" * 40),
        (sha, "x.txt", 5, "third"),
        (sha, "two words.txt", 1, "spaced"),
    ]


def test_unquote_paths():
    assert agent._unquote("plain/path.txt") == "plain/path.txt"
    assert agent._unquote('"b/sp ace \\"q\\"\\t\\303\\251.txt"') == 'b/sp ace "q"\té.txt'


# ---------------------------------------------------------------- history findings


@needs_git
def test_deleted_secret_is_found_with_commit_and_line(tmp_path, capsys):
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {"app/config.py": "# config\n\n" + _aws_line()})
    _commit(repo, {"app/config.py": None, "README.md": "hi\n"})

    found = scan_directory(str(repo))
    assert [f.to_dict() for f in found] == [{
        "agent": "git_history",
        "rule_id": "aws-access-key-id",
        "severity": "high",
        "file": f"app/config.py@{added[:12]}",
        "line": 3,
        "message": f"Possible AWS access key ID (in git history: added in commit {added[:12]}, not in current files)",
        "redacted_match": "AKIA****",
    }]
    assert main([str(repo)]) == 1
    out = capsys.readouterr()
    for value in FAKE_VALUES:
        assert value not in out.out and value not in out.err


@needs_git
def test_secret_removed_from_a_file_that_still_exists(tmp_path):
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {"settings.py": "DEBUG = True\n" + _pw_line()})
    _commit(repo, {"settings.py": "DEBUG = True\n"})
    assert _rows(scan_directory(str(repo))) == [("generic-secret-assignment", f"settings.py@{added[:12]}", 2)]


@needs_git
def test_secret_still_in_current_files_is_not_reported_twice(tmp_path):
    repo = _init(tmp_path / "repo")
    _commit(repo, {"a.py": _aws_line(), "b.py": _pw_line()})
    _commit(repo, {"a.py": None, "moved/a.py": _aws_line()})  # same value, now in another file
    assert scan_directory(str(repo)) == []


@needs_git
def test_same_value_is_reported_once_at_the_oldest_commit(tmp_path):
    repo = _init(tmp_path / "repo")
    first = _commit(repo, {"keys.txt": _aws_line()})
    _commit(repo, {"keys.txt": _aws_line() + "x\n" + _aws_line()})
    _commit(repo, {"keys.txt": None})
    assert _rows(scan_directory(str(repo))) == [("aws-access-key-id", f"keys.txt@{first[:12]}", 1)]


@needs_git
def test_rotated_secrets_on_the_same_line_get_different_fingerprints(tmp_path):
    repo = _init(tmp_path / "repo")
    one = _commit(repo, {"cfg.ini": _pw_line(FAKE_PW)})
    two = _commit(repo, {"cfg.ini": _pw_line(FAKE_PW_2)})
    _commit(repo, {"cfg.ini": "# moved to a vault\n"})
    found = scan_directory(str(repo))
    assert _rows(found) == [
        ("generic-secret-assignment", f"cfg.ini@{one[:12]}", 1),
        ("generic-secret-assignment", f"cfg.ini@{two[:12]}", 1),
    ]
    assert len({fingerprint(f.to_dict()) for f in found}) == 2


@needs_git
def test_clean_repo(tmp_path, capsys):
    repo = _init(tmp_path / "repo")
    _commit(repo, {"main.py": "print('hello')\n"})
    _commit(repo, {"main.py": "print('bye')\n"})
    assert main([str(repo)]) == 0
    assert json.loads(capsys.readouterr().out) == []


@needs_git
def test_other_branches_and_tags_are_scanned(tmp_path):
    repo = _init(tmp_path / "repo")
    _commit(repo, {"a.txt": "a\n"})
    _git(repo, "checkout", "-q", "-b", "side")
    side = _commit(repo, {"side.txt": _aws_line()})
    _git(repo, "checkout", "-q", "main")
    assert _rows(scan_directory(str(repo))) == [("aws-access-key-id", f"side.txt@{side[:12]}", 1)]


@needs_git
def test_subfolder_scans_only_its_own_history(tmp_path):
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {"app/cfg.py": _aws_line(), "other/cfg.py": _pw_line()})
    _commit(repo, {"app/cfg.py": None, "other/cfg.py": None, "app/keep.txt": "x\n"})
    assert _rows(scan_directory(str(repo / "app"))) == [("aws-access-key-id", f"cfg.py@{added[:12]}", 1)]


@needs_git
def test_exclude_and_skipped_folders(tmp_path):
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {
        "legacy/a.py": _aws_line(),
        "legacy-new/a.py": _aws_line(FAKE_AWS_2),
        "node_modules/x/a.js": _pw_line(),
        ".venv/a.py": _pw_line(FAKE_PW_2),
    })
    _commit(repo, {p: None for p in ("legacy/a.py", "legacy-new/a.py", "node_modules/x/a.js", ".venv/a.py")})
    assert _rows(scan_directory(str(repo), exclude=("legacy",))) == [
        ("aws-access-key-id", f"legacy-new/a.py@{added[:12]}", 1),
    ]


@needs_git
def test_excluded_current_file_does_not_hide_history(tmp_path):
    # The secrets agent does not report an excluded file, so its value is not "current".
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {"old.py": _aws_line(), "fixtures/same.py": _aws_line()})
    _commit(repo, {"old.py": None})
    assert scan_directory(str(repo)) == []
    assert _rows(scan_directory(str(repo), exclude=("fixtures",))) == [("aws-access-key-id", f"old.py@{added[:12]}", 1)]


@needs_git
def test_binary_and_oversized_blobs_are_skipped(tmp_path):
    repo = _init(tmp_path / "repo")
    _commit(repo, {
        "blob.bin": b"\x00\x01" + _aws_line().encode(),
        "big.txt": _aws_line(FAKE_AWS_2) + "x" * (6 * 1024 * 1024),
    })
    _commit(repo, {"blob.bin": None, "big.txt": None})
    assert scan_directory(str(repo)) == []


@needs_git
def test_unusual_paths_and_non_utf8_content(tmp_path):
    repo = _init(tmp_path / "repo")
    name = 'sp ace "q"\té.txt'  # git quotes it and adds a TAB after it in "+++" lines
    added = _commit(repo, {name: _aws_line(), "two words.txt": _aws_line(FAKE_AWS_2),
                           "latin1.txt": b"caf\xe9\n" + _pw_line().encode()})
    _commit(repo, {name: None, "two words.txt": None, "latin1.txt": None})
    assert sorted(_rows(scan_directory(str(repo)))) == [
        ("aws-access-key-id", f"{name}@{added[:12]}", 1),
        ("aws-access-key-id", f"two words.txt@{added[:12]}", 1),
        ("generic-secret-assignment", f"latin1.txt@{added[:12]}", 2),
    ]


# ---------------------------------------------------------------- the repo cannot hide history or run programs


@needs_git
def test_repo_settings_cannot_hide_history(tmp_path):
    repo = _init(tmp_path / "repo")
    # Root commit, with a committed .gitattributes that marks everything binary.
    added = _commit(repo, {".gitattributes": "* -diff\n", "cfg.py": "a\n\n\n" + _aws_line()})
    _commit(repo, {"cfg.py": "a\n"})
    for key, value in (("log.showRoot", "false"), ("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"),
                       ("diff.interHunkContext", "9"), ("diff.context", "9"), ("diff.renames", "copies")):
        _git(repo, "config", key, value)
    assert _rows(scan_directory(str(repo))) == [("aws-access-key-id", f"cfg.py@{added[:12]}", 4)]


def _marker_program(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "MARKER-PROGRAM-RAN"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\necho ran >> '{marker}'\ncat \"$@\" 2>/dev/null\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script, marker


@needs_git
@pytest.mark.skipif(os.name != "posix", reason="uses a shell script as the marker program")
def test_repo_config_never_runs_a_program(tmp_path):
    script, marker = _marker_program(tmp_path)
    repo = _init(tmp_path / "repo")
    added = _commit(repo, {"cfg.txt": _aws_line()})
    _commit(repo, {"cfg.txt": "gone\n"})
    _git(repo, "config", "diff.external", str(script))
    _git(repo, "config", "diff.evil.textconv", str(script))
    _git(repo, "config", "core.pager", str(script))
    _git(repo, "config", "pager.log", str(script))
    # info/attributes is read even with --attr-source; only --no-textconv stops this driver.
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "attributes").write_text("* diff=evil\n")
    # A commit with a (fake) signature: with log.showSignature, git would run gpg.program on it.
    # It changes a file, so it is in the scanned history.
    _git(repo, "config", "log.showSignature", "true")
    _git(repo, "config", "gpg.program", str(script))
    (repo / "signed.txt").write_text("signed\n")
    _git(repo, "add", "signed.txt")
    signed = (
        f"tree {_git(repo, 'write-tree').strip()}\nparent {_git(repo, 'rev-parse', 'HEAD').strip()}\n"
        "author t <t@example.invalid> 1700000000 +0000\ncommitter t <t@example.invalid> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    sha = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"], input=signed,
                         check=True, capture_output=True, text=True, env=SAFE_ENV).stdout.strip()
    _git(repo, "update-ref", "refs/heads/main", sha)

    found = scan_directory(str(repo))
    assert not marker.exists(), "a program from the repo config was run"
    assert _rows(found) == [("aws-access-key-id", f"cfg.txt@{added[:12]}", 1)]  # the scan still worked


@needs_git
def test_git_environment_from_the_caller_is_ignored(tmp_path, monkeypatch):
    clean = _init(tmp_path / "clean")
    _commit(clean, {"a.txt": "a\n"})
    dirty = _init(tmp_path / "dirty")
    _commit(dirty, {"a.txt": _aws_line()})
    _commit(dirty, {"a.txt": "b\n"})
    monkeypatch.setenv("GIT_DIR", str(dirty / ".git"))  # would make git read the other repo
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "missing"))
    assert scan_directory(str(clean)) == []


# ---------------------------------------------------------------- history that cannot be read is never clean


@needs_git
def test_not_a_git_repository(tmp_path):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "a.txt").write_text("a\n")
    found = scan_directory(str(folder))
    assert [(f.rule_id, f.severity, f.file, f.message) for f in found] == [
        (UNSCANNED, "low", "", "git history not scanned: not a git repository"),
    ]


@needs_git
def test_repo_with_no_commits(tmp_path):
    repo = _init(tmp_path / "repo")
    (repo / "a.txt").write_text(_aws_line())  # not committed: the secrets agent's job
    assert [f.message for f in scan_directory(str(repo))] == ["git history not scanned: the repository has no commits"]


@needs_git
def test_shallow_clone_is_reported(tmp_path):
    origin = _init(tmp_path / "origin")
    _commit(origin, {"old.txt": _aws_line()})
    _commit(origin, {"old.txt": None})
    _commit(origin, {"new.txt": "n\n"})
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", "--depth", "1", f"file://{origin}", str(clone))
    found = scan_directory(str(clone))
    assert [(f.rule_id, f.message) for f in found] == [
        (UNSCANNED, "git history not scanned: shallow clone: history before the clone depth is missing"),
    ]


@needs_git
def test_partial_clone_is_not_scanned(tmp_path, monkeypatch):
    origin = _init(tmp_path / "origin")
    _commit(origin, {"old.txt": _aws_line()})
    _commit(origin, {"old.txt": None})
    _git(origin, "config", "uploadpack.allowFilter", "true")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", "--filter=blob:none", "--no-checkout", f"file://{origin}", str(clone))
    calls = []
    real = agent._run_tool
    monkeypatch.setattr(agent, "_run_tool", lambda cmd, *a, **kw: calls.append(cmd) or real(cmd, *a, **kw))
    assert [f.message for f in scan_directory(str(clone))] == [
        "git history not scanned: partial clone (missing objects would be fetched from the network)",
    ]
    assert not any("log" in cmd for cmd in calls)  # nothing was read that could trigger a fetch


@needs_git
def test_scan_does_not_modify_the_repo(tmp_path):
    repo = _init(tmp_path / "repo")
    _commit(repo, {"a.txt": _aws_line()})
    _commit(repo, {"a.txt": None})
    before = _snapshot(repo)
    scan_directory(str(repo))
    assert _snapshot(repo) == before


# ---------------------------------------------------------------- tool failures raise


class FakeGit:
    """Stands in for git: answers the repo checks, then a chosen result for one subcommand."""

    def __init__(self, fail_on="log", code=0, stderr="", raises=None):
        self.fail_on, self.code, self.stderr, self.raises = fail_on, code, stderr, raises
        self.calls = []

    def run(self, cmd, timeout, cwd=None, env=None, errors=None):
        sub = next(c for c in cmd[1:] if not c.startswith("-") and "=" not in c and c != "-c")
        self.calls.append({"sub": sub, "timeout": timeout, "env": env, "errors": errors})
        if sub == self.fail_on:
            if self.raises:
                raise self.raises
            return subprocess.CompletedProcess(cmd, self.code, "", self.stderr)
        answers = {"rev-parse": "true\n" if "--is-inside-work-tree" in cmd else "false\n",
                   "config": "", "rev-list": "a" * 40 + "\n"}
        return subprocess.CompletedProcess(cmd, 1 if sub == "config" else 0, answers.get(sub, ""), "")


def _fake(monkeypatch, **kwargs) -> FakeGit:
    fake = FakeGit(**kwargs)
    monkeypatch.setattr(agent, "_run_tool", fake.run)
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/fake/bin/git")
    return fake


def test_missing_git_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(agent.shutil, "which", lambda name: None)
    with pytest.raises(GitHistoryError, match="git is not installed"):
        scan_directory(str(tmp_path))
    assert main([str(tmp_path)]) == 2
    assert "git is not installed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"fail_on": "log", "code": 128, "stderr": "fatal: FAKE-GIT-OUTPUT"}, "git log failed with exit code 128"),
        ({"fail_on": "rev-list", "code": 129}, "git rev-list failed with exit code 129"),
        ({"fail_on": "rev-parse", "code": 128, "stderr": "fatal: detected dubious ownership"}, "rev-parse failed"),
        ({"fail_on": "log", "raises": subprocess.TimeoutExpired(["git"], 300)}, "timed out"),
    ],
)
def test_git_failures_raise_never_return_clean(tmp_path, monkeypatch, kwargs, message):
    _fake(monkeypatch, **kwargs)
    with pytest.raises(GitHistoryError, match=message) as info:
        scan_directory(str(tmp_path))
    assert "FAKE-GIT-OUTPUT" not in str(info.value)


def test_one_deadline_for_the_whole_scan(tmp_path, monkeypatch):
    fake = _fake(monkeypatch, fail_on="none")
    now = [0.0]

    def clock():
        now[0] += 70.0  # every check costs 70s
        return now[0]

    with pytest.raises(GitHistoryError, match="timed out"):
        scan_directory(str(tmp_path), clock=clock)
    assert [c["timeout"] for c in fake.calls] == [230.0, 160.0, 90.0, 20.0]
    assert all(c["errors"] == "replace" for c in fake.calls)


def test_git_runs_without_caller_git_settings(tmp_path, monkeypatch):
    fake = _fake(monkeypatch, fail_on="none")
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/bin/false")
    scan_directory(str(tmp_path))
    for call in fake.calls:
        env = call["env"]
        assert "GIT_DIR" not in env and "GIT_EXTERNAL_DIFF" not in env
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_uses_the_shared_process_runner():
    assert agent._run_tool is shared_proc.run_tool


def test_cli_not_a_directory(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


# ---------------------------------------------------------------- this repository


@needs_git
def test_fixtures_add_no_history_findings():
    # Everything ever committed under tests/fixtures is still there, so nothing is history-only.
    assert scan_directory(str(FIXTURES)) == []
