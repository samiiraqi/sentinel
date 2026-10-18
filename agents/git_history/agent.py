"""Git history agent: finds secrets that were committed once and are no longer
in the current files, so they are still in the git history.

SAME RULES as the secrets agent (agents.secrets.agent.iter_matches) on every
line added by every commit reachable from any ref (git log --all). A secret
whose value is still in the current files is skipped: the secrets agent
reports it. Each remaining (rule, path, value) is reported once, at the
oldest commit that added it.

READ-ONLY and OFFLINE: only `git rev-parse`, `git config --get-regexp`,
`git rev-list` and `git log` are run, with --no-optional-locks. History is
never changed, nothing is fetched, and a partial clone (which could fetch
missing objects from the network) is not scanned.

THE SCANNED REPO CANNOT CHANGE THE SCAN OR RUN PROGRAMS: system and global
git config are ignored and GIT_* settings are removed. Repo config that
could run a program (diff.external, textconv drivers, core.pager, gpg for
signatures) is turned off by flags. Repo settings that could hide history
are overridden: .gitattributes (e.g. "* -diff") by an empty attribute
source, log.showRoot, diff prefixes, inter-hunk context, renames and
replace refs.

RAW VALUES NEVER LEAVE THE AGENT. Each value is redacted (secrets.redact)
as soon as it is matched; only its sha256 is kept in memory, to compare
values, and never printed. Git's own output is never put in an error message.

FINDINGS: agent "git_history", the secrets rule id and severity, and
file "<path>@<12-char commit>" (the commit lives in the file field, so the
same path and line in two commits never share a fingerprint).

NEVER LOOKS CLEAN BY ACCIDENT: a missing git, a bad exit code or a timeout
raises GitHistoryError. A folder that is not in a git repository, a repo
with no commits, a shallow clone (scanned, but older history is missing)
and a partial clone each give a low "git-history-unscanned" finding.
Merge commits, reflogs and unreachable objects are not scanned; binary
files and files over 5 MB are skipped, as in the secrets agent.

TIME LIMIT: commits are read in batches; all git runs share one deadline
of TIMEOUT_SECONDS.

Usage: python -m agents.git_history.agent <folder> [--exclude TEXT ...]
Exit code: 0 = no findings, 1 = findings, 2 = error.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

from agents.secrets import agent as secrets_agent
from shared.models import Finding
from shared.paths import is_excluded
from shared.proc import run_tool as _run_tool

AGENT_NAME = "git_history"
UNSCANNED_RULE = "git-history-unscanned"
UNSCANNED_SEVERITY = "low"
TIMEOUT_SECONDS = 300  # cap for a whole scan
MIN_RUN_SECONDS = 1.0  # do not start a git run with less time than this left
BATCH_SIZE = 200  # commits per `git log` run
COMMIT_CHARS = 12
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's well-known empty tree
INSTALL_HINT = "git is not installed or not on PATH"

# Global options for every git run (before the subcommand).
GIT_GLOBAL = [
    "--no-pager",
    "--no-optional-locks",
    "--no-replace-objects",
    f"--attr-source={EMPTY_TREE}",  # .gitattributes in the repo cannot mark files binary
    "-c", "core.attributesFile=" + os.devnull,
    "-c", "core.bigFileThreshold=5m",  # larger blobs show as binary (like the secrets agent's 5 MB cap)
    "-c", "core.quotePath=true",
    "-c", "log.showRoot=true",
]
# Options for `git log -p`: fixed output format, no program from the repo config.
LOG_OPTIONS = [
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-show-signature",
    "--no-renames",
    "--diff-merges=off",  # merge commits are not scanned (documented)
    "--no-walk=unsorted",
    "--patch",
    "--unified=0",
    "--inter-hunk-context=0",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--relative",
    "--format=commit %H",
]

HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


class GitHistoryError(RuntimeError):
    """git is missing, failed, timed out, or returned output we cannot read."""


def _unscanned(reason: str) -> Finding:
    return Finding(
        agent=AGENT_NAME,
        rule_id=UNSCANNED_RULE,
        severity=UNSCANNED_SEVERITY,
        file="",
        line=0,
        message=f"git history not scanned: {reason}",
        redacted_match="",
    )


def _value_hash(rule_id: str, value: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{value}".encode("utf-8", "surrogatepass")).hexdigest()


def _env() -> dict:
    """git's environment: no GIT_* settings from the caller, no system or global
    config, no prompts, no lazy fetches, stable (C) messages."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    })
    return env


class _Git:
    """Runs read-only git commands in one folder, all within one deadline."""

    def __init__(self, git: str, root: str, clock):
        self.git, self.root, self.clock = git, root, clock
        self.deadline = clock() + TIMEOUT_SECONDS

    def run(self, args: list[str], ok_codes=(0,)) -> subprocess.CompletedProcess:
        remaining = self.deadline - self.clock()
        if remaining < MIN_RUN_SECONDS:
            raise GitHistoryError(f"git timed out after {TIMEOUT_SECONDS}s")
        cmd = [self.git, *GIT_GLOBAL, *args]
        try:
            proc = _run_tool(cmd, remaining, cwd=self.root, env=_env(), errors="replace")
        except subprocess.TimeoutExpired as exc:
            raise GitHistoryError(f"git timed out after {TIMEOUT_SECONDS}s") from exc
        if proc.returncode not in ok_codes:
            # git's output is never shown: it could hold file content.
            raise GitHistoryError(f"git {args[0]} failed with exit code {proc.returncode}")
        return proc


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of a path ("a\\tb", "\\303\\251")."""
    if not (len(path) >= 2 and path[0] == path[-1] == '"'):
        return path
    out, i, body = bytearray(), 0, path[1:-1]
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if re.fullmatch(r"[0-7]{3}", body[i + 1:i + 4]):
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
                continue
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
        out.extend(ch.encode("utf-8", "surrogatepass"))
        i += 1
    return out.decode("utf-8", "replace")


def parse_log(text: str):
    """Yield (commit, path, line, added text) for every added line in `git log -p -U0` output.

    Hunk sizes from the @@ headers decide which lines are content, so a
    content line that looks like a header ("+++ b/x", "commit ...") is never
    mistaken for one. Deleted files and binary files add no lines.
    """
    commit = path = None
    old_left = new_left = 0
    line_no = 0
    for raw in text.split("\n"):
        if old_left > 0 or new_left > 0:  # inside a hunk
            if raw.startswith("+"):
                if path is not None and commit is not None:
                    yield commit, path, line_no, raw[1:]
                line_no += 1
                new_left -= 1
            elif raw.startswith("-"):
                old_left -= 1
            elif raw.startswith(" "):  # context line (not expected with -U0)
                line_no += 1
                old_left -= 1
                new_left -= 1
            # "\ No newline at end of file" changes nothing
            continue
        if raw.startswith("commit "):
            sha = raw[len("commit "):]
            commit = sha if SHA.match(sha) else None
            path = None
        elif raw.startswith("+++ "):
            # git adds a TAB after a name with a space; a real TAB in a name is quoted as \t.
            name = raw[4:-1] if raw.endswith("\t") else raw[4:]
            target = _unquote(name)
            path = target[2:] if target.startswith("b/") else None  # "/dev/null": file deleted
        elif raw.startswith("diff --git "):
            path = None
        else:
            m = HUNK.match(raw)
            if m:
                old_left = int(m.group(1)) if m.group(1) is not None else 1
                line_no = int(m.group(2))
                new_left = int(m.group(3)) if m.group(3) is not None else 1


def _skipped(rel_path: str, exclude: tuple[str, ...]) -> bool:
    parts = rel_path.split("/")
    return any(p in secrets_agent.SKIP_DIRS for p in parts[:-1]) or is_excluded(rel_path, exclude)


def current_value_hashes(root: str, exclude: tuple[str, ...] = ()) -> set[str]:
    """Hashes of (rule, value) for every secret the secrets agent finds in the
    current files (same walk, same exclude). Values are never kept."""
    hashes = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in secrets_agent.SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, d))
            and not is_excluded(os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/"), exclude)
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if is_excluded(os.path.relpath(full, root).replace(os.sep, "/"), exclude):
                continue
            text = secrets_agent._read_text(full)
            if text is None:
                continue
            hashes.update(_value_hash(rule.rule_id, value) for rule, _, value in secrets_agent.iter_matches(text))
    return hashes


def _history_findings(text: str, exclude: tuple[str, ...], current: set[str], seen: set) -> list[Finding]:
    findings = []
    for commit, path, line_no, added in parse_log(text):
        if _skipped(path, exclude):
            continue
        for rule, _, value in secrets_agent.iter_matches(added):
            value_hash = _value_hash(rule.rule_id, value)
            key = (path, value_hash)
            if value_hash in current or key in seen:
                continue
            seen.add(key)
            short = commit[:COMMIT_CHARS]
            findings.append(
                Finding(
                    agent=AGENT_NAME,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    file=f"{path}@{short}",
                    line=line_no,
                    message=f"{rule.message} (in git history: added in commit {short}, not in current files)",
                    redacted_match=secrets_agent.redact(value),
                )
            )
    return findings


def _repo_state(git: _Git) -> str | None:
    """None if the history can be scanned, else the reason it cannot."""
    proc = git.run(["rev-parse", "--is-inside-work-tree"], ok_codes=(0, 128))
    if proc.returncode == 128:
        if "not a git repository" in (proc.stderr or ""):
            return "not a git repository"
        # e.g. "detected dubious ownership": git refused to read it
        raise GitHistoryError("git rev-parse failed with exit code 128")
    if proc.stdout.strip() != "true":
        return "not inside a git working tree"
    promisor = git.run(
        ["config", "--get-regexp", r"^(remote\..*\.promisor|extensions\.partialclone)$"], ok_codes=(0, 1)
    )
    if promisor.returncode == 0 and promisor.stdout.strip():
        return "partial clone (missing objects would be fetched from the network)"
    if not git.run(["rev-list", "--all", "--max-count=1"]).stdout.strip():
        return "the repository has no commits"
    return None


def scan_directory(path: str, exclude: tuple[str, ...] = (), clock=time.monotonic) -> list[Finding]:
    """Scan the git history of a folder for secrets that are no longer in its files.

    Paths whose relative path matches a value in `exclude` (by whole path
    components, see shared.paths.is_excluded) are skipped.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    git_path = shutil.which("git")
    if git_path is None:
        raise GitHistoryError(INSTALL_HINT)
    exclude = tuple(v for v in exclude if v)
    git = _Git(git_path, root, clock)

    reason = _repo_state(git)
    if reason is not None:
        return [_unscanned(reason)]
    findings = []
    if git.run(["rev-parse", "--is-shallow-repository"]).stdout.strip() == "true":
        findings.append(_unscanned("shallow clone: history before the clone depth is missing"))

    # Oldest first, so each secret is reported at the commit that first added it.
    commits = git.run(["rev-list", "--all", "--topo-order", "--reverse", "--", "."]).stdout.split()
    if not all(SHA.match(c) for c in commits):
        raise GitHistoryError("unexpected git rev-list output")
    current = current_value_hashes(root, exclude)
    seen = set()
    for start in range(0, len(commits), BATCH_SIZE):
        batch = commits[start:start + BATCH_SIZE]
        out = git.run(["log", *LOG_OPTIONS, *batch, "--", "."]).stdout
        findings.extend(_history_findings(out, exclude, current, seen))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.git_history.agent",
        description="Read-only scan of a folder's git history for secrets that are no longer in its files.",
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip files/folders named TEXT, or under path TEXT from FOLDER (repeatable)",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(args.folder, exclude=tuple(args.exclude))
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2
    except GitHistoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
