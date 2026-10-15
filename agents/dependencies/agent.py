"""Dependencies agent: finds known-vulnerable Python and npm packages.

NETWORK: unlike the other agents, this agent CONTACTS ONLINE VULNERABILITY
DATABASES. pip-audit queries PyPI (pypi.org) and npm audit queries the npm
registry (registry.npmjs.org). Only package names and versions are sent;
no source code, file contents, or secrets. Use --offline to refuse to run.

READ-ONLY: nothing is installed, fixed, or changed in the scanned folder.
- pip-audit runs with --disable-pip --no-deps on a temporary copy of the
  PINNED lines only (name==version), so pip never installs or runs package
  code. Unpinned lines cannot be audited that way; each one is reported as
  an "unpinned-dependency" finding instead.
- "-r" includes are followed only to files inside the scanned folder
  (after symlinks). Anything that cannot be checked (a missing, outside or
  cyclic include, "-c", "-e", "--index-url", "--extra-index-url") becomes
  an "unaudited-dependency" finding: a partial scan never looks clean.
  URL credentials (user:token@) are redacted from every finding.
- npm audit runs with --package-lock-only (reads package-lock.json only;
  node_modules is never touched) and a fixed --registry, so a scanned
  repo's .npmrc cannot send the package list elsewhere. "fix" is never run.

Usage: python -m agents.dependencies.agent <folder> [--exclude TEXT ...] [--offline]
Exit code: 0 = no findings, 1 = findings, 2 = error (including --offline).
"""

import argparse
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from shared.models import Finding

AGENT_NAME = "dependencies"
TIMEOUT_SECONDS = 300
NPM_REGISTRY = "https://registry.npmjs.org/"
PIP_AUDIT_HINT = "pip-audit is not installed. Run: pip install -r requirements-dependencies.txt"
NPM_HINT = "npm is not installed (needed to audit package-lock.json)"
OFFLINE_MESSAGE = (
    "offline mode: the dependencies agent must contact online vulnerability "
    "databases (PyPI, npm registry), so it refuses to run"
)

# pip-audit gives no severity, so every Python vulnerability gets this one.
PYTHON_VULN_SEVERITY = "high"
UNPINNED_SEVERITY = "medium"
UNAUDITED_SEVERITY = "low"
NPM_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "low"}
NPM_DEFAULT_SEVERITY = "medium"

REQUIREMENTS_GLOB = "requirements*.txt"
NPM_LOCKFILE = "package-lock.json"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

# name[extras]==version[; marker]. "===" and wildcards (==1.*) do not match.
_PINNED = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?"
    r"\s*==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$"
)
_HASH_OPTION = re.compile(r"\s+--hash[=\s]\S+")
_COMMENT = re.compile(r"(^|\s)#.*$")
_GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
_URL_USERINFO = re.compile(r"://[^/@\s]+@")

# Requirement-file options we act on. Any other option line is ignored.
_OPTIONS = {
    "-r": "requirement", "--requirement": "requirement",
    "-c": "constraint", "--constraint": "constraint",
    "-e": "editable", "--editable": "editable",
    "-i": "index-url", "--index-url": "index-url",
    "--extra-index-url": "extra-index-url",
}
# Why an option line leaves something unaudited ("requirement" has its own reasons).
_OPTION_REASONS = {
    "constraint": "constraints file skipped: it limits versions but is not a dependency list",
    "editable": "editable requirement cannot be audited by name and version",
    "index-url": "custom package index: packages may not come from PyPI, so PyPI advisories may not match",
    "extra-index-url": "extra package index: packages may come from another source (dependency confusion risk)",
}


class DependenciesError(RuntimeError):
    """A tool is missing, failed, or returned output we cannot read."""


def normalize_name(name: str) -> str:
    """PEP 503 name: lowercase, runs of - _ . become one -."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- Python


def redact_url_credentials(text: str) -> str:
    """Hide user:password@ in URLs (index URLs and VCS links can hold tokens)."""
    return _URL_USERINFO.sub("://***@", text)


def _parse_option(line: str) -> tuple[str, str] | None:
    """(kind, value) for an option line we act on, else None. Handles -rX, -r X, --opt=X, --opt X."""
    if line.startswith("--"):
        match = re.match(r"^(--[A-Za-z-]+)(?:\s*=\s*|\s+|$)(.*)$", line)
        if not match:
            return None
        flag, value = match[1], match[2]
    else:
        flag, value = line[:2], line[2:].lstrip(" =")
    kind = _OPTIONS.get(flag)
    return (kind, value.strip()) if kind else None


def parse_requirements(
    text: str,
) -> tuple[list[tuple[int, str, str]], list[tuple[int, str]], list[tuple[int, str, str, str]]]:
    """Split a requirements file into pinned lines, unpinned lines and options.

    Returns (pinned, unpinned, options): pinned items are (line, name,
    version), unpinned items are (line, requirement text), options are
    (line, kind, value, line text) for -r, -c, -e, --index-url and
    --extra-index-url. Other option lines are ignored. Continuation lines
    (ending in \\) are joined. Texts have URL credentials redacted.
    """
    pinned, unpinned, options = [], [], []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        line = lines[i]
        while line.endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line[:-1] + " " + lines[i]
        i += 1
        line = _COMMENT.sub("", line).strip()
        if not line:
            continue
        if line.startswith("-"):
            option = _parse_option(line)
            if option:
                options.append((start, option[0], redact_url_credentials(option[1]), redact_url_credentials(line)))
            continue
        line = _HASH_OPTION.sub("", " " + line).strip()
        match = _PINNED.match(line)
        if match:
            pinned.append((start, match["name"], match["version"]))
        else:
            unpinned.append((start, redact_url_credentials(line)))
    return pinned, unpinned, options


def _cve_or_id(vuln: dict) -> str:
    cves = sorted(a for a in vuln.get("aliases") or [] if str(a).startswith("CVE-"))
    return cves[0] if cves else str(vuln.get("id", ""))


def parse_pip_audit_output(data: dict, file: str, lines: dict[tuple[str, str], int]) -> list[Finding]:
    """Turn pip-audit JSON into Findings.

    `lines` maps (normalized name, version) to the line in `file`.
    Packages pip-audit had to skip become "unaudited-dependency" findings.
    """
    findings, seen = [], set()
    for dep in data.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", ""))
        version = str(dep.get("version", ""))
        line = lines.get((normalize_name(name), version), 0)
        if line == 0:  # skipped deps have no version; match on name only
            line = next((ln for (n, _), ln in lines.items() if n == normalize_name(name)), 0)

        if dep.get("skip_reason"):
            findings.append(
                Finding(
                    agent=AGENT_NAME,
                    rule_id="unaudited-dependency",
                    severity=UNAUDITED_SEVERITY,
                    file=file,
                    line=line,
                    message=f"{name}: could not be audited ({dep['skip_reason']})",
                    redacted_match=name,
                )
            )
            continue

        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            rule_id = _cve_or_id(vuln)
            key = (normalize_name(name), version, rule_id)
            if key in seen:  # pip-audit can list the same advisory twice
                continue
            seen.add(key)
            ids = sorted(({str(vuln.get("id", ""))} | {str(a) for a in vuln.get("aliases") or []}) - {rule_id, ""})
            fixes = ", ".join(str(v) for v in vuln.get("fix_versions") or []) or "none"
            also = f" (also {', '.join(ids)})" if ids else ""
            findings.append(
                Finding(
                    agent=AGENT_NAME,
                    rule_id=rule_id,
                    severity=PYTHON_VULN_SEVERITY,
                    file=file,
                    line=line,
                    message=f"{name} {version}: {rule_id}{also}; fixed in: {fixes}",
                    redacted_match=f"{name}=={version}",
                )
            )
    return findings


def _unpinned_findings(file: str, unpinned: list[tuple[int, str]]) -> list[Finding]:
    return [
        Finding(
            agent=AGENT_NAME,
            rule_id="unpinned-dependency",
            severity=UNPINNED_SEVERITY,
            file=file,
            line=line,
            message="requirement is not pinned to an exact version (==), so it cannot be audited without installing it",
            redacted_match=text,
        )
        for line, text in unpinned
    ]


def _run_pip_audit(pinned: list[tuple[int, str, str]], rel_file: str) -> dict:
    """Run pip-audit on a temporary file holding only name==version lines."""
    unique = sorted({(normalize_name(n), v) for _, n, v in pinned})
    # pip-audit settings can come from PIP_AUDIT_* env vars (e.g. another
    # service URL); drop them so only the fixed command below applies.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_AUDIT_")}
    with tempfile.TemporaryDirectory(prefix="sentinel-deps-") as tmp:
        req = os.path.join(tmp, "requirements.txt")
        with open(req, "w", encoding="utf-8") as fh:
            fh.writelines(f"{n}=={v}\n" for n, v in unique)
        cmd = [
            sys.executable, "-m", "pip_audit",
            "-r", req,
            "--disable-pip",
            "--no-deps",
            "--vulnerability-service", "pypi",
            "--format", "json",
            "--progress-spinner", "off",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=env, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise DependenciesError(f"pip-audit timed out after {TIMEOUT_SECONDS}s on {rel_file}") from exc

    # Exit 0 = clean, 1 = vulnerabilities OR an error, so the JSON decides.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        data = None
    if proc.returncode not in (0, 1) or not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise DependenciesError(f"pip-audit failed on {rel_file} (exit code {proc.returncode})")
    return data


def _unaudited(file: str, line: int, text: str, reason: str) -> Finding:
    return Finding(
        agent=AGENT_NAME,
        rule_id="unaudited-dependency",
        severity=UNAUDITED_SEVERITY,
        file=file,
        line=line,
        message=f"not audited: {reason}",
        redacted_match=text,
    )


def _inside(root_real: str, real: str) -> bool:
    return os.path.commonpath([root_real, real]) == root_real


def _resolve_include(root_real: str, including: str, value: str, stack: tuple[str, ...]) -> tuple[str | None, str]:
    """(real path, "") for an include we can follow, else (None, reason)."""
    if not value:
        return None, "include has no file name"
    if "://" in value:
        return None, "remote include (URL) cannot be followed"
    # pip resolves -r relative to the file that contains it.
    target = os.path.realpath(os.path.join(os.path.dirname(including), value))
    if not _inside(root_real, target):
        return None, "include resolves outside the scanned folder"
    if target in stack:
        return None, "include cycle"
    if not os.path.isfile(target):
        return None, "include file not found"
    return target, ""


def scan_requirements(root_real: str, real: str, done: set[str], stack: tuple[str, ...] = ()) -> list[Finding]:
    """Audit one requirements file (a real path inside root_real) and its -r includes.

    `done` holds files already scanned, so none is scanned twice; `stack`
    holds the include chain, to detect cycles. Anything that cannot be
    checked becomes an "unaudited-dependency" finding, never silence.
    """
    done.add(real)
    rel_file = os.path.relpath(real, root_real).replace(os.sep, "/")
    with open(real, encoding="utf-8", errors="replace") as fh:
        pinned, unpinned, options = parse_requirements(fh.read())

    findings = _unpinned_findings(rel_file, unpinned)
    if pinned:
        lines = {}
        for line, name, version in pinned:
            lines.setdefault((normalize_name(name), version), line)
        findings += parse_pip_audit_output(_run_pip_audit(pinned, rel_file), rel_file, lines)

    for line, kind, value, text in options:
        if kind != "requirement":
            findings.append(_unaudited(rel_file, line, text, _OPTION_REASONS[kind]))
            continue
        target, reason = _resolve_include(root_real, real, value, stack + (real,))
        if target is None:
            findings.append(_unaudited(rel_file, line, text, reason))
        elif target not in done:  # already scanned: its findings are reported once
            findings += scan_requirements(root_real, target, done, stack + (real,))
    return findings


# ---------------------------------------------------------------- npm


def _lockfile_packages(lock_text: str) -> dict:
    """The "packages" map of a lockfile (empty if it cannot be read)."""
    try:
        packages = json.loads(lock_text).get("packages")
    except (json.JSONDecodeError, AttributeError):
        return {}
    return packages if isinstance(packages, dict) else {}


def _lockfile_info(packages: dict, lock_lines: list[str], node: str) -> tuple[str, int]:
    """Installed version and line of `node` (e.g. node_modules/lodash) in a lockfile."""
    entry = packages.get(node)
    version = str(entry.get("version", "")) if isinstance(entry, dict) else ""
    needle = json.dumps(node) + ":"
    line = next((i for i, text in enumerate(lock_lines, 1) if needle in text), 0)
    return version, line


def parse_npm_audit_output(data: dict, file: str, lock_text: str = "") -> list[Finding]:
    """Turn `npm audit --json` (report version 2) into Findings.

    One finding per advisory per package. "via" entries that are plain
    strings only point to another vulnerable package and are skipped; that
    package is reported on its own.
    """
    findings, seen = [], set()
    packages, lock_lines = _lockfile_packages(lock_text), lock_text.splitlines()
    vulns = data.get("vulnerabilities") or {}
    for pkg_name, pkg in sorted(vulns.items()):
        if not isinstance(pkg, dict):
            continue
        nodes = pkg.get("nodes") or []
        version, line = _lockfile_info(packages, lock_lines, str(nodes[0])) if nodes else ("", 0)
        match = f"{pkg_name}@{version}" if version else f"{pkg_name}@{pkg.get('range', '')}"
        fix = "yes" if pkg.get("fixAvailable") else "no"
        for via in pkg.get("via") or []:
            if not isinstance(via, dict):
                continue
            ghsa = _GHSA.search(str(via.get("url", "")))
            rule_id = ghsa.group(0) if ghsa else f"npm-advisory-{via.get('source', 'unknown')}"
            if (pkg_name, rule_id) in seen:
                continue
            seen.add((pkg_name, rule_id))
            findings.append(
                Finding(
                    agent=AGENT_NAME,
                    rule_id=rule_id,
                    severity=NPM_SEVERITY.get(str(via.get("severity", "")).lower(), NPM_DEFAULT_SEVERITY),
                    file=file,
                    line=line,
                    message=f"{match}: {via.get('title', '')}; fix available: {fix}",
                    redacted_match=match,
                )
            )
    return findings


def _pip_audit_installed() -> bool:
    return importlib.util.find_spec("pip_audit") is not None


def _npm_path() -> str | None:
    return shutil.which("npm")


def _run_npm_audit(folder: str, rel_file: str) -> dict:
    npm = _npm_path()
    if npm is None:
        raise DependenciesError(NPM_HINT)
    cmd = [
        npm, "audit",
        "--json",
        "--package-lock-only",
        "--registry", NPM_REGISTRY,
        "--prefix", folder,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, cwd=folder, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise DependenciesError(f"npm audit timed out after {TIMEOUT_SECONDS}s on {rel_file}") from exc

    # npm exits 1 when it finds vulnerabilities AND on errors, so the JSON decides.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DependenciesError(f"could not parse npm audit JSON for {rel_file} (exit code {proc.returncode})") from exc
    if not isinstance(data, dict):
        raise DependenciesError(f"unexpected npm audit output for {rel_file}")
    if "error" in data:
        err = data["error"] if isinstance(data["error"], dict) else {}
        raise DependenciesError(f"npm audit failed on {rel_file}: {err.get('code', 'unknown')} {err.get('summary', '')}".strip())
    if data.get("auditReportVersion") != 2 or not isinstance(data.get("vulnerabilities"), dict):
        raise DependenciesError(f"unsupported npm audit output for {rel_file} (need npm 7 or newer)")
    return data


def scan_lockfile(path: str, rel_file: str) -> list[Finding]:
    """Audit one package-lock.json."""
    data = _run_npm_audit(os.path.dirname(path), rel_file)
    with open(path, encoding="utf-8", errors="replace") as fh:
        lock_text = fh.read()
    return parse_npm_audit_output(data, rel_file, lock_text)


# ---------------------------------------------------------------- scan


def find_manifests(root: str, exclude: tuple[str, ...] = ()) -> tuple[list[str], list[str]]:
    """Relative paths of requirements*.txt and package-lock.json files under root."""
    requirements, lockfiles = [], []
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(folder, name), root).replace(os.sep, "/")
            if any(value in rel for value in exclude):
                continue
            if fnmatch.fnmatch(name, REQUIREMENTS_GLOB):
                requirements.append(rel)
            elif name == NPM_LOCKFILE:
                lockfiles.append(rel)
    return requirements, lockfiles


def scan_directory(path: str, exclude: tuple[str, ...] = (), offline: bool = False) -> list[Finding]:
    """Audit every requirements*.txt and package-lock.json under a folder.

    Files whose path contains any value in `exclude` are skipped. A tool is
    only needed if files for its ecosystem exist. If a needed tool is
    missing or fails, DependenciesError is raised: a scan that could not
    check never reports "no vulnerabilities".
    """
    if offline:
        raise DependenciesError(OFFLINE_MESSAGE)
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    exclude = tuple(v for v in exclude if v)
    requirements, lockfiles = find_manifests(root, exclude)

    if requirements and not _pip_audit_installed():
        raise DependenciesError(PIP_AUDIT_HINT)
    if lockfiles and _npm_path() is None:
        raise DependenciesError(NPM_HINT)

    findings = []
    root_real = os.path.realpath(root)
    done: set[str] = set()
    for rel in requirements:
        real = os.path.realpath(os.path.join(root, rel))
        if not _inside(root_real, real):
            findings.append(_unaudited(rel, 0, rel, "file is a link to outside the scanned folder"))
        elif real not in done:
            findings += scan_requirements(root_real, real, done)
    for rel in lockfiles:
        findings += scan_lockfile(os.path.join(root, rel), rel)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.dependencies.agent",
        description=(
            "Read-only audit of requirements*.txt (pip-audit) and package-lock.json "
            "(npm audit). Contacts online vulnerability databases; sends only "
            "package names and versions."
        ),
    )
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TEXT",
        help="skip files whose path contains TEXT (repeatable)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="refuse to run, because this agent needs network access",
    )
    args = parser.parse_args(argv)

    try:
        findings = scan_directory(args.folder, exclude=tuple(args.exclude), offline=args.offline)
    except NotADirectoryError as exc:
        print(f"error: not a directory: {exc}", file=sys.stderr)
        return 2
    except DependenciesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
