"""Path matching for the agents' --exclude option.

Matching is by whole path components, never by substring, so a value like
".venv" cannot accidentally hide "prod.venv-config".

- A value without "/" (e.g. ".venv") matches any path that has a component
  exactly equal to it, at any depth.
- A value with "/" (e.g. "tests/fixtures") matches that path from the scan
  root, and everything below it, on component boundaries.

Both "/" and "\\" are separators. A leading "./" and leading or trailing
"/" are ignored. Empty values (and ".") match nothing. No wildcards.

relative_to_root turns a path a tool reports (e.g. Checkov's absolute
parsing_errors paths) into a path relative to the scan root.

is_gha_file says which files the gha agent owns (GitHub Actions workflows
and action definitions). Other agents skip them, so the same file never
gets two sets of findings.

is_test_file says which files are test code, by path only: anything under
a "tests" folder, plus test_*.py and *_test.py. Matching is by whole path
components, so "src/tests.py" and "latest_data.py" are not test files.
"""

import os

YAML_SUFFIXES = (".yml", ".yaml")
ACTION_FILES = ("action.yml", "action.yaml")


def _parts(path: str) -> list[str]:
    return [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]


def is_excluded(rel_path: str, exclude: tuple[str, ...]) -> bool:
    """True if `rel_path` (relative to the scan root) matches any value in `exclude`."""
    parts = _parts(rel_path)
    for value in exclude:
        want = _parts(value)
        if not want:
            continue
        if len(want) == 1:
            if want[0] in parts:
                return True
        elif parts[: len(want)] == want:
            return True
    return False


def relative_to_root(path: str, root: str) -> str | None:
    """Path relative to root with "/" separators, or None if it is not inside root."""
    try:
        rel = os.path.relpath(os.path.join(root, path), root).replace(os.sep, "/")
    except ValueError:  # Windows: another drive
        return None
    if rel in (".", "..") or rel.startswith("../"):
        return None
    return rel


def is_gha_file(rel_path: str) -> bool:
    """True for a workflow (.github/workflows/*.yml|yaml, at any depth) or an action.yml|yaml file."""
    parts = _parts(rel_path)
    if not parts:
        return False
    if parts[-1] in ACTION_FILES:
        return True
    return parts[-1].endswith(YAML_SUFFIXES) and parts[-3:-1] == [".github", "workflows"]


def is_test_file(rel_path: str) -> bool:
    """True if `rel_path` (relative to the scan root) is under a tests/ folder or named test_*.py / *_test.py."""
    parts = _parts(rel_path)
    if not parts:
        return False
    name = parts[-1]
    return "tests" in parts[:-1] or (name.startswith("test_") and name.endswith(".py")) or name.endswith("_test.py")
