"""Path matching for the agents' --exclude option.

Matching is by whole path components, never by substring, so a value like
".venv" cannot accidentally hide "prod.venv-config".

- A value without "/" (e.g. ".venv") matches any path that has a component
  exactly equal to it, at any depth.
- A value with "/" (e.g. "tests/fixtures") matches that path from the scan
  root, and everything below it, on component boundaries.

Both "/" and "\\" are separators. A leading "./" and leading or trailing
"/" are ignored. Empty values (and ".") match nothing. No wildcards.
"""


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
