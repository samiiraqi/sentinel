"""CI gate: with SENTINEL_REQUIRE_ALL_TESTS=1, any skip fails the run.

CI sets the variable so a missing tool (fastapi, checkov, ...) can never
silently skip tests. Tests marked @pytest.mark.live (opt-in, network) may
still skip. Local runs without the variable skip as before.
"""

import os

GATE_VAR = "SENTINEL_REQUIRE_ALL_TESTS"

_bad_skips = []


def _gate_on():
    return os.environ.get(GATE_VAR) == "1"


def _record(report):
    # Collect reports (module-level importorskip) have no keywords: never allowed.
    if _gate_on() and report.skipped and "live" not in getattr(report, "keywords", {}):
        _bad_skips.append(report.nodeid)


def pytest_collectreport(report):
    _record(report)


def pytest_runtest_logreport(report):
    _record(report)


def pytest_sessionfinish(session, exitstatus):
    if _bad_skips:
        session.exitstatus = 1


def pytest_terminal_summary(terminalreporter):
    if _bad_skips:
        terminalreporter.section(f"{GATE_VAR}=1: skipped tests are not allowed", red=True)
        for nodeid in _bad_skips:
            terminalreporter.line(f"NOT ALLOWED: skipped {nodeid}", red=True)
