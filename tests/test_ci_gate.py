"""Tests for the SENTINEL_REQUIRE_ALL_TESTS gate in tests/conftest.py.

Each case runs a tiny pytest project in a subprocess that uses a copy of
our real conftest.py, so the gate under test is the one CI uses.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

CONFTEST = Path(__file__).parent / "conftest.py"

INI = """[pytest]
addopts = --strict-markers
markers =
    live: opt-in network test
"""

TOOL_SKIP = """
import pytest

@pytest.mark.skipif(True, reason="tool not installed")
def test_needs_tool():
    pass

def test_ok():
    pass
"""

MODULE_SKIP = """
import pytest
pytest.importorskip("sentinel_tool_that_does_not_exist")

def test_hidden():
    pass
"""

LIVE_SKIP = """
import pytest

@pytest.mark.live
@pytest.mark.skipif(True, reason="live test: opt-in")
def test_live():
    pass

def test_ok():
    pass
"""


def _run(tmp_path, test_source, gate):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "pytest.ini").write_text(INI)
    (tmp_path / "test_sample.py").write_text(test_source)
    env = {k: v for k, v in os.environ.items() if k != "SENTINEL_REQUIRE_ALL_TESTS"}
    if gate:
        env["SENTINEL_REQUIRE_ALL_TESTS"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )


def test_gate_on_tool_skip_fails_and_names_test(tmp_path):
    result = _run(tmp_path, TOOL_SKIP, gate=True)
    assert result.returncode == 1, result.stdout
    assert "NOT ALLOWED: skipped test_sample.py::test_needs_tool" in result.stdout


def test_gate_on_module_importorskip_fails(tmp_path):
    result = _run(tmp_path, MODULE_SKIP, gate=True)
    assert result.returncode == 1, result.stdout
    assert "NOT ALLOWED: skipped test_sample.py" in result.stdout


def test_gate_on_live_skip_is_allowed(tmp_path):
    result = _run(tmp_path, LIVE_SKIP, gate=True)
    assert result.returncode == 0, result.stdout
    assert "1 passed, 1 skipped" in result.stdout


def test_gate_off_tool_skip_still_skips(tmp_path):
    result = _run(tmp_path, TOOL_SKIP, gate=False)
    assert result.returncode == 0, result.stdout
    assert "1 passed, 1 skipped" in result.stdout
    assert "NOT ALLOWED" not in result.stdout
