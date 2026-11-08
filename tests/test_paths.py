import pytest

from shared.paths import is_excluded, is_gha_file, is_test_file, relative_to_root


@pytest.mark.parametrize(
    "rel_path, expected",
    [
        ("tests/helpers.py", True),
        ("pkg/tests/sub/helpers.py", True),
        ("./tests/helpers.py", True),
        ("test_app.py", True),
        ("pkg/test_app.py", True),
        ("app_test.py", True),
        ("pkg/app_test.py", True),
        ("app.py", False),
        ("src/tests.py", False),  # a file named tests.py, not a tests/ folder
        ("src/test/app.py", False),  # only "tests" counts as a folder name
        ("src/mytests/app.py", False),
        ("src/tests_old/app.py", False),
        ("latest_data.py", False),
        ("contest_app.py", False),
        ("test_notes.txt", False),
        ("", False),
    ],
)
def test_is_test_file(rel_path, expected):
    assert is_test_file(rel_path) is expected


@pytest.mark.parametrize(
    "value, rel_path, expected",
    [
        # A single name matches a whole component at any depth.
        (".venv", ".venv/lib/x.py", True),
        (".venv", "app/.venv/x.py", True),
        (".venv", ".venv", True),
        (".venv", "prod.venv-config", False),
        (".venv", ".venv-old/x.txt", False),
        (".venv", "my.venv", False),
        ("node_modules", "node_modules/dep/a.js", True),
        ("node_modules", "web/node_modules/dep/a.js", True),
        ("node_modules", "node_modules_backup/a.js", False),
        ("node_modules", "not_node_modules.txt", False),
        ("main.tf", "main.tf", True),
        ("main.tf", "infra/main.tf", True),
        ("main.tf", "xmain.tf", False),
        ("main.tf", "main.tf.bak", False),
        # A value with "/" is a path prefix from the scan root.
        ("tests/fixtures", "tests/fixtures/a.txt", True),
        ("tests/fixtures", "tests/fixtures", True),
        ("tests/fixtures", "tests/fixtures_old/a.txt", False),
        ("tests/fixtures", "other/tests/fixtures/a.txt", False),
        ("tests/fixtures", "tests/fixtures.py", False),
        ("web/node_modules", "web/node_modules/dep/a.js", True),
        ("web/node_modules", "app/web/node_modules/dep/a.js", False),
        ("web/node_modules", "web/node_modules2/a.js", False),
    ],
)
def test_component_matching(value, rel_path, expected):
    assert is_excluded(rel_path, (value,)) is expected


@pytest.mark.parametrize("value", ["./tests/fixtures/", "tests/fixtures/", "/tests/fixtures", "tests\\fixtures"])
def test_value_normalisation(value):
    assert is_excluded("tests/fixtures/a.txt", (value,))
    assert not is_excluded("tests/fixtures_old/a.txt", (value,))


def test_backslash_separators_in_path():
    assert is_excluded("tests\\fixtures\\a.txt", ("tests/fixtures",))
    assert is_excluded("app\\.venv\\x.py", (".venv",))
    assert not is_excluded("app\\prod.venv-config", (".venv",))


@pytest.mark.parametrize("value", ["", ".", "./", "/"])
def test_empty_values_match_nothing(value):
    assert not is_excluded("a/b.txt", (value,))


def test_no_values_and_multiple_values():
    assert not is_excluded("a/b.txt", ())
    assert is_excluded("b/c.txt", ("a", "b"))


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/scan/root/main.tf", "main.tf"),
        ("/scan/root/a/b/c.yaml", "a/b/c.yaml"),
        ("/scan/root/a/../b.tf", "b.tf"),
        ("sub/x.tf", "sub/x.tf"),  # relative paths are taken from root
        ("/scan/root", None),
        ("/scan/rootx/main.tf", None),
        ("/scan/root/../main.tf", None),
        ("/elsewhere/main.tf", None),
    ],
)
def test_relative_to_root(path, expected):
    assert relative_to_root(path, "/scan/root") == expected



@pytest.mark.parametrize(
    "rel_path, expected",
    [
        (".github/workflows/ci.yml", True),
        (".github/workflows/ci.yaml", True),
        ("./.github/workflows/ci.yml", True),
        ("app/.github/workflows/ci.yml", True),
        ("action.yml", True),
        ("actions/setup/action.yaml", True),
        (".github/workflows/deep/ci.yml", False),  # GitHub does not read subfolders
        (".github/workflows/notes.txt", False),
        (".github/dependabot.yml", False),
        ("workflows/ci.yml", False),
        ("github/workflows/ci.yml", False),
        ("my-action.yml", False),
        ("k8s/deployment.yaml", False),
        ("", False),
    ],
)
def test_is_gha_file(rel_path, expected):
    assert is_gha_file(rel_path) is expected
