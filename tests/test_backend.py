import getpass
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

# The backend needs requirements-backend.txt; skip cleanly when it is missing (e.g. CI).
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import backend.__main__ as backend_main  # noqa: E402
from backend.app import create_app  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"

needs_checkov = pytest.mark.skipif(
    importlib.util.find_spec("checkov") is None,
    reason="checkov not installed (pip install -r requirements-terraform.txt)",
)

# FAKE values from the fixtures, split so this file does not trip the
# secrets scan in CI. None may appear in any response.
FAKE_SECRETS = [
    "AKIA" + "IOSFODNN7EXAMPLE",
    "FAKEKEYDATAFORTESTSONLY" + "NOTAREALKEY000000",
    "FakePassw0rd" + "ForTests",
    "sk-" + "ant-FAKE-KEY-FOR-TESTS-ONLY-000000",
]


def _snapshot(root: Path) -> dict:
    """Hash + mtime of every file, to prove nothing changes."""
    snap = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            snap[str(p)] = (hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns)
    return snap


@pytest.fixture
def log(tmp_path):
    return tmp_path / "audit" / "decisions.jsonl"


@pytest.fixture
def client(log):
    return TestClient(create_app(scan_path=str(FIXTURES), log_path=str(log)))


@pytest.fixture
def first_fp(client):
    return client.get("/report").json()["findings"][0]["fingerprint"]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_report_has_findings_with_fingerprints(client):
    report = client.get("/report").json()
    assert report["scanned_path"] == str(FIXTURES.resolve())
    assert report["findings"]
    for f in report["findings"]:
        assert len(f["fingerprint"]) == 16
    assert "secrets" in {f["agent"] for f in report["findings"]}


@needs_checkov
def test_report_includes_terraform(client):
    report = client.get("/report").json()
    assert report["agents"]["terraform"]["status"] == "ok"
    assert "CKV_AWS_24" in {f["rule_id"] for f in report["findings"]}


def test_post_decision_writes_one_line(client, log, first_fp):
    assert client.get("/decisions").json() == []
    resp = client.post("/decisions", json={"fingerprint": first_fp, "decision": "approve", "note": "ok"})
    assert resp.status_code == 200
    record = resp.json()
    assert record["fingerprint"] == first_fp
    assert record["decision"] == "approve"
    assert len(log.read_text().splitlines()) == 1
    assert client.get("/decisions").json() == [record]


def test_unknown_fingerprint_is_404(client, log):
    resp = client.post("/decisions", json={"fingerprint": "0" * 16, "decision": "approve"})
    assert resp.status_code == 404
    assert not log.exists()


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "delete"},
        {"decision": "APPROVE"},
        {"decision": "approve", "note": "x" * 501},
        {"decision": "approve", "fingerprint": "../../etc/passwd"},
        {},
    ],
)
def test_invalid_body_is_422(client, log, first_fp, body):
    resp = client.post("/decisions", json={"fingerprint": first_fp, **body})
    assert resp.status_code == 422
    assert not log.exists()


def test_note_of_500_chars_is_accepted(client, first_fp):
    resp = client.post("/decisions", json={"fingerprint": first_fp, "decision": "defer", "note": "x" * 500})
    assert resp.status_code == 200


def test_approver_and_path_in_request_are_ignored(client, log, first_fp, tmp_path):
    other_log = tmp_path / "other.jsonl"
    resp = client.post(
        "/decisions",
        json={
            "fingerprint": first_fp,
            "decision": "reject",
            "approver": "someone-else",
            "path": "/",
            "log_path": str(other_log),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["approver"] == getpass.getuser()
    [line] = log.read_text().splitlines()
    assert json.loads(line)["approver"] == getpass.getuser()
    assert not other_log.exists()
    assert client.get("/report").json()["scanned_path"] == str(FIXTURES.resolve())


def test_app_does_not_modify_scanned_files(client, first_fp):
    before = _snapshot(FIXTURES)
    client.get("/report")
    client.post("/decisions", json={"fingerprint": first_fp, "decision": "approve"})
    client.get("/decisions")
    assert _snapshot(FIXTURES) == before


def test_full_fake_secret_never_in_responses(client, first_fp):
    bodies = [client.get("/report").text]
    bodies.append(client.post("/decisions", json={"fingerprint": first_fp, "decision": "defer"}).text)
    bodies.append(client.get("/decisions").text)
    for body in bodies:
        for value in FAKE_SECRETS:
            assert value not in body


def test_server_binds_to_localhost_only(monkeypatch, tmp_path):
    assert backend_main.HOST == "127.0.0.1"
    calls = []
    monkeypatch.setattr(backend_main.uvicorn, "run", lambda app, **kw: calls.append(kw))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "d.jsonl"))
    backend_main.main()  # uvicorn.run is replaced; no real server starts
    assert calls == [{"host": "127.0.0.1", "port": 8000}]
    assert "0.0.0.0" not in Path(backend_main.__file__).read_text()
