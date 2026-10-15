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


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_cors_allows_dashboard_origin(client, origin):
    resp = client.get("/health", headers={"Origin": origin})
    assert resp.headers["access-control-allow-origin"] == origin
    assert "access-control-allow-credentials" not in resp.headers


@pytest.mark.parametrize("origin", ["http://evil.example", "http://localhost:3000", "null"])
def test_cors_rejects_other_origins(client, origin):
    resp = client.get("/health", headers={"Origin": origin})
    assert "access-control-allow-origin" not in resp.headers
    preflight = client.options(
        "/decisions", headers={"Origin": origin, "Access-Control-Request-Method": "POST"}
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_cors_preflight_limits_methods_and_headers(client):
    headers = {"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"}
    resp = client.options("/decisions", headers={**headers, "Access-Control-Request-Headers": "content-type"})
    assert resp.status_code == 200
    assert set(resp.headers["access-control-allow-methods"].split(", ")) == {"GET", "POST"}
    assert client.options(
        "/decisions", headers={**headers, "Access-Control-Request-Method": "DELETE"}
    ).status_code == 400
    assert client.options(
        "/decisions", headers={**headers, "Access-Control-Request-Headers": "authorization"}
    ).status_code == 400


def test_cors_never_returns_wildcard(client):
    origins = ["http://localhost:5173", "http://127.0.0.1:5173", "http://evil.example"]
    for origin in origins:
        for resp in (
            client.get("/report", headers={"Origin": origin}),
            client.options("/report", headers={"Origin": origin, "Access-Control-Request-Method": "GET"}),
        ):
            assert resp.headers.get("access-control-allow-origin") != "*"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def counted(monkeypatch, log):
    """App with a fake clock; counts how often the orchestrator scans."""
    import backend.app as backend_app

    calls = []
    real_run_all = backend_app.run_all

    def counting_run_all(*args, **kwargs):
        calls.append(1)
        return real_run_all(*args, **kwargs)

    monkeypatch.setattr(backend_app, "run_all", counting_run_all)
    clock = FakeClock()
    client = TestClient(create_app(scan_path=str(FIXTURES), log_path=str(log), clock=clock))
    return client, clock, calls


def test_cache_is_used_for_decision_lookup(counted):
    client, clock, calls = counted
    fp = client.get("/report").json()["findings"][0]["fingerprint"]
    assert len(calls) == 1
    clock.now += 29
    assert client.post("/decisions", json={"fingerprint": fp, "decision": "defer"}).status_code == 200
    assert len(calls) == 1  # lookup came from the cache, no rescan


def test_cache_is_cleared_after_a_decision(counted):
    client, clock, calls = counted
    fp = client.get("/report").json()["findings"][0]["fingerprint"]
    client.post("/decisions", json={"fingerprint": fp, "decision": "defer"})
    client.post("/decisions", json={"fingerprint": fp, "decision": "approve"})
    assert len(calls) == 2  # second POST had to rescan


def test_cache_expires_after_30_seconds(counted):
    client, clock, calls = counted
    fp = client.get("/report").json()["findings"][0]["fingerprint"]
    clock.now += 30
    assert client.post("/decisions", json={"fingerprint": fp, "decision": "defer"}).status_code == 200
    assert len(calls) == 2


def test_get_report_always_rescans(counted):
    client, clock, calls = counted
    client.get("/report")
    client.get("/report")
    assert len(calls) == 2


def test_unknown_fingerprint_is_404_with_warm_cache(counted, log):
    client, clock, calls = counted
    client.get("/report")
    resp = client.post("/decisions", json={"fingerprint": "0" * 16, "decision": "approve"})
    assert resp.status_code == 404
    assert len(calls) == 1
    assert not log.exists()


# ---------------------------------------------------------------- dependencies agent

from agents.dependencies import agent as dependencies_agent  # noqa: E402
from orchestrator import orchestrator  # noqa: E402
from shared.models import Finding  # noqa: E402

DEP_FINDING = Finding(
    agent="dependencies",
    rule_id="CVE-2018-18074",
    severity="high",
    file="requirements.txt",
    line=1,
    message="requests 2.19.0: CVE-2018-18074; fixed in: 2.20.0",
    redacted_match="requests==2.19.0",
)


def _no_tools(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("no tool or network call expected")

    monkeypatch.setattr(dependencies_agent.subprocess, "run", fail)


def test_dependencies_findings_in_report_and_decidable(monkeypatch, log):
    monkeypatch.setitem(orchestrator.AGENTS, "dependencies", lambda path, exclude=(), offline=False: [DEP_FINDING])
    client = TestClient(create_app(scan_path=str(FIXTURES), log_path=str(log), offline=False))
    report = client.get("/report").json()
    assert report["agents"]["dependencies"] == {"status": "ok", "error": None, "count": 1}
    dep = [f for f in report["findings"] if f["agent"] == "dependencies"]
    assert [f["rule_id"] for f in dep] == ["CVE-2018-18074"]

    resp = client.post("/decisions", json={"fingerprint": dep[0]["fingerprint"], "decision": "reject"})
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "CVE-2018-18074"


def test_offline_env_marks_dependencies_failed(monkeypatch, log):
    _no_tools(monkeypatch)
    monkeypatch.setenv("SENTINEL_OFFLINE", "1")
    report = TestClient(create_app(scan_path=str(FIXTURES), log_path=str(log))).get("/report").json()
    assert report["agents"]["dependencies"]["status"] == "failed"
    assert "offline mode" in report["agents"]["dependencies"]["error"]
    assert report["agents"]["secrets"]["status"] == "ok"
    assert report["findings"]


def test_online_by_default(monkeypatch, log):
    monkeypatch.delenv("SENTINEL_OFFLINE", raising=False)
    seen = []
    monkeypatch.setitem(
        orchestrator.AGENTS, "dependencies", lambda path, exclude=(), offline=False: seen.append(offline) or []
    )
    TestClient(create_app(scan_path=str(FIXTURES), log_path=str(log))).get("/report")
    assert seen == [False]
