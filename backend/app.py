"""Sentinel backend API (FastAPI).

READ-ONLY on scanned files. The scan folder is fixed when the app is
created and is never taken from a request. The only thing the API writes
is the append-only audit log, via approval.decisions.record_decision.
The approver is the server's OS user, never a request field.

NETWORK: every scan runs the dependencies agent, which contacts online
vulnerability databases (package names and versions only). Set
SENTINEL_OFFLINE=1 to stop that; the agent then shows as failed.

TIME BUDGET: GET /report waits for the whole scan. The dependencies agent
is limited by SENTINEL_DEPS_TIME_BUDGET (default 300 seconds). For the
backend we recommend SENTINEL_DEPS_TIME_BUDGET=120, so a page load never
waits more than about two minutes for it; if it runs out, the agent shows
as failed with the files it did not audit.
"""

import getpass
import json
import os
import threading
import time
from typing import Callable, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from approval.decisions import fingerprint, record_decision
from orchestrator.orchestrator import run_all

DEFAULT_LOG_PATH = "audit/decisions.jsonl"
DEFAULT_SELF_EXCLUDE = ("tests/fixtures", ".venv")  # only when scanning "."
MAX_NOTE_CHARS = 500
REPORT_CACHE_SECONDS = 30
# Only the local dashboard dev server may call the API from a browser. Never "*".
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


class DecisionIn(BaseModel):
    """Body of POST /decisions. Any other field (e.g. approver, path) is ignored."""

    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    decision: Literal["approve", "reject", "defer"]
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)


def _read_log(log_path: str) -> list[dict]:
    records = []
    try:
        fh = open(log_path, encoding="utf-8")
    except FileNotFoundError:
        return records
    with fh:
        for line in fh:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    return records


def create_app(
    scan_path: str | None = None,
    log_path: str | None = None,
    exclude: tuple[str, ...] = (),
    clock: Callable[[], float] = time.monotonic,
    offline: bool | None = None,
) -> FastAPI:
    scan_path = scan_path or os.environ.get("SENTINEL_SCAN_PATH") or "."
    log_path = log_path or os.environ.get("SENTINEL_AUDIT_LOG") or DEFAULT_LOG_PATH
    if offline is None:
        offline = os.environ.get("SENTINEL_OFFLINE") == "1"
    if not exclude and os.path.abspath(scan_path) == os.path.abspath("."):
        exclude = DEFAULT_SELF_EXCLUDE
    exclude = tuple(exclude)
    approver = getpass.getuser()

    app = FastAPI(title="Sentinel", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )

    # In-memory cache of the latest report, so POST /decisions does not rescan
    # every time. GET /report always rescans and replaces it; a recorded
    # decision clears it.
    cache: dict = {"report": None, "at": 0.0}
    cache_lock = threading.Lock()

    def build_report() -> dict:
        report = run_all(scan_path, exclude=exclude, offline=offline)
        report["findings"] = [{**f, "fingerprint": fingerprint(f)} for f in report["findings"]]
        with cache_lock:
            cache["report"], cache["at"] = report, clock()
        return report

    def cached_report() -> dict:
        with cache_lock:
            report, at = cache["report"], cache["at"]
        if report is not None and clock() - at < REPORT_CACHE_SECONDS:
            return report
        return build_report()

    def clear_cache() -> None:
        with cache_lock:
            cache["report"], cache["at"] = None, 0.0

    # Plain "def" endpoints: the scan is blocking work, so FastAPI runs them in a thread pool.
    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/report")
    def report() -> dict:
        return build_report()

    @app.get("/decisions")
    def list_decisions() -> list[dict]:
        return _read_log(log_path)

    @app.post("/decisions")
    def create_decision(body: DecisionIn) -> dict:
        matches = [f for f in cached_report()["findings"] if f["fingerprint"] == body.fingerprint]
        if not matches:
            raise HTTPException(status_code=404, detail="unknown fingerprint")
        record = record_decision(log_path, matches[0], body.decision, approver, body.note)
        clear_cache()
        return record

    return app
