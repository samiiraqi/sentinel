"""Run the API locally: python -m backend

Binds to 127.0.0.1 only, so the API is never exposed on the network.
Scan folder: SENTINEL_SCAN_PATH (default "."). Audit log: SENTINEL_AUDIT_LOG
(default audit/decisions.jsonl). SENTINEL_OFFLINE=1: the dependencies agent
does not contact online vulnerability databases (it shows as failed).
"""

import uvicorn

from backend.app import create_app

HOST = "127.0.0.1"
PORT = 8000


def main() -> None:
    uvicorn.run(create_app(), host=HOST, port=PORT)


if __name__ == "__main__":
    main()
