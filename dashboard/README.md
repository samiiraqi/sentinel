# Sentinel Dashboard

React + TypeScript (Vite) page that shows the latest Sentinel report: totals by severity, each agent's status, and every finding, with a "Scan incomplete" banner if any agent failed.
From the findings table you can approve, reject, or defer a finding with an optional note; the backend writes each decision to the audit log.
It talks only to the local backend at `http://127.0.0.1:8000` (start it with `python -m backend` from the repo root).
Run it with `npm install` and `npm run dev`, then open `http://127.0.0.1:5173`.
