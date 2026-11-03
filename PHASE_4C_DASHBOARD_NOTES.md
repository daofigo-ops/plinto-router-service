# Phase 4C — Local Web Dashboard

This phase adds a local browser dashboard on top of the existing safe CLI scanner.

## New backend API

- `app/api/server.py` — FastAPI application for local dashboard data.
- Default bind: `127.0.0.1:8787`.
- Reads latest reports, inventory, scan history, and pentest audit logs.
- Can trigger the same CLI scanner through a controlled API endpoint.
- Pentest mode still requires explicit ownership confirmation.

## New frontend

- `app/dashboard/` — React + Vite dashboard.
- Pages:
  - Overview
  - Devices
  - Findings
  - Run Scan
  - History
  - Reports
  - Pentest Log

## Start API

```bash
cd plinto-audit
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app.api.server
```

## Start frontend

```bash
cd app/dashboard
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## Safety model

The dashboard does not bypass scanner guardrails:

- private-network rules remain enforced by the CLI scanner;
- pentest mode requires explicit authorization confirmation;
- passwords are never shown in dashboard views;
- pentest logs are redacted;
- no DNS modification or router configuration changes are implemented.
