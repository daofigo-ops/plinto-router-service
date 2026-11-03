# Plinto Local Dashboard

Local browser dashboard for Plinto Network Audit.

## Start backend API

From the project root:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app.api.server
```

The API binds to `127.0.0.1:8787` by default.

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

## Safety

The dashboard reads local reports and can trigger the same safe CLI scanner. Pentest options remain restricted and require explicit ownership confirmation.
