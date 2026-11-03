# Plinto Network Audit

Plinto Network Audit is an authorized private-network scanner for routers, gateways, IoT devices, internal web services, and development servers.

The default product flow is intentionally safe:

```text
scan -> audit -> report
```

It does **not** perform password guessing, brute force, router exploitation, DNS changes, or public-IP scanning.

## Current build

```text
Phase 4A — Authorized Pentest Mode + DNS Audit Foundation
```

Included features:

- Private LAN scanning only by default.
- HTTP/HTTPS service detection.
- Router/admin/device fingerprinting.
- Path-based safe fingerprinting.
- Risk scoring and recommendations.
- CSV, JSON, and HTML reports.
- Timestamped scan history.
- Latest report copies.
- Local device inventory tracking.
- Visible DNS audit and resolver classification.
- Restricted authorized Pentest Mode.
- Redacted JSONL pentest audit log.
- Doctor command for setup checks.

## Install

```bash
cd plinto-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Check setup

```bash
python3 -m app.main doctor
```

## Normal safe scan

Scan the detected local subnet:

```bash
python3 -m app.main scan --local
```

Scan the detected gateway only:

```bash
python3 -m app.main scan --local --gateway
```

Scan a specific private host:

```bash
python3 -m app.main scan 192.168.1.1
```

Scan with selected ports:

```bash
python3 -m app.main scan 192.168.1.0/24 --ports 80,443,8000,8080
```

## Reports

By default, reports are written to a timestamped folder:

```text
reports/scans/YYYY-MM-DD_HH-MM-SS/
  report.json
  report.csv
  report.html
```

Latest copies are also written:

```text
reports/latest.json
reports/latest.csv
reports/latest.html
```

The local inventory file is:

```text
data/device_inventory.json
```

## DNS audit

DNS audit is passive and audit-only. It looks for visible DNS resolver values near DNS-related page text and classifies them as:

- Known Safe
- Internal
- Needs Review
- Suspicious

It never changes DNS settings.

Disable DNS audit:

```bash
python3 -m app.main scan --local --no-dns-audit
```

## Authorized Pentest Mode

Pentest Mode is disabled by default and requires explicit authorization flags.

Dry-run plan only:

```bash
python3 -m app.main scan --local --gateway --pentest --i-own-this-network
```

Validate known credentials you provide:

```bash
cp config/credentials.example.yaml config/credentials.yaml
nano config/credentials.yaml

python3 -m app.main scan --local --gateway \
  --pentest --i-own-this-network \
  --credentials config/credentials.yaml \
  --apply-pentest
```

Rules:

- Private IP ranges only.
- Requires `--pentest`.
- Requires `--i-own-this-network`.
- Real validation requires `--apply-pentest`.
- No brute force.
- No large wordlists.
- HTTP Basic/Digest only in Phase 4A.
- Form logins are detected but not attempted.
- Rate-limited and logged.
- Passwords are never written to reports or logs.

Pentest audit log:

```text
reports/pentest_audit.jsonl
```

## Optional default credential audit

Default credential checking is disabled in `config/plinto.yaml`:

```yaml
pentest:
  allow_default_credential_check: false
```

Only enable this for a device/network you own or are explicitly authorized to test.

Then run:

```bash
python3 -m app.main scan 192.168.1.1 \
  --pentest --i-own-this-network \
  --check-defaults --apply-pentest
```

The built-in list is intentionally tiny and capped. This is validation, not brute force.

## Config

Main config file:

```text
config/plinto.yaml
```

Key defaults:

```yaml
scan:
  private_only: true
  deep_fingerprint: true

dns:
  audit_visible_dns: true

pentest:
  enabled: false
  allow_default_credential_check: false
  dry_run: true
  rate_limit_seconds: 1.0
```

## What this tool intentionally does not do

- No unauthorized login.
- No password cracking.
- No router DNS modification.
- No public IP scanning.
- No device configuration changes.
- No router-specific attack automation.

## Suggested next stage

Phase 4B should be the local web dashboard:

```text
FastAPI backend
React/Vite dashboard
Latest scan overview
Inventory viewer
Scan history browser
Report download/open buttons
Manual scan trigger
```

## Interactive console menu

Phase 4B adds a terminal menu:

```bash
python3 -m app.main menu
```

Menu actions include local scan, gateway scan, custom target scan, pentest dry-run, restricted pentest validation, doctor checks, and latest report paths.

Pentest actions still require explicit ownership confirmation and the phrase `I OWN THIS NETWORK`. No DNS changes, no router configuration changes, and no brute force are performed.

If a pentest credential is skipped with `Credential entry is scoped to different target_ips/target_ports`, update `config/credentials.yaml` so the `target_ips` and `target_ports` match the discovered service, for example `192.168.31.1` and `8443`.

## Phase 4C — Local Web Dashboard

Start the local API from the project root:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python3 -m app.api.server
```

Start the dashboard frontend:

```bash
cd app/dashboard
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

Dashboard pages:

- Overview
- Devices
- Findings
- Run Scan
- History
- Reports
- Pentest Log

The dashboard is local-first. The API binds to `127.0.0.1:8787` by default. Pentest actions remain restricted and require explicit ownership/authorization confirmation.
