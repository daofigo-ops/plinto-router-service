# Phase 2 Notes — Fingerprinting + HTML Report + Local Subnet Detection

Phase 2 upgrades Phase 1.1 without changing the safety model.

## Added files

### `app/scanner/local_network.py`
Detects the current private LAN target. It can return either:

- the local `/24` range, for example `192.168.1.0/24`; or
- the default gateway IP when `--gateway` is used.

It still passes through the private-scope guard, so public IP scanning remains blocked.

### `app/scanner/path_probe.py`
Adds safe extra path probes on services that already responded. This helps classify common router and app paths without logging in or changing anything.

Checked paths include examples such as:

- `/login`
- `/admin`
- `/cgi-bin/luci`
- `/webpages/login.html`
- `/userRpm/LoginRpm.htm`
- `/Main_Login.asp`
- `/HNAP1/`
- `/docs`
- `/openapi.json`
- `/health`

### `app/reports/html_report.py`
Creates a readable HTML report with:

- executive summary metrics;
- host grouping;
- service classification;
- risk badges;
- evidence;
- risk reasons;
- recommendations;
- extra path signals.

### `app/reports/summary.py`
Builds scan-level metrics for console, JSON, and HTML reports.

## Updated files

### `app/main.py`
Added:

- `--local`
- `--gateway`
- `--local-prefix`
- `--format html`
- `--format all`
- `--no-deep-fingerprint`
- `--max-extra-paths`
- console scan summary
- HTML report writing

### `app/models.py`
Added:

- `PathProbeResult`
- `ScanSummary`
- `path_probes`
- `recommendations`

### `app/scanner/fingerprint.py`
Improved classification for:

- possible router/gateway services;
- TP-Link, D-Link, ASUS, OpenWrt and other router patterns;
- NGINX;
- Uvicorn/FastAPI;
- Apache;
- Node/Express;
- Grafana;
- Portainer;
- Home Assistant;
- Prometheus;
- server-error web services.

### `app/scanner/risk_score.py`
Now adds human-readable recommendations, not only a score.

### `data/fingerprints.yaml`
Expanded fingerprint rules.

## Safety boundary preserved

Phase 2 still does not perform:

- password guessing;
- credential stuffing;
- login attempts;
- router changes;
- DNS changes;
- exploitation;
- public-IP scans.

All actions are read-only HTTP/HTTPS probes against private LAN targets.

## Useful commands

```bash
python3 -m app.main scan --local
python3 -m app.main scan --local --gateway
python3 -m app.main scan 192.168.1.1
python3 -m app.main scan 192.168.1.0/24 --format html
python3 -m app.main scan 192.168.1.0/24 --no-deep-fingerprint
```
