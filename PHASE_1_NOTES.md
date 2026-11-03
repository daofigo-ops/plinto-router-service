# Phase 1 Notes

## What was changed from the old archive

The legacy project mixed IP scanning, default-password attempts, PhantomJS/CasperJS browser automation, screenshots, and DNS-setting changes.

This Phase 1 rewrite keeps only the legitimate audit idea:

1. discover HTTP/HTTPS services on private LANs;
2. classify visible device/admin panels;
3. score risk from passive/non-invasive HTTP signals;
4. export reports.

## Safety decisions

- RFC1918 private IPv4 ranges only:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
- no public IP scanning;
- no credentials;
- no login attempts;
- no configuration changes;
- no DNS modifications;
- host-count safety cap enabled.

## File map

```text
app/main.py                    CLI entrypoint
app/config.py                  scan config and port parsing
app/models.py                  pydantic models for probes, fingerprints, risks, findings
app/safety/scope_guard.py      private-range guard and max-host validation
app/scanner/http_probe.py      async HTTP/HTTPS probing
app/scanner/fingerprint.py     transparent pattern-based device classification
app/scanner/risk_score.py      risk scoring logic
app/scanner/discovery.py       scan orchestration
app/reports/json_report.py     JSON writer
app/reports/csv_report.py      CSV writer
data/fingerprints.yaml         editable device/vendor fingerprint rules
reports/                       generated output folder
```


---

## Phase 1.1 fix

The CLI was changed from Typer/Click to Python's built-in `argparse` to avoid dependency compatibility errors on Python 3.12+ and to ensure this command works consistently:

```bash
python -m app.main scan 192.168.1.1
```

A convenience shorthand is also supported:

```bash
python -m app.main 192.168.1.1
```
