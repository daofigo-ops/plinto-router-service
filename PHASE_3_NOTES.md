# Phase 3 Notes — Beta Polish + Scan History + Config + Doctor

Phase 3 keeps the project safe and audit-only while making it easier to use repeatedly.

## What changed

### 1. Config-driven defaults

A new file was added:

```text
config/plinto.yaml
```

It controls default ports, timeout, concurrency, report behavior, local subnet prefix, fingerprint settings, and inventory tracking.

### 2. Scan history

Reports no longer need to overwrite each other. By default, every scan writes to:

```text
reports/scans/YYYY-MM-DD_HH-MM-SS/
  report.json
  report.csv
  report.html
```

The latest copies are also refreshed:

```text
reports/latest.json
reports/latest.csv
reports/latest.html
```

Disable history when needed:

```bash
python3 -m app.main scan 192.168.1.1 --no-history
```

### 3. Device inventory

The scanner now keeps a local inventory file:

```text
data/device_inventory.json
```

It can show:

- new services
- changed services
- unchanged services
- known services not seen in the current run

Disable inventory when needed:

```bash
python3 -m app.main scan --local --no-inventory
```

### 4. Better terminal output

The console now shows:

- findings table
- scan summary
- top recommended actions
- inventory delta
- report paths

### 5. Improved HTML report

The HTML report now has:

- executive summary cards
- risk mix strip
- top action queue
- inventory delta section
- grouped host cards
- richer recommendations and evidence
- print-friendly CSS

### 6. Doctor command

New command:

```bash
python3 -m app.main doctor
```

It checks:

- Python version
- required packages
- config loading
- report directory writability
- inventory directory writability
- fingerprint file
- local subnet detection
- gateway detection

## Still intentionally not included

Phase 3 still does **not** do any of the following:

- password guessing
- login attempts
- brute forcing
- DNS modification
- router configuration changes
- public IP scanning

This remains an authorized private-network audit tool.
