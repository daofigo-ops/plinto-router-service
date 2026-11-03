# Phase 4A Notes — Authorized Pentest Mode + DNS Audit Foundation

Phase 4A adds a restricted, audit-first Pentest Mode while keeping the default tool behavior safe:

```text
scan -> audit -> report
```

It does **not** add router exploitation, brute force, public-IP scanning, DNS hijacking, or automatic configuration changes.

## New safety model

Pentest Mode requires explicit CLI confirmation:

```bash
python3 -m app.main scan --local --pentest --i-own-this-network
```

Even then, the default is dry-run. Real credential validation requires:

```bash
--apply-pentest
```

## New files

```text
app/pentest/credentials.py      Loads user-supplied credential YAML safely.
app/pentest/auth_check.py       Restricted HTTP Basic/Digest credential validation.
app/pentest/audit_log.py        JSONL audit log with no passwords.
app/safety/pentest_guard.py     Ownership/private-network/rate-limit guardrails.
app/dns/known_resolvers.py      Known public resolver labels.
app/dns/dns_audit.py            Audit-only visible DNS extraction and classification.
config/credentials.example.yaml Safe example credential file.
```

## DNS audit behavior

DNS audit is passive/audit-only. It searches visible page/path content for resolver values near DNS-related keywords, classifies them as known safe, internal, suspicious, or needing review, and adds recommendations. It never changes DNS settings.

## Pentest validation behavior

Pentest Mode supports only controlled validation:

- user-supplied known credentials,
- optional tiny factory-default audit if enabled in config,
- HTTP Basic/Digest only,
- form logins are detected but not attempted,
- private IP ranges only,
- rate-limited attempts,
- full JSONL attempt logging,
- passwords never stored in reports or audit logs.

## Default credential checking

This is disabled by default in `config/plinto.yaml`:

```yaml
pentest:
  allow_default_credential_check: false
```

To use it in an owned lab/network, set it to `true`, then run with `--check-defaults --apply-pentest`.

## Example commands

Dry-run pentest plan:

```bash
python3 -m app.main scan --local --gateway --pentest --i-own-this-network
```

Validate supplied known credentials:

```bash
python3 -m app.main scan --local --gateway \
  --pentest --i-own-this-network \
  --credentials config/credentials.yaml \
  --apply-pentest
```

Optional default credential audit on owned devices only:

```bash
python3 -m app.main scan 192.168.1.1 \
  --pentest --i-own-this-network \
  --check-defaults --apply-pentest
```

## Still not included

- No DNS modification.
- No router-specific attack scripts.
- No brute-force wordlists.
- No public target scanning.
- No form-login automation.
- No hidden actions.
