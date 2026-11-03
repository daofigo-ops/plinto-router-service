# Phase 4B Console Notes — Interactive Terminal Launcher

This build adds an interactive console menu on top of the Phase 4A safe audit and authorized pentest foundation.

## New command

```bash
python3 -m app.main menu
```

You can also use:

```bash
python3 -m app.main interactive
```

## Menu actions

1. Local LAN scan
2. Gateway-only scan
3. Custom target scan
4. Pentest dry-run
5. Pentest validation
6. Doctor
7. Show latest report paths
0. Exit

## Pentest safety behavior

Pentest actions still require explicit confirmation. The interactive menu asks the user to confirm ownership/authorization and type:

```text
I OWN THIS NETWORK
```

Without that phrase, pentest actions are cancelled.

Active credential validation is still restricted by all Phase 4A guardrails:

- private IP targets only
- no brute force
- no DNS changes
- no router setting changes
- user-supplied credentials only unless default-check is explicitly enabled in config
- passwords are never written to reports or logs
- every attempt is logged in JSONL

## Fixing credential scope skips

If the pentest audit log says:

```text
Credential entry is scoped to different target_ips/target_ports.
```

then the credentials file does not match the discovered service.

Example for a router at `192.168.31.1:8443`:

```yaml
credentials:
  - label: "Lab test router"
    username: "admin"
    password: "YOUR_REAL_PASSWORD"
    auth_type: "auto"
    target_ips:
      - "192.168.31.1"
    target_ports:
      - 8443
```

Then run:

```bash
python3 -m app.main menu
```

or directly:

```bash
python3 -m app.main scan 192.168.31.1 \
  --ports 8443 \
  --pentest --i-own-this-network \
  --credentials config/credentials.yaml \
  --apply-pentest
```

## Next suggested stage

After this console menu, the browser dashboard can be built as the next phase. The console menu is useful for terminal-first operation on VPS or local Linux machines, while the dashboard will provide a richer visual interface.
