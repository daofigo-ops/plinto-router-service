from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models import DeviceFinding


INVENTORY_VERSION = "0.3.0"


def service_key(finding: DeviceFinding) -> str:
    return f"{finding.ip}:{finding.port}/{finding.scheme}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_snapshot(finding: DeviceFinding) -> dict[str, Any]:
    return {
        "ip": finding.ip,
        "port": finding.port,
        "scheme": finding.scheme,
        "url": finding.url,
        "status_code": finding.status_code,
        "server": finding.server,
        "title": finding.title,
        "vendor_guess": finding.vendor_guess,
        "device_type": finding.device_type,
        "confidence": finding.confidence,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "recommendations": finding.recommendations,
        "scanned_at": finding.scanned_at,
    }


def _empty_inventory() -> dict[str, Any]:
    return {
        "tool": "Plinto Network Audit",
        "version": INVENTORY_VERSION,
        "created_at": _now(),
        "updated_at": _now(),
        "services": {},
    }


def load_inventory(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_inventory()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return _empty_inventory()
        data.setdefault("services", {})
        return data
    except (json.JSONDecodeError, OSError):
        return _empty_inventory()


def update_inventory(findings: list[DeviceFinding], path: Path, target: str) -> dict[str, Any]:
    """Update local inventory and return a compact change summary.

    The inventory is intentionally local-only JSON. It does not send data anywhere.
    """
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    inventory = load_inventory(path)
    services: dict[str, Any] = inventory.setdefault("services", {})
    seen_keys: set[str] = set()
    now = _now()

    changes: dict[str, Any] = {
        "inventory_path": str(path),
        "target": target,
        "new_services": [],
        "changed_services": [],
        "missing_known_services": [],
        "unchanged_services": 0,
        "total_known_services": 0,
    }

    for finding in findings:
        key = service_key(finding)
        seen_keys.add(key)
        snapshot = _finding_snapshot(finding)
        existing = services.get(key)

        if not existing:
            services[key] = {
                "first_seen": now,
                "last_seen": now,
                "seen_count": 1,
                "last": snapshot,
            }
            changes["new_services"].append({"key": key, "service": snapshot})
            continue

        tracked_fields = ["status_code", "server", "title", "vendor_guess", "device_type", "risk_score", "risk_level"]
        changed_fields: dict[str, dict[str, Any]] = {}
        previous = existing.get("last", {})
        for field in tracked_fields:
            old = previous.get(field)
            new = snapshot.get(field)
            if old != new:
                changed_fields[field] = {"old": old, "new": new}

        existing["last_seen"] = now
        existing["seen_count"] = int(existing.get("seen_count", 0)) + 1
        existing["last"] = snapshot

        if changed_fields:
            changes["changed_services"].append({"key": key, "changes": changed_fields, "service": snapshot})
        else:
            changes["unchanged_services"] += 1

    # Missing-known-services is advisory. A service can be missing because the user scanned a smaller target.
    for key, value in services.items():
        if key not in seen_keys:
            last = value.get("last", {}) if isinstance(value, dict) else {}
            changes["missing_known_services"].append({
                "key": key,
                "last_seen": value.get("last_seen") if isinstance(value, dict) else None,
                "ip": last.get("ip"),
                "port": last.get("port"),
                "scheme": last.get("scheme"),
                "device_type": last.get("device_type"),
                "risk_level": last.get("risk_level"),
            })

    inventory["updated_at"] = now
    inventory["last_target"] = target
    inventory["total_known_services"] = len(services)
    changes["total_known_services"] = len(services)

    path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False), encoding="utf-8")
    return changes
