from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from app.models import FingerprintResult, ServiceProbe


DEFAULT_RULES: list[dict[str, Any]] = [
    {"vendor": "TP-Link", "device_type": "Router", "patterns": ["tp-link", "tplink", "archer", "td-w", "tl-wr"]},
    {"vendor": "D-Link", "device_type": "Router", "patterns": ["d-link", "dlink", "dir-", "dsl-"]},
    {"vendor": "NETGEAR", "device_type": "Router", "patterns": ["netgear", "nighthawk", "routerlogin"]},
    {"vendor": "ASUS", "device_type": "Router", "patterns": ["asus", "asuswrt"]},
    {"vendor": "MikroTik", "device_type": "Router", "patterns": ["mikrotik", "routeros", "winbox"]},
    {"vendor": "OpenWrt", "device_type": "Router", "patterns": ["openwrt", "luci", "cgi-bin/luci"]},
    {"vendor": "Ubiquiti", "device_type": "Network Device", "patterns": ["ubiquiti", "unifi", "airmax"]},
    {"vendor": "Huawei", "device_type": "Router", "patterns": ["huawei", "hg8245", "echolife"]},
    {"vendor": "ZTE", "device_type": "Router", "patterns": ["zte", "zxhn", "f660", "f670"]},
    {"vendor": "FiberHome", "device_type": "Router", "patterns": ["fiberhome", "an5506", "hg6245"]},
    {"vendor": "Hikvision", "device_type": "CCTV/NVR", "patterns": ["hikvision", "web components", "ip camera", "nvr"]},
    {"vendor": "Dahua", "device_type": "CCTV/NVR", "patterns": ["dahua", "web service", "dvr", "nvr"]},
    {"vendor": "Synology", "device_type": "NAS", "patterns": ["synology", "diskstation", "dsm"]},
    {"vendor": "QNAP", "device_type": "NAS", "patterns": ["qnap", "turbo nas", "qts"]},
    {"vendor": "HP", "device_type": "Printer", "patterns": ["hp laserjet", "hewlett-packard", "embedded web server"]},
    {"vendor": "Generic Printer", "device_type": "Printer", "patterns": ["printer", "cups", "epson", "canon", "brother"]},
    {"vendor": "NGINX", "device_type": "Web Server", "patterns": ["nginx", "welcome to nginx"]},
    {"vendor": "Uvicorn/FastAPI", "device_type": "Python API Server", "patterns": ["uvicorn", "fastapi", "openapi.json", "swagger ui", "redoc"]},
    {"vendor": "Apache", "device_type": "Web Server", "patterns": ["apache", "apache2 ubuntu default page"]},
    {"vendor": "Node/Express", "device_type": "Node Web Service", "patterns": ["express", "x-powered-by: express"]},
    {"vendor": "Grafana", "device_type": "Dashboard Service", "patterns": ["grafana"]},
    {"vendor": "Portainer", "device_type": "Container Admin Panel", "patterns": ["portainer"]},
]


def load_rules(path: Path) -> list[dict[str, Any]]:
    """Load fingerprint rules from YAML, falling back to built-in defaults."""
    if not path.exists():
        return DEFAULT_RULES

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = data.get("rules")
        if isinstance(rules, list) and rules:
            return rules
    except yaml.YAMLError:
        pass

    return DEFAULT_RULES


def combined_probe_text(probe: ServiceProbe) -> str:
    pieces = [
        f"server: {probe.server or ''}",
        f"title: {probe.title or ''}",
        f"content-type: {probe.content_type or ''}",
        f"auth: {probe.auth_header or ''}",
        f"redirect: {probe.redirect_location or ''}",
        probe.body_sample or "",
    ]
    for path_probe in probe.path_probes:
        pieces.extend(
            [
                f"path: {path_probe.path}",
                f"path-title: {path_probe.title or ''}",
                f"path-server: {path_probe.server or ''}",
                f"path-auth: {path_probe.auth_header or ''}",
                f"path-redirect: {path_probe.redirect_location or ''}",
                path_probe.body_sample or "",
            ]
        )
    return "\n".join(pieces).lower()


def _gateway_like_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version != 4:
        return False
    last_octet = int(str(address).split(".")[-1])
    return last_octet in {1, 254}


def _auth_or_login_signal(probe: ServiceProbe, text: str) -> bool:
    if probe.auth_header:
        return True
    if "login" in text or "password" in text or "username" in text:
        return True
    return any(item.auth_header for item in probe.path_probes)


def fingerprint_probe(probe: ServiceProbe, rules: list[dict[str, Any]]) -> FingerprintResult:
    """Classify a probe using transparent non-invasive signals."""
    text = combined_probe_text(probe)
    evidence_boost: list[str] = []

    if probe.status_code and probe.status_code >= 500:
        evidence_boost.append(f"status:{probe.status_code}")

    path_hits = [item for item in probe.path_probes if item.status_code in {200, 301, 302, 401, 403}]
    if path_hits:
        evidence_boost.extend(f"path:{item.path}:{item.status_code}" for item in path_hits[:4])

    best: FingerprintResult | None = None

    for rule in rules:
        patterns = [str(item).lower() for item in rule.get("patterns", [])]
        matched = [pattern for pattern in patterns if pattern and pattern in text]
        if not matched:
            continue

        confidence = min(0.95, 0.45 + (0.15 * len(matched)) + (0.05 * min(len(path_hits), 2)))
        evidence = [f"matched:{item}" for item in matched[:5]] + evidence_boost[:4]
        candidate = FingerprintResult(
            vendor_guess=str(rule.get("vendor", "Unknown")),
            device_type=str(rule.get("device_type", "Unknown")),
            confidence=confidence,
            evidence=evidence,
        )

        if best is None or candidate.confidence > best.confidence:
            best = candidate

    if best:
        return best

    # Generic admin panel detection when vendor is unknown.
    generic_markers = ["login", "password", "admin", "router", "wireless", "configuration", "setup"]
    generic_hits = [marker for marker in generic_markers if marker in text]
    if len(generic_hits) >= 2:
        return FingerprintResult(
            vendor_guess="Unknown",
            device_type="Possible Admin Panel",
            confidence=0.4,
            evidence=[f"generic:{item}" for item in generic_hits[:5]] + evidence_boost[:4],
        )

    # Common home/office gateway heuristic: private .1/.254 over web management ports.
    if _gateway_like_ip(probe.ip) and probe.port in {80, 443, 8080, 8443}:
        confidence = 0.3
        evidence = ["heuristic:gateway-like-ip", f"service:{probe.scheme}:{probe.port}"]
        if _auth_or_login_signal(probe, text):
            confidence = 0.45
            evidence.append("signal:auth-or-login")
        return FingerprintResult(
            vendor_guess="Unknown",
            device_type="Possible Router/Gateway",
            confidence=confidence,
            evidence=evidence + evidence_boost[:4],
        )

    if probe.server:
        server = probe.server.lower()
        if "uvicorn" in server:
            return FingerprintResult(
                vendor_guess="Uvicorn/FastAPI",
                device_type="Python API Server",
                confidence=0.6,
                evidence=["server:uvicorn"] + evidence_boost[:4],
            )
        if "nginx" in server:
            return FingerprintResult(
                vendor_guess="NGINX",
                device_type="Web Server",
                confidence=0.55,
                evidence=["server:nginx"] + evidence_boost[:4],
            )

    if probe.status_code and probe.status_code >= 500:
        return FingerprintResult(
            vendor_guess="Unknown",
            device_type="Web Service With Errors",
            confidence=0.25,
            evidence=evidence_boost[:4],
        )

    return FingerprintResult(evidence=evidence_boost[:4])
