from __future__ import annotations

from app.models import FingerprintResult, RiskResult, ServiceProbe


SENSITIVE_DEVICE_TYPES = {
    "Router",
    "Possible Router/Gateway",
    "CCTV/NVR",
    "NAS",
    "Network Device",
    "Possible Admin Panel",
    "Container Admin Panel",
    "Dashboard Service",
}

DEV_SERVICE_TYPES = {"Python API Server", "Node Web Service", "Web Service With Errors"}


def risk_level(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _add_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def score_probe(probe: ServiceProbe, fingerprint: FingerprintResult) -> RiskResult:
    """Score exposure risk from non-invasive signals."""
    score = 0
    reasons: list[str] = []
    recommendations: list[str] = []

    if probe.scheme == "http":
        score += 20
        reasons.append("Service endpoint is reachable over unencrypted HTTP")
        _add_unique(recommendations, "Prefer HTTPS for admin/service panels or restrict HTTP to trusted LAN hosts only.")

    if probe.status_code in {200, 301, 302, 303, 307, 308, 401, 403}:
        score += 10
        reasons.append(f"HTTP service responded with status {probe.status_code}")

    if probe.status_code and probe.status_code >= 500:
        score += 15
        reasons.append(f"Service returned server error status {probe.status_code}")
        _add_unique(recommendations, "Check the application logs for this service and fix the server-side error.")

    if probe.auth_header or any(item.auth_header for item in probe.path_probes):
        score += 15
        reasons.append("Authentication challenge is exposed")
        _add_unique(recommendations, "Verify that exposed admin login uses strong credentials and is not reachable from untrusted networks.")

    if fingerprint.device_type in SENSITIVE_DEVICE_TYPES:
        score += 20
        reasons.append(f"Looks like a sensitive device type: {fingerprint.device_type}")
        _add_unique(recommendations, "Restrict sensitive device admin pages to trusted devices/VLANs and disable WAN-side administration.")

    if fingerprint.device_type == "CCTV/NVR":
        score += 10
        reasons.append("Camera/NVR interfaces are high-value targets and should be isolated")
        _add_unique(recommendations, "Place CCTV/NVR devices on a separate VLAN and block unnecessary web admin access.")

    if fingerprint.device_type in DEV_SERVICE_TYPES:
        score += 10
        reasons.append(f"Development-style or error-prone service detected: {fingerprint.device_type}")
        _add_unique(recommendations, "Put development services behind a reverse proxy or firewall and avoid exposing debug/dev servers broadly.")

    if probe.port not in {80, 443}:
        score += 5
        reasons.append(f"Management-like service found on non-standard port {probe.port}")

    title_or_body = f"{probe.title or ''}\n{probe.body_sample or ''}".lower()
    if "welcome to nginx" in title_or_body:
        score += 5
        reasons.append("Default nginx welcome page appears to be exposed")
        _add_unique(recommendations, "Replace or disable default web server landing pages so services are not unnecessarily advertised.")

    weak_markers = ["admin", "login", "router", "wireless", "configuration", "setup"]
    path_text = "\n".join(
        f"{item.path} {item.title or ''} {item.redirect_location or ''}" for item in probe.path_probes
    ).lower()
    if any(marker in (probe.title or "").lower() for marker in weak_markers) or any(marker in path_text for marker in weak_markers):
        score += 10
        reasons.append("Page/path signals suggest an administrative interface")
        _add_unique(recommendations, "Confirm that this admin interface is expected, patched, and limited to trusted users.")

    if fingerprint.device_type in {"Router", "Possible Router/Gateway"}:
        _add_unique(recommendations, "Verify router firmware is current, remote administration is disabled, and DNS settings are known/trusted.")

    score = min(100, score)
    if not recommendations:
        recommendations.append("No immediate action from passive scan signals; review manually if this service should not be visible.")

    return RiskResult(risk_score=score, risk_level=risk_level(score), risk_reasons=reasons, recommendations=recommendations)
