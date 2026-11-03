from __future__ import annotations

import re
from ipaddress import ip_address

from app.dns.known_resolvers import classify_resolver
from app.models import DNSAuditResult, DeviceFinding, DNSResolverFinding

IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
DNS_CONTEXT_RE = re.compile(r"(dns|nameserver|name server|resolver|primarydns|secondarydns|wan dns|dhcp dns)", re.I)


def _candidate_text(finding: DeviceFinding) -> str:
    parts: list[str] = []
    for value in [finding.title, finding.server, finding.auth_header, finding.redirect_location]:
        if value:
            parts.append(value)
    for probe in finding.path_probes:
        for value in [probe.path, probe.title, probe.redirect_location, probe.body_sample]:
            if value:
                parts.append(value)
    return "\n".join(parts)[:120_000]


def _extract_contextual_ips(text: str) -> list[str]:
    """Extract IPs that appear near DNS/resolver words.

    This avoids treating every IP address in a random webpage as a DNS resolver.
    """
    ips: list[str] = []
    for match in IPV4_RE.finditer(text):
        start = max(0, match.start() - 120)
        end = min(len(text), match.end() + 120)
        context = text[start:end]
        if DNS_CONTEXT_RE.search(context):
            ip = match.group(0)
            if ip not in ips:
                ips.append(ip)
    return ips


def audit_dns_visibility(finding: DeviceFinding) -> DNSAuditResult:
    """Audit visible DNS resolver values without changing router settings."""
    text = _candidate_text(finding)
    ips = _extract_contextual_ips(text)
    resolvers: list[DNSResolverFinding] = []
    for raw_ip in ips[:8]:
        try:
            ip_address(raw_ip)
        except ValueError:
            continue
        status, provider = classify_resolver(raw_ip)
        resolvers.append(DNSResolverFinding(ip=raw_ip, status=status, provider=provider))

    router_like = "router" in finding.device_type.lower() or "gateway" in finding.device_type.lower()
    if not resolvers:
        if router_like:
            return DNSAuditResult(
                checked=True,
                status="Not Visible",
                resolvers=[],
                recommendation="DNS settings were not visible through safe probes. Review DNS manually on the router admin page if this is your gateway.",
            )
        return DNSAuditResult(checked=False, status="Not Applicable", resolvers=[], recommendation="No visible DNS configuration signals found for this service.")

    statuses = {item.status for item in resolvers}
    if "Suspicious" in statuses:
        status = "Suspicious"
        recommendation = "One or more DNS resolver values use special-use or suspicious ranges. Confirm this was configured intentionally."
    elif "Needs Review" in statuses:
        status = "Needs Review"
        recommendation = "Unknown public DNS resolver detected. Verify whether this resolver is trusted and intentionally configured."
    elif statuses <= {"Known Safe", "Internal"}:
        status = "Looks Normal"
        recommendation = "Visible DNS values look like known public or internal resolvers. Confirm they match your intended configuration."
    else:
        status = "Needs Review"
        recommendation = "DNS resolver visibility produced mixed results. Review manually."

    return DNSAuditResult(checked=True, status=status, resolvers=resolvers, recommendation=recommendation)


def apply_dns_audit(findings: list[DeviceFinding]) -> list[DeviceFinding]:
    for finding in findings:
        finding.dns_audit = audit_dns_visibility(finding)
        if finding.dns_audit.checked and finding.dns_audit.status in {"Suspicious", "Needs Review"}:
            finding.risk_score = min(100, finding.risk_score + (20 if finding.dns_audit.status == "Suspicious" else 10))
            finding.risk_level = "Critical" if finding.risk_score >= 70 else "High" if finding.risk_score >= 45 else "Medium" if finding.risk_score >= 25 else "Low"
            if finding.dns_audit.recommendation not in finding.recommendations:
                finding.recommendations.append(finding.dns_audit.recommendation)
            reason = f"DNS audit status: {finding.dns_audit.status}"
            if reason not in finding.risk_reasons:
                finding.risk_reasons.append(reason)
    return findings
