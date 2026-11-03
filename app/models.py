from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class PathProbeResult(BaseModel):
    """Non-invasive check of a common web/admin path on an already discovered service."""

    path: str
    url: str
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    content_type: str | None = None
    auth_header: str | None = None
    redirect_location: str | None = None
    body_sample: str | None = None
    error: str | None = None


class ServiceProbe(BaseModel):
    """Raw HTTP/HTTPS probe result for one IP:port endpoint."""

    ip: str
    port: int
    scheme: str
    url: str
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    content_type: str | None = None
    auth_header: str | None = None
    redirect_location: str | None = None
    body_sample: str | None = None
    error: str | None = None
    path_probes: list[PathProbeResult] = Field(default_factory=list)
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FingerprintResult(BaseModel):
    """Best-effort classification based on non-invasive HTTP signals."""

    vendor_guess: str = "Unknown"
    device_type: str = "Unknown"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class RiskResult(BaseModel):
    """Simple risk score and reasoning for prioritizing follow-up."""

    risk_score: int = 0
    risk_level: str = "Low"
    risk_reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class DNSResolverFinding(BaseModel):
    """One DNS resolver value seen during safe DNS audit."""

    ip: str
    status: str = "Needs Review"
    provider: str = "Unknown"


class DNSAuditResult(BaseModel):
    """Audit-only DNS visibility result. No DNS values are changed."""

    checked: bool = False
    status: str = "Not Checked"
    resolvers: list[DNSResolverFinding] = Field(default_factory=list)
    recommendation: str = "DNS audit was not requested or no DNS signals were visible."

    def flat_summary(self) -> str:
        if not self.checked:
            return self.status
        resolver_text = ", ".join(f"{item.ip} ({item.status}/{item.provider})" for item in self.resolvers)
        return f"{self.status}: {resolver_text}" if resolver_text else self.status


class PentestAttempt(BaseModel):
    """Redacted result of one authorized validation attempt."""

    target: str
    url: str
    auth_type: str = "auto"
    credential_label: str
    result: str = "skipped"  # skipped, failed, success, error
    status_code: int | None = None
    reason: str = ""
    attempted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DeviceFinding(BaseModel):
    """Final finding written to reports."""

    ip: str
    port: int
    scheme: str
    url: str
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    content_type: str | None = None
    auth_header: str | None = None
    redirect_location: str | None = None
    path_probes: list[PathProbeResult] = Field(default_factory=list)
    vendor_guess: str = "Unknown"
    device_type: str = "Unknown"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"
    risk_reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    dns_audit: DNSAuditResult = Field(default_factory=DNSAuditResult)
    pentest_attempts: list[PentestAttempt] = Field(default_factory=list)
    pentest_notes: list[str] = Field(default_factory=list)
    scanned_at: str

    def flat_dict(self) -> dict[str, Any]:
        """Return report-friendly primitives."""
        data = self.model_dump()
        data["path_probes"] = "; ".join(
            f"{item.path}:{item.status_code or '-'}:{item.title or item.redirect_location or ''}".strip(":")
            for item in self.path_probes
        )
        data["evidence"] = "; ".join(self.evidence)
        data["risk_reasons"] = "; ".join(self.risk_reasons)
        data["recommendations"] = "; ".join(self.recommendations)
        data["dns_audit"] = self.dns_audit.flat_summary()
        data["pentest_attempts"] = "; ".join(
            f"{item.result}:{item.auth_type}:{item.status_code or '-'}:{item.reason}" for item in self.pentest_attempts
        )
        data["pentest_notes"] = "; ".join(self.pentest_notes)
        return data


class ScanSummary(BaseModel):
    """High-level scan metrics for console and HTML/JSON reports."""

    target: str
    started_at: str
    finished_at: str
    unique_hosts: int = 0
    service_count: int = 0
    http_only_count: int = 0
    https_count: int = 0
    router_like_count: int = 0
    admin_like_count: int = 0
    server_error_count: int = 0
    dns_checked_count: int = 0
    dns_needs_review_count: int = 0
    pentest_attempt_count: int = 0
    pentest_success_count: int = 0
    highest_risk_level: str = "Low"
    highest_risk_score: int = 0
    risk_counts: dict[str, int] = Field(default_factory=dict)
    top_actions: list[str] = Field(default_factory=list)
