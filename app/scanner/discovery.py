from __future__ import annotations

from pathlib import Path

from app.config import ScanConfig
from app.models import DeviceFinding
from app.safety.scope_guard import iter_hosts_limited, validate_private_scope
from app.scanner.fingerprint import fingerprint_probe, load_rules
from app.scanner.http_probe import probe_hosts
from app.scanner.path_probe import enrich_with_path_probes
from app.scanner.risk_score import score_probe


async def scan_network(config: ScanConfig) -> list[DeviceFinding]:
    """Run a safe, non-invasive HTTP/HTTPS discovery scan."""
    network = validate_private_scope(config.target, private_only=config.private_only)
    hosts = list(iter_hosts_limited(network, max_hosts=config.max_hosts))

    rules = load_rules(Path(config.fingerprint_file))
    probes = await probe_hosts(
        hosts=hosts,
        ports=config.ports,
        timeout=config.timeout,
        concurrency=config.concurrency,
    )

    if config.deep_fingerprint:
        probes = await enrich_with_path_probes(
            probes=probes,
            timeout=config.timeout,
            concurrency=config.concurrency,
            max_extra_paths=config.max_extra_paths,
        )

    findings: list[DeviceFinding] = []
    for probe in probes:
        fp = fingerprint_probe(probe, rules)
        risk = score_probe(probe, fp)
        findings.append(
            DeviceFinding(
                ip=probe.ip,
                port=probe.port,
                scheme=probe.scheme,
                url=probe.url,
                status_code=probe.status_code,
                server=probe.server,
                title=probe.title,
                content_type=probe.content_type,
                auth_header=probe.auth_header,
                redirect_location=probe.redirect_location,
                path_probes=probe.path_probes,
                vendor_guess=fp.vendor_guess,
                device_type=fp.device_type,
                confidence=fp.confidence,
                evidence=fp.evidence,
                risk_score=risk.risk_score,
                risk_level=risk.risk_level,
                risk_reasons=risk.risk_reasons,
                recommendations=risk.recommendations,
                scanned_at=probe.scanned_at,
            )
        )

    return sorted(findings, key=lambda item: (item.ip, item.port, item.scheme))
