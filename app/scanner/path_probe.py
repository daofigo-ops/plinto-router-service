from __future__ import annotations

import asyncio
from collections.abc import Iterable

import httpx

from app.models import PathProbeResult, ServiceProbe
from app.scanner.http_probe import extract_title


COMMON_PATHS = [
    "/login",
    "/admin",
    "/status",
    "/setup",
    "/cgi-bin/luci",
    "/webpages/login.html",
    "/userRpm/LoginRpm.htm",
    "/Main_Login.asp",
    "/login.cgi",
    "/goform/login",
    "/index.asp",
    "/HNAP1/",
    "/api/docs",
    "/docs",
    "/openapi.json",
    "/health",
]

INTERESTING_STATUS = {200, 301, 302, 303, 307, 308, 401, 403, 500}


def should_probe_extra_paths(probe: ServiceProbe) -> bool:
    if probe.error:
        return False
    if probe.status_code is None:
        return False
    # Only enrich endpoints that visibly respond. We are not brute forcing paths.
    return probe.status_code in {200, 301, 302, 303, 307, 308, 401, 403, 404, 500}


async def _probe_path(
    client: httpx.AsyncClient,
    probe: ServiceProbe,
    path: str,
    semaphore: asyncio.Semaphore,
) -> PathProbeResult | None:
    base = probe.url.rstrip("/")
    url = f"{base}{path}"
    async with semaphore:
        try:
            response = await client.get(url)
            text = response.text if response.content else ""
            result = PathProbeResult(
                path=path,
                url=url,
                status_code=response.status_code,
                server=response.headers.get("server"),
                title=extract_title(text),
                content_type=response.headers.get("content-type"),
                auth_header=response.headers.get("www-authenticate"),
                redirect_location=response.headers.get("location"),
                body_sample=text[:1500] if text else None,
            )
            # Plain 404 pages often have generic titles such as "Error response".
            # Keep them out of fingerprinting so common paths like /admin do not
            # create false admin-panel detections.
            if response.status_code == 404 and not result.auth_header and not result.redirect_location:
                return None

            if response.status_code in INTERESTING_STATUS or result.title or result.auth_header or result.redirect_location:
                return result
            return None
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.ProtocolError):
            return None
        except httpx.HTTPError as exc:
            return PathProbeResult(path=path, url=url, error=str(exc)[:180])


async def enrich_with_path_probes(
    probes: Iterable[ServiceProbe],
    timeout: float,
    concurrency: int,
    max_extra_paths: int,
) -> list[ServiceProbe]:
    """Safely check common admin/service paths on already discovered web services."""
    probe_list = list(probes)
    if max_extra_paths <= 0:
        return probe_list

    candidates = [probe for probe in probe_list if should_probe_extra_paths(probe)]
    if not candidates:
        return probe_list

    paths = COMMON_PATHS[:max_extra_paths]
    semaphore = asyncio.Semaphore(concurrency)
    timeout_config = httpx.Timeout(timeout, connect=timeout)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)

    async with httpx.AsyncClient(
        timeout=timeout_config,
        limits=limits,
        verify=False,
        follow_redirects=False,
        headers={
            "User-Agent": "PlintoAudit/0.2 authorized-private-network-audit",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
    ) as client:
        tasks: list[tuple[ServiceProbe, asyncio.Task[PathProbeResult | None]]] = []
        for probe in candidates:
            for path in paths:
                tasks.append((probe, asyncio.create_task(_probe_path(client, probe, path, semaphore))))

        for probe, task in tasks:
            result = await task
            if result is not None:
                probe.path_probes.append(result)

    return probe_list
