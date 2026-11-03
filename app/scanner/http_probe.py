from __future__ import annotations

import asyncio
import re
from html import unescape
from typing import Iterable

import httpx

from app.models import ServiceProbe

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def schemes_for_port(port: int) -> list[str]:
    """Pick likely schemes for a port.

    We try only likely combinations to keep the scan lightweight and non-invasive.
    """
    if port in {443, 8443, 9443}:
        return ["https"]
    return ["http"]


def extract_title(html: str | None) -> str | None:
    if not html:
        return None
    match = TITLE_RE.search(html[:100_000])
    if not match:
        return None
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:160] if title else None


def response_text_sample(response: httpx.Response, limit: int = 5000) -> str | None:
    content_type = response.headers.get("content-type", "").lower()
    if response.content and (
        "text/" in content_type
        or "json" in content_type
        or "xml" in content_type
        or "html" in content_type
        or not content_type
    ):
        try:
            return response.text[:limit]
        except UnicodeDecodeError:
            return None
    return None


async def probe_url(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    scheme: str,
    semaphore: asyncio.Semaphore,
) -> ServiceProbe | None:
    url = f"{scheme}://{ip}:{port}/"
    async with semaphore:
        try:
            response = await client.get(url)
            text = response_text_sample(response)

            return ServiceProbe(
                ip=ip,
                port=port,
                scheme=scheme,
                url=url,
                status_code=response.status_code,
                server=response.headers.get("server"),
                title=extract_title(text),
                content_type=response.headers.get("content-type"),
                auth_header=response.headers.get("www-authenticate"),
                redirect_location=response.headers.get("location"),
                body_sample=text,
            )
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.ProtocolError):
            return None
        except httpx.HTTPError as exc:
            return ServiceProbe(ip=ip, port=port, scheme=scheme, url=url, error=str(exc)[:240])


async def probe_hosts(
    hosts: Iterable[str],
    ports: list[int],
    timeout: float,
    concurrency: int,
) -> list[ServiceProbe]:
    """Probe likely HTTP/HTTPS services on host:port combinations."""
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
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
        },
    ) as client:
        tasks = []
        for ip in hosts:
            for port in ports:
                for scheme in schemes_for_port(port):
                    tasks.append(probe_url(client, ip, port, scheme, semaphore))

        results = await asyncio.gather(*tasks)

    # Keep real HTTP responses and informative HTTP errors only.
    return [item for item in results if item is not None and (item.status_code is not None or item.error)]
