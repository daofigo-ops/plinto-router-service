from __future__ import annotations

import ipaddress
from collections.abc import Iterable


PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class ScopeError(ValueError):
    """Raised when a requested scan target is outside the safe scope."""


def parse_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse an IP or CIDR target into a network object."""
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScopeError(f"Invalid target network/IP: {target}") from exc


def is_rfc1918_private(network: ipaddress._BaseNetwork) -> bool:
    """Return True only for RFC1918 private IPv4 ranges.

    Python's ipaddress.is_private also treats documentation/test ranges as private.
    For this tool we intentionally restrict Phase 1 to common LAN ranges only.
    """
    if network.version != 4:
        return False
    return any(network.subnet_of(private_net) for private_net in PRIVATE_RANGES)


def validate_private_scope(target: str, private_only: bool = True) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    network = parse_network(target)
    if private_only and not is_rfc1918_private(network):
        allowed = ", ".join(str(item) for item in PRIVATE_RANGES)
        raise ScopeError(
            f"Refusing to scan {target}. Plinto allows only RFC1918 private LAN ranges: {allowed}."
        )
    return network


def iter_hosts_limited(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    max_hosts: int,
) -> Iterable[str]:
    """Yield host IPs but stop if a network is too large."""
    host_count = network.num_addresses

    # For /32 targets, .hosts() returns the address; for normal networks it excludes network/broadcast.
    usable_hosts = list(network.hosts()) if host_count <= max_hosts + 2 else None
    count = len(usable_hosts) if usable_hosts is not None else host_count

    if count > max_hosts:
        raise ScopeError(
            f"Target {network} is too large for this run ({count} addresses). "
            f"Use a smaller range or increase --max-hosts intentionally."
        )

    if usable_hosts is not None:
        for host in usable_hosts:
            yield str(host)
        return

    for host in network.hosts():
        yield str(host)
