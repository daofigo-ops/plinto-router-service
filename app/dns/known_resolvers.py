from __future__ import annotations

from ipaddress import ip_address


KNOWN_SAFE_RESOLVERS: dict[str, str] = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
}


def classify_resolver(ip: str) -> tuple[str, str]:
    """Return status/category and provider note for a DNS resolver IP."""
    try:
        parsed = ip_address(ip)
    except ValueError:
        return "Invalid", "Invalid IP"

    if ip in KNOWN_SAFE_RESOLVERS:
        return "Known Safe", KNOWN_SAFE_RESOLVERS[ip]
    if parsed.is_private:
        return "Internal", "Private/internal resolver"
    if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
        return "Suspicious", "Non-routable/special-use address"
    return "Needs Review", "Unknown public resolver"
