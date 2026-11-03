from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

from app.safety.scope_guard import is_rfc1918_private


class LocalNetworkError(RuntimeError):
    """Raised when the local private network cannot be detected."""


def _private_ip_from_socket_route() -> str | None:
    """Find the primary local IPv4 address using the OS routing table.

    UDP connect does not need to send payloads; it asks the OS which local
    address would be used for the route. If there is no route, it fails safely.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.2)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return ip if is_rfc1918_private(ipaddress.ip_network(f"{address}/32", strict=False)) else None


def _private_ip_from_hostname() -> str | None:
    try:
        candidates = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        candidates = []

    for ip in candidates:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if is_rfc1918_private(ipaddress.ip_network(f"{address}/32", strict=False)):
            return ip
    return None


def _gateway_from_proc_route() -> str | None:
    """Linux-only default gateway lookup from /proc/net/route."""
    route_file = Path("/proc/net/route")
    if not route_file.exists():
        return None

    try:
        for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            destination, gateway_hex = parts[1], parts[2]
            if destination != "00000000":
                continue
            gateway_int = int(gateway_hex, 16)
            gateway_ip = socket.inet_ntoa(gateway_int.to_bytes(4, "little"))
            gateway_addr = ipaddress.ip_address(gateway_ip)
            if is_rfc1918_private(ipaddress.ip_network(f"{gateway_addr}/32", strict=False)):
                return gateway_ip
    except Exception:
        return None
    return None


def detect_local_target(prefix: int = 24, gateway_only: bool = False) -> str:
    """Return the current private LAN CIDR or gateway IP.

    Default behavior intentionally uses /24 because it is a practical and safe
    home/office LAN assumption. The result still passes the private-scope guard.
    """
    if prefix < 24 or prefix > 32:
        raise LocalNetworkError("For safety, --local-prefix must be between 24 and 32.")

    ip = _private_ip_from_socket_route() or _private_ip_from_hostname()
    gateway = _gateway_from_proc_route()

    if gateway_only:
        if gateway:
            return gateway
        raise LocalNetworkError("Could not detect a private default gateway on this machine.")

    if not ip:
        raise LocalNetworkError("Could not detect a private local IPv4 address on this machine.")

    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
