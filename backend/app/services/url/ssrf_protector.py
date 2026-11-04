"""Server-Side Request Forgery (SSRF) and DNS Rebinding Protection Engine."""

import socket
import ipaddress
from typing import Tuple, List
from urllib.parse import urlparse


class SSRFViolationError(Exception):
    """Raised when an inspected URL targets an internal or forbidden IP/hostname."""
    pass


# Private, loopback, link-local, and cloud metadata IP networks (IPv4 & IPv6)
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),          # Loopback
    ipaddress.ip_network("10.0.0.0/8"),           # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local & Cloud Metadata (AWS/GCP/Azure)
    ipaddress.ip_network("100.64.0.0/10"),        # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),         # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),        # Benchmarking
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("0.0.0.0/8"),            # Current network
    # IPv6
    ipaddress.ip_network("::1/128"),              # Loopback
    ipaddress.ip_network("::/128"),               # Unspecified
    ipaddress.ip_network("fc00::/7"),             # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),            # Link-local
    ipaddress.ip_network("ff00::/8"),             # Multicast
]

FORBIDDEN_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "instance-data"
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Checks whether an IP address belongs to any disallowed/internal network."""
    for network in DISALLOWED_NETWORKS:
        if ip in network:
            return True, f"IP {ip} belongs to disallowed network {network}"
    return False, ""


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Safely resolves a hostname to IPv4/IPv6 addresses and verifies none belong to
    disallowed private/internal networks, mitigating DNS rebinding vulnerabilities.
    """
    host_clean = hostname.strip().lower()

    if host_clean in FORBIDDEN_HOSTNAMES:
        raise SSRFViolationError(f"Access to hostname '{host_clean}' is prohibited (SSRF Protection).")

    # If already a literal IP address
    try:
        ip = ipaddress.ip_address(host_clean)
        blocked, reason = is_ip_blocked(ip)
        if blocked:
            raise SSRFViolationError(f"Prohibited destination: {reason} (SSRF Protection).")
        return [str(ip)]
    except ValueError:
        pass

    # Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(host_clean, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFViolationError(f"Unable to resolve hostname '{host_clean}': {e}")

    resolved_ips: List[str] = []
    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            blocked, reason = is_ip_blocked(ip)
            if blocked:
                raise SSRFViolationError(
                    f"Hostname '{host_clean}' resolves to prohibited destination: {reason} (SSRF / DNS Rebinding Protection)."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        except ValueError:
            continue

    if not resolved_ips:
        raise SSRFViolationError(f"Hostname '{host_clean}' could not be resolved to a valid IP address.")

    return resolved_ips


def validate_url_for_safe_inspection(url: str) -> None:
    """
    Complete security gate for any outbound URL inspection.
    Validates scheme, hostname, and resolves IP against SSRF rules.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("http", "https"):
        raise SSRFViolationError(f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted for safety.")

    if not parsed.hostname:
        raise SSRFViolationError("URL does not contain a valid destination host.")

    resolve_and_validate_hostname(parsed.hostname)
