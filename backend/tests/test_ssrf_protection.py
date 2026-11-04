"""Unit tests for Server-Side Request Forgery (SSRF) and DNS Rebinding Protection."""

import socket
import pytest
from unittest.mock import patch

from app.services.url.ssrf_protector import (
    validate_url_for_safe_inspection,
    resolve_and_validate_hostname,
    SSRFViolationError,
)


def test_block_loopback_ipv4():
    """Verify 127.0.0.1 and loopback IPv4 addresses are strictly blocked."""
    with pytest.raises(SSRFViolationError, match="disallowed network"):
        validate_url_for_safe_inspection("http://127.0.0.1/admin")

    with pytest.raises(SSRFViolationError, match="disallowed network"):
        validate_url_for_safe_inspection("http://127.0.0.2:8080/metrics")


def test_block_loopback_hostnames():
    """Verify localhost variants are blocked before DNS lookup."""
    for host in ["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]:
        with pytest.raises(SSRFViolationError, match="prohibited"):
            validate_url_for_safe_inspection(f"http://{host}:8000/api")


def test_block_rfc1918_private_ranges():
    """Verify 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 are blocked."""
    rfc1918_ips = [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.1.100",
    ]
    for ip in rfc1918_ips:
        with pytest.raises(SSRFViolationError, match="disallowed network"):
            validate_url_for_safe_inspection(f"http://{ip}/internal")


def test_block_cloud_metadata_ips_and_names():
    """Verify AWS/GCP/Azure link-local metadata endpoints are blocked."""
    with pytest.raises(SSRFViolationError, match="disallowed network"):
        validate_url_for_safe_inspection("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFViolationError, match="prohibited"):
        validate_url_for_safe_inspection("http://metadata.google.internal/computeMetadata/v1/")

    with pytest.raises(SSRFViolationError, match="prohibited"):
        validate_url_for_safe_inspection("http://instance-data/latest/meta-data/")


def test_block_multicast_carrier_grade_nat_and_zero():
    """Verify 0.0.0.0/8, 100.64.0.0/10, 224.0.0.0/4 (multicast) are blocked."""
    special_ips = [
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
    ]
    for ip in special_ips:
        with pytest.raises(SSRFViolationError, match="disallowed network"):
            validate_url_for_safe_inspection(f"http://{ip}/status")


def test_block_ipv6_loopback_and_link_local():
    """Verify IPv6 loopback (::1), link-local (fe80::), and ULA (fc00::) are blocked."""
    ipv6_blocked = [
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
    ]
    for ip6 in ipv6_blocked:
        with pytest.raises(SSRFViolationError, match="disallowed network"):
            resolve_and_validate_hostname(ip6)


def test_block_unsupported_schemes():
    """Verify non-HTTP schemes are rejected by the SSRF validator."""
    with pytest.raises(SSRFViolationError, match="Invalid URL scheme"):
        validate_url_for_safe_inspection("ftp://example.com/file")

    with pytest.raises(SSRFViolationError, match="Invalid URL scheme"):
        validate_url_for_safe_inspection("file:///etc/passwd")

    with pytest.raises(SSRFViolationError, match="Invalid URL scheme"):
        validate_url_for_safe_inspection("gopher://127.0.0.1:70")


def test_block_empty_or_missing_hostname():
    """Verify URLs without a destination host are rejected."""
    with pytest.raises(SSRFViolationError, match="valid destination host"):
        validate_url_for_safe_inspection("http://")


def test_allow_valid_public_ip():
    """Verify public Internet IP addresses are allowed through."""
    ips = resolve_and_validate_hostname("93.184.216.34")  # example.com public IP
    assert "93.184.216.34" in ips

    ips_dns = resolve_and_validate_hostname("8.8.8.8")  # Google public DNS
    assert "8.8.8.8" in ips_dns


def test_dns_rebinding_detection_via_mock():
    """Verify that if a domain resolves to a private IP, it is blocked (DNS Rebinding prevention)."""
    # Simulate a domain that resolves to 192.168.1.50
    mock_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.50", 80))
    ]
    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        with pytest.raises(SSRFViolationError, match="resolves to prohibited destination"):
            resolve_and_validate_hostname("attacker-controlled-rebinding.com")


def test_valid_public_domain_resolution_via_mock():
    """Verify that a domain resolving to a public IP passes validation."""
    mock_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
    ]
    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        ips = resolve_and_validate_hostname("secure-banking-portal.org")
        assert "93.184.216.34" in ips

