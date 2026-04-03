"""SSRF-safe URL validation for outbound HTTP requests.

Validates URLs before making HTTP requests to prevent Server-Side Request
Forgery (SSRF) attacks.  Enforces HTTPS-only, rejects private/reserved IP
ranges, and resolves hostnames to verify the target is not internal.
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmark testing
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",  # GCP metadata
        "169.254.169.254",  # AWS/Azure/GCP metadata endpoint
    }
)


def _is_private_ip(addr: str) -> bool:
    """Check whether an IP address falls in a blocked network range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable → reject
    return any(ip in network for network in _BLOCKED_NETWORKS)


def validate_url(url: str, *, allow_http: bool = False) -> str:
    """Validate a URL for safe outbound HTTP requests.

    Args:
        url: The URL to validate.
        allow_http: If True, permit ``http://`` in addition to ``https://``.
            Defaults to False (HTTPS only).

    Returns:
        The validated URL (unchanged).

    Raises:
        ValueError: If the URL fails any validation check.
    """
    parsed = urlparse(url)

    # --- scheme ---
    allowed_schemes = {"https"} if not allow_http else {"https", "http"}
    if parsed.scheme not in allowed_schemes:
        raise ValueError(
            f"URL scheme must be {' or '.join(sorted(allowed_schemes))}, "
            f"got '{parsed.scheme}' in '{url}'"
        )

    # --- hostname ---
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"URL is missing a hostname: '{url}'")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"URL hostname '{hostname}' is blocked")

    # --- reject raw IP addresses as hostnames ---
    # SSL/TLS certificates are issued for domain names, not IPs.
    # A raw IP bypasses proper certificate validation.
    try:
        ipaddress.ip_address(hostname)
        raise ValueError(f"URL must use a hostname, not a raw IP address: '{hostname}'")
    except ValueError as exc:
        if "raw IP address" in str(exc):
            raise
        # Not an IP → it's a proper hostname, continue

    # --- resolve DNS and check all IPs ---
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = str(sockaddr[0])
        if _is_private_ip(ip_str):
            raise ValueError(f"URL '{url}' resolves to blocked IP {ip_str}")

    logger.debug("URL validated: %s", url)
    return url
