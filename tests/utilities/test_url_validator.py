from unittest.mock import patch

import pytest

from oidcauthlib.utilities.url_validator import validate_url


class TestSchemeValidation:
    def test_https_accepted(self) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
            assert (
                validate_url("https://example.com/register")
                == "https://example.com/register"
            )

    def test_http_rejected_by_default(self) -> None:
        with pytest.raises(ValueError, match="scheme must be https"):
            validate_url("http://example.com/register")

    def test_http_accepted_when_allowed(self) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
            assert (
                validate_url("http://example.com/register", allow_http=True)
                == "http://example.com/register"
            )

    def test_ftp_rejected(self) -> None:
        with pytest.raises(ValueError, match="scheme must be"):
            validate_url("ftp://example.com/file")

    def test_empty_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="scheme must be"):
            validate_url("//example.com/path")


class TestHostnameValidation:
    def test_missing_hostname_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing a hostname"):
            validate_url("https:///path")

    def test_localhost_rejected(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://localhost/register")

    def test_localhost_localdomain_rejected(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://localhost.localdomain/register")

    def test_metadata_endpoint_rejected(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://169.254.169.254/latest/meta-data/")

    def test_gcp_metadata_rejected(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://metadata.google.internal/computeMetadata/")


class TestPrivateIPRanges:
    """Validate that all RFC 1918 and reserved ranges are rejected."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "127.0.0.2",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.1.1",
            "0.0.0.1",
            "100.64.0.1",
        ],
    )
    def test_private_ipv4_rejected(self, ip: str) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", (ip, 443))]
            with pytest.raises(ValueError, match="blocked IP"):
                validate_url("https://some-external-host.com/register")

    @pytest.mark.parametrize(
        "ip",
        [
            "::1",
            "fc00::1",
            "fe80::1",
        ],
    )
    def test_private_ipv6_rejected(self, ip: str) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(10, 1, 6, "", (ip, 443, 0, 0))]
            with pytest.raises(ValueError, match="blocked IP"):
                validate_url("https://some-external-host.com/register")


class TestPublicIPsAccepted:
    @pytest.mark.parametrize(
        "ip",
        [
            "93.184.216.34",
            "8.8.8.8",
            "104.16.132.229",
        ],
    )
    def test_public_ipv4_accepted(self, ip: str) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", (ip, 443))]
            validate_url("https://example.com/register")


class TestDNSResolutionFailure:
    def test_unresolvable_hostname_rejected(self) -> None:
        with patch(
            "oidcauthlib.utilities.url_validator.socket.getaddrinfo"
        ) as mock_gai:
            import socket

            mock_gai.side_effect = socket.gaierror("Name or service not known")
            with pytest.raises(ValueError, match="Cannot resolve hostname"):
                validate_url("https://nonexistent.invalid/register")
