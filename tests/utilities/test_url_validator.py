from unittest.mock import patch

import pytest

from oidcauthlib.utilities.url_validator import validate_url


class TestSchemeValidation:
    def test_https_accepted(self) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
            assert validate_url("https://example.com/register") == "https://example.com/register"

    def test_http_rejected_by_default(self) -> None:
        with pytest.raises(ValueError, match="scheme must be https"):
            validate_url("http://example.com/register")

    def test_http_accepted_when_allowed(self) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
            assert validate_url("http://example.com/register", allow_http=True) == "http://example.com/register"

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

    def test_gcp_metadata_rejected(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://metadata.google.internal/computeMetadata/")


class TestRawIPRejection:
    """SSL/TLS certs are issued for hostnames, not IPs. Raw IPs must be rejected."""

    def test_public_ipv4_rejected(self) -> None:
        with pytest.raises(ValueError, match="raw IP address"):
            validate_url("https://93.184.216.34/register")

    def test_private_ipv4_rejected(self) -> None:
        with pytest.raises(ValueError, match="raw IP address"):
            validate_url("https://10.0.0.1/register")

    def test_loopback_ipv4_rejected(self) -> None:
        with pytest.raises(ValueError, match="raw IP address"):
            validate_url("https://127.0.0.1/register")

    def test_metadata_ip_rejected(self) -> None:
        """AWS/GCP/Azure metadata endpoint as raw IP (caught by hostname blocklist)."""
        with pytest.raises(ValueError, match="blocked"):
            validate_url("https://169.254.169.254/latest/meta-data/")

    def test_ipv6_rejected(self) -> None:
        with pytest.raises(ValueError, match="raw IP address"):
            validate_url("https://[::1]/register")


class TestDNSRebindingProtection:
    """Hostnames that resolve to private IPs are rejected after DNS resolution."""

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
    def test_private_ipv4_resolved_rejected(self, ip: str) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
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
    def test_private_ipv6_resolved_rejected(self, ip: str) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(10, 1, 6, "", (ip, 443, 0, 0))]
            with pytest.raises(ValueError, match="blocked IP"):
                validate_url("https://some-external-host.com/register")


class TestEnvVarAllowHttp:
    """AUTH_ALLOW_HTTP_URLS env var globally enables allow_http."""

    def test_env_var_allows_http(self) -> None:
        with patch.dict("os.environ", {"AUTH_ALLOW_HTTP_URLS": "true"}):
            assert (
                validate_url("http://keycloak:8080/realms/test/.well-known/openid-configuration")
                == "http://keycloak:8080/realms/test/.well-known/openid-configuration"
            )

    def test_env_var_skips_private_ip_check(self) -> None:
        with patch.dict("os.environ", {"AUTH_ALLOW_HTTP_URLS": "true"}):
            with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
                mock_gai.return_value = [(2, 1, 6, "", ("172.18.0.5", 8080))]
                validate_url("http://keycloak:8080/realms/test")
                mock_gai.assert_not_called()

    def test_env_var_false_keeps_https_only(self) -> None:
        with patch.dict("os.environ", {"AUTH_ALLOW_HTTP_URLS": "false"}):
            with pytest.raises(ValueError, match="AUTH_ALLOW_HTTP_URLS"):
                validate_url("http://example.com/register")


class TestPublicHostnamesAccepted:
    @pytest.mark.parametrize(
        "ip",
        [
            "93.184.216.34",
            "8.8.8.8",
            "104.16.132.229",
        ],
    )
    def test_public_hostname_resolving_to_public_ip(self, ip: str) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", (ip, 443))]
            validate_url("https://example.com/register")


class TestDNSResolutionFailure:
    def test_unresolvable_hostname_rejected(self) -> None:
        with patch("oidcauthlib.utilities.url_validator.socket.getaddrinfo") as mock_gai:
            import socket

            mock_gai.side_effect = socket.gaierror("Name or service not known")
            with pytest.raises(ValueError, match="Cannot resolve hostname"):
                validate_url("https://nonexistent.invalid/register")
