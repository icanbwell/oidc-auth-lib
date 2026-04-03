from typing import Any

from oidcauthlib.auth.config.auth_config import AuthConfig


def _base_kwargs() -> dict[str, Any]:
    """Return the minimum required fields for AuthConfig."""
    return dict(
        auth_provider="test",
        friendly_name="Test Provider",
        audience="https://api.example.com",
        client_id="client123",
        scope="openid profile",
    )


# ── Explicit endpoint fields ─────────────────────────────────────────


class TestAuthConfigExplicitEndpoints:
    def test_explicit_endpoints(self) -> None:
        cfg = AuthConfig(
            **_base_kwargs(),
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
        )
        assert cfg.authorization_endpoint == "https://idp.example.com/authorize"
        assert cfg.token_endpoint == "https://idp.example.com/token"

    def test_endpoints_are_optional(self) -> None:
        cfg = AuthConfig(**_base_kwargs())
        assert cfg.authorization_endpoint is None
        assert cfg.token_endpoint is None

    def test_coexist_with_well_known_uri(self) -> None:
        cfg = AuthConfig(
            **_base_kwargs(),
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
        )
        assert cfg.well_known_uri is not None
        assert cfg.authorization_endpoint is not None
        assert cfg.token_endpoint is not None


# ── PKCE configuration ───────────────────────────────────────────────


class TestAuthConfigPKCE:
    def test_pkce_defaults(self) -> None:
        cfg = AuthConfig(**_base_kwargs())
        assert cfg.use_pkce is True
        assert cfg.pkce_method == "S256"

    def test_pkce_disabled(self) -> None:
        cfg = AuthConfig(**_base_kwargs(), use_pkce=False, pkce_method=None)
        assert cfg.use_pkce is False
        assert cfg.pkce_method is None

    def test_pkce_plain(self) -> None:
        cfg = AuthConfig(**_base_kwargs(), pkce_method="plain")
        assert cfg.pkce_method == "plain"


# ── DCR fields ───────────────────────────────────────────────────────


class TestAuthConfigDCRFields:
    def test_registration_url(self) -> None:
        cfg = AuthConfig(
            **_base_kwargs(),
            registration_url="https://idp.example.com/register",
        )
        assert cfg.registration_url == "https://idp.example.com/register"

    def test_registration_url_defaults_to_none(self) -> None:
        cfg = AuthConfig(**_base_kwargs())
        assert cfg.registration_url is None
