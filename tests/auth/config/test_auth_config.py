import pytest
from pydantic import ValidationError
from oidcauthlib.auth.config.auth_config import AuthConfig


def test_auth_config_creation() -> None:
    config: AuthConfig = AuthConfig(
        auth_provider="test",
        friendly_name="Test Provider",
        audience="aud",
        issuer="issuer",
        client_id="cid",
        client_secret="secret",  # pragma: allowlist secret
        well_known_uri="uri",
        scope="openid profile email",
    )
    assert config.auth_provider == "test"
    assert config.audience == "aud"
    assert config.issuer == "issuer"
    assert config.client_id == "cid"
    assert config.client_secret == "secret"  # pragma: allowlist secret
    assert config.well_known_uri == "uri"


def test_auth_config_forbid_extra() -> None:
    with pytest.raises(ValidationError):
        AuthConfig(
            auth_provider="a",
            audience="b",
            issuer="c",
            extra_field="not allowed",  # type: ignore[call-arg]
        )


def test_auth_config_accepts_registration_url_without_client_id() -> None:
    """DCR configs can omit client_id if registration_url is provided."""
    config = AuthConfig(
        auth_provider="dcr-provider",
        friendly_name="DCR Provider",
        audience="aud",
        scope="openid",
        registration_url="https://idp.example.com/register",
        well_known_uri="https://idp.example.com/.well-known/openid-configuration",
    )
    assert config.client_id is None
    assert config.registration_url == "https://idp.example.com/register"


def test_auth_config_rejects_missing_client_id_and_registration_url() -> None:
    """Must have at least client_id or registration_url."""
    with pytest.raises(ValidationError, match="client_id or registration_url"):
        AuthConfig(
            auth_provider="broken",
            friendly_name="Broken",
            audience="aud",
            scope="openid",
            well_known_uri="https://idp.example.com/.well-known/openid-configuration",
        )


def test_auth_config_accepts_both_client_id_and_registration_url() -> None:
    """Having both is valid (registration_url used as fallback)."""
    config = AuthConfig(
        auth_provider="both",
        friendly_name="Both",
        audience="aud",
        scope="openid",
        client_id="cid",
        registration_url="https://idp.example.com/register",
    )
    assert config.client_id == "cid"
    assert config.registration_url == "https://idp.example.com/register"
