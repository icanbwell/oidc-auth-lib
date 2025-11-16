import pytest
from pydantic import ValidationError
from datetime import datetime, timedelta, UTC
from oidcauthlib.auth.models.token import Token
from oidcauthlib.auth.config.auth_config import AuthConfig


def test_token_is_valid_future() -> None:
    expires: datetime = datetime.now(UTC) + timedelta(minutes=10)
    token: Token = Token(token="abc", expires=expires)
    assert token.is_valid() is True


def test_token_is_valid_expired() -> None:
    expires: datetime = datetime.now(UTC) - timedelta(minutes=10)
    token: Token = Token(token="abc", expires=expires)
    assert token.is_valid() is False


def test_token_is_valid_no_expiry() -> None:
    token: Token = Token(token="abc")
    assert token.is_valid() is False


def test_auth_config_creation() -> None:
    config: AuthConfig = AuthConfig(
        auth_provider="test",
        friendly_name="Test Provider",
        audience="aud",
        issuer="issuer",
        client_id="cid",
        client_secret="secret",  # pragma: allowlist secret
        well_known_uri="uri",
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
            auth_provider="a", audience="b", issuer="c", extra_field="not allowed"
        )  # type: ignore[call-arg]
