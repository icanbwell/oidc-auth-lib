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
