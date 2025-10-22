import pytest
from datetime import datetime
from oidcauthlib.auth.models.auth import AuthInformation
from oidcauthlib.auth.models.cache_item import CacheItem


def test_auth_information_creation() -> None:
    now: datetime = datetime.utcnow()
    info: AuthInformation = AuthInformation(
        redirect_uri="http://localhost",
        claims={"role": "admin"},
        audience=["api1", "api2"],
        expires_at=now,
        email="user@example.com",
        subject="subj",
        user_name="user1",
    )
    assert info.redirect_uri == "http://localhost"
    assert info.claims is not None and info.claims["role"] == "admin"
    assert info.audience == ["api1", "api2"]
    assert info.expires_at == now
    assert info.email == "user@example.com"
    assert info.subject == "subj"
    assert info.user_name == "user1"


def test_auth_information_forbid_extra() -> None:
    with pytest.raises(Exception):
        AuthInformation(redirect_uri="x", extra_field="not allowed")  # type: ignore[call-arg]


def test_cache_item_creation() -> None:
    now = datetime.utcnow()
    item = CacheItem(key="foo", value="bar", created=now)
    assert item.key == "foo"
    assert item.value == "bar"
    assert item.created == now
    assert item.deleted is None
    # Test serialization
    data = item.model_dump()
    assert data["key"] == "foo"
    assert data["value"] == "bar"
    assert data["created"] == now
