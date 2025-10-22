import pytest
import asyncio
from oidcauthlib.utilities.cached import cached
from oidcauthlib.utilities.mongo_url_utils import MongoUrlHelpers


@pytest.mark.asyncio
async def test_cached_decorator() -> None:
    calls: list[int] = []

    @cached
    async def foo(x: int) -> int:
        calls.append(x)
        await asyncio.sleep(0.01)
        return x * 2

    result1: int = await foo(3)
    result2: int = await foo(3)
    assert result1 == 6
    assert result2 == 6
    assert calls == [3]  # Only called once


def test_add_credentials_to_mongo_url() -> None:
    url = "mongodb://mongo:27017?appName=fhir-server"
    username = "user"
    password = "pass"  # pragma: allowlist secret
    new_url = MongoUrlHelpers.add_credentials_to_mongo_url(
        mongo_url=url, username=username, password=password
    )
    assert new_url.startswith(
        "mongodb://user:pass@mongo:27017"  # pragma: allowlist secret
    )

    # No credentials
    assert (
        MongoUrlHelpers.add_credentials_to_mongo_url(
            mongo_url=url, username=None, password=None
        )
        == url
    )

    # Already has credentials
    url2 = "mongodb://old:creds@mongo:27017"  # pragma: allowlist secret
    new_url2 = MongoUrlHelpers.add_credentials_to_mongo_url(
        mongo_url=url2,
        username="new",
        password="creds",  # pragma: allowlist secret
    )
    assert new_url2.startswith(
        "mongodb://new:creds@mongo:27017"  # pragma: allowlist secret
    )
