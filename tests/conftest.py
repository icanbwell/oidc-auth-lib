"""
Shared test fixtures and utilities for auth tests.
"""

from typing import List, override, AsyncGenerator

import pytest

from oidcauthlib.container.container_registry import ContainerRegistry
from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.container.oidc_authlib_container_factory import (
    OidcAuthLibContainerFactory,
)
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


class MockEnvironmentVariables(AbstractEnvironmentVariables):
    """Mock environment variables for testing"""

    def __init__(self, providers: List[str]) -> None:
        self._providers = providers

    @property
    @override
    def auth_providers(self) -> List[str]:
        return self._providers

    @property
    @override
    def oauth_cache(self) -> str:
        return "memory"

    @property
    @override
    def mongo_uri(self) -> str | None:
        return None

    @property
    @override
    def mongo_db_name(self) -> str | None:
        return None

    @property
    @override
    def mongo_db_username(self) -> str | None:
        return None

    @property
    @override
    def mongo_db_password(self) -> str | None:
        return None

    @property
    @override
    def mongo_db_auth_cache_collection_name(self) -> str | None:
        return None

    @property
    @override
    def mongo_db_cache_disable_delete(self) -> bool | None:
        return None

    @property
    @override
    def oauth_referring_email(self) -> str | None:
        return None

    @property
    @override
    def oauth_referring_subject(self) -> str | None:
        return None

    @property
    @override
    def auth_redirect_uri(self) -> str | None:
        return None


def create_test_container() -> IContainer:
    """
    Create a singleton-like dependency injection container for tests.
    :return: IContainer
    """
    container: IContainer = OidcAuthLibContainerFactory().create_container()
    # Register the MockEnvironmentVariables for testing
    container.singleton(
        AbstractEnvironmentVariables,
        lambda c: MockEnvironmentVariables(providers=["test_provider"]),
    )
    return container


@pytest.fixture(scope="function")
async def test_container() -> AsyncGenerator[IContainer, None]:
    test_container: IContainer = create_test_container()
    async with ContainerRegistry.override(container=test_container) as container:
        yield container
