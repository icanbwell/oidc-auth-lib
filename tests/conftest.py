"""
Shared test fixtures and utilities for auth tests.
"""

from typing import List, override, AsyncGenerator, Any

import pytest
from pymongo import AsyncMongoClient

from oidcauthlib.container.container_registry import ContainerRegistry
from oidcauthlib.container.interfaces import IContainer
from oidcauthlib.container.oidc_authlib_container_factory import (
    OidcAuthLibContainerFactory,
)
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)
from oidcauthlib.utilities.mongo_url_utils import MongoUrlHelpers


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
    return container


@pytest.fixture(scope="function")
async def test_container() -> AsyncGenerator[IContainer, None]:
    test_container: IContainer = create_test_container()
    async with ContainerRegistry.override(container=test_container) as container:
        yield container


@pytest.fixture(scope="function", autouse=True)
async def initialize_caches(test_container: IContainer) -> AsyncGenerator[None, None]:
    """
    Drop the test database before each test to ensure a clean state.
    """

    environment_variables = test_container.resolve(OidcEnvironmentVariables)
    db_name = environment_variables.mongo_db_name
    if not db_name:
        raise ValueError("mongo_db_name is required in environment variables")
    mongo_url = environment_variables.mongo_uri
    if not mongo_url:
        raise ValueError("mongo_uri is required in environment variables")
    connection_string = MongoUrlHelpers.add_credentials_to_mongo_url(
        mongo_url=mongo_url,
        username=environment_variables.mongo_db_username,
        password=environment_variables.mongo_db_password,
    )
    # use mongo client to drop the test database to ensure a clean state
    mongo_client: AsyncMongoClient[dict[str, Any]] = AsyncMongoClient(
        connection_string,
        appname="OidcAuthLib",
    )
    await mongo_client.drop_database(db_name)

    yield

    # Note: No explicit cleanup needed - storage factory manages lifecycle
