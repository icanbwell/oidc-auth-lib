"""
Shared test fixtures and utilities for auth tests.
"""

from typing import List, override
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
