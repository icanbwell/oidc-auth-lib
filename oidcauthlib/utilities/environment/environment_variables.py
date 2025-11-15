import os
from typing import Optional, override

from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)


class EnvironmentVariables(AbstractEnvironmentVariables):
    @staticmethod
    @override
    def str2bool(v: str | None) -> bool:
        return v is not None and str(v).lower() in ("yes", "true", "t", "1", "y")

    @property
    @override
    def oauth_cache(self) -> str:
        return os.environ.get("OAUTH_CACHE", "memory")

    @property
    @override
    def mongo_uri(self) -> Optional[str]:
        return os.environ.get("MONGO_URL")

    @property
    @override
    def mongo_db_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_NAME")

    @property
    @override
    def mongo_db_username(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_USERNAME")

    @property
    @override
    def mongo_db_password(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_PASSWORD")

    @property
    @override
    def mongo_db_auth_cache_collection_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_AUTH_CACHE_COLLECTION_NAME")

    @property
    @override
    def mongo_db_cache_disable_delete(self) -> Optional[bool]:
        return self.str2bool(os.environ.get("MONGO_DB_AUTH_CACHE_DISABLE_DELETE"))

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        auth_providers: str | None = os.environ.get("AUTH_PROVIDERS")
        return (
            [p.strip() for p in auth_providers.split(",")] if auth_providers else None
        )

    @property
    @override
    def oauth_referring_email(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_EMAIL")

    @property
    @override
    def oauth_referring_subject(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_SUBJECT")

    @property
    @override
    def auth_redirect_uri(self) -> Optional[str]:
        return os.environ.get("AUTH_REDIRECT_URI")
