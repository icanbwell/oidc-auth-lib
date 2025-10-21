import os
from typing import Optional


class EnvironmentVariables:
    @staticmethod
    def str2bool(v: str | None) -> bool:
        return v is not None and str(v).lower() in ("yes", "true", "t", "1", "y")

    @property
    def oauth_cache(self) -> str:
        return os.environ.get("OAUTH_CACHE", "memory")

    @property
    def mongo_uri(self) -> Optional[str]:
        return os.environ.get("MONGO_URL")

    @property
    def mongo_db_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_NAME")

    @property
    def mongo_db_username(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_USERNAME")

    @property
    def mongo_db_password(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_PASSWORD")

    @property
    def mongo_db_auth_cache_collection_name(self) -> Optional[str]:
        return os.environ.get("MONGO_DB_AUTH_CACHE_COLLECTION_NAME")

    @property
    def mongo_db_cache_disable_delete(self) -> Optional[bool]:
        return self.str2bool(os.environ.get("MONGO_DB_AUTH_CACHE_DISABLE_DELETE"))

    @property
    def auth_providers(self) -> Optional[list[str]]:
        auth_providers: str | None = os.environ.get("AUTH_PROVIDERS")
        return auth_providers.split(",") if auth_providers else None

    @property
    def oauth_referring_email(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_EMAIL")

    @property
    def oauth_referring_subject(self) -> Optional[str]:
        return os.environ.get("OAUTH_REFERRING_SUBJECT")

    @property
    def server_base_url(self) -> Optional[str]:
        return os.environ.get("SERVER_BASE_URL")

    @property
    def auth_redirect_uri(self) -> Optional[str]:
        return os.environ.get("AUTH_REDIRECT_URI")

    @property
    def mongo_dynamic_client_registration_collection(self) -> str:
        return os.environ.get(
            "MONGO_DYNAMIC_CLIENT_REGISTRATION_COLLECTION", "oauth-clients"
        )

    @property
    def mongo_oauth_transactions_collection_name(self) -> str:
        return os.environ.get(
            "MONGO_OAUTH_TRANSACTIONS_COLLECTION_NAME", "oauth-transactions"
        )

    @property
    def mongo_oauth_client_codes_collection_name(self) -> str:
        return os.environ.get(
            "MONGO_OAUTH_CLIENT_CODES_COLLECTION_NAME", "oauth-client-codes"
        )

    @property
    def default_model(self) -> str:
        return os.environ.get(
            "DEFAULT_MODEL_NAME", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        )

    @property
    def model_override(self) -> Optional[str]:
        return os.environ.get("MODEL_OVERRIDE")
