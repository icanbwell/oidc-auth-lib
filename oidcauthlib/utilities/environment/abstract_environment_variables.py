from typing import Optional
from abc import ABC, abstractmethod


class AbstractEnvironmentVariables(ABC):
    @staticmethod
    def str2bool(v: str | None) -> bool:
        return v is not None and str(v).lower() in ("yes", "true", "t", "1", "y")

    @property
    @abstractmethod
    def oauth_cache(self) -> str:
        pass

    @property
    @abstractmethod
    def mongo_uri(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def mongo_db_name(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def mongo_db_username(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def mongo_db_password(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def mongo_db_auth_cache_collection_name(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def mongo_db_cache_disable_delete(self) -> Optional[bool]:
        pass

    @property
    @abstractmethod
    def auth_providers(self) -> Optional[list[str]]:
        pass

    @property
    @abstractmethod
    def oauth_referring_email(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def oauth_referring_subject(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def auth_redirect_uri(self) -> Optional[str]:
        pass
