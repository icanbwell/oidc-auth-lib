from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.config.auth_config import AuthConfig
import pytest
from typing import Any, Dict, List, override, Optional

from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables


class DummyEnvVars(EnvironmentVariables):
    def __init__(self, providers: list[str], configs: dict[str, Any]) -> None:
        self._providers: Optional[list[str]] = providers
        self._configs: dict[str, Any] = configs

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        return self._providers

    def get(self, key: str, default: Any = None) -> Any:
        return self._configs.get(key, default)

    @property
    @override
    def auth_redirect_uri(self) -> str | None:
        return ""

    @property
    @override
    def mongo_db_auth_cache_collection_name(self) -> str | None:
        return ""

    @property
    @override
    def mongo_db_cache_disable_delete(self) -> bool | None:
        return False

    @property
    @override
    def mongo_uri(self) -> str | None:
        return ""

    @property
    @override
    def mongo_db_name(self) -> str | None:
        return ""

    @property
    @override
    def oauth_cache(self) -> str:
        return ""

    @property
    @override
    def oauth_referring_subject(self) -> str | None:
        return ""


def test_get_auth_configs_for_all_auth_providers() -> None:
    providers: List[str] = ["a", "b"]
    configs: Dict[str, Any] = {}
    env: DummyEnvVars = DummyEnvVars(providers, configs)
    reader: AuthConfigReader = AuthConfigReader(environment_variables=env)

    def dummy_read_config_for_auth_provider(auth_provider: str) -> AuthConfig:
        return AuthConfig(
            auth_provider=auth_provider,
            friendly_name=auth_provider,
            audience="aud",
            issuer="iss",
            client_id="cid",
            client_secret=None,
            well_known_uri=None,
        )

    setattr(
        reader, "read_config_for_auth_provider", dummy_read_config_for_auth_provider
    )
    configs_list: List[AuthConfig] = reader.get_auth_configs_for_all_auth_providers()
    assert len(configs_list) == 2
    assert configs_list[0].auth_provider == "a"
    assert configs_list[1].auth_provider == "b"


def test_init_type_and_value_errors() -> None:
    with pytest.raises(ValueError):
        AuthConfigReader(environment_variables=None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AuthConfigReader(environment_variables=object())  # type: ignore[arg-type]
