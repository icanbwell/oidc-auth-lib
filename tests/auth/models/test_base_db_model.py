from oidcauthlib.auth.models.base_db_model import BaseDbModel
from bson import ObjectId
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.config.auth_config import AuthConfig
from typing import Any, List, Dict, override
import pytest


def test_base_db_model_creation_and_serialization() -> None:
    obj: BaseDbModel = BaseDbModel()
    assert isinstance(obj.id, ObjectId)
    # Test alias
    data: dict[str, str] = obj.model_dump(by_alias=True)
    assert "_id" in data
    assert data["_id"] == str(obj.id)
    # Test serializer
    json_data: str = obj.model_dump_json()
    assert str(obj.id) in json_data


class DummyEnvVars(EnvironmentVariables):
    def __init__(self, providers: List[str], configs: Dict[str, Any]) -> None:
        self._providers: List[str] = providers
        self._configs: Dict[str, Any] = configs

    @property
    @override
    def auth_providers(self) -> List[str]:
        return self._providers

    def get(self, key: str, default: Any = None) -> Any:
        return self._configs.get(key, default)


def test_get_auth_configs_for_all_auth_providers() -> None:
    providers: List[str] = ["a", "b"]
    configs: Dict[str, Any] = {}
    env: DummyEnvVars = DummyEnvVars(providers, configs)
    reader: AuthConfigReader = AuthConfigReader(environment_variables=env)

    # Patch read_config_for_auth_provider to return a dummy AuthConfig
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
