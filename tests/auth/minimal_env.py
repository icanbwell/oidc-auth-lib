from typing import Any
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables


class MinimalEnv(EnvironmentVariables):
    def __init__(self, auth_providers: list[str], configs: dict[str, Any]) -> None:
        super().__init__()
        self._auth_providers = auth_providers
        self._configs = configs

    @property
    def auth_providers(self) -> list[str]:
        return self._auth_providers

    def get_config(self, provider: str) -> Any:
        return self._configs[provider]
