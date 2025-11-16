import threading
from typing import Dict, List, Optional, override

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables


class DummyEnvVars(EnvironmentVariables):
    def __init__(self, providers: list[str]) -> None:
        self._providers: Optional[list[str]] = providers

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        return self._providers

    # Provide stubs for abstract properties not needed in this test
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
        return "memory"

    @property
    @override
    def oauth_referring_subject(self) -> str | None:
        return ""

    @property
    @override
    def auth_redirect_uri(self) -> str | None:
        return ""

    @property
    @override
    def oauth_referring_email(self) -> str | None:
        return ""


class CountingAuthConfigReader(AuthConfigReader):
    def __init__(self, *, environment_variables: EnvironmentVariables) -> None:
        super().__init__(environment_variables=environment_variables)
        self._calls: Dict[str, int] = {}

    @override
    def read_config_for_auth_provider(self, *, auth_provider: str) -> AuthConfig | None:
        # Count calls per provider
        self._calls[auth_provider] = self._calls.get(auth_provider, 0) + 1
        return AuthConfig(
            auth_provider=auth_provider,
            friendly_name=auth_provider,
            audience=f"aud-{auth_provider}",
            issuer=f"iss-{auth_provider}",
            client_id=f"cid-{auth_provider}",
            client_secret=None,
            well_known_uri=f"https://well-known/{auth_provider}",
            scope="openid profile email",
        )

    def calls(self, provider: str) -> int:
        return self._calls.get(provider, 0)


def test_thread_safe_initialization() -> None:
    providers: List[str] = ["alpha", "beta", "gamma"]
    env: DummyEnvVars = DummyEnvVars(providers)
    reader: CountingAuthConfigReader = CountingAuthConfigReader(
        environment_variables=env
    )

    # Prepare threads all calling the method concurrently
    results: List[List[AuthConfig]] = []
    errors: List[Exception] = []
    start_barrier = threading.Barrier(parties=25)

    def worker() -> None:
        try:
            start_barrier.wait()
            configs = reader.get_auth_configs_for_all_auth_providers()
            results.append(configs)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors occurred in threads: {errors}"
    # All threads should have received the same list instance (cached object identity)
    first_list = results[0]
    for r in results[1:]:
        assert r is first_list
    # Each provider's config read should have been called exactly once
    for p in providers:
        assert reader.calls(p) == 1, f"Provider {p} initialized {reader.calls(p)} times"
    # Verify contents
    assert {c.auth_provider for c in first_list} == set(providers)

    # Subsequent single-thread call should reuse cache (no additional calls)
    again = reader.get_auth_configs_for_all_auth_providers()
    assert again is first_list
    for p in providers:
        assert reader.calls(p) == 1
