from typing import Optional, override


from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)


class NoProvidersEnvVars(OidcEnvironmentVariables):
    """Env vars stub that returns None for auth_providers (no env vars set)."""

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        return None

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
        return "memory"

    @property
    @override
    def oauth_referring_subject(self) -> str | None:
        return ""

    @property
    @override
    def oauth_referring_email(self) -> str | None:
        return ""


class WithProvidersEnvVars(NoProvidersEnvVars):
    """Env vars stub that returns a fixed list of providers."""

    def __init__(self, providers: list[str]) -> None:
        self._providers = providers

    @property
    @override
    def auth_providers(self) -> Optional[list[str]]:
        return self._providers


def _make_auth_config(name: str) -> AuthConfig:
    """Create a minimal valid AuthConfig for testing."""
    return AuthConfig(
        auth_provider=name,
        friendly_name=name,
        audience=f"aud-{name}",
        scope="openid profile email",
        client_id=f"cid-{name}",
    )


class TestRegisterAuthConfigsSeedsWhenNoEnvVars:
    """register_auth_configs seeds the reader when no env vars exist."""

    def test_seeds_reader_with_external_configs(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        configs = [_make_auth_config("alpha"), _make_auth_config("beta")]
        reader.register_auth_configs(configs=configs)

        all_configs = reader.get_auth_configs_for_all_auth_providers()
        assert len(all_configs) == 2
        names = {c.auth_provider for c in all_configs}
        assert names == {"alpha", "beta"}


class TestRegisterAuthConfigsMergesWithEnvVars:
    """register_auth_configs merges with existing env-var configs without duplicates."""

    def test_merges_without_duplicates(self) -> None:
        env = WithProvidersEnvVars(["existing"])
        reader = AuthConfigReader(environment_variables=env)

        # Stub read_config_for_auth_provider so env-var loading works
        def fake_read(*, auth_provider: str) -> AuthConfig:
            return _make_auth_config(auth_provider)

        reader.read_config_for_auth_provider = fake_read  # type: ignore[method-assign]

        # Pre-load env-var configs
        reader.get_auth_configs_for_all_auth_providers()

        # Register an external config that is new
        reader.register_auth_configs(configs=[_make_auth_config("external")])

        all_configs = reader.get_auth_configs_for_all_auth_providers()
        assert len(all_configs) == 2
        names = {c.auth_provider for c in all_configs}
        assert names == {"existing", "external"}

    def test_skips_duplicate_provider_from_env_vars(self) -> None:
        env = WithProvidersEnvVars(["existing"])
        reader = AuthConfigReader(environment_variables=env)

        def fake_read(*, auth_provider: str) -> AuthConfig:
            return _make_auth_config(auth_provider)

        reader.read_config_for_auth_provider = fake_read  # type: ignore[method-assign]
        reader.get_auth_configs_for_all_auth_providers()

        # Try to register a config with the same name (case-insensitive)
        reader.register_auth_configs(configs=[_make_auth_config("EXISTING")])

        all_configs = reader.get_auth_configs_for_all_auth_providers()
        assert len(all_configs) == 1
        assert all_configs[0].auth_provider == "existing"


class TestRegisterAuthConfigsIdempotent:
    """Calling register_auth_configs twice with the same provider doesn't duplicate."""

    def test_no_duplicate_on_repeated_registration(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        config = _make_auth_config("alpha")
        reader.register_auth_configs(configs=[config])
        reader.register_auth_configs(configs=[config])

        all_configs = reader.get_auth_configs_for_all_auth_providers()
        assert len(all_configs) == 1
        assert all_configs[0].auth_provider == "alpha"


class TestRegisteredConfigsFindableViaGetConfig:
    """Registered configs are findable via get_config_for_auth_provider."""

    def test_find_registered_config(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        reader.register_auth_configs(configs=[_make_auth_config("myProvider")])

        found = reader.get_config_for_auth_provider(auth_provider="myprovider")
        assert found is not None
        assert found.auth_provider == "myProvider"

    def test_not_found_returns_none(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        reader.register_auth_configs(configs=[_make_auth_config("alpha")])

        found = reader.get_config_for_auth_provider(auth_provider="nonexistent")
        assert found is None


class TestGetAllProvidersEmptyWhenNoEnvVarsAndNoRegistration:
    """get_auth_configs_for_all_auth_providers returns empty list when no env vars and no registration."""

    def test_returns_empty_list(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        all_configs = reader.get_auth_configs_for_all_auth_providers()
        assert all_configs == []


class TestRegisterAuthConfigsEmptyListIsNoop:
    """Passing an empty list to register_auth_configs is a no-op."""

    def test_empty_list_noop(self) -> None:
        env = NoProvidersEnvVars()
        reader = AuthConfigReader(environment_variables=env)

        reader.register_auth_configs(configs=[])
        # _auth_configs should still be None (not initialized)
        assert reader._auth_configs is None
