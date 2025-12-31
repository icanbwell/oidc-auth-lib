from oidcauthlib.utilities.environment.oidc_environment_variables import (
    OidcEnvironmentVariables,
)


class CacheToCollectionMapper:
    def __init__(self, *, environment_variables: OidcEnvironmentVariables) -> None:
        """Initialize the cache to collection mapper."""
        self.environment_variables = environment_variables
        if self.environment_variables is None:
            raise ValueError("Environment variables must be provided")
        if not isinstance(environment_variables, OidcEnvironmentVariables):
            raise TypeError(
                f"environment_variables must be an instance of EnvironmentVariables: {type(environment_variables).__name__}"
            )

    # noinspection PyMethodMayBeStatic
    def get_collection_for_cache(self, *, cache_name: str) -> str | None:
        """Map cache name to collection name.

        Args:
            cache_name: Name of the cache.

        Returns:
            str: Corresponding collection name.
        """
        mapping = {
            "well_known_configuration": self.environment_variables.well_known_configuration_collection_name,
        }
        return mapping.get(cache_name)
