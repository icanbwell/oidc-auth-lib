from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from oidcauthlib.auth.models.client_key_set import ClientKeySet


class WellKnownConfigurationCacheResult(BaseModel):
    SCHEMA_VERSION: ClassVar[int] = 1

    model_config = ConfigDict(extra="ignore")

    schema_version: int = Field(default=1, description="Schema version for cache invalidation on model changes")
    well_known_uri: str = Field(description="The well-known configuration URI used to fetch the configuration")
    well_known_config: dict[str, object] | None = Field(description="The OIDC well-known configuration document")
    client_key_set: ClientKeySet | None = Field(description="The client key set containing JWKS and related info")

    def is_schema_current(self) -> bool:
        return self.schema_version == self.SCHEMA_VERSION
