from pydantic import BaseModel, Field

from oidcauthlib.auth.models.client_key_set import ClientKeySet


class WellKnownConfigurationCacheResult(BaseModel):
    well_known_uri: str = Field(
        description="The well-known configuration URI used to fetch the configuration"
    )
    well_known_config: dict[str, object] | None = Field(
        description="The OIDC well-known configuration document"
    )
    client_key_set: ClientKeySet | None = Field(
        description="The client key set containing JWKS and related info"
    )
