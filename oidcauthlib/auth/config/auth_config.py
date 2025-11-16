from pydantic import BaseModel, ConfigDict, Field
from typing import Optional


class AuthConfig(BaseModel):
    """
    Represent the configuration for an auth provider.  Usually read from environment variables.
    """

    model_config = ConfigDict(extra="forbid")  # Prevents any additional properties

    auth_provider: str = Field(
        ...,
        description="The name of the auth provider, typically used to identify the provider in logs and error messages.",
    )
    friendly_name: str = Field(
        ...,
        description="A friendly name for the auth provider, used for display purposes.",
    )
    audience: str = Field(
        ...,
        description="The audience for the auth provider, typically the API or service that the token is intended for.",
    )
    issuer: Optional[str] = Field(
        default=None,
        description="The issuer of the token, typically the URL of the auth provider.",
    )
    client_id: str = Field(
        ...,
        description="The client ID for the auth provider, used to identify the application making the request.",
    )
    client_secret: Optional[str] = Field(
        default=None,
        description="The client secret for the auth provider, used to authenticate the application making the request.",
    )
    well_known_uri: Optional[str] = Field(
        default=None,
        description="The URI to the well-known configuration of the auth provider, used to discover endpoints and other metadata.",
    )
