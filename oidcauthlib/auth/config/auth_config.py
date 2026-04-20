from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Optional, Any, Literal, Self


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
    client_id: Optional[str] = Field(
        default=None,
        description="The client ID for the auth provider. Optional when using DCR (registration_url).",
    )
    client_secret: Optional[str] = Field(
        default=None,
        description="The client secret for the auth provider, used to authenticate the application making the request.",
    )
    well_known_uri: Optional[str] = Field(
        default=None,
        description="The URI to the well-known configuration of the auth provider, used to discover endpoints and other metadata.",
    )

    scope: str = Field(
        ...,
        description="The scopes requested for the auth provider, typically a space-separated list of scopes.",
    )

    extra_info: dict[str, Any] | None = Field(
        default=None,
        description=(
            "A dictionary of extra string configuration values for the auth provider. "
            "Keys and values must be strings (for example, settings derived from environment "
            "variables or other string-based configuration sources)."
        ),
    )

    authorization_endpoint: Optional[str] = Field(
        default=None,
        description="The authorization endpoint URL (explicit-endpoints flow).",
    )
    token_endpoint: Optional[str] = Field(
        default=None,
        description="The token endpoint URL (explicit-endpoints flow).",
    )
    use_pkce: bool = Field(
        default=True,
        description="Whether to use PKCE. Defaults to True (OAuth 2.1 standard).",
    )
    pkce_method: Literal["S256", "plain"] | None = Field(
        default="S256",
        description="PKCE challenge method. Defaults to S256.",
    )
    registration_url: Optional[str] = Field(
        default=None,
        description="RFC 7591 Dynamic Client Registration endpoint URL.",
    )

    @model_validator(mode="after")
    def _require_client_id_or_registration_url(self) -> Self:
        if not self.client_id and not self.registration_url:
            raise ValueError(
                f"AuthConfig for '{self.auth_provider}' must have either client_id or registration_url (for DCR)"
            )
        return self
