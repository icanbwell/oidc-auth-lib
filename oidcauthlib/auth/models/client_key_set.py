from typing import Any

from joserfc._keys import KeySet
from pydantic import BaseModel, Field, SkipValidation

from oidcauthlib.auth.config.auth_config import AuthConfig


class ClientKeySet(BaseModel):
    auth_config: AuthConfig = Field(description="OIDC authentication configuration")
    well_known_config: dict[str, Any] | None = Field(
        default=None, description="OIDC well-known configuration document"
    )
    jwks: SkipValidation[KeySet | None] = Field(
        default=None, description="JSON Web Key Set for token verification"
    )
    kids: list[str] | None = Field(
        default=None, description="List of Key IDs (kid) available in the JWKS"
    )

    model_config = {"arbitrary_types_allowed": True}
