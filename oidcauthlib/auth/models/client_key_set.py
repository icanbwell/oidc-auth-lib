from typing import Any, Dict

from pydantic import BaseModel, Field

from oidcauthlib.auth.config.auth_config import AuthConfig


class ClientKeySet(BaseModel):
    auth_config: AuthConfig = Field(description="OIDC authentication configuration")
    well_known_config: dict[str, Any] | None = Field(
        description="OIDC well-known configuration document"
    )
    kids: list[str] | None = Field(
        description="List of Key IDs (kid) available in the JWKS"
    )
    keys: list[Dict[str, Any]] | None = Field(description="List of keys in the JWKS")
