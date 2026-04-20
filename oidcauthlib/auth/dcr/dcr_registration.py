from datetime import datetime
from typing import Any, Optional

from pydantic import Field

from oidcauthlib.auth.models.base_db_model import BaseDbModel


class DcrRegistration(BaseDbModel):
    """Persisted DCR credentials in MongoDB."""

    created: datetime = Field(description="When the registration was created.")
    updated: Optional[datetime] = Field(default=None, description="When the registration was last updated.")
    auth_provider: str = Field(description="The normalized auth provider key.")
    registration_url: str = Field(description="The DCR endpoint URL.")
    client_id: str = Field(description="The client_id from DCR.")
    client_secret: Optional[str] = Field(default=None, description="The client_secret from DCR (if any).")
    client_secret_expires_at: int = Field(
        default=0,
        description="Unix timestamp when client_secret expires. 0 = no expiry.",
    )
    registration_response: dict[str, Any] = Field(default_factory=dict, description="The full DCR response.")
