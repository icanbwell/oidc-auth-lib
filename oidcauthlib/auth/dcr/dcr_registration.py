from datetime import datetime
from typing import Any, ClassVar, Optional

from pydantic import Field

from oidcauthlib.auth.models.base_db_model import BaseDbModel


class DcrRegistration(BaseDbModel):
    """Persisted DCR credentials in MongoDB."""

    SCHEMA_VERSION: ClassVar[int] = 3

    schema_version: int = Field(default=0, description="Schema version for cache invalidation on model changes")
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

    def is_schema_current(self) -> bool:
        return self.schema_version == self.SCHEMA_VERSION
