from typing import Any

from joserfc._keys import KeySet
from pydantic import BaseModel

from oidcauthlib.auth.config.auth_config import AuthConfig


class ClientKeySet(BaseModel):
    auth_config: AuthConfig
    well_known_config: dict[str, Any] | None
    jwks: KeySet | None
    kids: list[str] | None
