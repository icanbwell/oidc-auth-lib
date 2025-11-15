from datetime import datetime
from typing import Optional, Any, List, Union

from pydantic import BaseModel, ConfigDict


class AuthInformation(BaseModel):
    """
    Represents the information about the authenticated user or client.
    """

    model_config = ConfigDict(extra="forbid")  # Prevents any additional properties

    redirect_uri: Optional[str] = None
    """The URI to redirect to after authentication, if applicable."""
    claims: Optional[dict[str, Any]] = None
    """The claims associated with the authenticated user or client."""
    audience: Optional[Union[str, List[str]]] = None
    """The audience for which the token is intended, can be a single string or a list of strings."""
    expires_at: Optional[datetime] = None
    """The expiration time of the authentication token, if applicable."""

    email: Optional[str] = None
    """The email of the authenticated user, if available."""
    subject: Optional[str] = None
    """The subject (sub) claim from the token, representing the unique identifier of the user."""

    user_name: Optional[str] = None
    """The name of the authenticated user, if available."""
