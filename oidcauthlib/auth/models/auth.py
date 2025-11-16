from datetime import datetime
from typing import Optional, Any, List, Union

from pydantic import BaseModel, ConfigDict, Field


class AuthInformation(BaseModel):
    """
    Represents the information about the authenticated user or client.
    """

    model_config = ConfigDict(extra="forbid")  # Prevents any additional properties

    redirect_uri: Optional[str] = Field(
        default=None,
        description="The URI to redirect to after authentication, if applicable.",
    )
    claims: Optional[dict[str, Any]] = Field(
        default=None,
        description="The claims associated with the authenticated user or client.",
    )
    audience: Optional[Union[str, List[str]]] = Field(
        default=None,
        description="The audience for which the token is intended; can be a single string or a list of strings.",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="The expiration time of the authentication token, if applicable.",
    )

    email: Optional[str] = Field(
        default=None, description="The email of the authenticated user, if available."
    )
    subject: Optional[str] = Field(
        default=None,
        description="The subject (sub) claim from the token, representing the unique identifier of the user.",
    )
    user_name: Optional[str] = Field(
        default=None, description="The name of the authenticated user, if available."
    )
