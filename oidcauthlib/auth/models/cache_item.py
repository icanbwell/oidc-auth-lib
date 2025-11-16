from datetime import datetime
from typing import Optional

from oidcauthlib.auth.models.base_db_model import BaseDbModel
from pydantic import Field


class CacheItem(BaseDbModel):
    """
    Represents a cache item with a key and value.
    This model is used to store key-value pairs in the cache.
    """

    key: str = Field(
        ...,
        description="The key for the cache item; used to identify the item in the cache.",
    )
    value: Optional[str] = Field(
        default=None,
        description="The value associated with the key in the cache item; arbitrary string data.",
    )

    deleted: datetime | None = Field(
        default=None,
        description="The timestamp when the cache item was deleted, if applicable.",
    )
    created: datetime = Field(
        ..., description="The creation time of the cache item as a datetime object."
    )
