"""
Override the root-level autouse fixtures that require MongoDB.
Auth unit tests use mocks exclusively and do not need database access.
"""

from typing import AsyncGenerator

import pytest


@pytest.fixture(scope="function", autouse=True)
async def initialize_caches() -> AsyncGenerator[None, None]:
    """No-op override of the root conftest's initialize_caches fixture."""
    yield
