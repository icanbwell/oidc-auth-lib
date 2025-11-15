import threading
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from oidcauthlib.container.interfaces import IContainer


class ContainerRegistry:
    """
    Registry using the complete protocol.
    """

    _default_container: IContainer | None = None
    _current_container: IContainer | None = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def set_default(cls, container: IContainer) -> None:
        """Set the default container."""
        with cls._lock:
            cls._default_container = container
            if cls._current_container is None:
                cls._current_container = container

    @classmethod
    def get_current(cls) -> IContainer:
        """Get the current active container."""
        with cls._lock:
            if cls._current_container is None:
                raise RuntimeError(
                    "No container registered. Call ContainerRegistry.set_default() first."
                )
            return cls._current_container

    @classmethod
    @asynccontextmanager
    async def override(cls, container: IContainer) -> AsyncGenerator[IContainer, None]:
        """Temporarily override the current container."""
        with cls._lock:
            old_container = cls._current_container
            cls._current_container = container

        try:
            yield container
        finally:
            with cls._lock:
                cls._current_container = old_container

    @classmethod
    def reset(cls) -> None:
        """Reset to default container."""
        with cls._lock:
            cls._current_container = cls._default_container
