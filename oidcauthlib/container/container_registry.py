import threading
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import AsyncGenerator

from oidcauthlib.container.interfaces import IContainer

# Context variable for request-scoped containers (thread-safe for async)
_request_container: ContextVar[IContainer | None] = ContextVar(
    "request_container", default=None
)


class ContainerRegistry:
    """
    Registry using the complete protocol.
    Supports both application-level (default) and request-scoped containers.
    """

    _default_container: IContainer | None = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def set_default(cls, container: IContainer) -> None:
        """Set the default (application-level) container."""
        with cls._lock:
            cls._default_container = container

    @classmethod
    def get_current(cls) -> IContainer:
        """
        Get the current active container.
        Returns request-scoped container if available, otherwise the default container.
        """
        # Check for request-scoped container first
        request_container = _request_container.get()
        if request_container is not None:
            return request_container

        # Fall back to default container
        with cls._lock:
            if cls._default_container is None:
                raise RuntimeError(
                    "No container registered. Call ContainerRegistry.set_default() first."
                )
            return cls._default_container

    @classmethod
    def set_scoped(cls, container: IContainer) -> None:
        """Set the request-scoped container for the current context."""
        _request_container.set(container)

    @classmethod
    def clear_scoped(cls) -> None:
        """Clear the request-scoped container for the current context."""
        _request_container.set(None)

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
