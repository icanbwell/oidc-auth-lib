"""
FastAPI middleware for request-scoped dependency injection.

This middleware creates a new scoped container for each request,
allowing services registered with .scoped() or .register() to be
instantiated once per request and shared across all dependencies
within that request.
"""

from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from oidcauthlib.container.container_registry import ContainerRegistry
from oidcauthlib.container.interfaces import IContainer


class ContainerScopeMiddleware(BaseHTTPMiddleware):
    """
    Middleware that creates a scoped container for each HTTP request.

    Usage:
        app = FastAPI()
        app.add_middleware(ContainerScopeMiddleware)
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Create a scoped container for this request."""
        # Get the default container and create a child scope
        default_container: IContainer = ContainerRegistry.get_current()
        scoped_container: IContainer = default_container.create_scope()

        # Set the scoped container for this request context
        ContainerRegistry.set_scoped(scoped_container)

        try:
            # Process the request with the scoped container
            response = await call_next(request)
            return response
        finally:
            # Clean up the scoped container after the request
            ContainerRegistry.clear_scoped()
