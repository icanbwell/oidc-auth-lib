"""
middleware.py - Enhanced version with X-Request-ID header support
"""

import logging
import typing
from typing import override
from uuid import uuid4
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from oidcauthlib.container.container_registry import ContainerRegistry
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["REQUEST_SCOPE"])

# Paths for which request logging should be suppressed (e.g., health checks)
_SUPPRESSED_LOG_PATHS = {"/health", "/health/"}


class RequestScopeMiddleware(BaseHTTPMiddleware):
    """
    Middleware that manages request scope lifecycle for dependency injection.

    Features:
    - Supports X-Request-ID header for request tracing
    - Adds X-Request-ID to response headers
    - Comprehensive logging (suppressed for health endpoint)
    - Proper cleanup even on errors

    Usage:
        app = FastAPI()
        app.add_middleware(RequestScopeMiddleware)
    """

    @override
    async def dispatch(
        self,
        request: Request,
        call_next: typing.Callable[[Request], typing.Awaitable[Response]],
    ) -> Response:
        """Process each request with request scope management."""

        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid4())
            if request.url.path not in _SUPPRESSED_LOG_PATHS:
                logger.debug(f"Generated new request ID: {request_id}")
        else:
            if request.url.path not in _SUPPRESSED_LOG_PATHS:
                logger.debug(f"Using request ID from header: {request_id}")

        # Store request ID in request state for access in endpoints
        request.state.request_id = request_id

        # Begin request scope
        ContainerRegistry.begin_request_scope(request_id)
        if request.url.path not in _SUPPRESSED_LOG_PATHS:
            logger.debug(
                f"→ {request.method} {request.url.path} (request_id={request_id[:8]}...)"
            )

        try:
            # Process the request
            response = await call_next(request)

            # Add request ID to response headers for tracing
            response.headers["X-Request-ID"] = request_id

            if request.url.path not in _SUPPRESSED_LOG_PATHS:
                logger.debug(
                    f"← {request.method} {request.url.path} "
                    f"[{response.status_code}] "
                    f"(request_id={request_id[:8]}...)"
                )

            return response

        except Exception as e:
            if request.url.path not in _SUPPRESSED_LOG_PATHS:
                logger.error(
                    f"✗ {request.method} {request.url.path} "
                    f"(request_id={request_id[:8]}...): {type(e).__name__}: {e}",
                    exc_info=True,
                )
            raise

        finally:
            # Always clean up request scope
            ContainerRegistry.end_request_scope()
            if request.url.path not in _SUPPRESSED_LOG_PATHS:
                logger.debug(
                    f"Request scope cleaned up (request_id={request_id[:8]}...)"
                )
