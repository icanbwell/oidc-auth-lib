import logging
import typing
import re
from typing import Optional, Sequence, Pattern

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.token_reader import TokenReader

logger = logging.getLogger(__name__)


class TokenReaderMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware to extract and decode Authorization tokens, attaching the decoded token to request.state.token.
    Supports regex-based route matching for requiring or optionally allowing tokens.

    Args:
        require_token_routes: List of regex patterns. If a request path matches any, a valid token is required.
        optional_token_routes: List of regex patterns. If a request path matches any, token is optional.
        If a path matches both, require_token_routes takes precedence.
    """

    def __init__(
        self,
        app: ASGIApp,
        auth_config_reader: AuthConfigReader,
        algorithms: Optional[list[str]] = None,
        require_token_routes: Optional[Sequence[str]] = None,
        optional_token_routes: Optional[Sequence[str]] = None,
    ):
        super().__init__(app)
        self.token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=algorithms
        )
        self.require_token_patterns: list[Pattern[str]] = [
            re.compile(p) for p in (require_token_routes or [])
        ]
        self.optional_token_patterns: list[Pattern[str]] = [
            re.compile(p) for p in (optional_token_routes or [])
        ]

    @staticmethod
    def _is_route_match(path: str, patterns: list[Pattern[str]]) -> bool:
        return any(p.match(path) for p in patterns)

    async def dispatch(
        self,
        request: Request,
        call_next: typing.Callable[[Request], typing.Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        require_token = self._is_route_match(path, self.require_token_patterns)
        optional_token = self._is_route_match(path, self.optional_token_patterns)

        # If neither parameter is set, require token for all routes except /health
        if not self.require_token_patterns and not self.optional_token_patterns:
            enforce_token = path != "/health"
        else:
            enforce_token = require_token or (
                not optional_token and not self.require_token_patterns
            )
        try:
            auth_header = request.headers.get("authorization")
            token: str | None = self.token_reader.extract_token(
                authorization_header=auth_header
            )
            if token:
                # Decode token (signature verification ON)
                decoded = await self.token_reader.decode_token_async(
                    token=token, verify_signature=True
                )
                request.state.token = decoded
            else:
                request.state.token = None
                if enforce_token:
                    return JSONResponse(
                        {"detail": "Authorization token required"}, status_code=401
                    )
        except Exception as e:
            logger.exception(f"Error reading token: {e}")
            request.state.token = None
            if enforce_token:
                return JSONResponse(
                    {"detail": "Invalid or missing authorization token"},
                    status_code=401,
                )
        response = await call_next(request)
        return response
