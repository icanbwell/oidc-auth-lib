import logging
import typing
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.token_reader import TokenReader

logger = logging.getLogger(__name__)


class TokenReaderMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        auth_config_reader: AuthConfigReader,
        algorithms: Optional[list[str]] = None,
    ):
        super().__init__(app)
        self.token_reader = TokenReader(
            auth_config_reader=auth_config_reader, algorithms=algorithms
        )

    async def dispatch(
        self,
        request: Request,
        call_next: typing.Callable[[Request], typing.Awaitable[Response]],
    ) -> Response:
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
        except Exception as e:
            logger.exception(f"Error reading token: {e}")
            request.state.token = None  # Optionally, log or handle error
        response = await call_next(request)
        return response
