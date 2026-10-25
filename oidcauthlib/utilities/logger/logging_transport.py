import logging

import httpx2
from typing import override

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.utilities.logger.logging_response import (
    LoggingResponse,
)

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["HTTP"])


class LoggingTransport(httpx2.AsyncBaseTransport):
    """
    A custom HTTP transport that logs request and response details.
    This class extends httpx2.AsyncBaseTransport to log the request method, URL,
    headers, and content before sending the request, and logs the response status code,
    headers, and content as it is streamed back.
    It is designed to wrap the transport used by authlib's httpx_client integration
    (authlib.integrations.httpx_client, which is httpx2-based as of authlib 1.8.0 --
    see authlib#909), so it must be built on httpx2, not httpx, to be a valid
    `transport=` for that client.
    This transport can be used to monitor and debug HTTP requests and responses in an application.
    """

    def __init__(self, transport: httpx2.AsyncBaseTransport) -> None:
        """
        Initialize the LoggingTransport with a given transport.
        Args:
            transport (httpx2.AsyncBaseTransport): The underlying transport to wrap.
            This transport will handle the actual HTTP requests and responses.
        """
        self.transport: httpx2.AsyncBaseTransport = transport

    @override
    async def handle_async_request(self, request: httpx2.Request) -> LoggingResponse:
        """
        Handle an asynchronous HTTP request, logging the request details and returning a LoggingResponse.
        Args:
            request (httpx2.Request): The HTTP request to handle.
        Returns:
            LoggingResponse: A custom response object that logs the response details.
        """
        # log the request
        logger.debug(f" ====== Request: {request.method} {request.url} =====")
        logger.debug(f"Headers: {request.headers}")
        if request.content:
            logger.debug(f"Content: {request.content.decode('utf-8', errors='ignore')}")

        response = await self.transport.handle_async_request(request)

        return LoggingResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )
