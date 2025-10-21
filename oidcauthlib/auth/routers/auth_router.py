import logging
import traceback

from enum import Enum
from typing import Any, Sequence, Annotated, Union, List, Optional

from fastapi import APIRouter
from fastapi import params
from fastapi.params import Depends
from fastapi.responses import RedirectResponse
from starlette.datastructures import URL
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, Response

from oidcauthlib.api_container import (
    get_auth_manager,
    get_auth_config_reader,
    get_environment_variables,
)
from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import (
    AuthConfigReader,
)

from oidcauthlib.auth.fastapi_auth_manager import FastAPIAuthManager
from oidcauthlib.utilities.environment.environment_variables import EnvironmentVariables
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class AuthRouter:
    """
    AuthRouter is a FastAPI router for handling authentication-related routes.
    """

    def __init__(
        self,
        *,
        prefix: str = "/auth_test",
        tags: list[str | Enum] | None = None,
        dependencies: Sequence[params.Depends] | None = None,
    ) -> None:
        """
        Initialize the AuthRouter with a prefix, tags, and dependencies.
        Args:
            prefix (str): The prefix for the router's routes, default is "/auth".
            tags (list[str | Enum] | None): Tags to categorize the routes, default is ["models"].
            dependencies (Sequence[params.Depends] | None): Dependencies to be applied to all routes in this router, default is an empty list.
        """
        self.prefix = prefix
        self.tags = tags or ["models"]
        self.dependencies = dependencies or []
        self.router = APIRouter(
            prefix=self.prefix, tags=self.tags, dependencies=self.dependencies
        )
        self._register_routes()

    def _register_routes(self) -> None:
        """Register all routes for this router"""
        self.router.add_api_route(
            "/login", self.login, methods=["GET"], response_model=None
        )
        self.router.add_api_route(
            "/callback",
            self.auth_callback,
            methods=["GET", "POST"],
            response_model=None,
        )
        self.router.add_api_route(
            "/signout",
            self.signout,
            methods=["GET"],
            response_model=None,
        )

    # noinspection PyMethodMayBeStatic
    async def login(
        self,
        request: Request,
        auth_manager: Annotated[AuthManager, Depends(get_auth_manager)],
        auth_config_reader: Annotated[
            AuthConfigReader, Depends(get_auth_config_reader)
        ],
        environment_variables: Annotated[
            EnvironmentVariables, Depends(get_environment_variables)
        ],
        audience: str | None = None,
    ) -> Union[RedirectResponse, JSONResponse]:
        """
        Handle the login route for authentication.
        This route initiates the authentication process by redirecting the user to the
        authorization server's login page.
        Args:
            request (Request): The incoming request object.
            auth_manager (AuthManager): The authentication manager instance.
            auth_config_reader (AuthConfigReader): The authentication configuration reader instance.
            environment_variables (EnvironmentVariables): The environment variables instance.
            audience (str | None): The audience for which to authenticate. If None, the first audience from the config will be used.
        """
        auth_redirect_uri_text: Optional[str] = environment_variables.auth_redirect_uri
        redirect_uri1: URL = (
            URL(auth_redirect_uri_text)
            if auth_redirect_uri_text
            else request.url_for("auth_callback")
        )

        try:
            my_audience: str | None = audience
            auth_config: AuthConfig | None
            if audience is None:
                auth_configs: List[AuthConfig] = (
                    auth_config_reader.get_auth_configs_for_all_auth_providers()
                )
                auth_config = auth_configs[0] if auth_configs else None
                my_audience = auth_config.audience if auth_config else None
                if my_audience is None:
                    raise ValueError("No audience found in auth configuration")
            else:
                provider_for_audience: str | None = (
                    auth_config_reader.get_provider_for_audience(audience=audience)
                )
                if provider_for_audience is None:
                    raise ValueError(f"No provider found for audience: {audience}")

                auth_config = auth_config_reader.get_config_for_auth_provider(
                    auth_provider=provider_for_audience
                )
                if auth_config is None:
                    raise ValueError(
                        f"auth_config must not be None for provider: {audience}"
                    )

            if not auth_config:
                raise ValueError("No auth config found")

            if not isinstance(auth_config, AuthConfig):
                raise TypeError("auth_config is not of type AuthConfig")

            if not my_audience:
                raise ValueError("my_audience must not be None")

            issuer: str | None = auth_config.issuer

            if not issuer:
                raise ValueError("issuer must not be None in auth config")

            url = await auth_manager.create_authorization_url(
                redirect_uri=str(redirect_uri1),
                audience=my_audience,
                issuer=issuer,
                url=str(request.url),
                referring_email=environment_variables.oauth_referring_email,
                referring_subject=environment_variables.oauth_referring_subject,
            )

            logger.info(
                f"Redirecting to authorization URL: {url} (audience: {my_audience})"
            )

            return RedirectResponse(url, status_code=302)
        except Exception as e:
            logger.exception(f"Error processing auth login: {e}\n")
            return JSONResponse(
                content={"error": f"Error processing auth login: {e}\n"},
                status_code=500,
            )

    # noinspection PyMethodMayBeStatic
    async def auth_callback(
        self,
        request: Request,
        auth_manager: Annotated[FastAPIAuthManager, Depends(get_auth_manager)],
    ) -> Union[JSONResponse, HTMLResponse]:
        logger.info(f"Received request for auth callback: {request.url}")
        try:
            content: dict[str, Any] = await auth_manager.read_callback_response(
                request=request,
            )
            return JSONResponse(content)
        except Exception as e:
            exc: str = traceback.format_exc()
            logger.error(f"Error processing auth callback: {e}\n{exc}")
            return JSONResponse(
                content={"error": f"Error processing auth callback: {e}\n{exc}"},
                status_code=500,
            )

    # noinspection PyMethodMayBeStatic
    async def signout(
        self,
        request: Request,
        auth_manager: Annotated[FastAPIAuthManager, Depends(get_auth_manager)],
    ) -> Response:
        """
        Handle the signout route for authentication.
        This route logs out the user by clearing authentication tokens and optionally redirects to a confirmation page or login.
        Args:
            request (Request): The incoming request object.
            auth_manager (AuthManager): The authentication manager instance.
        """
        logger.info(f"Received request for signout: {request.url}")
        try:
            signout_url = await auth_manager.create_signout_url(request=request)
            # If signout_url is provided, redirect to it
            if signout_url:
                logger.info(f"Redirecting to signout URL: {signout_url}")
                return RedirectResponse(signout_url, status_code=302)
            # Otherwise, return a simple confirmation page
            html_content = "<html><body><h2>Signed Out</h2><p>You have been signed out.</p></body></html>"
            return HTMLResponse(content=html_content, status_code=200)
        except Exception as e:
            exc: str = traceback.format_exc()
            logger.error(f"Error processing signout: {e}\n{exc}")
            return JSONResponse(
                content={"error": f"Error processing signout: {e}\n{exc}"},
                status_code=500,
            )

    def get_router(self) -> APIRouter:
        """ """
        return self.router
