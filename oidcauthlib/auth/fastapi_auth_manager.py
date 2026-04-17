import json
import logging
import traceback
from typing import Any, Dict

import httpx
from authlib.integrations.starlette_client import StarletteOAuth2App
from fastapi import Request
from starlette.responses import JSONResponse, HTMLResponse, Response, RedirectResponse

from oidcauthlib.auth.auth_helper import AuthHelper
from oidcauthlib.auth.auth_manager import AuthManager
from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.well_known_configuration.well_known_configuration_cache_result import (
    WellKnownConfigurationCacheResult,
)
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class FastAPIAuthManager(AuthManager):
    def __init__(
        self,
        *,
        environment_variables: AbstractEnvironmentVariables,
        auth_config_reader: AuthConfigReader,
        token_reader: TokenReader,
        well_known_configuration_manager: WellKnownConfigurationManager,
    ) -> None:
        """
        Initialize the TokenStorageAuthManager with required components.
        Args:
            environment_variables (AbstractEnvironmentVariables): Environment variables handler.
            auth_config_reader (AuthConfigReader): Reader for authentication configuration.
            token_reader (TokenReader): Reader for decoding and validating tokens.
        Raises:
            ValueError: If token_exchange_manager is None.
            TypeError: If token_exchange_manager is not an instance of TokenExchangeManager.
        """
        logger.debug(f"Initializing {self.__class__.__name__}")
        super().__init__(
            environment_variables=environment_variables,
            auth_config_reader=auth_config_reader,
            token_reader=token_reader,
            well_known_configuration_manager=well_known_configuration_manager,
        )

    async def read_callback_response(self, *, request: Request) -> Response:
        """
        Handle the callback response from the OIDC provider after the user has authenticated.

        This method retrieves the authorization code and state from the request,
        decodes the state to get the tool name, and exchanges the authorization code for an access
        token and ID token. It then stores the tokens in a MongoDB collection if they do
        not already exist, or updates the existing token if it does.
        Args:
            request (Request): The FastAPI request object containing the callback data.
        Returns:
            dict[str, Any]: A dictionary containing the token information, state, code, and email.
        """
        state: str | None = request.query_params.get("state")
        code: str | None = request.query_params.get("code")
        if state is None:
            raise ValueError("State must be provided in the callback")
        state_decoded: Dict[str, Any] = AuthHelper.decode_state(state)
        logger.debug(f"State decoded: {state_decoded}")
        logger.debug(f"Code received: {code}")
        url: str | None = state_decoded.get("url")
        logger.debug(f"URL retrieved: {url}")
        auth_provider: str | None = state_decoded.get("auth_provider")
        if auth_provider is None:
            raise ValueError("Auth provider must be provided in the state")

        # now find the AuthConfig for this
        auth_config: AuthConfig | None = self.get_auth_config_for_auth_provider(auth_provider=auth_provider)
        if auth_config is None:
            raise ValueError(f"No AuthConfig found for auth provider: {auth_provider}")
        client: StarletteOAuth2App = await self.create_oauth_client(name=auth_provider)
        # create masked client secret for logging
        masked_client_text: str
        if client.client_secret is None:
            masked_client_text = "None"
        elif client.client_secret == "":
            masked_client_text = "empty"
        elif len(client.client_secret) > 3:
            masked_client_text = f"{client.client_secret[:3]}{'X' * len(client.client_secret[3:])}"
        else:
            masked_client_text = "XXX"
        logger.debug(f"OAuth client: {auth_provider} {client.client_id} {masked_client_text}")
        # Retrieve OAuth state data (code_verifier, redirect_uri, nonce) from
        # our cache instead of request.session — the gateway does not use
        # SessionMiddleware.  State was saved by create_authorization_url.
        token = await self._authorize_access_token_from_cache(
            client=client,
            request=request,
            auth_provider=auth_provider,
            state=state,
        )

        return await self.process_token_async(
            code=code,
            state_decoded=state_decoded,
            token_dict=token,
            auth_config=auth_config,
            url=url,
        )

    async def _authorize_access_token_from_cache(
        self,
        *,
        client: StarletteOAuth2App,
        request: Request,
        auth_provider: str,
        state: str,
    ) -> dict[str, Any]:
        """Exchange the authorization code for a token using cache-backed state.

        Replaces ``client.authorize_access_token(request)`` which requires
        ``SessionMiddleware``.  State data (code_verifier, redirect_uri,
        nonce) is retrieved from ``self.cache`` where it was stored by
        ``create_authorization_url``.
        """
        error = request.query_params.get("error")
        if error:
            from authlib.integrations.base_client import OAuthError

            description = request.query_params.get("error_description")
            raise OAuthError(error=error, description=description)

        code = request.query_params.get("code")

        # Retrieve state data saved by create_authorization_url
        cache_key = f"_state_{auth_provider}_{state}"
        cached_value = await self.cache.get(cache_key)
        if cached_value:
            state_data = json.loads(cached_value).get("data", {})
            await self.cache.delete(cache_key)
        else:
            logger.warning(
                "No cached state data found for key=%s — token exchange may fail (missing code_verifier/redirect_uri)",
                cache_key,
            )
            state_data = {}

        # Build params for fetch_access_token
        params: Dict[str, Any] = {"code": code, "state": state}
        if state_data.get("code_verifier"):
            params["code_verifier"] = state_data["code_verifier"]
        redirect_uri = state_data.get("redirect_uri")
        if redirect_uri:
            params["redirect_uri"] = redirect_uri

        token = await client.fetch_access_token(**params)  # type: ignore[no-untyped-call]

        # Parse id_token if present (OpenID Connect).
        # parse_id_token requires jwks_uri in server_metadata to verify the
        # signature.  When the provider was registered with explicit endpoints
        # (no server_metadata_url), jwks_uri is unavailable — skip gracefully.
        if "id_token" in token and state_data.get("nonce"):
            has_jwks = bool(client.server_metadata.get("jwks_uri"))
            if has_jwks:
                userinfo = await client.parse_id_token(
                    token,
                    nonce=state_data["nonce"],
                    leeway=120,
                )
                token["userinfo"] = userinfo
            else:
                logger.debug("Skipping id_token parsing — no jwks_uri in server metadata")

        return token  # type: ignore[no-any-return]

    # noinspection PyMethodMayBeStatic
    async def process_token_async(
        self,
        *,
        code: str | None,
        state_decoded: Dict[str, Any],
        token_dict: dict[str, Any],
        auth_config: AuthConfig,
        url: str | None,
    ) -> Response:
        """
        Process the token asynchronously.  Subclass can override this method to customize token processing.

        :param code:
        :param state_decoded:
        :param token_dict:
        :param auth_config:
        :param url:
        :return: JSONResponse containing the token dictionary.
        """
        logger.debug(f"Processing token: {code}")
        return JSONResponse(token_dict)

    async def create_signout_url(self, request: Request) -> str:
        """
        Create the signout (logout) URL for the OIDC provider.
        This method constructs the logout URL using the provider's end_session_endpoint,
        and includes id_token_hint and post_logout_redirect_uri if available.
        Args:
            request (Request): The FastAPI request object.
        Returns:
            str: The logout URL to redirect the user to for signout.
        """
        # Try to extract audience from query params, session, or state
        audience = request.query_params.get("audience")
        if not audience:
            # Try to get from state if present
            state = request.query_params.get("state")
            if state:
                try:
                    state_decoded = AuthHelper.decode_state(state)
                    audience = state_decoded.get("audience")
                except Exception:
                    audience = None
        if not audience:
            # Fallback to first configured audience
            auth_configs = self.auth_config_reader.get_auth_configs_for_all_auth_providers()
            audience = auth_configs[0].audience if auth_configs else None
        if not audience:
            raise ValueError("No audience found for signout")
        # Get AuthConfig for audience
        auth_provider = self.auth_config_reader.get_provider_for_audience(audience=audience)
        if not auth_provider:
            raise ValueError(f"No auth provider found for audience: {audience}")
        auth_config = self.auth_config_reader.get_config_for_auth_provider(auth_provider=auth_provider)
        if not auth_config:
            raise ValueError(f"No AuthConfig found for audience: {audience}")
        # Discover end_session_endpoint
        end_session_endpoint = None
        if auth_config.well_known_uri:
            try:
                well_known_result: (
                    WellKnownConfigurationCacheResult | None
                ) = await self.well_known_configuration_manager.get_async(auth_config=auth_config)
                well_known_config: dict[str, Any] | None = (
                    well_known_result.well_known_config if well_known_result else None
                )
                end_session_endpoint = well_known_config.get("end_session_endpoint") if well_known_config else None
            except Exception as e:
                logger.warning(f"Could not discover end_session_endpoint: {e}")
        if not end_session_endpoint and auth_config.issuer:
            end_session_endpoint = auth_config.issuer.rstrip("/") + "/protocol/openid-connect/logout"
        if not end_session_endpoint:
            raise ValueError("No end_session_endpoint found for signout")
        # Try to get id_token from cache (if available)
        id_token = None
        try:
            token_text = await self.cache.get(key=audience)
            if token_text:
                token: Dict[str, Any] = json.loads(token_text)
                id_token = token.get("id_token")
        except Exception as e:
            logger.warning(f"Could not get id_token for signout: {e}")
        # Build post_logout_redirect_uri
        post_logout_redirect_uri = str(request.url_for("login")) if hasattr(request, "url_for") else self.redirect_uri
        # Build logout URL
        params = {}
        if id_token:
            params["id_token_hint"] = id_token
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        logout_url = httpx.URL(end_session_endpoint).copy_merge_params(params)
        logger.info(f"Constructed signout URL: {logout_url}")
        return str(logout_url)

    async def sign_out(
        self,
        *,
        request: Request,
    ) -> Response:
        """
        Handle the sign_out route for authentication.
        This route logs out the user by clearing authentication tokens and optionally redirects to a confirmation page or login.
        Args:
            request (Request): The incoming request object.
        """
        logger.info(f"Received request for signout: {request.url}")
        try:
            sign_out_url = await self.create_signout_url(request=request)

            await self.process_sign_out_async(
                request=request,
            )
            # If sign_out_url is provided, redirect to it
            if sign_out_url:
                logger.info(f"Redirecting to sign_out URL: {sign_out_url}")
                return RedirectResponse(sign_out_url, status_code=302)
            # Otherwise, return a simple confirmation page
            html_content = "<html><body><h2>Signed Out</h2><p>You have been signed out.</p></body></html>"
            return HTMLResponse(content=html_content, status_code=200)
        except Exception as e:
            exc: str = traceback.format_exc()
            logger.error(f"Error processing sign_out: {e}\n{exc}")
            return JSONResponse(
                content={"error": f"Error processing sign_out: {e}\n{exc}"},
                status_code=500,
            )

    async def process_sign_out_async(
        self,
        *,
        request: Request,
    ) -> None:
        """
        Process the sign_out asynchronously.  Subclass can override this method to customize sign_out processing.

        :param request:
        """
        pass
