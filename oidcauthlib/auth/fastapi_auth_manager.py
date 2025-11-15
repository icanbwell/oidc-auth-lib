import json
import logging
from typing import Any, Dict

import httpx
from authlib.integrations.starlette_client import StarletteOAuth2App
from fastapi import Request
from oidcauthlib.auth.auth_helper import AuthHelper
from oidcauthlib.auth.auth_manager import AuthManager

from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class FastAPIAuthManager(AuthManager):
    async def read_callback_response(self, *, request: Request) -> dict[str, Any]:
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
        audience: str | None = state_decoded.get("audience")
        logger.debug(f"Audience retrieved: {audience}")
        issuer: str | None = state_decoded.get("issuer")
        if issuer is None:
            raise ValueError("Issuer must be provided in the callback")
        logger.debug(f"Issuer retrieved: {issuer}")
        url: str | None = state_decoded.get("url")
        logger.debug(f"URL retrieved: {url}")
        logger.debug(f"Creating OAuth2 client for audience: {audience}")
        if audience is None:
            raise ValueError("Audience must be provided in the callback")
        client: StarletteOAuth2App = self.create_oauth_client(audience=audience)
        masked_client_text: str
        if client.client_secret is None:
            masked_client_text = "None"
        elif client.client_secret == "":
            masked_client_text = "empty"
        elif len(client.client_secret) > 3:
            masked_client_text = (
                f"{client.client_secret[:3]}{'X' * len(client.client_secret[3:])}"
            )
        else:
            masked_client_text = "XXX"
        logger.debug(f"OAuth client: {client.client_id} {masked_client_text}")
        token: dict[str, Any] = await client.authorize_access_token(request)  # type: ignore[no-untyped-call]

        return token

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
            auth_configs = (
                self.auth_config_reader.get_auth_configs_for_all_auth_providers()
            )
            audience = auth_configs[0].audience if auth_configs else None
        if not audience:
            raise ValueError("No audience found for signout")
        # Get AuthConfig for audience
        auth_provider = self.auth_config_reader.get_provider_for_audience(
            audience=audience
        )
        if not auth_provider:
            raise ValueError(f"No auth provider found for audience: {audience}")
        auth_config = self.auth_config_reader.get_config_for_auth_provider(
            auth_provider=auth_provider
        )
        if not auth_config:
            raise ValueError(f"No AuthConfig found for audience: {audience}")
        # Discover end_session_endpoint
        end_session_endpoint = None
        if auth_config.well_known_uri:
            try:
                async with httpx.AsyncClient(timeout=5) as async_client:
                    resp = await async_client.get(auth_config.well_known_uri)
                resp.raise_for_status()
                end_session_endpoint = resp.json().get("end_session_endpoint")
            except Exception as e:
                logger.warning(f"Could not discover end_session_endpoint: {e}")
        if not end_session_endpoint and auth_config.issuer:
            end_session_endpoint = (
                auth_config.issuer.rstrip("/") + "/protocol/openid-connect/logout"
            )
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
        post_logout_redirect_uri = (
            str(request.url_for("login"))
            if hasattr(request, "url_for")
            else self.redirect_uri
        )
        # Build logout URL
        params = {}
        if id_token:
            params["id_token_hint"] = id_token
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        logout_url = httpx.URL(end_session_endpoint).copy_merge_params(params)
        logger.info(f"Constructed signout URL: {logout_url}")
        return str(logout_url)
