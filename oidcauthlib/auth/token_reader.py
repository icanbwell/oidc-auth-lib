import datetime
import json
import logging
import time
import uuid
from typing import Optional, Any, Dict, List, cast
from uuid import UUID
from zoneinfo import ZoneInfo

from joserfc import jwt, jws
from joserfc._rfc7515.model import CompactSignature
from joserfc.errors import ExpiredTokenError

from oidcauthlib.auth.exceptions.authorization_bearer_token_expired_exception import (
    AuthorizationBearerTokenExpiredException,
)
from oidcauthlib.auth.exceptions.authorization_bearer_token_invalid_exception import (
    AuthorizationBearerTokenInvalidException,
)
from oidcauthlib.auth.exceptions.authorization_bearer_token_missing_exception import (
    AuthorizationBearerTokenMissingException,
)
from oidcauthlib.auth.models.token import Token
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from .models.client_key_set import ClientKeySet
from .well_known_config_manager import WellKnownConfigurationManager

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class TokenReader:
    """
    TokenReader is a utility class for reading and verifying JWT tokens using JWKS (JSON Web Key Set).
    """

    def __init__(
        self,
        *,
        algorithms: Optional[list[str]] = None,
        well_known_manager: WellKnownConfigurationManager,
    ):
        """
        Initializes the TokenReader with the JWKS URI or Well-Known URI, issuer, audience, and algorithms.
        Args:
            algorithms (Optional[list[str]]): The list of algorithms to use for verifying the JWT.
            well_known_manager (WellKnownConfigurationManager): The manager to handle well-known configurations and JWKS.
        """
        self.uuid: UUID = uuid.uuid4()
        self.algorithms: List[str] | None = algorithms or None

        self.well_known_manager = well_known_manager
        if self.well_known_manager is None:
            raise ValueError("WellKnownConfigurationManager must be provided")
        if not isinstance(self.well_known_manager, WellKnownConfigurationManager):
            raise TypeError(
                "well_known_manager must be an instance of WellKnownConfigurationManager"
            )

    async def fetch_well_known_config_and_jwks_async(self) -> None:
        await self.well_known_manager.fetch_well_known_config_and_jwks_async()

    @staticmethod
    def get_kid_from_token(*, token: str) -> Optional[str]:
        """
        Extracts the 'kid' (Key ID) from the JWT token header.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[str]: The 'kid' if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        try:
            token_content: CompactSignature = jws.extract_compact(token.encode())
            return token_content.headers().get("kid")
        except Exception as e:
            logger.exception(f"Failed to extract 'kid' from token: {e}")
            raise AuthorizationBearerTokenInvalidException(
                message=f"Could not extract kid header from token [{type(e)}]. Please check the token: {token}",
                token=token,
            ) from e
        if len(self.jwks.keys) > 0:
            return  # If JWKS is already fetched, skip fetching again

        logger.debug(f"Fetching well-known configurations and JWKS for id {self.uuid}.")

        self.well_known_configs = []  # Reset well-known configs before fetching

        keys: List[Dict[str, Any]] = []
        for auth_config in [c for c in self.auth_configs if c.well_known_uri]:
            if not auth_config.well_known_uri:
                logger.warning(
                    f"AuthConfig {auth_config} does not have a well-known URI, skipping JWKS fetch."
                )
                continue

            well_known_config: Dict[
                str, Any
            ] = await self.fetch_well_known_config_async(
                well_known_uri=auth_config.well_known_uri
            )

            jwks_uri = await self.get_jwks_uri_async(
                well_known_config=well_known_config
            )
            if not jwks_uri:
                logger.warning(
                    f"AuthConfig {auth_config} does not have a JWKS URI, skipping JWKS fetch."
                )
                continue

            async with httpx.AsyncClient() as client:
                try:
                    logger.info(f"Fetching JWKS from {jwks_uri}")
                    response = await client.get(jwks_uri)
                    response.raise_for_status()
                    jwks_data: Dict[str, Any] = response.json()
                    for key in jwks_data.get("keys", []):
                        kid = key.get("kid")
                        # if there is no matching "kid" in keys then add it
                        if not any([k.get("kid") == kid for k in keys]):
                            keys.append(key)
                        else:
                            # Log warning if a duplicate kid is found
                            logger.warning(
                                f"Duplicate key ID '{kid}' found when fetching JWKS from {jwks_uri}. "
                                f"This may indicate overlapping keys from different providers. "
                                f"Skipping duplicate key from {auth_config.auth_provider}."
                            )

                    logger.info(
                        f"Successfully fetched JWKS from {jwks_uri}, keys= {len(keys)}"
                    )
                except httpx.HTTPStatusError as e:
                    logger.exception(e)
                    raise ValueError(
                        f"Failed to fetch JWKS from {jwks_uri} with status {e.response.status_code} : {e}"
                    )
                except ConnectError as e:
                    raise ConnectionError(
                        f"Failed to connect to JWKS URI: {jwks_uri}: {e}"
                    )

        self.jwks = KeySet.import_key_set(
            {
                "keys": keys,
            }
        )
        logger.debug(f"Fetched JWKS with {len(self.jwks.keys)} keys.")

    @staticmethod
    def extract_token(*, authorization_header: str | None) -> Optional[str]:
        """
        Extracts the JWT token from the Authorization header.
        Args:
            authorization_header (str | None): The Authorization header string.
        Returns:
            Optional[str]: The extracted JWT token if present, otherwise None.
        """
        if not authorization_header:
            return None
        parts = authorization_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

    async def decode_token_async(
        self, *, token: str, verify_signature: bool
    ) -> Dict[str, Any] | None:
        """
        Decode a JWT token, optionally without verifying its signature.
        Args:
            token (str): The JWT token string to decode.
            verify_signature (bool): Whether to verify the signature using JWKS. Default is True.
        Returns:
            Dict[str, Any]: The decoded claims of the JWT token, or None if not a JWT.
        """
        if not token:
            raise ValueError("Token must not be empty")
        # Only attempt to decode if token looks like a JWT (contains two dots)
        if token.count(".") != 2:
            logger.warning(
                f"Token does not appear to be a JWT, skipping decode: {token}"
            )
            return None

        if verify_signature:
            await self.fetch_well_known_config_and_jwks_async()
            kid: str | None = self.get_kid_from_token(token=token)
            client_key_set: ClientKeySet | None = (
                self.well_known_manager.get_client_key_set_for_kid(kid=kid)
            )
            if not client_key_set:
                raise AuthorizationBearerTokenMissingException(
                    message=f"No matching JWKS found for kid: {kid}. Please check the token: {token}",
                )
            try:
                decoded = jwt.decode(
                    token, client_key_set.jwks, algorithms=self.algorithms
                )
                return decoded.claims
            except Exception as e:
                logger.exception(f"Failed to decode token: {e}")
                raise AuthorizationBearerTokenMissingException(
                    message=f"Invalid token provided [{type(e)}]. Please check the token: {token}",
                ) from e
        else:
            try:
                token_content = jws.extract_compact(token.encode())
                return cast(Dict[str, Any], json.loads(token_content.payload))
            except Exception as e:
                logger.exception(f"Failed to decode token without verification: {e}")
                raise AuthorizationBearerTokenInvalidException(
                    message=f"Invalid token provided [{type(e)}]. Please check the token: {token}",
                    token=token,
                ) from e

    async def verify_token_async(self, *, token: str) -> Token | None:
        """
        Verify a JWT token asynchronously using the JWKS from the provided URI.

        Args:
            token: The JWT token string to validate.
        Returns:
            The decoded claims if the token is valid.
        Throws:
            AuthorizationBearerTokenExpiredException: If the token has expired.
            AuthorizationBearerTokenInvalidException: If the token is invalid for any other reason.

        """
        if not token:
            raise ValueError("Token must not be empty")
        await self.fetch_well_known_config_and_jwks_async()

        exp_str: str = "None"
        now_str: str = "None"
        issuer: Optional[str] = None
        audience: Optional[str] = None
        try:
            kid: str | None = self.get_kid_from_token(token=token)
            client_key_set: ClientKeySet | None = (
                self.well_known_manager.get_client_key_set_for_kid(kid=kid)
            )
            if not client_key_set:
                raise ValueError(
                    f"No matching JWKS found for kid: {kid}. Please check the token: {token}"
                )

            # Validate the token
            verified = jwt.decode(
                token, client_key_set.jwks, algorithms=self.algorithms
            )
            issuer = verified.claims.get("iss")
            audience = verified.claims.get("aud") or verified.claims.get(
                "client_id"
            )  # AWS Cognito does not have aud claim but has client_id

            # Require audience to be present (either 'aud' or 'client_id')
            if audience is None:
                raise AuthorizationBearerTokenInvalidException(
                    message="Token is missing 'aud' and 'client_id' claims",
                    token=token,
                )

            # Validate that the token matches a configured provider securely.
            # Require audience to match; if an issuer is configured for that provider, require the issuer to match as well.
            token_matches_config = False
            for auth_config in self.auth_configs:
                audience_matches = audience == auth_config.audience
                if not audience_matches:
                    continue

                # Check if both issuer and audience match this provider's configuration
                if auth_config.issuer is not None:
                    if issuer == auth_config.issuer:
                        token_matches_config = True
                        logger.debug(
                            f"Token matched auth config: provider={auth_config.auth_provider}, "
                            f"issuer_matches=True, audience_matches=True"
                        )
                        break
                    else:
                        # audience matched, but issuer did not; try the next provider
                        continue

                # No issuer configured for this provider; audience match is sufficient
                token_matches_config = True
                logger.debug(
                    f"Token matched auth config: provider={auth_config.auth_provider}, "
                    f"issuer_matches=False (not configured), audience_matches=True"
                )
                break

            if not token_matches_config:
                logger.warning(
                    f"Token validation failed: issuer '{issuer}' and audience '{audience}' "
                    f"do not match any configured auth provider"
                )
                raise AuthorizationBearerTokenInvalidException(
                    message=f"Token issuer '{issuer}' and audience '{audience}' do not match any configured auth provider",
                    token=token,
                )

            exp = verified.claims.get("exp")
            now = time.time()
            # convert exp and now to ET (America/New_York) for logging
            tz = None
            # noinspection PyBroadException
            try:
                tz = ZoneInfo("America/New_York")
            except Exception:
                tz = None  # fallback to localtime if zoneinfo fails

            def to_eastern_time(ts: Optional[float]) -> str:
                """Convert a timestamp to a formatted string in Eastern Time (ET)."""
                if not ts:
                    return "None"
                # noinspection PyBroadException
                try:
                    dt = (
                        datetime.datetime.fromtimestamp(ts, tz)
                        if tz
                        else datetime.datetime.fromtimestamp(ts)
                    )
                    return dt.strftime("%Y-%m-%d %I:%M:%S %p %Z")  # AM/PM format
                except Exception:
                    return str(ts)

            exp_str = to_eastern_time(exp)
            now_str = to_eastern_time(now)
            # Create claims registry
            claims_requests = jwt.JWTClaimsRegistry()
            claims_requests.validate(verified.claims)

            logger.debug(f"Successfully verified token: {token}")
            return Token.create_from_token(token=token)
        except ExpiredTokenError as e:
            logger.warning(f"Token has expired: {token}")
            raise AuthorizationBearerTokenExpiredException(
                message=f"This OAuth Token has expired. Exp: {exp_str}, Now: {now_str}."
                + "\nPlease Sign Out and Sign In to get a fresh OAuth token."
                + f"\nissuer: {issuer}, audience: {audience}",
                expires=exp_str,
                now=now_str,
                token=token,
                issuer=issuer,
                audience=audience,
            ) from e
        except AuthorizationBearerTokenInvalidException:
            # Re-raise our custom validation exceptions without wrapping them
            raise
        except Exception as e:
            raise AuthorizationBearerTokenInvalidException(
                message=f"Invalid token provided. Exp: {exp_str}, Now: {now_str}. Please check the token:\n{token}.",
                token=token,
            ) from e
