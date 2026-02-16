import datetime
import json
import logging
import time
import uuid
from typing import Optional, Any, Dict, List, cast
from uuid import UUID

from joserfc import jwt, jws
from joserfc.errors import ExpiredTokenError
from joserfc.jwk import KeySet

from zoneinfo import ZoneInfo

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import (
    AuthConfigReader,
)
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
from oidcauthlib.auth.well_known_configuration.well_known_configuration_manager import (
    WellKnownConfigurationManager,
)

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class TokenReader:
    """
    TokenReader verifies and decodes JWT access tokens using provider JWKS, driven by configured AuthConfig entries.

    Responsibilities:
    - Extract tokens from Authorization headers.
    - Decode tokens optionally without signature verification for inspection.
    - Verify tokens against JWKS, enforcing audience and issuer alignment with configured providers.
    - Validate claim structures and expiration.

    Security & Privacy:
    - Does not log full tokens or sensitive claims; only high-level statuses.
    - Enforces audience presence and issuer check (if configured) to prevent token confusion across providers.
    - JWKS is retrieved via WellKnownConfigurationManager and must be loaded before verification.

    Public API:
    - extract_token(authorization_header): parse "Bearer <token>" header.
    - decode_token_async(token, verify_signature): decode claims; optionally verify with JWKS.
    - verify_token_async(token): fully validate a token; raises typed exceptions on failure.
    - is_token_valid_async(access_token): boolean validity check (expiration and signature).

    Notes:
    - All verification operations are async and depend on WellKnownConfigurationManager.
    - Algorithms used for verification are configurable via the constructor.
    """

    def __init__(
        self,
        *,
        algorithms: Optional[list[str]] = None,
        auth_config_reader: AuthConfigReader,
        well_known_config_manager: WellKnownConfigurationManager,
    ):
        """
        Initialize TokenReader with dependencies and verification settings.

        Args:
            algorithms: Allowed JWT algorithms for signature verification (e.g., ["RS256"]).
            auth_config_reader: Provider configuration reader used for issuer/audience validation.
            well_known_config_manager: Manager responsible for well-known configs and JWKS retrieval.
        Raises:
            ValueError: If required dependencies or provider configs are missing.
            TypeError: If dependency types do not match expected classes.
        Usage:
            Create a TokenReader with allowed algorithms, an AuthConfigReader, and a WellKnownConfigurationManager.
        """
        self.uuid: UUID = uuid.uuid4()
        self.algorithms: List[str] | None = algorithms or None

        self.auth_config_reader: AuthConfigReader = auth_config_reader
        if self.auth_config_reader is None:
            raise ValueError("AuthConfigReader must be provided")
        if not isinstance(self.auth_config_reader, AuthConfigReader):
            raise TypeError(
                "auth_config_reader must be an instance of AuthConfigReader"
            )

        self.auth_configs: List[AuthConfig] = (
            self.auth_config_reader.get_auth_configs_for_all_auth_providers()
        )
        if not self.auth_configs:
            raise ValueError("At least one AuthConfig must be provided")

        # Initialize new manager (replaces inline JWKS + well-known handling)
        self._well_known_config_manager: WellKnownConfigurationManager = (
            well_known_config_manager
        )
        if not isinstance(
            self._well_known_config_manager, WellKnownConfigurationManager
        ):
            raise TypeError(
                "well_known_config_manager must be an instance of WellKnownConfigurationManager"
            )

    @staticmethod
    def extract_token(*, authorization_header: str | None) -> Optional[str]:
        """
        Extract a JWT token from an HTTP Authorization header.

        Args:
            authorization_header: Header string (e.g., "Bearer eyJ..."), or None.
        Returns:
            The compact JWT string if present, otherwise None.
        Example:
            Passing "Bearer abc.def.ghi" returns "abc.def.ghi".
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
        Decode a JWT token's claims, optionally verifying the signature.

        Args:
            token: Compact JWT string.
            verify_signature: If True, verify signature using JWKS; if False, parse without verification.
        Returns:
            Decoded claims dict, or None if the input is not a compact JWT.
        Raises:
            AuthorizationBearerTokenMissingException: On failure while verifying signature.
            AuthorizationBearerTokenInvalidException: On failure while parsing without verification.
            RuntimeError: If JWKS is not available when verification is requested.
        Security:
            Avoid logging full tokens or payloads; only minimal error context is included.
        Usage:
            Call decode_token_async with a token; set verify_signature to True to validate signatures.
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
            jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
            if not jwks:
                raise RuntimeError("JWKS must be fetched before verifying tokens")
            try:
                decoded = jwt.decode(token, jwks, algorithms=self.algorithms)
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
        Verify a JWT token against JWKS and configured provider constraints.

        Args:
            token: Compact JWT string to validate.
        Returns:
            Token: A Token object if verification succeeds.
        Raises:
            AuthorizationBearerTokenExpiredException: If the token has expired.
            AuthorizationBearerTokenInvalidException: If issuer/audience mismatch or signature invalid.
            ValueError: If token is empty.
        Behavior:
            - Validates expiration, audience presence, and matches against configured providers.
            - Accepts client_id as audience for providers like AWS Cognito.
        Usage:
            Call verify_token_async with a token to perform full validation; handle typed exceptions on failure.
        """
        if not token:
            raise ValueError("Token must not be empty")

        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()

        # get kids from jwks for logging
        jwks_kids = [key.get("kid") for key in jwks.keys]
        well_known_urls = await self._well_known_config_manager.get_well_known_urls()

        exp_str: str = "None"
        now_str: str = "None"
        issuer: Optional[str] = None
        audience: Optional[str] = None
        try:
            # Validate the token
            verified = jwt.decode(token, jwks, algorithms=self.algorithms)
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
                    message=f"Token issuer '{issuer}' and audience '{audience}' do not match any configured auth provider"
                    f". JWKS Kids: {jwks_kids}. Configured well-known URLs: {well_known_urls}",
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
                message=f"{type(e)}: Invalid token provided."
                f" Exp: {exp_str}, Now: {now_str}."
                f" Please check the token:\n{token}."
                f"\nIssuer: {issuer}, Audience: {audience}. "
                f"\nJWKS Kids: {jwks_kids}"
                f"\nConfigured well-known URLs: {well_known_urls}",
                token=token,
            ) from e

    async def is_token_valid_async(self, access_token: str) -> bool:
        """
        Check if a JWT is currently valid (signature and not expired).

        Args:
            access_token: Compact JWT string.
        Returns:
            True if valid; False if expired or invalid.
        Notes:
            Useful for quick health checks; does not raise exceptions.
        Usage:
            Call is_token_valid_async with an access token to get a boolean validity result.
        """
        assert access_token, "Access token must not be empty"
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            verified = jwt.decode(access_token, jwks, algorithms=self.algorithms)
            exp = verified.claims.get("exp")
            now = time.time()
            if exp and exp < now:
                logger.warning(f"Token has expired. Exp: {exp}, Now: {now}")
                return False
            return True
        except ExpiredTokenError:
            logger.warning("Token has expired.")
            return False
        except Exception as e:
            logger.exception(f"Token is invalid: {e}")
            return False
