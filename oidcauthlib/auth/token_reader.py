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
    TokenReader is a utility class for reading and verifying JWT tokens using JWKS (JSON Web Key Set).
    """

    def __init__(
        self,
        *,
        algorithms: Optional[list[str]] = None,
        auth_config_reader: AuthConfigReader,
        well_known_config_manager: WellKnownConfigurationManager,
    ):
        """
        Initializes the TokenReader with the JWKS URI or Well-Known URI, issuer, audience, and algorithms.
        Args:
            algorithms (Optional[list[str]]): The list of algorithms to use for verifying the JWT.
            auth_config_reader (AuthConfigReader): The configuration reader for authentication settings.
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

        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()

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

    # noinspection PyMethodMayBeStatic
    async def get_jwks_uri_async(
        self, *, well_known_config: Dict[str, Any]
    ) -> str | None:
        """
        Retrieves the JWKS URI and issuer from the well-known OpenID Connect configuration.
        Returns:
            tuple: (jwks_uri, issuer)
        Raises:
            ValueError: If required fields are missing.
        """
        jwks_uri: str | None = well_known_config.get("jwks_uri")
        issuer = well_known_config.get("issuer")
        if not jwks_uri:
            raise ValueError(
                f"jwks_uri not found in well-known configuration: {well_known_config}"
            )
        if not issuer:
            raise ValueError(
                f"issuer not found in well-known configuration: {well_known_config}"
            )
        return jwks_uri

    async def get_subject_from_token_async(self, *, token: str) -> Optional[str]:
        """
        Extracts the 'sub' (subject) claim from the JWT token.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[str]: The subject claim if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            claims = jwt.decode(token, jwks, algorithms=self.algorithms).claims
            return claims.get("email") or claims.get("sub")
        except Exception as e:
            logger.exception(f"Failed to extract subject from token: {e}")
            return None

    async def get_expires_from_token_async(
        self, token: str
    ) -> Optional[datetime.datetime]:
        """
        Extracts the 'exp' (expiration) claim from the JWT token.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[datetime.datetime]: The expiration time as a datetime object if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            claims = jwt.decode(token, jwks, algorithms=self.algorithms).claims
            exp = claims.get("exp")
            if exp:
                return datetime.datetime.fromtimestamp(exp, tz=ZoneInfo("UTC"))
            return None
        except Exception as e:
            logger.exception(f"Failed to extract expiration from token: {e}")
            return None

    async def get_issuer_from_token_async(self, token: str) -> Optional[str]:
        """
        Extracts the 'iss' (issuer) claim from the JWT token.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[str]: The issuer claim if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            claims = jwt.decode(token, jwks, algorithms=self.algorithms).claims
            return claims.get("iss")
        except Exception as e:
            logger.exception(f"Failed to extract issuer from token: {e}")
            return None

    async def get_audience_from_token_async(self, token: str) -> Optional[str]:
        """
        Extracts the 'aud' (audience) claim from the JWT token.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[str]: The audience claim if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            claims = jwt.decode(token, jwks, algorithms=self.algorithms).claims
            return claims.get("aud") or claims.get(
                "client_id"
            )  # AWS Cognito does not have aud claim but has client_id
        except Exception as e:
            logger.exception(f"Failed to extract audience from token: {e}")
            return None

    async def get_issued_from_token_async(
        self, token: str
    ) -> Optional[datetime.datetime]:
        """
        Extracts the 'iat' (issued at) claim from the JWT token.
        Args:
            token (str): The JWT token string.
        Returns:
            Optional[datetime.datetime]: The issued at time as a datetime object if present, otherwise None.
        """
        if not token:
            raise ValueError("Token must not be empty")
        jwks: KeySet = await self._well_known_config_manager.get_jwks_async()
        try:
            claims = jwt.decode(token, jwks, algorithms=self.algorithms).claims
            iat = claims.get("iat")
            if iat:
                return datetime.datetime.fromtimestamp(iat, tz=ZoneInfo("UTC"))
            return None
        except Exception as e:
            logger.exception(f"Failed to extract created at from token: {e}")
            return None

    async def is_token_valid_async(self, access_token: str) -> bool:
        """
        Checks if the provided access token is valid (not expired and properly signed).
        Args:
            access_token (str): The JWT access token string.
        Returns:
            bool: True if the token is valid, False otherwise.
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
