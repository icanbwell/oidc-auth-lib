import logging
from typing import Any, Dict, List, cast
import httpx
from httpx import ConnectError
from joserfc.jwk import KeySet

from oidcauthlib.auth.config.auth_config import AuthConfig
from oidcauthlib.auth.config.auth_config_reader import AuthConfigReader
from oidcauthlib.auth.models.client_key_set import ClientKeySet

logger = logging.getLogger(__name__)


class WellKnownConfigurationManager:
    """
    Manages the retrieval and storage of well-known OIDC configurations and JWKS for multiple AuthConfigs.

    """

    def __init__(self, *, auth_config_reader: AuthConfigReader):
        """
        Initializes the WellKnownConfigurationManager with the provided AuthConfigReader.
        :param auth_config_reader:
        """
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

        self.client_key_sets: list[
            ClientKeySet
        ] = []  # will be loaded asynchronously later
        self._loaded: bool = False

    async def fetch_well_known_config_and_jwks_async(self) -> None:
        if self._loaded:
            return
        logger.debug("Fetching well-known configurations and JWKS.")
        self.client_key_sets = []
        for auth_config in [
            c for c in self.auth_configs if getattr(c, "well_known_uri", None)
        ]:
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
                    keys: List[Dict[str, Any]] = []
                    for key in jwks_data.get("keys", []):
                        if not any([k.get("kid") == key.get("kid") for k in keys]):
                            keys.append(key)
                    logger.info(
                        f"Successfully fetched JWKS from {jwks_uri}, keys= {len(keys)}"
                    )
                    self.client_key_sets.append(
                        ClientKeySet(
                            auth_config=auth_config,
                            well_known_config=well_known_config,
                            jwks=KeySet.import_key_set({"keys": keys}),
                            kids=[
                                cast(str, key.get("kid"))
                                for key in keys
                                if key.get("kid")
                            ],
                        )
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

    @staticmethod
    async def fetch_well_known_config_async(*, well_known_uri: str) -> Dict[str, Any]:
        if not well_known_uri:
            raise ValueError("well_known_uri is not set")
        async with httpx.AsyncClient() as client:
            try:
                logger.info(f"Fetching OIDC discovery document from {well_known_uri}")
                response = await client.get(well_known_uri)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                raise ValueError(
                    f"Failed to fetch OIDC discovery document from {well_known_uri} with status {e.response.status_code} : {e}"
                )
            except ConnectError as e:
                raise ConnectionError(
                    f"Failed to connect to OIDC discovery document: {well_known_uri}: {e}"
                )

    @staticmethod
    async def get_jwks_uri_async(*, well_known_config: Dict[str, Any]) -> str | None:
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

    def get_client_key_set_for_kid(self, *, kid: str | None) -> ClientKeySet | None:
        """
        Retrieves the ClientKeySet that contains the specified Key ID (kid).

        :param kid:
        :return:
        """
        if kid is None:
            return None

        for client_key_set in self.client_key_sets:
            if client_key_set.kids and kid in client_key_set.kids:
                return client_key_set
        return None
