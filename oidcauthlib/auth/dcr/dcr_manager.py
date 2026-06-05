import logging
import time
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId

from oidcauthlib.auth.dcr.dcr_client import DcrClient
from oidcauthlib.auth.dcr.dcr_registration import DcrRegistration
from oidcauthlib.auth.repository.base_repository import AsyncBaseRepository
from oidcauthlib.auth.repository.repository_factory import RepositoryFactory
from oidcauthlib.utilities.environment.abstract_environment_variables import (
    AbstractEnvironmentVariables,
)
from oidcauthlib.utilities.logger.log_levels import SRC_LOG_LEVELS
from oidcauthlib.utilities.url_validator import validate_url

logger = logging.getLogger(__name__)
logger.setLevel(SRC_LOG_LEVELS["AUTH"])


class DcrManager:
    """Resolves OAuth client credentials via DCR with MongoDB persistence."""

    def __init__(
        self,
        *,
        environment_variables: AbstractEnvironmentVariables,
        collection_name: str,
        redirect_uri: str,
        dcr_client: DcrClient | None = None,
    ) -> None:
        self._collection_name = collection_name
        self._redirect_uri = redirect_uri
        self._repository: AsyncBaseRepository[DcrRegistration] = RepositoryFactory.get_repository(
            repository_type=environment_variables.oauth_cache,
            environment_variables=environment_variables,
        )
        self._dcr_client = dcr_client or DcrClient()

    async def resolve_dcr_credentials(
        self,
        *,
        auth_provider: str,
        registration_url: str | None,
        client_id: str | None = None,
        client_name: str | None = None,
        client_uri: str | None = None,
        logo_uri: str | None = None,
        contacts: list[str] | None = None,
    ) -> DcrRegistration | None:
        if client_id:
            logger.info(
                "DCR: Skipping registration for '%s' — client_id already provided (client_id=%s)",
                auth_provider,
                client_id,
            )
            return None

        if not registration_url:
            logger.error(
                "DCR: No registration_url and no client_id for '%s' — cannot resolve credentials",
                auth_provider,
            )
            raise ValueError(
                f"registration_url is required for DCR when client_id is not provided (auth_provider='{auth_provider}')"
            )

        validate_url(registration_url)

        logger.info(
            "DCR: Resolving credentials for '%s' via registration_url='%s'",
            auth_provider,
            registration_url,
        )

        cached = await self._find_cached(
            auth_provider=auth_provider,
            registration_url=registration_url,
        )

        if cached and not self._is_expired(cached):
            logger.info(
                "DCR: Using cached credentials for '%s' — client_id=%s, expires_at=%s",
                auth_provider,
                cached.client_id,
                cached.client_secret_expires_at or "never",
            )
            return cached

        if cached and self._is_expired(cached):
            logger.info(
                "DCR: Cached credentials for '%s' are expired (client_id=%s, expired_at=%s) — re-registering",
                auth_provider,
                cached.client_id,
                cached.client_secret_expires_at,
            )
        else:
            logger.info(
                "DCR: No cached credentials found for '%s' — performing new registration at '%s'",
                auth_provider,
                registration_url,
            )

        dcr_response = await self._dcr_client.register(
            registration_url=registration_url,
            redirect_uri=self._redirect_uri,
            client_name=client_name,
            client_uri=client_uri,
            logo_uri=logo_uri,
            contacts=contacts,
        )

        registration = await self._persist(
            auth_provider=auth_provider,
            registration_url=registration_url,
            dcr_response=dcr_response,
        )
        logger.info(
            "DCR: Persisted credentials for '%s' — client_id=%s",
            auth_provider,
            registration.client_id,
        )
        return registration

    async def _find_cached(
        self,
        *,
        auth_provider: str,
        registration_url: str,
    ) -> DcrRegistration | None:
        logger.debug(
            "DCR: Querying cache for auth_provider='%s', registration_url='%s', collection='%s'",
            auth_provider,
            registration_url,
            self._collection_name,
        )
        results = await self._repository.find_many(
            collection_name=self._collection_name,
            model_class=DcrRegistration,
            filter_dict={
                "auth_provider": auth_provider,
                "registration_url": registration_url,
            },
        )
        if results:
            result = results[0]
            if not result.is_schema_current():
                logger.info(
                    "DCR: Stale schema version for '%s' (stored=%d, current=%d); treating as cache miss",
                    auth_provider,
                    result.schema_version,
                    DcrRegistration.SCHEMA_VERSION,
                )
                return None
            logger.debug(
                "DCR: Cache hit for '%s' — found %d result(s), client_id=%s",
                auth_provider,
                len(results),
                results[0].client_id,
            )
            return result
        else:
            logger.debug(
                "DCR: Cache miss for '%s' at '%s'",
                auth_provider,
                registration_url,
            )
        return None

    @staticmethod
    def _is_expired(registration: DcrRegistration) -> bool:
        if registration.client_secret_expires_at == 0:
            return False
        return registration.client_secret_expires_at < int(time.time())

    async def _persist(
        self,
        *,
        auth_provider: str,
        registration_url: str,
        dcr_response: dict[str, Any],
    ) -> DcrRegistration:
        now = datetime.now(UTC)
        registration = DcrRegistration(
            _id=ObjectId(),
            schema_version=DcrRegistration.SCHEMA_VERSION,
            created=now,
            auth_provider=auth_provider,
            registration_url=registration_url,
            client_id=dcr_response["client_id"],
            client_secret=dcr_response.get("client_secret"),
            client_secret_expires_at=dcr_response.get("client_secret_expires_at", 0),
            registration_response=dcr_response,
        )

        def on_insert(item: DcrRegistration) -> DcrRegistration:
            item.created = now
            return item

        def on_update(item: DcrRegistration) -> DcrRegistration:
            item.updated = now
            return item

        persisted_id = await self._repository.insert_or_update(
            collection_name=self._collection_name,
            item=registration,
            keys={
                "auth_provider": auth_provider,
                "registration_url": registration_url,
            },
            model_class=DcrRegistration,
            on_insert=on_insert,
            on_update=on_update,
        )

        # Return with the actual persisted ID (may differ on update)
        return registration.model_copy(update={"id": persisted_id})
