"""Startup validation of the reader-tier configuration.

When reader scopes are configured, the configuration must be one the resolver can
apply safely. Every refusal names the rule that failed, never a client name or key.
"""

from collections.abc import Sequence

from oidcauthlib.authorization.client_keys import (
    ClientKeysFormatError,
    parse_client_keys_strict,
)
from oidcauthlib.authorization.client_slugs import ACCESS_SCOPE_PREFIX, WILDCARD_SLUG
from oidcauthlib.authorization.scopes import PATIENT_SCOPE_PREFIX

# Scopes every token carries; as a reader requirement they would admit everyone.
GENERIC_SCOPES = frozenset({"openid", "profile", "email", "groups"})


class ReaderConfigurationError(ValueError):
    """The reader-tier configuration is unsafe to apply."""


def validate_reader_configuration(
    *,
    reader_scopes: Sequence[str],
    admin_scopes: Sequence[str],
    client_keys_raw: str,
) -> None:
    """Refuse an unsafe reader-tier configuration. A no-op when no reader scopes are set.

    Raises:
        ReaderConfigurationError: when reader scopes are set and the client-key
            mapping fails the strict parser, is empty, or has a name containing
            ``*``; a reader scope overlaps an administrator scope, starts with
            ``access/`` or ``patient/``, is generic (``openid``, ``profile``,
            ``email``, ``groups``) or ends in ``*.*``; or any administrator scope
            starts with ``access/`` (a reader holding ``access/*.*`` would then be
            an administrator).
    """
    if not reader_scopes:
        return
    try:
        clients = parse_client_keys_strict(raw=client_keys_raw)
    except ClientKeysFormatError as exc:
        raise ReaderConfigurationError(f"the client-key mapping is invalid: {exc}") from exc
    if not clients:
        raise ReaderConfigurationError("the client-key mapping is empty")
    if any(WILDCARD_SLUG in name for name in clients):
        raise ReaderConfigurationError(
            f"a client name contains '{WILDCARD_SLUG}', which collides with the wildcard slug"
        )
    admin_normalized = {scope.strip().casefold() for scope in admin_scopes}
    for scope in reader_scopes:
        normalized = scope.strip().casefold()
        if normalized in admin_normalized:
            raise ReaderConfigurationError("a reader scope overlaps an administrator scope")
        if normalized.startswith(ACCESS_SCOPE_PREFIX) or normalized.startswith(PATIENT_SCOPE_PREFIX):
            raise ReaderConfigurationError(
                f"a reader scope starts with '{ACCESS_SCOPE_PREFIX}' or '{PATIENT_SCOPE_PREFIX}'"
            )
        if normalized in GENERIC_SCOPES:
            raise ReaderConfigurationError("a reader scope is a generic scope every token carries")
        if normalized.endswith("*.*"):
            raise ReaderConfigurationError("a reader scope ends in '*.*'")
    if any(scope.strip().casefold().startswith(ACCESS_SCOPE_PREFIX) for scope in admin_scopes):
        raise ReaderConfigurationError(
            f"an administrator scope starts with '{ACCESS_SCOPE_PREFIX}': "
            "a reader holding the wildcard access scope would be an administrator"
        )
