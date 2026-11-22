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
from oidcauthlib.authorization.scopes import PATIENT_SCOPE_PREFIX, has_blank_scope, normalize_scope

# Scopes every token carries; as a reader requirement they would admit everyone.
GENERIC_SCOPES = frozenset({"openid", "profile", "email", "address", "phone", "offline_access", "groups"})
# A reader scope with this suffix would read like the all-tenants access scope.
WILDCARD_SCOPE_SUFFIX = "*.*"


class ReaderConfigurationError(ValueError):
    """The reader-tier configuration is unsafe to apply."""


def validate_reader_configuration(
    *,
    reader_scopes: Sequence[str],
    admin_scopes: Sequence[str],
    client_keys_raw: str,
) -> None:
    """Refuse an unsafe reader-tier configuration.

    A blank, non-printing or padded entry in either scope list is always refused, because
    scopes match exactly and a blank requirement is satisfiable by a blank held scope. An
    administrator requirement made only of generic scopes is always refused too. The
    remaining checks are skipped when no reader scopes are set.

    Args:
        reader_scopes: the scopes that together grant the reader tier.
        admin_scopes: the scopes that together grant the administrator tier.
        client_keys_raw: the raw client-key mapping setting.

    Raises:
        ReaderConfigurationError: when either scope list has a blank or non-printing
            entry or an entry with surrounding whitespace; when every administrator
            scope is generic; when reader scopes are set and the client-key
            mapping fails the strict parser, is empty, or has a name containing
            ``*``; a reader scope overlaps an administrator scope, starts with
            ``access/`` or ``patient/``, is generic (``openid``, ``profile``,
            ``email``, ``address``, ``phone``, ``offline_access``, ``groups``) or
            ends in ``*.*``; or any administrator scope starts with ``access/`` (a
            reader holding ``access/*.*`` would then be an administrator).
    """
    # Materialize: the lists are read several times, and a generator is used up by the first pass.
    readers = tuple(reader_scopes)
    admins = tuple(admin_scopes)
    for scopes in (readers, admins):
        if has_blank_scope(scopes=scopes) or any(scope != scope.strip() for scope in scopes):
            raise ReaderConfigurationError(
                "a scope is blank, has characters that do not print, or has surrounding whitespace"
            )
    if admins and all(normalize_scope(scope=scope) in GENERIC_SCOPES for scope in admins):
        # Checked before the no-reader-scopes return: an administrator requirement made only of
        # scopes every token carries (for example ["openid"]) makes every verified token an admin.
        raise ReaderConfigurationError("an administrator requirement made only of generic scopes admits every token")
    if not readers:
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
    admin_normalized = {normalize_scope(scope=scope) for scope in admins}
    for scope in readers:
        normalized = normalize_scope(scope=scope)
        if normalized in admin_normalized:
            raise ReaderConfigurationError("a reader scope overlaps an administrator scope")
        if normalized.startswith(ACCESS_SCOPE_PREFIX) or normalized.startswith(PATIENT_SCOPE_PREFIX):
            raise ReaderConfigurationError(
                f"a reader scope starts with '{ACCESS_SCOPE_PREFIX}' or '{PATIENT_SCOPE_PREFIX}'"
            )
        if normalized in GENERIC_SCOPES:
            raise ReaderConfigurationError("a reader scope is a generic scope every token carries")
        if normalized.endswith(WILDCARD_SCOPE_SUFFIX):
            raise ReaderConfigurationError(f"a reader scope ends in '{WILDCARD_SCOPE_SUFFIX}'")
    if any(normalize_scope(scope=scope).startswith(ACCESS_SCOPE_PREFIX) for scope in admins):
        raise ReaderConfigurationError(
            f"an administrator scope starts with '{ACCESS_SCOPE_PREFIX}': "
            "a reader holding the wildcard access scope would be an administrator"
        )
