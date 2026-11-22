"""Pure authorization helpers: administrator and tenant-reader tiers from OAuth scopes.

Every decision is a pure function of the values passed in. The package reads no
environment variable, performs no file or network I/O and imports nothing else from
``oidcauthlib``, so callers keep control of token verification, user lookup and
configuration. Its only side effect is a standard-library ``logging`` warning that
carries a slug or a count, never a client name or key.
"""

from oidcauthlib.authorization.admin_access import (
    AdminAccess,
    AdminTier,
    DenialReason,
    resolve_admin_access,
)
from oidcauthlib.authorization.client_keys import (
    ClientKeysFormatError,
    parse_client_keys_lenient,
    parse_client_keys_strict,
)
from oidcauthlib.authorization.client_slugs import (
    ClientSlugResolver,
    slug_from_access_scope,
)
from oidcauthlib.authorization.reader_configuration import (
    ReaderConfigurationError,
    validate_reader_configuration,
)
from oidcauthlib.authorization.scopes import has_admin_scopes, has_patient_scope

__all__ = [
    "AdminAccess",
    "AdminTier",
    "ClientKeysFormatError",
    "ClientSlugResolver",
    "DenialReason",
    "ReaderConfigurationError",
    "has_admin_scopes",
    "has_patient_scope",
    "parse_client_keys_lenient",
    "parse_client_keys_strict",
    "resolve_admin_access",
    "slug_from_access_scope",
    "validate_reader_configuration",
]
