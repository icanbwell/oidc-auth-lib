"""Which tier a caller's merged scopes grant: administrator, tenant reader, or denied.

Pure: scopes in, ``AdminAccess`` out. No web framework, environment or network.

Order of the rules:

1. any ``patient/`` scope denies, even with an administrator or reader scope;
2. every administrator scope held: ``ADMIN``, unrestricted;
3. every reader scope held plus at least one ``access/<slug>.*`` whose slug
   selects a client: ``READER``, limited to those clients' keys. ``access/*.*``
   is honored only when ``allow_all_tenants`` is set, and then means every
   client in the resolver (a set, so a record outside it stays administrator-only);
4. anything else is denied, with the reason that names the missing piece.

Scope matching is exact on the required scopes, and ``access/*.*`` alone never
grants the reader tier.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from oidcauthlib.authorization.client_slugs import (
    WILDCARD_SLUG,
    ClientSlugResolver,
    slug_from_access_scope,
)
from oidcauthlib.authorization.scopes import has_admin_scopes, has_patient_scope


class AdminTier(StrEnum):
    ADMIN = "admin"
    READER = "reader"


class DenialReason(StrEnum):
    """Why a caller was denied; also usable as a metric label."""

    PATIENT_SCOPE = "patient_scope"
    NOT_A_READER = "not_a_reader"
    NO_ACCESS_SCOPE = "no_access_scope"
    UNMAPPED_ACCESS_SCOPE = "unmapped_access_scope"


@dataclass(frozen=True)
class AdminAccess:
    """The outcome of a tier decision.

    ``tier`` is ``None`` when the caller is denied, with ``denial_reason`` set.
    ``allowed_client_keys`` has three meanings, enforced in ``__post_init__``:

    * ``None``: unrestricted. Only the ``ADMIN`` tier carries it.
    * a non-empty set: the client keys a ``READER`` may read.
    * an empty set: a denied caller. A denied caller never carries ``None``, so
      no code path can read a denial as "all tenants".

    Prefer the ``admin``, ``reader`` and ``denied`` constructors.
    """

    tier: AdminTier | None
    allowed_client_keys: frozenset[str] | None
    denial_reason: DenialReason | None

    def __post_init__(self) -> None:
        if self.tier is AdminTier.READER and not self.allowed_client_keys:
            raise ValueError("a reader needs a non-empty set of client keys it may read")
        if self.tier is AdminTier.ADMIN and self.allowed_client_keys is not None:
            raise ValueError("the admin tier is unrestricted: allowed_client_keys must be None")
        if self.tier is None:
            if self.denial_reason is None:
                raise ValueError("a denied caller needs a denial reason")
            if self.allowed_client_keys != frozenset():
                raise ValueError("a denied caller carries an empty set of client keys, never None")

    @classmethod
    def admin(cls) -> "AdminAccess":
        return cls(tier=AdminTier.ADMIN, allowed_client_keys=None, denial_reason=None)

    @classmethod
    def reader(cls, *, allowed_client_keys: frozenset[str]) -> "AdminAccess":
        return cls(
            tier=AdminTier.READER,
            allowed_client_keys=allowed_client_keys,
            denial_reason=None,
        )

    @classmethod
    def denied(cls, *, reason: DenialReason) -> "AdminAccess":
        return cls(tier=None, allowed_client_keys=frozenset(), denial_reason=reason)


def resolve_admin_access(
    *,
    scopes: Iterable[str],
    admin_scopes: Sequence[str],
    reader_scopes: Sequence[str],
    clients: ClientSlugResolver,
    allow_all_tenants: bool,
) -> AdminAccess:
    """The tier ``scopes`` (the merged token and userinfo scopes) grant.

    ``admin_scopes`` and ``reader_scopes`` are all-of requirements; an empty one
    admits nobody. ``allow_all_tenants`` lets ``access/*.*`` select every client
    in ``clients``. Never raises.
    """
    held = set(scopes)
    if has_patient_scope(scopes=held):
        return AdminAccess.denied(reason=DenialReason.PATIENT_SCOPE)
    if has_admin_scopes(scopes=held, required_scopes=admin_scopes):
        return AdminAccess.admin()
    # An empty requirement would admit everyone (``issubset`` of the empty set).
    if not reader_scopes or not set(reader_scopes).issubset(held):
        return AdminAccess.denied(reason=DenialReason.NOT_A_READER)
    slugs = {slug for scope in held if (slug := slug_from_access_scope(scope=scope)) is not None}
    if not slugs:
        return AdminAccess.denied(reason=DenialReason.NO_ACCESS_SCOPE)
    if WILDCARD_SLUG in slugs and allow_all_tenants and clients.all_keys:
        return AdminAccess.reader(allowed_client_keys=clients.all_keys)
    keys = frozenset(key for slug in slugs - {WILDCARD_SLUG} for key in clients.keys_for(slug=slug))
    if not keys:
        return AdminAccess.denied(reason=DenialReason.UNMAPPED_ACCESS_SCOPE)
    return AdminAccess.reader(allowed_client_keys=keys)
