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

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from oidcauthlib.authorization.client_slugs import (
    WILDCARD_SLUG,
    ClientSlugResolver,
    slug_from_access_scope,
)
from oidcauthlib.authorization.scopes import has_admin_scopes, has_blank_scope, has_patient_scope


logger = logging.getLogger(__name__)


class AdminTier(StrEnum):
    """The tier a granted caller holds; a denied caller has no tier."""

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
    # repr=False: client keys identify tenants and stay out of logs and tracebacks.
    allowed_client_keys: frozenset[str] | None = field(repr=False)
    denial_reason: DenialReason | None

    def __post_init__(self) -> None:
        if self.tier is not None:
            # A plain string such as "reader" (for example after a JSON round trip) is coerced, so
            # the invariants below apply to it; an unknown value raises ValueError.
            object.__setattr__(self, "tier", AdminTier(self.tier))
            if self.denial_reason is not None:
                raise ValueError("a granted caller carries no denial reason")
        if isinstance(self.allowed_client_keys, str | bytes):
            # A bare string would silently become a set of its characters.
            raise TypeError("allowed_client_keys must be a collection of keys, not a string")
        if self.allowed_client_keys is not None and not isinstance(self.allowed_client_keys, frozenset):
            # A mutable set would let a caller widen the decision after it was made.
            object.__setattr__(self, "allowed_client_keys", frozenset(self.allowed_client_keys))
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
        """An unrestricted administrator."""
        return cls(tier=AdminTier.ADMIN, allowed_client_keys=None, denial_reason=None)

    @classmethod
    def reader(cls, *, allowed_client_keys: frozenset[str]) -> "AdminAccess":
        """A tenant reader limited to ``allowed_client_keys`` (which must not be empty)."""
        return cls(
            tier=AdminTier.READER,
            allowed_client_keys=allowed_client_keys,
            denial_reason=None,
        )

    @classmethod
    def denied(cls, *, reason: DenialReason) -> "AdminAccess":
        """A denied caller: no tier, an empty key set and the ``reason``."""
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

    ``admin_scopes`` and ``reader_scopes`` are all-of requirements; an empty one,
    or one with a blank entry, admits nobody. Entries of ``scopes`` that are not
    strings are ignored (and counted in one warning). ``allow_all_tenants`` lets ``access/*.*`` select every
    client in ``clients``, including a client whose own slug is ambiguous. Never
    raises.

    Args:
        scopes: the merged token and userinfo scopes of the caller.
        admin_scopes: every one of these must be held for the administrator tier.
        reader_scopes: every one of these must be held for the reader tier.
        clients: resolves ``access/<slug>.*`` scopes to client keys.
        allow_all_tenants: whether ``access/*.*`` selects every client.
    """
    all_scopes = list(scopes)
    held = {scope for scope in all_scopes if isinstance(scope, str)}
    if ignored := len(all_scopes) - sum(1 for scope in all_scopes if isinstance(scope, str)):
        # Count only: a malformed claim can only narrow the decision, but operators should see it.
        logger.warning("Ignored %d held scope entries that are not strings", ignored)
    if has_patient_scope(scopes=held):
        return AdminAccess.denied(reason=DenialReason.PATIENT_SCOPE)
    if has_admin_scopes(scopes=held, required_scopes=admin_scopes):
        return AdminAccess.admin()
    # An empty requirement would admit everyone (``issubset`` of the empty set).
    required_reader_scopes = tuple(reader_scopes)  # a generator would be used up by the first pass
    if (
        not required_reader_scopes
        or has_blank_scope(scopes=required_reader_scopes)
        or not set(required_reader_scopes).issubset(held)
    ):
        return AdminAccess.denied(reason=DenialReason.NOT_A_READER)
    slugs = {slug for scope in held if (slug := slug_from_access_scope(scope=scope)) is not None}
    if not slugs:
        return AdminAccess.denied(reason=DenialReason.NO_ACCESS_SCOPE)
    if WILDCARD_SLUG in slugs and allow_all_tenants and clients.all_keys:
        # Count only: the grant covers every client, and a key or name can identify a tenant.
        logger.info("Granted reader access to all %d clients through the all-tenants scope", len(clients.all_keys))
        return AdminAccess.reader(allowed_client_keys=clients.all_keys)
    keys = frozenset(key for slug in slugs - {WILDCARD_SLUG} for key in clients.keys_for(slug=slug))
    if not keys:
        return AdminAccess.denied(reason=DenialReason.UNMAPPED_ACCESS_SCOPE)
    return AdminAccess.reader(allowed_client_keys=keys)
