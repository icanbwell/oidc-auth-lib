"""Which client keys an ``access/<slug>.*`` scope selects.

A slug is the text between ``access/`` and the trailing ``.*`` of the scope. The
prefix and suffix match exactly and case-sensitively, like the FHIR server's own
``access/`` check. The slug selects the client whose name, stripped and with ASCII
letters lowercased, equals the slug stripped and lowercased the same way; other
characters are never folded, so ``ß`` and ``SS`` stay different. One slug selects one
key. A slug that matches no name is unmapped; two names that lowercase alike make the
slug ambiguous, and an ambiguous slug selects nothing (logged by slug only, never by
key). The ``*`` slug is the wildcard and never selects a single key.
"""

import logging
import string
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

logger = logging.getLogger(__name__)

ACCESS_SCOPE_PREFIX = "access/"
ACCESS_SCOPE_SUFFIX = ".*"
# ``access/*.*``: every client in the mapping, honored only when a caller opts in.
WILDCARD_SLUG = "*"


_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def normalize_slug(*, slug: str) -> str:
    """Strip a slug or a client name and lowercase its ASCII letters so they compare equal.

    Only ``A`` to ``Z`` is folded. ``str.casefold`` would also map ``ß`` to ``ss`` and the
    Kelvin sign to ``k``, which would let a scope the identity provider treats as different
    select a client.
    """
    return slug.strip().translate(_ASCII_LOWER)


def slug_from_access_scope(*, scope: str) -> str | None:
    """The slug of an ``access/<slug>.*`` scope, normalized; ``None`` for any other scope.

    The ``access/`` prefix and the ``.*`` suffix match exactly and case-sensitively, so
    ``Access/Tenant.*`` and ``ACCESS/TENANT.*`` give ``None``, as they select nothing on the
    FHIR server. The slug is normalized with ``normalize_slug``: ``access/Tenant.*`` gives
    ``tenant`` and ``access/*.*`` gives ``*``. The suffix must be exactly ``.*``:
    ``access/demo.read``, ``access/*.read``, ``access/demo`` and an empty slug
    (``access/.*``) all give ``None``. The scope is not stripped: a padded scope gives
    ``None``, because the reader and administrator requirements match exactly and a held
    scope must not grant more than the server would.

    Args:
        scope: any scope string.
    """
    if not scope.startswith(ACCESS_SCOPE_PREFIX):
        return None
    if not scope.endswith(ACCESS_SCOPE_SUFFIX):
        return None
    body = scope[len(ACCESS_SCOPE_PREFIX) :]
    slug = normalize_slug(slug=body[: -len(ACCESS_SCOPE_SUFFIX)])
    return slug or None


@dataclass(frozen=True)
class ClientSlugResolver:
    """Slug to its one client key, and every eligible client key.

    ``all_keys`` is what ``access/*.*`` selects when a caller opts in. It holds every
    eligible client's key, including the keys of clients whose slug is ambiguous (which
    ``keys_for`` refuses one by one). Client keys identify tenants, so both fields stay
    out of ``repr``.
    """

    keys_by_slug: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}), repr=False)
    all_keys: frozenset[str] = field(default=frozenset(), repr=False)

    @classmethod
    def from_client_keys(
        cls,
        *,
        clients: Mapping[str, str],
        is_eligible: Callable[[str, str], bool] | None = None,
    ) -> "ClientSlugResolver":
        """Build the resolver from a ``name -> key`` map.

        Args:
            clients: the client-key mapping. Entries with a blank name or key, or a
                key that is not a string (for example a JSON ``null`` or number), are
                skipped.
            is_eligible: optional strategy ``(name, key) -> bool``. A client it
                rejects is in neither ``keys_by_slug`` nor ``all_keys``, and does
                not take part in ambiguity checks.
        """
        keys_by_slug_candidates: dict[str, list[str]] = {}
        skipped_non_string = 0
        for name, key in clients.items():
            if not isinstance(key, str):
                skipped_non_string += 1
                continue
            slug = normalize_slug(slug=str(name))
            clean_key = key.strip()
            if not slug or not clean_key:
                continue
            if is_eligible is not None and not is_eligible(str(name), clean_key):
                continue
            keys_by_slug_candidates.setdefault(slug, []).append(clean_key)
        if skipped_non_string:
            logger.warning(
                "Skipped %d client-key entries whose key is not a string; their clients select nothing",
                skipped_non_string,
            )
        keys_by_slug: dict[str, str] = {}
        for slug, keys in keys_by_slug_candidates.items():
            if slug == WILDCARD_SLUG:
                continue
            if len(keys) > 1:
                logger.warning(
                    "Client names that lowercase to %s are ambiguous; the access slug selects no client",
                    slug,
                )
                continue
            keys_by_slug[slug] = keys[0]
        return cls(
            keys_by_slug=MappingProxyType(keys_by_slug),
            all_keys=frozenset(key for keys in keys_by_slug_candidates.values() for key in keys),
        )

    def keys_for(self, *, slug: str) -> frozenset[str]:
        """The one key ``slug`` selects, or an empty set when it is unmapped or ambiguous."""
        key = self.keys_by_slug.get(normalize_slug(slug=slug))
        return frozenset() if key is None else frozenset({key})

    def slugs_by_key(self, *, keys: frozenset[str]) -> Mapping[str, str]:
        """Each of ``keys`` that has an unambiguous slug, with that slug.

        The slug is a bounded label that is safe to use in metrics and audit
        records where the key itself must not appear.
        """
        return MappingProxyType({key: slug for slug, key in self.keys_by_slug.items() if key in keys})
