"""Scope predicates: the patient deny and the all-of match on required scopes."""

from collections.abc import Collection, Iterable

# A token carrying any patient-scoped grant is a patient or patient-app token and
# is never an administrator, even if it also holds an administrator scope. The
# check is a prefix match on the trimmed, casefolded scope, so ``Patient/*.read``
# matches but ``Patient.read`` (no slash) does not.
PATIENT_SCOPE_PREFIX = "patient/"


def normalize_scope(*, scope: str) -> str:
    """Strip and casefold a scope so scopes that differ only by padding or case compare equal."""
    return scope.strip().casefold()


def has_blank_scope(*, scopes: Iterable[str]) -> bool:
    """True when any scope is empty or whitespace only.

    A blank required scope, for example the ``[""]`` that ``"".split(",")`` gives for an
    unset setting, is satisfied by any held scope list that contains ``""`` (a token
    scope claim split on single spaces with a double or trailing space does). Callers
    treat a requirement list with a blank entry as unsatisfiable.
    """
    return any(not scope.strip() for scope in scopes)


def has_patient_scope(*, scopes: Iterable[str]) -> bool:
    """True when any scope starts with ``patient/`` (trimmed, case-insensitive)."""
    return any(normalize_scope(scope=scope).startswith(PATIENT_SCOPE_PREFIX) for scope in scopes)


def has_admin_scopes(*, scopes: Iterable[str], required_scopes: Collection[str]) -> bool:
    """True when ``scopes`` holds every required scope exactly and no ``patient/`` scope.

    An empty ``required_scopes`` is always False: ``set().issubset(anything)`` is
    True, so an empty requirement (for example an unset setting) would otherwise
    admit every verified token. A requirement list with a blank entry is False for
    the same reason (see ``has_blank_scope``). This is the one check every
    administrator path applies to the merged scope set.

    Args:
        scopes: the scopes the caller holds.
        required_scopes: every one of these must be held, matched exactly.
    """
    if not required_scopes or has_blank_scope(scopes=required_scopes):
        return False
    held = set(scopes)
    if has_patient_scope(scopes=held):
        return False
    return set(required_scopes).issubset(held)
