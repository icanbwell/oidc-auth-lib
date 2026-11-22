"""Scope predicates: the patient deny and the all-of match on required scopes."""

from collections.abc import Collection, Iterable

# A token carrying any patient-scoped grant is a patient or patient-app token and
# is never an administrator, even if it also holds an administrator scope. The
# check is a prefix match on the trimmed, casefolded scope, so ``Patient/*.read``
# matches but ``Patient.read`` (no slash) does not.
PATIENT_SCOPE_PREFIX = "patient/"


def has_patient_scope(*, scopes: Iterable[str]) -> bool:
    """True when any scope starts with ``patient/`` (trimmed, case-insensitive)."""
    return any(scope.strip().casefold().startswith(PATIENT_SCOPE_PREFIX) for scope in scopes)


def has_admin_scopes(*, scopes: Iterable[str], required_scopes: Collection[str]) -> bool:
    """True when ``scopes`` holds every required scope exactly and no ``patient/`` scope.

    An empty ``required_scopes`` is always False: ``set().issubset(anything)`` is
    True, so an empty requirement (for example an unset setting) would otherwise
    admit every verified token. This is the one check every administrator path
    applies to the merged scope set.
    """
    if not required_scopes:
        return False
    held = set(scopes)
    if has_patient_scope(scopes=held):
        return False
    return set(required_scopes).issubset(held)
