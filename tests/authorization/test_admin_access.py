import pytest

from oidcauthlib.authorization.admin_access import (
    AdminAccess,
    AdminTier,
    DenialReason,
    resolve_admin_access,
)
from oidcauthlib.authorization.client_slugs import ClientSlugResolver

CLIENTS = ClientSlugResolver.from_client_keys(
    clients={
        "SyntheticOne": "synthetic-key-1",
        "SyntheticTwo": "synthetic-key-2",
        "Dup": "synthetic-key-3",
        "dup": "synthetic-key-4",
    }
)
ADMIN = ["example/admin"]
READER = ["example/reader"]


def _resolve(
    *, scopes: list[str], allow_all_tenants: bool = False, reader_scopes: list[str] | None = None
) -> AdminAccess:
    return resolve_admin_access(
        scopes=scopes,
        admin_scopes=ADMIN,
        reader_scopes=READER if reader_scopes is None else reader_scopes,
        clients=CLIENTS,
        allow_all_tenants=allow_all_tenants,
    )


@pytest.mark.parametrize(
    ("scopes", "allow_all", "tier", "keys", "reason"),
    [
        (["patient/x", "example/admin"], False, None, frozenset(), DenialReason.PATIENT_SCOPE),
        (
            ["Patient/x", "example/reader", "access/syntheticone.*"],
            False,
            None,
            frozenset(),
            DenialReason.PATIENT_SCOPE,
        ),
        (["example/admin", "example/reader"], False, AdminTier.ADMIN, None, None),
        (["example/admin"], False, AdminTier.ADMIN, None, None),
        (["example/reader"], False, None, frozenset(), DenialReason.NO_ACCESS_SCOPE),
        (["example/reader", "access/unknown.*"], False, None, frozenset(), DenialReason.UNMAPPED_ACCESS_SCOPE),
        (["example/reader", "access/dup.*"], False, None, frozenset(), DenialReason.UNMAPPED_ACCESS_SCOPE),
        (["example/reader", "access/*.*"], True, AdminTier.READER, CLIENTS.all_keys, None),
        (["example/reader", "access/*.*"], False, None, frozenset(), DenialReason.UNMAPPED_ACCESS_SCOPE),
        (["example/other", "access/syntheticone.*"], False, None, frozenset(), DenialReason.NOT_A_READER),
        (["access/syntheticone.*"], False, None, frozenset(), DenialReason.NOT_A_READER),
        (["example/reader", "access/syntheticone.*"], False, AdminTier.READER, frozenset({"synthetic-key-1"}), None),
        (["example/reader", "Access/SyntheticOne.*"], False, AdminTier.READER, frozenset({"synthetic-key-1"}), None),
        (
            ["example/reader", "access/syntheticone.*", "access/synthetictwo.*"],
            False,
            AdminTier.READER,
            frozenset({"synthetic-key-1", "synthetic-key-2"}),
            None,
        ),
        (["example/reader", "access/syntheticone.read"], False, None, frozenset(), DenialReason.NO_ACCESS_SCOPE),
        ([], False, None, frozenset(), DenialReason.NOT_A_READER),
    ],
)
def test_resolve_admin_access(
    scopes: list[str],
    allow_all: bool,
    tier: AdminTier | None,
    keys: frozenset[str] | None,
    reason: DenialReason | None,
) -> None:
    access = _resolve(scopes=scopes, allow_all_tenants=allow_all)
    assert access.tier is tier
    assert access.allowed_client_keys == keys
    assert access.denial_reason == reason


def test_empty_reader_scopes_deny_readers() -> None:
    access = _resolve(scopes=["access/syntheticone.*"], reader_scopes=[])
    assert access.tier is None
    assert access.denial_reason is DenialReason.NOT_A_READER


def test_wildcard_with_no_clients_is_denied() -> None:
    empty = ClientSlugResolver.from_client_keys(clients={})
    access = resolve_admin_access(
        scopes=["example/reader", "access/*.*"],
        admin_scopes=ADMIN,
        reader_scopes=READER,
        clients=empty,
        allow_all_tenants=True,
    )
    assert access.tier is None
    assert access.denial_reason is DenialReason.UNMAPPED_ACCESS_SCOPE


def test_empty_admin_scopes_admit_nobody_as_admin() -> None:
    access = resolve_admin_access(
        scopes=["example/admin"],
        admin_scopes=[],
        reader_scopes=READER,
        clients=CLIENTS,
        allow_all_tenants=False,
    )
    assert access.tier is None


def test_denied_access_has_empty_allowed_set() -> None:
    for scopes in (["patient/x"], ["example/reader"], ["example/reader", "access/none.*"], []):
        access = _resolve(scopes=scopes)
        assert access.tier is None
        assert access.allowed_client_keys == frozenset()
        assert access.allowed_client_keys is not None


def test_denial_reason_values_are_stable_strings() -> None:
    assert [reason.value for reason in DenialReason] == [
        "patient_scope",
        "not_a_reader",
        "no_access_scope",
        "unmapped_access_scope",
    ]


def test_constructors_build_valid_values() -> None:
    assert AdminAccess.admin().allowed_client_keys is None
    reader = AdminAccess.reader(allowed_client_keys=frozenset({"k"}))
    assert reader.tier is AdminTier.READER
    denied = AdminAccess.denied(reason=DenialReason.NOT_A_READER)
    assert denied.allowed_client_keys == frozenset()


@pytest.mark.parametrize(
    ("tier", "keys", "reason"),
    [
        (AdminTier.READER, None, None),
        (AdminTier.READER, frozenset(), None),
        (None, frozenset(), None),
        (None, None, DenialReason.NOT_A_READER),
        (None, frozenset({"k"}), DenialReason.NOT_A_READER),
        (AdminTier.ADMIN, frozenset(), None),
        (AdminTier.ADMIN, frozenset({"k"}), None),
    ],
)
def test_admin_access_invariants(
    tier: AdminTier | None, keys: frozenset[str] | None, reason: DenialReason | None
) -> None:
    with pytest.raises(ValueError):
        AdminAccess(tier=tier, allowed_client_keys=keys, denial_reason=reason)


@pytest.mark.parametrize(
    ("admin_scopes", "reader_scopes", "held", "reason"),
    [
        ([""], READER, ["openid", "", "profile"], DenialReason.NOT_A_READER),
        (ADMIN, [""], ["openid", "", "access/syntheticone.*"], DenialReason.NOT_A_READER),
        (ADMIN, ["example/reader", " "], ["example/reader", " ", "access/syntheticone.*"], DenialReason.NOT_A_READER),
    ],
)
def test_a_blank_required_scope_never_grants_a_tier(
    admin_scopes: list[str], reader_scopes: list[str], held: list[str], reason: DenialReason
) -> None:
    access = resolve_admin_access(
        scopes=held,
        admin_scopes=admin_scopes,
        reader_scopes=reader_scopes,
        clients=CLIENTS,
        allow_all_tenants=False,
    )

    assert access == AdminAccess.denied(reason=reason)


def test_non_string_scopes_are_ignored_instead_of_raising() -> None:
    access = _resolve(scopes=["example/reader", 5, None, "access/syntheticone.*"])  # type: ignore[list-item]

    assert access == AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))


def test_a_mutable_key_set_is_frozen_and_cannot_widen_the_decision() -> None:
    keys = {"synthetic-key-1"}
    access = AdminAccess(tier=AdminTier.READER, allowed_client_keys=keys, denial_reason=None)  # type: ignore[arg-type]

    keys.add("synthetic-key-2")

    assert access.allowed_client_keys == frozenset({"synthetic-key-1"})
    assert isinstance(access.allowed_client_keys, frozenset)


def test_client_keys_do_not_appear_in_repr() -> None:
    access = AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))

    assert "synthetic-key-1" not in repr(access)
    assert "synthetic-key-1" not in str(access)


def test_wildcard_selects_every_client_including_one_whose_slug_is_ambiguous() -> None:
    access = _resolve(scopes=["example/reader", "access/*.*"], allow_all_tenants=True)

    assert access.allowed_client_keys == CLIENTS.all_keys
    assert {"synthetic-key-3", "synthetic-key-4"} <= (access.allowed_client_keys or frozenset())
    assert CLIENTS.keys_for(slug="dup") == frozenset()
