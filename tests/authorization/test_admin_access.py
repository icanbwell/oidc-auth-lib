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
        (["example/reader", "access/SyntheticOne.*"], False, AdminTier.READER, frozenset({"synthetic-key-1"}), None),
        (["example/reader", "Access/SyntheticOne.*"], False, None, frozenset(), DenialReason.NO_ACCESS_SCOPE),
        (["example/reader", "ACCESS/SYNTHETICONE.*"], False, None, frozenset(), DenialReason.NO_ACCESS_SCOPE),
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
    access = _resolve(scopes=["example/reader", 5, None, "access/syntheticone.*"])  # type: ignore[list-item]  # deliberately off-type input
    assert access == AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))


def test_a_mutable_key_set_is_frozen_and_cannot_widen_the_decision() -> None:
    keys = {"synthetic-key-1"}
    access = AdminAccess(tier=AdminTier.READER, allowed_client_keys=keys, denial_reason=None)  # type: ignore[arg-type]  # deliberately off-type input
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


@pytest.mark.parametrize("keys", ["key-1", b"key-1"])
def test_a_bare_string_is_refused_instead_of_becoming_a_set_of_characters(keys: str | bytes) -> None:
    with pytest.raises(TypeError):
        AdminAccess.reader(allowed_client_keys=keys)  # type: ignore[arg-type]  # deliberately off-type input


def test_an_invisible_character_requirement_never_grants_a_tier() -> None:
    access = resolve_admin_access(
        scopes=["\u200b", "access/syntheticone.*"],
        admin_scopes=["\u200b"],
        reader_scopes=["\u200b"],
        clients=CLIENTS,
        allow_all_tenants=False,
    )

    assert access == AdminAccess.denied(reason=DenialReason.NOT_A_READER)


@pytest.mark.parametrize(
    ("admin_scopes", "reader_scopes", "expected"),
    [
        # A malformed admin requirement can never grant admin; a caller that holds the reader scopes stays a reader.
        ([None], READER, AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))),
        ([5], READER, AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))),
        (ADMIN, [None], AdminAccess.denied(reason=DenialReason.NOT_A_READER)),
        (ADMIN, [5], AdminAccess.denied(reason=DenialReason.NOT_A_READER)),
        ([None], [None], AdminAccess.denied(reason=DenialReason.NOT_A_READER)),
    ],
)
def test_a_non_string_requirement_entry_never_grants_a_tier_and_never_raises(
    admin_scopes: list[object], reader_scopes: list[object], expected: AdminAccess
) -> None:
    access = resolve_admin_access(
        scopes=["example/reader", "access/syntheticone.*"],
        admin_scopes=admin_scopes,  # type: ignore[arg-type]  # deliberately off-type input
        reader_scopes=reader_scopes,  # type: ignore[arg-type]  # deliberately off-type input
        clients=CLIENTS,
        allow_all_tenants=False,
    )

    assert access == expected
    assert access.tier is not AdminTier.ADMIN


def test_ignored_non_string_held_scopes_are_counted_in_one_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        _resolve(scopes=["example/reader", 5, None, "access/syntheticone.*"])  # type: ignore[list-item]  # deliberately off-type input

    assert [record.getMessage() for record in caplog.records] == ["Ignored 2 held scope entries that are not strings"]


def test_no_warning_when_every_held_scope_is_a_string(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        _resolve(scopes=["example/reader", "access/syntheticone.*"])

    assert caplog.records == []


def test_one_shot_iterator_requirements_never_grant_a_tier() -> None:
    admin_from_empty = resolve_admin_access(
        scopes=["other"],
        admin_scopes=iter(()),  # type: ignore[arg-type]  # deliberately off-type input
        reader_scopes=READER,
        clients=CLIENTS,
        allow_all_tenants=False,
    )
    reader_from_empty = resolve_admin_access(
        scopes=["other", "access/syntheticone.*"],
        admin_scopes=ADMIN,
        reader_scopes=iter(()),  # type: ignore[arg-type]  # deliberately off-type input
        clients=CLIENTS,
        allow_all_tenants=False,
    )
    reader_from_generator = resolve_admin_access(
        scopes=["example/reader", "access/syntheticone.*"],
        admin_scopes=ADMIN,
        reader_scopes=(scope for scope in READER),  # type: ignore[arg-type]  # deliberately off-type input
        clients=CLIENTS,
        allow_all_tenants=False,
    )

    assert admin_from_empty == AdminAccess.denied(reason=DenialReason.NOT_A_READER)
    assert reader_from_empty == AdminAccess.denied(reason=DenialReason.NOT_A_READER)
    assert reader_from_generator == AdminAccess.reader(allowed_client_keys=frozenset({"synthetic-key-1"}))


@pytest.mark.parametrize(
    ("tier", "keys", "reason"),
    [
        ("reader", None, None),
        ("reader", frozenset(), None),
        ("admin", frozenset({"synthetic-key-1"}), None),
        ("admn", None, None),
        (5, None, None),
        (AdminTier.ADMIN, None, DenialReason.NOT_A_READER),
        (AdminTier.READER, frozenset({"synthetic-key-1"}), DenialReason.PATIENT_SCOPE),
    ],
)
def test_access_with_an_inconsistent_or_unknown_tier_is_refused(
    tier: object, keys: frozenset[str] | None, reason: DenialReason | None
) -> None:
    with pytest.raises(ValueError):
        AdminAccess(tier=tier, allowed_client_keys=keys, denial_reason=reason)  # type: ignore[arg-type]  # deliberately off-type input


@pytest.mark.parametrize(("tier", "expected"), [("admin", AdminTier.ADMIN), ("reader", AdminTier.READER)])
def test_a_plain_string_tier_is_coerced_to_the_enum(tier: str, expected: AdminTier) -> None:
    keys = None if expected is AdminTier.ADMIN else frozenset({"synthetic-key-1"})

    access = AdminAccess(tier=tier, allowed_client_keys=keys, denial_reason=None)  # type: ignore[arg-type]  # deliberately off-type input

    assert access.tier is expected


def test_the_all_tenants_grant_is_logged_once_with_a_count_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("INFO"):
        access = _resolve(scopes=["example/reader", "access/*.*"], allow_all_tenants=True)

    assert access.tier is AdminTier.READER
    assert [record.getMessage() for record in caplog.records] == [
        f"Granted reader access to all {len(CLIENTS.all_keys)} clients through the all-tenants scope"
    ]


@pytest.mark.parametrize(
    ("scopes", "allow_all_tenants"),
    [
        (["example/reader", "access/*.*"], False),
        (["example/reader", "access/syntheticone.*"], True),
    ],
)
def test_no_all_tenants_log_when_the_wildcard_grant_is_not_used(
    scopes: list[str], allow_all_tenants: bool, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO"):
        _resolve(scopes=scopes, allow_all_tenants=allow_all_tenants)

    assert caplog.records == []
