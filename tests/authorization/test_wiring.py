"""The documented flow end to end: parse, validate, build the resolver, resolve."""

import pytest

from oidcauthlib.authorization import (
    AdminAccess,
    ClientSlugResolver,
    DenialReason,
    ReaderConfigurationError,
    parse_client_keys_lenient,
    parse_client_keys_strict,
    resolve_admin_access,
    validate_reader_configuration,
)

RAW_CLIENTS = "One=key-1,Two=key-2"
ADMIN = ["example/admin"]
READER = ["example/reader"]


def _access(*, scopes: list[str], raw: str = RAW_CLIENTS, allow_all_tenants: bool = False) -> AdminAccess:
    validate_reader_configuration(reader_scopes=READER, admin_scopes=ADMIN, client_keys_raw=raw)
    clients = ClientSlugResolver.from_client_keys(clients=parse_client_keys_strict(raw=raw))
    return resolve_admin_access(
        scopes=scopes,
        admin_scopes=ADMIN,
        reader_scopes=READER,
        clients=clients,
        allow_all_tenants=allow_all_tenants,
    )


@pytest.mark.parametrize(
    ("scopes", "allow_all", "expected"),
    [
        (["example/admin"], False, AdminAccess.admin()),
        (["example/reader", "access/one.*"], False, AdminAccess.reader(allowed_client_keys=frozenset({"key-1"}))),
        (
            ["example/reader", "ACCESS/TWO.*", "access/one.*"],
            False,
            AdminAccess.reader(allowed_client_keys=frozenset({"key-1", "key-2"})),
        ),
        (
            ["example/reader", "access/*.*"],
            True,
            AdminAccess.reader(allowed_client_keys=frozenset({"key-1", "key-2"})),
        ),
        (["example/reader", "access/*.*"], False, AdminAccess.denied(reason=DenialReason.UNMAPPED_ACCESS_SCOPE)),
        (["example/reader"], False, AdminAccess.denied(reason=DenialReason.NO_ACCESS_SCOPE)),
        (["example/admin", "patient/x.read"], False, AdminAccess.denied(reason=DenialReason.PATIENT_SCOPE)),
    ],
)
def test_validated_configuration_resolves_each_tier(scopes: list[str], allow_all: bool, expected: AdminAccess) -> None:
    assert _access(scopes=scopes, allow_all_tenants=allow_all) == expected


@pytest.mark.parametrize("raw", ["One=key-1,no-equals", "One=key-1,one=key-2", '{"One": null}', '{"One": "key-1"'])
def test_a_malformed_mapping_fails_at_startup_instead_of_reaching_the_resolver(raw: str) -> None:
    with pytest.raises(ReaderConfigurationError):
        _access(scopes=["example/reader", "access/one.*"], raw=raw)


@pytest.mark.parametrize("raw", ['{"One": null, "Two": "key-2"}', "One=key-1,{broken"])
def test_the_lenient_parser_keeps_what_it_can_read_without_inventing_keys(raw: str) -> None:
    clients = ClientSlugResolver.from_client_keys(clients=parse_client_keys_lenient(raw=raw))

    assert "None" not in clients.all_keys
