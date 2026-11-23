import pytest

from oidcauthlib.authorization.reader_configuration import (
    ReaderConfigurationError,
    validate_reader_configuration,
)

VALID_KEYS = "SyntheticOne=synthetic-key-1,SyntheticTwo=synthetic-key-2"


@pytest.mark.parametrize(
    ("reader_scopes", "admin_scopes", "keys"),
    [
        (["example/reader"], ["example/admin"], ""),
        (["example/reader"], ["example/admin"], "   "),
        (["example/reader"], ["example/admin"], '["SyntheticOne=k"]'),
        (["example/reader"], ["example/admin"], "SyntheticOne=k,no-equals"),
        (["example/reader"], ["example/admin"], "SyntheticOne=,Two=k"),
        (["example/reader"], ["example/admin"], "=k"),
        (["example/reader"], ["example/admin"], "One=k1,one=k2"),
        (["example/reader"], ["example/admin"], "One=k1,One=k2"),
        (["example/reader"], ["example/admin"], '{"One": "k1"'),
        (["example/reader"], ["example/admin"], "*=k1"),
        (["example/reader"], ["example/admin"], "Some*Name=k1"),
        (["example/admin"], ["example/admin"], VALID_KEYS),
        (["Example/Admin"], ["example/admin"], VALID_KEYS),
        (["access/syntheticone.*"], ["example/admin"], VALID_KEYS),
        (["Access/x"], ["example/admin"], VALID_KEYS),
        (["patient/x"], ["example/admin"], VALID_KEYS),
        (["openid"], ["example/admin"], VALID_KEYS),
        (["profile"], ["example/admin"], VALID_KEYS),
        (["Email"], ["example/admin"], VALID_KEYS),
        (["groups"], ["example/admin"], VALID_KEYS),
        (["example/*.*"], ["example/admin"], VALID_KEYS),
        (["example/reader"], ["access/*.*"], VALID_KEYS),
        (["example/reader"], ["Access/Anything.*"], VALID_KEYS),
        (["example/reader"], ["access/acme.*", "example/admin"], VALID_KEYS),
        ([""], ["example/admin"], VALID_KEYS),
        (["example/reader"], [""], VALID_KEYS),
        (["example/reader", " "], ["example/admin"], VALID_KEYS),
        ([" example/reader"], ["example/admin"], VALID_KEYS),
        (["example/reader"], ["example/admin "], VALID_KEYS),
        ([""], ["example/admin"], ""),
        ([], [""], ""),
        ([], [" example/admin"], ""),
        (["\u200b"], ["example/admin"], VALID_KEYS),
        (["example/reader"], ["\ufeffexample/admin"], VALID_KEYS),
        ([], ["\u200b"], ""),
    ],
)
def test_validate_reader_configuration_refuses(reader_scopes: list[str], admin_scopes: list[str], keys: str) -> None:
    with pytest.raises(ReaderConfigurationError):
        validate_reader_configuration(reader_scopes=reader_scopes, admin_scopes=admin_scopes, client_keys_raw=keys)


@pytest.mark.parametrize(
    ("reader_scopes", "admin_scopes", "keys"),
    [
        (["example/reader"], ["example/admin"], VALID_KEYS),
        (["example/reader"], ["example/admin"], '{"SyntheticOne": "synthetic-key-1"}'),
        ([], ["example/admin"], ""),
        ([], ["example/admin"], "not even parseable"),
    ],
)
def test_validate_reader_configuration_accepts(reader_scopes: list[str], admin_scopes: list[str], keys: str) -> None:
    validate_reader_configuration(reader_scopes=reader_scopes, admin_scopes=admin_scopes, client_keys_raw=keys)


def test_error_messages_never_contain_a_key_or_client_name() -> None:
    with pytest.raises(ReaderConfigurationError) as caught:
        validate_reader_configuration(
            reader_scopes=["example/reader"],
            admin_scopes=["example/admin"],
            client_keys_raw="SecretName=secret-key,secretname=other-key",
        )
    message = str(caught.value)
    assert "secret-key" not in message
    assert "other-key" not in message
    assert "SecretName" not in message


@pytest.mark.parametrize(
    ("reader_scopes", "admin_scopes"),
    [([None], ["example/admin"]), (["example/reader"], [None]), ([5], [5]), ([], [None])],
)
def test_a_non_string_scope_entry_is_refused_with_the_typed_error(
    reader_scopes: list[object], admin_scopes: list[object]
) -> None:
    with pytest.raises(ReaderConfigurationError):
        validate_reader_configuration(
            reader_scopes=reader_scopes,  # type: ignore[arg-type]  # deliberately off-type input
            admin_scopes=admin_scopes,  # type: ignore[arg-type]  # deliberately off-type input
            client_keys_raw=VALID_KEYS,
        )


@pytest.mark.parametrize("scope", ["address", "phone", "offline_access", "Offline_Access"])
def test_every_standard_oidc_scope_is_refused_as_a_reader_requirement(scope: str) -> None:
    with pytest.raises(ReaderConfigurationError):
        validate_reader_configuration(reader_scopes=[scope], admin_scopes=["example/admin"], client_keys_raw=VALID_KEYS)


def test_one_shot_iterators_are_validated_in_full() -> None:
    with pytest.raises(ReaderConfigurationError):
        validate_reader_configuration(
            reader_scopes=(scope for scope in ["example/reader", "openid"]),  # type: ignore[arg-type]  # deliberately off-type input
            admin_scopes=(scope for scope in ["example/admin"]),  # type: ignore[arg-type]  # deliberately off-type input
            client_keys_raw=VALID_KEYS,
        )


@pytest.mark.parametrize(
    ("reader_scopes", "admin_scopes"),
    [
        ([], ["openid"]),
        (["example/reader"], ["openid"]),
        ([], ["Profile", "EMAIL"]),
        ([], ["access/*.*"]),
        ([], ["access/acme.*"]),
        ([], ["openid", "access/acme.*"]),
        ([], ["Access/Acme.*", "groups"]),
        (["example/reader"], ["offline_access", "groups"]),
    ],
)
def test_an_administrator_requirement_made_only_of_generic_scopes_is_refused(
    reader_scopes: list[str], admin_scopes: list[str]
) -> None:
    with pytest.raises(ReaderConfigurationError):
        validate_reader_configuration(
            reader_scopes=reader_scopes, admin_scopes=admin_scopes, client_keys_raw=VALID_KEYS
        )


@pytest.mark.parametrize(
    ("reader_scopes", "admin_scopes"),
    [
        ([], ["openid", "example/admin"]),
        (["example/reader"], ["openid", "example/admin"]),
        ([], ["example/admin"]),
        ([], ["access/acme.*", "example/admin"]),
    ],
)
def test_an_administrator_requirement_with_a_specific_scope_is_accepted(
    reader_scopes: list[str], admin_scopes: list[str]
) -> None:
    validate_reader_configuration(reader_scopes=reader_scopes, admin_scopes=admin_scopes, client_keys_raw=VALID_KEYS)
