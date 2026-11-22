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
        ([" Example/Admin "], ["example/admin"], VALID_KEYS),
        (["access/syntheticone.*"], ["example/admin"], VALID_KEYS),
        (["Access/x"], ["example/admin"], VALID_KEYS),
        (["patient/x"], ["example/admin"], VALID_KEYS),
        (["openid"], ["example/admin"], VALID_KEYS),
        (["profile"], ["example/admin"], VALID_KEYS),
        (["Email"], ["example/admin"], VALID_KEYS),
        (["groups"], ["example/admin"], VALID_KEYS),
        (["example/*.*"], ["example/admin"], VALID_KEYS),
        (["example/reader"], ["access/*.*"], VALID_KEYS),
        (["example/reader"], [" Access/Anything.*"], VALID_KEYS),
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
        ([], ["access/*.*"], ""),
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
