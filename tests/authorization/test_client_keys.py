import pytest

from oidcauthlib.authorization.client_keys import (
    ClientKeysFormatError,
    parse_client_keys_lenient,
    parse_client_keys_strict,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", {}),
        ('{"SyntheticOne": "synthetic-key-1"}', {"SyntheticOne": "synthetic-key-1"}),
        ("One=k1,Two=k2", {"One": "k1", "Two": "k2"}),
        (" One = k1 , Two = k2 ", {"One": "k1", "Two": "k2"}),
        # A malformed JSON object falls back to comma parsing, which finds no usable entry.
        ('{"One": "k1"', {}),
        ("One=k1,no-equals,Two=k2", {"One": "k1", "Two": "k2"}),
        ("One=a=b", {"One": "a=b"}),
    ],
)
def test_lenient_keeps_today_behavior(raw: str, expected: dict[str, str]) -> None:
    assert parse_client_keys_lenient(raw=raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '["One=k1"]',
        '{"One": "k1"',
        '{"One": 1}',
        '{"One": {"nested": "k1"}}',
        '{"One": "k1", "One": "k2"}',
        "One=k1,One=k2",
        "One=k1,one=k2",
        "One=k1, one =k2",
        "One=k1,no-equals",
        "One=",
        "=synthetic-key-1",
        " = ",
        '{"": "k1"}',
        '{"One": ""}',
    ],
)
def test_strict_rejects(raw: str) -> None:
    with pytest.raises(ClientKeysFormatError):
        parse_client_keys_strict(raw=raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", {}),
        ("   ", {}),
        ('{"SyntheticOne": "synthetic-key-1"}', {"SyntheticOne": "synthetic-key-1"}),
        ("One=k1,Two=k2", {"One": "k1", "Two": "k2"}),
        (" One = k1 , Two = k2 ", {"One": "k1", "Two": "k2"}),
        ("One=a=b", {"One": "a=b"}),
    ],
)
def test_strict_accepts_valid(raw: str, expected: dict[str, str]) -> None:
    assert parse_client_keys_strict(raw=raw) == expected


def test_strict_error_never_contains_a_key_or_name() -> None:
    with pytest.raises(ClientKeysFormatError) as caught:
        parse_client_keys_strict(raw="SecretName=secret-key,secretname=other-key")
    message = str(caught.value)
    assert "secret-key" not in message
    assert "other-key" not in message
    assert "SecretName" not in message
