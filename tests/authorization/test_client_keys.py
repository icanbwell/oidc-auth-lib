import logging

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


def test_lenient_parser_logs_the_json_fallback_once_without_the_value(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        parse_client_keys_lenient(raw='{"SecretName": "secret-key"')

    messages = [record.getMessage() for record in caplog.records]
    assert any("falling back to comma parsing" in message for message in messages)
    assert all("SecretName" not in message and "secret-key" not in message for message in messages)


def test_lenient_parser_logs_only_a_count_of_dropped_entries(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        clients = parse_client_keys_lenient(raw="One=key-1,SecretOne,SecretTwo,,")

    assert clients == {"One": "key-1"}
    assert [record.getMessage() for record in caplog.records] == ["Dropped 2 client-key entries that have no '='"]


@pytest.mark.parametrize("raw", ["One=key-1,Two=key-2", '{"One": "key-1"}', "", "One=key-1,"])
def test_lenient_parser_logs_nothing_for_well_formed_or_empty_input(raw: str, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        parse_client_keys_lenient(raw=raw)

    assert caplog.records == []


def test_strict_parser_allows_two_names_to_share_one_key_as_aliases() -> None:
    assert parse_client_keys_strict(raw="One=key-1,Alias=key-1") == {"One": "key-1", "Alias": "key-1"}


def test_strict_parser_treats_names_that_differ_only_by_non_ascii_folding_as_distinct() -> None:
    assert parse_client_keys_strict(raw="Straße=key-1,STRASSE=key-2") == {
        "Straße": "key-1",
        "STRASSE": "key-2",
    }


def test_lenient_parser_logs_only_a_count_of_repeated_json_names(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        clients = parse_client_keys_lenient(raw='{"SecretOne": "k1", "SecretOne": "k2"}')

    assert clients == {"SecretOne": "k2"}
    assert [record.getMessage() for record in caplog.records] == [
        "Found 1 repeated names in the client-key mapping; the last value is kept"
    ]


def test_lenient_parser_keeps_only_string_json_values_and_logs_a_count(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        clients = parse_client_keys_lenient(raw='{"One": "k1", "Two": null, "Three": 3}')

    assert clients == {"One": "k1"}
    assert [record.getMessage() for record in caplog.records] == [
        "Dropped 2 client-key entries whose value is not a string"
    ]
