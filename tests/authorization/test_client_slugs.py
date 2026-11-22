import logging

import pytest

from oidcauthlib.authorization.client_slugs import (
    WILDCARD_SLUG,
    ClientSlugResolver,
    normalize_slug,
    slug_from_access_scope,
)


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("access/tenant.*", "tenant"),
        ("Access/Tenant.*", "tenant"),
        (" access/tenant.* ", "tenant"),
        ("access/*.*", "*"),
        ("access/a.b.*", "a.b"),
        ("user/example", None),
        ("access/.*", None),
        ("access/ .*", None),
        ("user/patient/x", None),
        ("xaccess/tenant.*", None),
        ("access/demo.read", None),
        ("access/*.read", None),
        ("access/demo", None),
        ("access/*", None),
        ("", None),
    ],
)
def test_slug_from_access_scope(scope: str, expected: str | None) -> None:
    assert slug_from_access_scope(scope=scope) == expected


def test_normalize_slug_strips_and_casefolds() -> None:
    assert normalize_slug(slug="  SyntheticOne ") == "syntheticone"


def test_wildcard_slug_constant() -> None:
    assert WILDCARD_SLUG == "*"


@pytest.mark.parametrize(
    ("clients", "slug", "expected"),
    [
        ({"SyntheticOne": "synthetic-key-1"}, "syntheticone", {"synthetic-key-1"}),
        ({"SyntheticOne": "synthetic-key-1"}, "SYNTHETICONE", {"synthetic-key-1"}),
        ({" SyntheticOne ": " synthetic-key-1 "}, " syntheticone ", {"synthetic-key-1"}),
        ({"SyntheticOne": "synthetic-key-1"}, "other", set()),
        ({"SyntheticOne": "k1", "syntheticone ": "k2"}, "syntheticone", set()),
        ({}, "syntheticone", set()),
        ({"": "synthetic-key-1"}, "", set()),
        ({"SyntheticOne": ""}, "syntheticone", set()),
        ({"*": "synthetic-key-1"}, "*", set()),
    ],
)
def test_keys_for(clients: dict[str, str], slug: str, expected: set[str]) -> None:
    resolver = ClientSlugResolver.from_client_keys(clients=clients)
    assert resolver.keys_for(slug=slug) == frozenset(expected)


def test_all_keys_holds_every_client_key() -> None:
    resolver = ClientSlugResolver.from_client_keys(clients={"One": "k1", "Two": "k2"})
    assert resolver.all_keys == frozenset({"k1", "k2"})


def test_is_eligible_excludes_a_client_from_every_view() -> None:
    resolver = ClientSlugResolver.from_client_keys(
        clients={"One": "k1", "Two": "k2"},
        is_eligible=lambda name, key: name != "Two",
    )
    assert resolver.all_keys == frozenset({"k1"})
    assert resolver.keys_for(slug="two") == frozenset()
    assert resolver.keys_for(slug="one") == frozenset({"k1"})


def test_ambiguity_is_judged_among_eligible_clients_only() -> None:
    resolver = ClientSlugResolver.from_client_keys(
        clients={"Demo": "k1", "demo ": "k2"},
        is_eligible=lambda name, key: key == "k2",
    )
    assert resolver.keys_for(slug="demo") == frozenset({"k2"})


def test_slugs_by_key_maps_only_unambiguous_requested_keys() -> None:
    resolver = ClientSlugResolver.from_client_keys(clients={"One": "k1", "Two": "k2", "Dup": "k3", "dup": "k4"})
    assert dict(resolver.slugs_by_key(keys=frozenset({"k1", "k3", "k4"}))) == {"k1": "one"}


def test_ambiguity_is_logged_by_slug_only(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        ClientSlugResolver.from_client_keys(clients={"Demo": "secret-key-a", "demo": "secret-key-b"})
    assert "demo" in caplog.text
    assert "secret-key-a" not in caplog.text
    assert "secret-key-b" not in caplog.text


@pytest.mark.parametrize("value", [None, 12345, True, ["k"], {"k": "v"}])
def test_a_client_whose_key_is_not_a_string_is_skipped(value: object) -> None:
    resolver = ClientSlugResolver.from_client_keys(
        clients={"Bad": value, "Good": "synthetic-key-1"}  # type: ignore[dict-item]  # deliberately off-type input
    )

    assert resolver.keys_for(slug="bad") == frozenset()
    assert resolver.all_keys == frozenset({"synthetic-key-1"})


def test_client_keys_do_not_appear_in_repr() -> None:
    resolver = ClientSlugResolver.from_client_keys(clients={"Demo": "synthetic-key-1"})

    assert "synthetic-key-1" not in repr(resolver)


def test_skipped_non_string_keys_are_counted_in_one_warning_without_names_or_keys(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        ClientSlugResolver.from_client_keys(
            clients={"SecretName": 12345, "OtherSecret": None, "Good": "synthetic-key-1"}  # type: ignore[dict-item]  # deliberately off-type input
        )

    messages = [record.getMessage() for record in caplog.records]
    assert messages == ["Skipped 2 client-key entries whose key is not a string; their clients select nothing"]
    assert "SecretName" not in messages[0]
    assert "12345" not in messages[0]


def test_no_warning_when_every_key_is_a_string(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        ClientSlugResolver.from_client_keys(clients={"Good": "synthetic-key-1"})

    assert caplog.records == []
