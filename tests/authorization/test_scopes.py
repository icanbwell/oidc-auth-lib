import pytest

from oidcauthlib.authorization.scopes import (
    PATIENT_SCOPE_PREFIX,
    has_admin_scopes,
    has_blank_scope,
    has_patient_scope,
    normalize_scope,
)


def test_patient_scope_prefix_constant() -> None:
    assert PATIENT_SCOPE_PREFIX == "patient/"


@pytest.mark.parametrize(
    ("scopes", "expected"),
    [
        (["Patient/x"], True),
        ([" patient/x"], True),
        (["patient/*.read"], True),
        (["PATIENT/*.*"], True),
        (["Patient.read"], False),
        (["user/patient"], False),
        (["xpatient/x"], False),
        (["example/admin"], False),
        ([], False),
    ],
)
def test_has_patient_scope(scopes: list[str], expected: bool) -> None:
    assert has_patient_scope(scopes=scopes) is expected


@pytest.mark.parametrize(
    ("scopes", "required", "expected"),
    [
        (["example/admin"], ["example/admin"], True),
        (["example/admin", "other"], ["example/admin"], True),
        (["example/admin"], ["example/admin", "example/second"], False),
        (["example/other"], ["example/admin"], False),
        (["example/admin"], [], False),
        ([], ["example/admin"], False),
        (["example/admin", "patient/x"], ["example/admin"], False),
        (["example/admin", " Patient/x"], ["example/admin"], False),
        (["Example/Admin"], ["example/admin"], False),
    ],
)
def test_has_admin_scopes(scopes: list[str], required: list[str], expected: bool) -> None:
    assert has_admin_scopes(scopes=scopes, required_scopes=required) is expected


@pytest.mark.parametrize(
    ("scopes", "expected"),
    [
        ([""], True),
        (["   "], True),
        (["a", ""], True),
        (["a", "b"], False),
        ([], False),
    ],
)
def test_has_blank_scope(scopes: list[str], expected: bool) -> None:
    assert has_blank_scope(scopes=scopes) is expected


@pytest.mark.parametrize("required", [[""], [" "], ["example/admin", ""]])
def test_a_blank_required_scope_admits_nobody_even_when_the_held_scopes_contain_a_blank(required: list[str]) -> None:
    held = "example/admin  other".split(" ")

    assert "" in held
    assert has_admin_scopes(scopes=held, required_scopes=required) is False


@pytest.mark.parametrize(
    ("scope", "expected"),
    [("  Example/Admin ", "example/admin"), ("STRASSE", "strasse"), ("Straße", "strasse"), ("", "")],
)
def test_normalize_scope(scope: str, expected: str) -> None:
    assert normalize_scope(scope=scope) == expected
