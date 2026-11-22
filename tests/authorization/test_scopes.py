import pytest

from oidcauthlib.authorization.scopes import (
    PATIENT_SCOPE_PREFIX,
    has_admin_scopes,
    has_patient_scope,
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
