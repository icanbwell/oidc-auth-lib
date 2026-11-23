import importlib

import pytest

EXPORTED_NAMES = [
    "AdminAccess",
    "AdminTier",
    "ClientKeysFormatError",
    "ClientSlugResolver",
    "DenialReason",
    "ReaderConfigurationError",
    "has_admin_scopes",
    "has_patient_scope",
    "parse_client_keys_lenient",
    "parse_client_keys_strict",
    "resolve_admin_access",
    "slug_from_access_scope",
    "validate_reader_configuration",
]


@pytest.mark.parametrize("name", EXPORTED_NAMES)
def test_public_exports(name: str) -> None:
    module = importlib.import_module("oidcauthlib.authorization")
    assert hasattr(module, name)
    assert name in module.__all__
