import pytest
from oidcauthlib.auth.auth_helper import AuthHelper
from typing import Any


def test_encode_and_decode_state() -> None:
    data: dict[str, str | None] = {"user": "alice", "scope": "openid"}
    encoded: str = AuthHelper.encode_state(data)
    decoded: dict[str, Any] = AuthHelper.decode_state(encoded)
    assert decoded == data


def test_encode_state_empty() -> None:
    data: dict[str, str | None] = {}
    encoded: str = AuthHelper.encode_state(data)
    decoded: dict[str, Any] = AuthHelper.decode_state(encoded)
    assert decoded == data


def test_decode_state_invalid_input() -> None:
    with pytest.raises(ValueError):
        AuthHelper.decode_state("")
    with pytest.raises(ValueError):
        AuthHelper.decode_state(None)  # type: ignore[arg-type]
    with pytest.raises(Exception):
        AuthHelper.decode_state("not_base64!!")
