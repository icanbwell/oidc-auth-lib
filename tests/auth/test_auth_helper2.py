from typing import Any

import pytest
from oidcauthlib.auth.auth_helper import AuthHelper


def test_encode_decode_state_roundtrip() -> None:
    cases: list[dict[str, Any]] = [
        {},
        {"foo": "bar"},
        {"key": None},
        {"special": "!@#$%^&*()_+-=~`"},
        {"unicode": "你好世界"},
        {"empty": "", "none": None},
    ]
    for case in cases:
        encoded = AuthHelper.encode_state(case)
        decoded = AuthHelper.decode_state(encoded)
        assert decoded == case


def test_decode_state_invalid() -> None:
    with pytest.raises(ValueError):
        AuthHelper.decode_state("not_base64!")
    with pytest.raises(ValueError):
        AuthHelper.decode_state("")
    # Not a dict after decoding
    import base64
    import json

    bad = base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode()).decode().rstrip("=")
    with pytest.raises(ValueError):
        AuthHelper.decode_state(bad)
