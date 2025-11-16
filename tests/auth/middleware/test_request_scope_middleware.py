import logging
import uuid

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from oidcauthlib.auth.middleware.request_scope_middleware import (
    RequestScopeMiddleware,
)
from oidcauthlib.container.container_registry import ContainerRegistry


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ok")
    async def ok_endpoint(request: Request) -> JSONResponse:
        # Return the request_id stored in state by the middleware
        return JSONResponse({"request_id": request.state.request_id})

    @app.get("/error")
    async def error_endpoint() -> JSONResponse:  # pragma: no cover - body always raises
        raise ValueError("boom")

    app.add_middleware(RequestScopeMiddleware)
    return app


@pytest.mark.parametrize("header_value", [None, "my-custom-id-123"])
def test_request_scope_middleware_success_path(
    header_value: str | None,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _build_app()
    caplog.set_level(logging.DEBUG)

    calls: list[tuple[str, str | None]] = []

    def fake_begin(request_id: str) -> str:  # mimic real signature returning id
        calls.append(("begin", request_id))
        return request_id

    def fake_end() -> None:
        calls.append(("end", None))

    monkeypatch.setattr(ContainerRegistry, "begin_request_scope", fake_begin)
    monkeypatch.setattr(ContainerRegistry, "end_request_scope", fake_end)

    headers = {}
    if header_value:
        headers["X-Request-ID"] = header_value

    client = TestClient(app)
    response = client.get("/ok", headers=headers)

    assert response.status_code == 200

    # Validate header presence & value
    assert "X-Request-ID" in response.headers
    returned_header = response.headers["X-Request-ID"]

    if header_value is None:
        # Generated UUID v4
        # Validate by constructing UUID and checking version
        generated_uuid = uuid.UUID(returned_header)
        assert generated_uuid.version == 4
    else:
        assert returned_header == header_value

    # Response JSON exposes same request_id via request.state
    body = response.json()
    assert body["request_id"] == returned_header

    # begin/end calls
    assert calls[0][0] == "begin"
    assert calls[-1][0] == "end"
    assert calls[0][1] == returned_header

    # Logging patterns
    prefix = returned_header[:8]
    # Start log arrow
    assert f"→ GET /ok (request_id={prefix}...)" in caplog.text
    # Success log arrow with status
    assert f"← GET /ok [200] (request_id={prefix}...)" in caplog.text
    # Cleanup debug
    assert f"Request scope cleaned up (request_id={prefix}...)" in caplog.text


def test_request_scope_middleware_error_path(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _build_app()
    caplog.set_level(logging.DEBUG)

    calls: list[tuple[str, str | None]] = []

    def fake_begin(request_id: str) -> str:
        calls.append(("begin", request_id))
        return request_id

    def fake_end() -> None:
        calls.append(("end", None))

    monkeypatch.setattr(ContainerRegistry, "begin_request_scope", fake_begin)
    monkeypatch.setattr(ContainerRegistry, "end_request_scope", fake_end)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/error")

    # FastAPI will produce a 500 response
    assert response.status_code == 500

    # On error path the header is not added (since exception short-circuits before adding header)
    assert "X-Request-ID" not in response.headers

    # Ensure begin then end called regardless of exception
    assert calls and calls[0][0] == "begin"
    assert calls[-1][0] == "end"
    request_id = calls[0][1]
    assert request_id is not None

    prefix = request_id[:8]
    # Error log symbol ✗ present
    assert f"✗ GET /error (request_id={prefix}...)" in caplog.text
    # Cleanup log present
    assert f"Request scope cleaned up (request_id={prefix}...)" in caplog.text

    # Ensure success arrow log NOT present
    assert f"← GET /error [200] (request_id={prefix}...)" not in caplog.text


def test_request_id_state_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    # Focused test that the request.state.request_id is accessible inside endpoint
    app = _build_app()

    captured_request_id: list[str] = []

    def fake_begin(request_id: str) -> str:
        captured_request_id.append(request_id)
        return request_id

    def fake_end() -> None:  # no-op
        pass

    monkeypatch.setattr(ContainerRegistry, "begin_request_scope", fake_begin)
    monkeypatch.setattr(ContainerRegistry, "end_request_scope", fake_end)

    client = TestClient(app)
    response = client.get("/ok")
    assert response.status_code == 200
    rid_header = response.headers["X-Request-ID"]
    assert captured_request_id[0] == rid_header
    assert response.json()["request_id"] == rid_header


def test_existing_short_header(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Edge case: very short header value to ensure slicing doesn't fail
    app = _build_app()
    caplog.set_level(logging.DEBUG)

    def fake_begin(request_id: str) -> str:
        return request_id

    def fake_end() -> None:
        pass

    monkeypatch.setattr(ContainerRegistry, "begin_request_scope", fake_begin)
    monkeypatch.setattr(ContainerRegistry, "end_request_scope", fake_end)

    client = TestClient(app)
    header_value = "abc"  # shorter than 8 chars
    response = client.get("/ok", headers={"X-Request-ID": header_value})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == header_value
    # log should include prefix (whole header) followed by '...' due to slicing
    assert f"(request_id={header_value}...)" in caplog.text
