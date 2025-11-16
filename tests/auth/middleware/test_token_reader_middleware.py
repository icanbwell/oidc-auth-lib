"""
Unit tests for TokenReaderMiddleware.
"""

from typing import Any

import pytest
from unittest.mock import AsyncMock, Mock
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from datetime import datetime, UTC, timedelta

from oidcauthlib.auth.middleware.token_reader_middleware import TokenReaderMiddleware
from oidcauthlib.auth.token_reader import TokenReader
from oidcauthlib.auth.models.token import Token


def create_mock_token(
    token_str: str = "valid.jwt.token",
    expires: datetime | None = None,
    claims: dict[str, Any] | None = None,
) -> Token:
    """Helper to create a mock Token object."""
    if expires is None:
        expires = datetime.now(UTC) + timedelta(hours=1)
    if claims is None:
        claims = {"sub": "user123", "iat": 1234567890}

    return Token(
        token=token_str,
        expires=expires,
        issued=datetime.now(UTC),
        claims=claims,
        issuer="https://auth.example.com",
    )


def create_app_with_middleware(
    token_reader: TokenReader,
    require_token_routes: list[str] | None = None,
    optional_token_routes: list[str] | None = None,
) -> FastAPI:
    """Helper to create a FastAPI app with TokenReaderMiddleware."""
    app = FastAPI()

    @app.get("/public")
    async def public_endpoint(request: Request) -> JSONResponse:
        token = getattr(request.state, "token", None)
        return JSONResponse({"message": "public", "has_token": token is not None})

    @app.get("/protected")
    async def protected_endpoint(request: Request) -> JSONResponse:
        token = getattr(request.state, "token", None)
        return JSONResponse({"message": "protected", "has_token": token is not None})

    @app.get("/health")
    async def health_endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/api/users")
    async def users_endpoint(request: Request) -> JSONResponse:
        token = getattr(request.state, "token", None)
        return JSONResponse({"message": "users", "has_token": token is not None})

    app.add_middleware(
        TokenReaderMiddleware,
        token_reader=token_reader,
        require_token_routes=require_token_routes,
        optional_token_routes=optional_token_routes,
    )
    return app


class TestTokenReaderMiddlewareInit:
    """Tests for TokenReaderMiddleware initialization."""

    def test_init_with_valid_token_reader(self) -> None:
        """Test middleware initializes correctly with a valid TokenReader."""
        mock_token_reader = Mock(spec=TokenReader)
        app = FastAPI()

        middleware = TokenReaderMiddleware(
            app=app,
            token_reader=mock_token_reader,
        )

        assert middleware.token_reader == mock_token_reader
        assert middleware.require_token_patterns == []
        assert middleware.optional_token_patterns == []

    def test_init_with_none_token_reader_raises_error(self) -> None:
        """Test middleware raises ValueError when token_reader is None."""
        app = FastAPI()

        with pytest.raises(
            ValueError, match="token_reader must be provided and cannot be None"
        ):
            TokenReaderMiddleware(
                app=app,
                token_reader=None,  # type: ignore[arg-type]
            )

    def test_init_with_route_patterns(self) -> None:
        """Test middleware initializes with route patterns."""
        mock_token_reader = Mock(spec=TokenReader)
        app = FastAPI()

        middleware = TokenReaderMiddleware(
            app=app,
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*", r"^/api/.*"],
            optional_token_routes=[r"^/public.*"],
        )

        assert len(middleware.require_token_patterns) == 2
        assert len(middleware.optional_token_patterns) == 1

    def test_is_route_match_helper(self) -> None:
        """Test the _is_route_match static method."""
        import re

        patterns = [re.compile(r"^/api/.*"), re.compile(r"^/protected.*")]

        assert TokenReaderMiddleware._is_route_match("/api/users", patterns)
        assert TokenReaderMiddleware._is_route_match("/protected/resource", patterns)
        assert not TokenReaderMiddleware._is_route_match("/public", patterns)


class TestTokenReaderMiddlewareDefaultBehavior:
    """Tests for default behavior when no route patterns are specified."""

    @pytest.mark.asyncio
    async def test_default_behavior_health_endpoint_no_token(self) -> None:
        """Test /health endpoint allows requests without token by default."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(token_reader=mock_token_reader)
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_default_behavior_other_endpoints_require_token(self) -> None:
        """Test non-health endpoints require token by default."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(token_reader=mock_token_reader)
        client = TestClient(app)

        response = client.get("/protected")

        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}

    @pytest.mark.asyncio
    async def test_default_behavior_with_valid_token(self) -> None:
        """Test default behavior allows valid token through."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="valid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(
            return_value=create_mock_token()
        )

        app = create_app_with_middleware(token_reader=mock_token_reader)
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer valid.jwt.token"}
        )

        assert response.status_code == 200
        assert response.json()["has_token"] is True


class TestTokenReaderMiddlewareRequireTokenRoutes:
    """Tests for require_token_routes parameter."""

    @pytest.mark.asyncio
    async def test_require_token_routes_blocks_without_token(self) -> None:
        """Test that routes matching require_token_routes block requests without token."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*", r"^/api/.*"],
        )
        client = TestClient(app)

        response = client.get("/protected")
        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}

        response = client.get("/api/users")
        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}

    @pytest.mark.asyncio
    async def test_require_token_routes_allows_non_matching_routes(self) -> None:
        """Test that routes not matching require_token_routes are allowed without token."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get("/public")
        assert response.status_code == 200
        assert response.json()["has_token"] is False

    @pytest.mark.asyncio
    async def test_require_token_routes_allows_with_valid_token(self) -> None:
        """Test that routes matching require_token_routes allow valid tokens."""
        mock_token = create_mock_token()
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="valid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=mock_token)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer valid.jwt.token"}
        )

        assert response.status_code == 200
        assert response.json()["has_token"] is True

    @pytest.mark.asyncio
    async def test_require_token_routes_blocks_invalid_token(self) -> None:
        """Test that routes matching require_token_routes block invalid tokens."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="invalid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer invalid.jwt.token"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid authorization token"}


class TestTokenReaderMiddlewareOptionalTokenRoutes:
    """Tests for optional_token_routes parameter."""

    @pytest.mark.asyncio
    async def test_optional_token_routes_allows_without_token(self) -> None:
        """Test that routes matching optional_token_routes allow requests without token."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        response = client.get("/public")
        assert response.status_code == 200
        assert response.json()["has_token"] is False

    @pytest.mark.asyncio
    async def test_optional_token_routes_accepts_valid_token(self) -> None:
        """Test that routes matching optional_token_routes accept valid tokens."""
        mock_token = create_mock_token()
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="valid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=mock_token)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/public", headers={"Authorization": "Bearer valid.jwt.token"}
        )

        assert response.status_code == 200
        assert response.json()["has_token"] is True

    @pytest.mark.asyncio
    async def test_optional_token_routes_ignores_invalid_token(self) -> None:
        """Test that routes matching optional_token_routes ignore invalid tokens and proceed."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="invalid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/public", headers={"Authorization": "Bearer invalid.jwt.token"}
        )

        assert response.status_code == 200
        assert response.json()["has_token"] is False

    @pytest.mark.asyncio
    async def test_optional_token_routes_non_matching_requires_token(self) -> None:
        """Test that when only optional_token_routes is specified, non-matching routes require token."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        # Non-matching route should require token
        response = client.get("/protected")
        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}


class TestTokenReaderMiddlewareBothRouteTypes:
    """Tests for interactions between require_token_routes and optional_token_routes."""

    @pytest.mark.asyncio
    async def test_require_takes_precedence_over_optional(self) -> None:
        """Test that require_token_routes takes precedence over optional_token_routes."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
            optional_token_routes=[r"^/protected.*"],  # Same pattern
        )
        client = TestClient(app)

        response = client.get("/protected")

        # Should require token since require_token_routes takes precedence
        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}

    @pytest.mark.asyncio
    async def test_mixed_route_patterns(self) -> None:
        """Test middleware with mixed route patterns."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        # Protected route requires token
        response = client.get("/protected")
        assert response.status_code == 401

        # Public route allows without token
        response = client.get("/public")
        assert response.status_code == 200
        assert response.json()["has_token"] is False

        # Other routes that don't match either pattern are allowed without token
        response = client.get("/api/users")
        assert response.status_code == 200
        assert response.json()["has_token"] is False


class TestTokenReaderMiddlewareTokenExtraction:
    """Tests for token extraction and verification."""

    @pytest.mark.asyncio
    async def test_valid_bearer_token_extracted(self) -> None:
        """Test that valid Bearer token is extracted and verified."""
        mock_token = create_mock_token()
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="valid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=mock_token)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer valid.jwt.token"}
        )

        assert response.status_code == 200
        mock_token_reader.extract_token.assert_called_once()
        mock_token_reader.verify_token_async.assert_called_once_with(
            token="valid.jwt.token"
        )

    @pytest.mark.asyncio
    async def test_missing_authorization_header(self) -> None:
        """Test request without Authorization header."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get("/protected")

        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}
        mock_token_reader.extract_token.assert_called_once_with(
            authorization_header=None
        )

    @pytest.mark.asyncio
    async def test_malformed_authorization_header(self) -> None:
        """Test request with malformed Authorization header."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get("/protected", headers={"Authorization": "InvalidFormat"})

        assert response.status_code == 401
        assert response.json() == {"detail": "Authorization token required"}


class TestTokenReaderMiddlewareErrorHandling:
    """Tests for error handling in TokenReaderMiddleware."""

    @pytest.mark.asyncio
    async def test_exception_during_token_verification_required_route(self) -> None:
        """Test exception during token verification on required route."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="some.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(
            side_effect=Exception("Verification failed")
        )

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer some.jwt.token"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid or missing authorization token"}

    @pytest.mark.asyncio
    async def test_exception_during_token_verification_optional_route(self) -> None:
        """Test exception during token verification on optional route allows through."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="some.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(
            side_effect=Exception("Verification failed")
        )

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/public.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/public", headers={"Authorization": "Bearer some.jwt.token"}
        )

        # Should allow through with token set to None
        assert response.status_code == 200
        assert response.json()["has_token"] is False

    @pytest.mark.asyncio
    async def test_exception_during_token_extraction(self) -> None:
        """Test exception during token extraction."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(
            side_effect=Exception("Extraction failed")
        )

        app = create_app_with_middleware(
            token_reader=mock_token_reader,
            require_token_routes=[r"^/protected.*"],
        )
        client = TestClient(app)

        response = client.get(
            "/protected", headers={"Authorization": "Bearer some.jwt.token"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid or missing authorization token"}


class TestTokenReaderMiddlewareRequestStateManagement:
    """Tests for request.state.token management."""

    @pytest.mark.asyncio
    async def test_token_attached_to_request_state(self) -> None:
        """Test that decoded token is attached to request.state."""
        mock_token = create_mock_token(
            token_str="valid.jwt.token",
            claims={"sub": "user123", "email": "user@example.com"},
        )
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value="valid.jwt.token")
        mock_token_reader.verify_token_async = AsyncMock(return_value=mock_token)

        app = FastAPI()

        @app.get("/check-state")
        async def check_state_endpoint(request: Request) -> JSONResponse:
            token = getattr(request.state, "token", None)
            if token:
                return JSONResponse(
                    {
                        "has_token": True,
                        "token_str": token.token,
                        "claims": token.claims,
                    }
                )
            return JSONResponse({"has_token": False})

        app.add_middleware(
            TokenReaderMiddleware,
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/check-state.*"],
        )

        client = TestClient(app)
        response = client.get(
            "/check-state", headers={"Authorization": "Bearer valid.jwt.token"}
        )

        assert response.status_code == 200
        json_data = response.json()
        assert json_data["has_token"] is True
        assert json_data["token_str"] == "valid.jwt.token"
        assert json_data["claims"]["sub"] == "user123"
        assert json_data["claims"]["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_token_state_none_when_no_token(self) -> None:
        """Test that request.state.token is None when no token provided."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = FastAPI()

        @app.get("/check-state")
        async def check_state_endpoint(request: Request) -> JSONResponse:
            token = getattr(request.state, "token", "not_set")
            return JSONResponse({"token": str(token) if token else None})

        app.add_middleware(
            TokenReaderMiddleware,
            token_reader=mock_token_reader,
            optional_token_routes=[r"^/check-state.*"],
        )

        client = TestClient(app)
        response = client.get("/check-state")

        assert response.status_code == 200
        assert response.json()["token"] is None


class TestTokenReaderMiddlewareComplexRoutePatterns:
    """Tests for complex regex route patterns."""

    @pytest.mark.asyncio
    async def test_complex_regex_patterns(self) -> None:
        """Test middleware with complex regex patterns."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = FastAPI()

        @app.get("/api/v1/users")
        async def api_v1_users() -> JSONResponse:
            return JSONResponse({"message": "users"})

        @app.get("/api/v2/users")
        async def api_v2_users() -> JSONResponse:
            return JSONResponse({"message": "users"})

        @app.get("/public/docs")
        async def public_docs() -> JSONResponse:
            return JSONResponse({"message": "docs"})

        app.add_middleware(
            TokenReaderMiddleware,
            token_reader=mock_token_reader,
            require_token_routes=[r"^/api/v[12]/.*"],
            optional_token_routes=[r"^/public/.*"],
        )

        client = TestClient(app)

        # API routes require token
        response = client.get("/api/v1/users")
        assert response.status_code == 401

        response = client.get("/api/v2/users")
        assert response.status_code == 401

        # Public routes are optional
        response = client.get("/public/docs")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_exact_path_matching(self) -> None:
        """Test exact path matching with regex."""
        mock_token_reader = Mock(spec=TokenReader)
        mock_token_reader.extract_token = Mock(return_value=None)

        app = FastAPI()

        @app.get("/admin")
        async def admin() -> JSONResponse:
            return JSONResponse({"message": "admin"})

        @app.get("/admin/users")
        async def admin_users() -> JSONResponse:
            return JSONResponse({"message": "admin users"})

        app.add_middleware(
            TokenReaderMiddleware,
            token_reader=mock_token_reader,
            require_token_routes=[r"^/admin$"],  # Exact match
        )

        client = TestClient(app)

        # Exact match requires token
        response = client.get("/admin")
        assert response.status_code == 401

        # Non-exact match allowed (when patterns specified, non-matching routes allowed)
        response = client.get("/admin/users")
        assert response.status_code == 200
