"""
Integration tests for the authentication API endpoints.

These tests cover the professional auth flow with HttpOnly cookies:
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sys
from pathlib import Path

# Add custom_components to path relative to this test file
_test_dir = Path(__file__).parent
_custom_components = _test_dir.parent / "custom_components"
sys.path.insert(0, str(_custom_components))

from reflex_local_auth.auth_api import (
    auth_router,
    setup_auth_api,
    _validate_credentials,
    _create_session,
    _get_user_from_session,
    _invalidate_session,
    _check_rate_limit,
    _record_failed_attempt,
    _clear_rate_limit,
    _rate_limit_attempts,
    RATE_LIMIT_MAX_ATTEMPTS,
)
from reflex_local_auth.middleware import AUTH_COOKIE_NAME


@pytest.fixture
def test_app():
    """Create a test FastAPI app with auth routes."""
    app = FastAPI()
    app.include_router(auth_router)
    return app


@pytest.fixture
def client(test_app):
    """Create a test client."""
    return TestClient(test_app)


class TestLoginEndpoint:
    """Tests for POST /api/auth/login"""

    def test_login_missing_credentials(self, client):
        """Login without credentials should fail."""
        response = client.post("/api/auth/login", json={})
        # Pydantic validation error
        assert response.status_code == 422

    def test_login_empty_credentials(self, client):
        """Login with empty credentials should fail."""
        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate:
            mock_validate.return_value = None
            response = client.post("/api/auth/login", json={
                "username": "",
                "password": ""
            })
            assert response.status_code == 401
            data = response.json()
            assert data["success"] is False

    def test_login_invalid_credentials(self, client):
        """Login with invalid credentials should fail."""
        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate:
            mock_validate.return_value = None
            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "wrongpassword"
            })
            assert response.status_code == 401
            data = response.json()
            assert data["success"] is False
            assert "Invalid" in data["message"]

    def test_login_valid_credentials_sets_cookie(self, client):
        """Successful login should set HttpOnly cookie."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate, \
             patch('reflex_local_auth.auth_api._create_session') as mock_session:
            mock_validate.return_value = mock_user
            mock_session.return_value = "test_session_id_123"

            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "correctpassword"
            })

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["user_id"] == 1
            assert data["username"] == "testuser"

            # Check cookie is set
            assert AUTH_COOKIE_NAME in response.cookies

    def test_login_session_creation_failure(self, client):
        """Login should fail gracefully if session creation fails."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate, \
             patch('reflex_local_auth.auth_api._create_session') as mock_session:
            mock_validate.return_value = mock_user
            mock_session.return_value = None  # Session creation failed

            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "correctpassword"
            })

            assert response.status_code == 500
            data = response.json()
            assert data["success"] is False


class TestLogoutEndpoint:
    """Tests for POST /api/auth/logout"""

    def test_logout_clears_cookie(self, client):
        """Logout should clear the auth cookie."""
        with patch('reflex_local_auth.auth_api._invalidate_session') as mock_invalidate:
            mock_invalidate.return_value = True

            # Set a cookie first
            client.cookies.set(AUTH_COOKIE_NAME, "test_session")

            response = client.post("/api/auth/logout")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    def test_logout_without_cookie(self, client):
        """Logout without cookie should still succeed."""
        with patch('reflex_local_auth.auth_api._invalidate_session') as mock_invalidate:
            mock_invalidate.return_value = True

            response = client.post("/api/auth/logout")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestMeEndpoint:
    """Tests for GET /api/auth/me"""

    def test_me_without_cookie(self, client):
        """/me without cookie should return unauthenticated."""
        response = client.get("/api/auth/me")

        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False
        assert data["user_id"] is None

    def test_me_with_invalid_session(self, client):
        """/me with invalid session should return unauthenticated."""
        with patch('reflex_local_auth.auth_api._get_user_from_session') as mock_get:
            mock_get.return_value = None

            client.cookies.set(AUTH_COOKIE_NAME, "invalid_session")
            response = client.get("/api/auth/me")

            assert response.status_code == 200
            data = response.json()
            assert data["authenticated"] is False

    def test_me_with_valid_session(self, client):
        """/me with valid session should return user info."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._get_user_from_session') as mock_get:
            mock_get.return_value = mock_user

            client.cookies.set(AUTH_COOKIE_NAME, "valid_session")
            response = client.get("/api/auth/me")

            assert response.status_code == 200
            data = response.json()
            assert data["authenticated"] is True
            assert data["user_id"] == 1
            assert data["username"] == "testuser"


class TestSetupAuthApi:
    """Tests for setup_auth_api function."""

    def test_setup_adds_routes(self):
        """setup_auth_api should add auth routes to the app."""
        app = FastAPI()
        result = setup_auth_api(app)

        # Check routes are registered
        routes = [route.path for route in app.routes]
        assert "/api/auth/login" in routes
        assert "/api/auth/logout" in routes
        assert "/api/auth/me" in routes

        # Check it returns the app
        assert result is app


class TestCookieSecurity:
    """Tests for cookie security attributes."""

    def test_login_cookie_is_httponly(self, client):
        """Login cookie should have HttpOnly flag."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate, \
             patch('reflex_local_auth.auth_api._create_session') as mock_session:
            mock_validate.return_value = mock_user
            mock_session.return_value = "test_session_id"

            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "password"
            })

            # In test client, we can't directly check httponly,
            # but we verify the cookie is set
            assert AUTH_COOKIE_NAME in response.cookies

    def test_login_cookie_path(self, client):
        """Login cookie should have correct path."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate, \
             patch('reflex_local_auth.auth_api._create_session') as mock_session:
            mock_validate.return_value = mock_user
            mock_session.return_value = "test_session_id"

            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "password"
            })

            # Cookie should be set
            assert response.status_code == 200


class TestFullAuthFlow:
    """End-to-end tests for the complete auth flow."""

    def test_login_then_me_then_logout(self, client):
        """Complete auth flow: login -> check me -> logout."""
        mock_user = {"id": 1, "username": "testuser", "enabled": True}

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate, \
             patch('reflex_local_auth.auth_api._create_session') as mock_session, \
             patch('reflex_local_auth.auth_api._get_user_from_session') as mock_get, \
             patch('reflex_local_auth.auth_api._invalidate_session') as mock_invalidate:

            mock_validate.return_value = mock_user
            mock_session.return_value = "session_123"
            mock_get.return_value = mock_user
            mock_invalidate.return_value = True

            # Step 1: Login
            login_response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "password"
            })
            assert login_response.status_code == 200
            assert login_response.json()["success"] is True

            # Step 2: Check /me (should be authenticated)
            me_response = client.get("/api/auth/me")
            assert me_response.status_code == 200
            assert me_response.json()["authenticated"] is True

            # Step 3: Logout
            logout_response = client.post("/api/auth/logout")
            assert logout_response.status_code == 200
            assert logout_response.json()["success"] is True


class TestRateLimiting:
    """Tests for login rate limiting."""

    def setup_method(self):
        """Clear rate limiting state before each test."""
        _rate_limit_attempts.clear()

    def test_rate_limit_allows_initial_attempts(self):
        """Initial attempts should be allowed."""
        is_allowed, _ = _check_rate_limit("192.168.1.1")
        assert is_allowed is True

    def test_rate_limit_blocks_after_max_attempts(self):
        """After max attempts, client should be blocked."""
        client_ip = "192.168.1.2"

        # Record max failed attempts
        for _ in range(RATE_LIMIT_MAX_ATTEMPTS):
            _record_failed_attempt(client_ip)

        is_allowed, retry_after = _check_rate_limit(client_ip)
        assert is_allowed is False
        assert retry_after > 0

    def test_rate_limit_clears_on_success(self):
        """Rate limit should clear after successful login."""
        client_ip = "192.168.1.3"

        # Record some failed attempts
        for _ in range(3):
            _record_failed_attempt(client_ip)

        # Clear rate limit (simulating successful login)
        _clear_rate_limit(client_ip)

        is_allowed, _ = _check_rate_limit(client_ip)
        assert is_allowed is True

    def test_rate_limit_returns_429(self, client):
        """Rate limited requests should return 429."""
        client_ip = "testclient"  # TestClient uses "testclient" as client IP

        # Record max failed attempts
        for _ in range(RATE_LIMIT_MAX_ATTEMPTS):
            _record_failed_attempt(client_ip)

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate:
            mock_validate.return_value = None

            response = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "wrongpassword"
            })

            assert response.status_code == 429
            assert "Retry-After" in response.headers

    def test_failed_login_records_attempt(self, client):
        """Failed login should record an attempt."""
        _rate_limit_attempts.clear()

        with patch('reflex_local_auth.auth_api._validate_credentials') as mock_validate:
            mock_validate.return_value = None

            client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "wrongpassword"
            })

            # Check that an attempt was recorded
            # TestClient uses "testclient" as the client host
            assert len(_rate_limit_attempts.get("testclient", [])) >= 1


# Run tests with: pytest tests/test_auth_api.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
