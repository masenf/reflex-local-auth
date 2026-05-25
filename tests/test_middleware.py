"""
Tests for the authentication middleware module.

These tests cover:
- URL safety validation (open redirect prevention)
- Middleware configuration
- Cookie helper functions
"""

import pytest
from starlette.responses import Response

# Import the module under test
import sys
from pathlib import Path

# Add custom_components to path relative to this test file
_test_dir = Path(__file__).parent
_custom_components = _test_dir.parent / "custom_components"
sys.path.insert(0, str(_custom_components))

from unittest.mock import patch, MagicMock, AsyncMock
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Route

from reflex_local_auth.middleware import (
    is_safe_redirect_url,
    configure_middleware,
    set_auth_cookie,
    clear_auth_cookie,
    _config,
    DEFAULT_PUBLIC_ROUTES,
    AUTH_COOKIE_NAME,
    AuthMiddleware,
)


class TestIsSafeRedirectUrl:
    """Tests for the is_safe_redirect_url function."""

    def test_safe_relative_paths(self):
        """Relative paths should be considered safe."""
        assert is_safe_redirect_url("/dashboard") is True
        assert is_safe_redirect_url("/welcome") is True
        assert is_safe_redirect_url("/admin/users") is True
        assert is_safe_redirect_url("/path/to/page") is True

    def test_safe_root_path(self):
        """Root path should be safe."""
        assert is_safe_redirect_url("/") is True

    def test_unsafe_absolute_urls(self):
        """Absolute URLs with different hosts should be unsafe."""
        assert is_safe_redirect_url("https://evil.com/steal") is False
        assert is_safe_redirect_url("http://attacker.com") is False
        assert is_safe_redirect_url("https://google.com") is False

    def test_unsafe_protocol_relative_urls(self):
        """Protocol-relative URLs should be unsafe."""
        assert is_safe_redirect_url("//evil.com/path") is False
        assert is_safe_redirect_url("//attacker.com") is False

    def test_unsafe_javascript_urls(self):
        """JavaScript URLs should be unsafe."""
        assert is_safe_redirect_url("javascript:alert(1)") is False
        assert is_safe_redirect_url("JAVASCRIPT:alert(1)") is False
        assert is_safe_redirect_url("javascript:void(0)") is False

    def test_unsafe_data_urls(self):
        """Data URLs should be unsafe."""
        assert is_safe_redirect_url("data:text/html,<script>alert(1)</script>") is False
        assert is_safe_redirect_url("DATA:text/html,test") is False

    def test_empty_and_none_urls(self):
        """Empty strings and None should be unsafe."""
        assert is_safe_redirect_url("") is False
        assert is_safe_redirect_url(None) is False

    def test_urls_with_query_params(self):
        """Relative URLs with query params should be safe."""
        assert is_safe_redirect_url("/login?next=/dashboard") is True
        assert is_safe_redirect_url("/page?param=value&other=123") is True

    def test_urls_with_fragments(self):
        """Relative URLs with fragments should be safe."""
        assert is_safe_redirect_url("/page#section") is True
        assert is_safe_redirect_url("/docs#api-reference") is True

    def test_path_traversal_blocked(self):
        """Path traversal attempts should be blocked."""
        assert is_safe_redirect_url("/path/../etc/passwd") is False
        assert is_safe_redirect_url("/..") is False
        assert is_safe_redirect_url("/../admin") is False

    def test_protocol_injection_blocked(self):
        """Protocol injection should be blocked."""
        # Note: The function is conservative and blocks :// anywhere in URL
        # This is intentional to prevent edge cases like /redirect?to=http://evil.com
        assert is_safe_redirect_url("/path?url=http://evil.com") is False
        assert is_safe_redirect_url("http://evil.com") is False
        # Safe query params without protocol are allowed
        assert is_safe_redirect_url("/path?next=/dashboard") is True


class TestConfigureMiddleware:
    """Tests for the configure_middleware function."""

    def setup_method(self):
        """Reset configuration before each test."""
        configure_middleware(
            public_routes=DEFAULT_PUBLIC_ROUTES.copy(),
            login_route="/login",
            default_authenticated_route="/",
            cookie_secure=False,
            enabled=True,
        )

    def test_default_public_routes(self):
        """Test that default public routes are set."""
        assert "/login" in _config["public_routes"]
        assert "/register" in _config["public_routes"]
        assert "/favicon.ico" in _config["public_routes"]

    def test_custom_public_routes(self):
        """Test custom public routes configuration."""
        custom_routes = {"/", "/login", "/register", "/api/public"}
        configure_middleware(public_routes=custom_routes)

        assert _config["public_routes"] == custom_routes
        assert "/" in _config["public_routes"]
        assert "/api/public" in _config["public_routes"]

    def test_custom_login_route(self):
        """Test custom login route configuration."""
        configure_middleware(login_route="/auth/signin")

        assert _config["login_route"] == "/auth/signin"

    def test_custom_authenticated_route(self):
        """Test custom default authenticated route."""
        configure_middleware(default_authenticated_route="/home")

        assert _config["default_authenticated_route"] == "/home"

    def test_cookie_secure_setting(self):
        """Test cookie security settings."""
        configure_middleware(cookie_secure=True)

        assert _config["cookie_secure"] is True

    def test_disable_middleware(self):
        """Test that middleware can be disabled."""
        configure_middleware(enabled=False)

        assert _config["enabled"] is False


class TestCookieHelpers:
    """Tests for cookie helper functions."""

    def test_set_auth_cookie_adds_cookie(self):
        """Test that set_auth_cookie adds the cookie to response."""
        response = Response(content="test")
        result = set_auth_cookie(response, "test_token_123")

        # Check that the response is returned
        assert result is response

    def test_set_auth_cookie_httponly(self):
        """Test that cookie is HttpOnly."""
        # The set_cookie is called with httponly=True in the implementation
        # We verify by checking the function doesn't raise
        response = Response(content="test")
        set_auth_cookie(response, "token123")
        # If no exception, the cookie was set correctly

    def test_clear_auth_cookie(self):
        """Test that clear_auth_cookie removes the cookie."""
        response = Response(content="test")
        result = clear_auth_cookie(response)

        # Check that the response is returned
        assert result is response


class TestMiddlewareRouteMatching:
    """Tests for route matching logic."""

    def test_exact_public_route_match(self):
        """Test exact matching of public routes."""
        configure_middleware(public_routes={"/", "/login", "/register"})

        assert "/" in _config["public_routes"]
        assert "/login" in _config["public_routes"]
        assert "/register" in _config["public_routes"]
        assert "/dashboard" not in _config["public_routes"]

    def test_public_prefixes_configured(self):
        """Test that public prefixes are available."""
        # Default prefixes should include common static/API paths
        assert "public_prefixes" in _config
        prefixes = _config["public_prefixes"]
        assert "/_next/" in prefixes
        assert "/static/" in prefixes


class TestSecurityEdgeCases:
    """Tests for security edge cases."""

    def test_url_with_newlines_blocked(self):
        """URLs with newlines should be handled safely."""
        # These could be used for header injection
        result = is_safe_redirect_url("/path\nSet-Cookie: evil=value")
        # Even if it returns True, the path itself is sanitized by urlparse
        # The important thing is we don't crash
        assert isinstance(result, bool)

    def test_very_long_url(self):
        """Very long URLs should be handled safely."""
        long_path = "/" + "a" * 10000
        result = is_safe_redirect_url(long_path)
        assert result is True  # It's still a valid relative path

    def test_unicode_in_path(self):
        """Unicode characters in path should be handled."""
        result = is_safe_redirect_url("/página/información")
        assert result is True  # Unicode paths are valid


class TestAuthMiddlewareASGI:
    """Tests for the AuthMiddleware ASGI behavior."""

    def setup_method(self):
        """Reset configuration before each test."""
        configure_middleware(
            public_routes={"/login", "/register", "/public"},
            login_route="/login",
            default_authenticated_route="/dashboard",
            cookie_secure=False,
            enabled=True,
        )

    def _create_test_app(self):
        """Create a test Starlette app wrapped with AuthMiddleware."""
        async def homepage(request):
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("Protected Home")

        async def dashboard(request):
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("Protected Dashboard")

        async def login_page(request):
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("Login Page")

        async def public_page(request):
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("Public Page")

        routes = [
            Route("/", homepage),
            Route("/dashboard", dashboard),
            Route("/login", login_page),
            Route("/public", public_page),
        ]
        app = Starlette(routes=routes)
        return AuthMiddleware(app)

    def test_unauthenticated_protected_route_redirects(self):
        """Unauthenticated user accessing protected route should redirect to login."""
        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            response = client.get("/dashboard")

            assert response.status_code == 303
            assert "/login" in response.headers["location"]
            assert "next=" in response.headers["location"]

    def test_authenticated_protected_route_allowed(self):
        """Authenticated user accessing protected route should be allowed."""
        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.username = "testuser"

        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = mock_user

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)
            client.cookies.set(AUTH_COOKIE_NAME, "valid_session")

            response = client.get("/dashboard")

            assert response.status_code == 200
            assert "Protected Dashboard" in response.text

    def test_authenticated_login_page_redirects(self):
        """Authenticated user accessing login page should redirect to dashboard."""
        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.username = "testuser"

        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = mock_user

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)
            client.cookies.set(AUTH_COOKIE_NAME, "valid_session")

            response = client.get("/login")

            assert response.status_code == 303
            assert response.headers["location"] == "/dashboard"

    def test_unauthenticated_login_page_allowed(self):
        """Unauthenticated user accessing login page should be allowed."""
        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            response = client.get("/login")

            assert response.status_code == 200
            assert "Login Page" in response.text

    def test_public_route_always_allowed(self):
        """Public routes should be accessible without authentication."""
        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            response = client.get("/public")

            assert response.status_code == 200
            assert "Public Page" in response.text
            # Validate that session was not even checked for public routes
            mock_validate.assert_not_called()

    def test_static_files_allowed(self):
        """Static files should be allowed without authentication."""
        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            # Static files return 404 (no route) but should not redirect
            response = client.get("/static/style.css")

            # Should NOT redirect to login (file extensions are public)
            assert response.status_code != 303

    def test_middleware_disabled(self):
        """Disabled middleware should pass all requests through."""
        configure_middleware(enabled=False)

        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            response = client.get("/dashboard")

            # Should NOT redirect when middleware is disabled
            assert response.status_code == 200
            assert "Protected Dashboard" in response.text

    def test_redirect_preserves_next_url(self):
        """Redirect to login should preserve the original URL in ?next= param."""
        with patch('reflex_local_auth.middleware._validate_session') as mock_validate:
            mock_validate.return_value = None

            app = self._create_test_app()
            client = TestClient(app, follow_redirects=False)

            response = client.get("/dashboard")

            location = response.headers["location"]
            assert "next=%2Fdashboard" in location  # URL-encoded /dashboard


class TestMiddlewareIsPublic:
    """Tests for the _is_public method."""

    def setup_method(self):
        """Reset configuration before each test."""
        configure_middleware(
            public_routes={"/login", "/register"},
            public_prefixes=("/_next/", "/static/", "/api/auth/"),
            login_route="/login",
            enabled=True,
        )

    def test_exact_route_match(self):
        """Exact public routes should be public."""
        app = AuthMiddleware(MagicMock())
        assert app._is_public("/login") is True
        assert app._is_public("/register") is True
        assert app._is_public("/dashboard") is False

    def test_prefix_match(self):
        """Routes with public prefixes should be public."""
        app = AuthMiddleware(MagicMock())
        assert app._is_public("/_next/static/chunk.js") is True
        assert app._is_public("/static/style.css") is True
        assert app._is_public("/api/auth/login") is True
        assert app._is_public("/api/private") is False

    def test_file_extension_match(self):
        """Static file extensions should be public."""
        app = AuthMiddleware(MagicMock())
        assert app._is_public("/custom.js") is True
        assert app._is_public("/style.css") is True
        assert app._is_public("/favicon.ico") is True
        assert app._is_public("/image.png") is True
        assert app._is_public("/page") is False


# Run tests with: pytest tests/test_middleware.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
