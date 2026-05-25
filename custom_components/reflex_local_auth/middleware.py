"""
ASGI Middleware for Server-Side Authentication with HttpOnly Cookies.

This middleware intercepts HTTP requests and validates authentication
before serving any page content, eliminating the "flash" of protected
content that occurs with client-side only authentication.

Usage:
    from reflex_local_auth import AuthMiddleware

    app = rx.App(
        api_transformer=AuthMiddleware,
    )
"""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING, Callable, Optional, Set, Tuple
from urllib.parse import quote, urlparse

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

# Configure module logger
logger = logging.getLogger("reflex_local_auth")

if TYPE_CHECKING:
    from .user import LocalUser

# Cookie configuration
AUTH_COOKIE_NAME = "_auth_session"
AUTH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days in seconds
AUTH_COOKIE_PATH = "/"
AUTH_COOKIE_SAMESITE = "lax"
AUTH_COOKIE_SECURE = False  # Set to True in production with HTTPS
AUTH_COOKIE_HTTPONLY = True

# Default route configuration
DEFAULT_PUBLIC_ROUTES: Set[str] = {
    "/login",
    "/register",
    "/favicon.ico",
    "/ping",
}

DEFAULT_PUBLIC_PREFIXES: Tuple[str, ...] = (
    "/_next/",
    "/static/",
    "/_upload/",
    "/_event/",
    "/api/auth/",  # Auth API endpoints must be public
)

DEFAULT_FILE_EXTENSIONS: Tuple[str, ...] = (
    ".js", ".css", ".ico", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".json",
)

# Module-level configuration (can be modified by users)
_config = {
    "public_routes": DEFAULT_PUBLIC_ROUTES.copy(),
    "public_prefixes": DEFAULT_PUBLIC_PREFIXES,
    "login_route": "/login",
    "default_authenticated_route": "/",
    "cookie_secure": AUTH_COOKIE_SECURE,
    "enabled": True,
}


def configure_middleware(
    *,
    public_routes: Optional[Set[str]] = None,
    public_prefixes: Optional[Tuple[str, ...]] = None,
    login_route: str = "/login",
    default_authenticated_route: str = "/",
    cookie_secure: bool = False,
    enabled: bool = True,
) -> None:
    """Configure the authentication middleware.

    Args:
        public_routes: Set of routes that don't require authentication.
        public_prefixes: Tuple of path prefixes that don't require authentication.
        login_route: The route to redirect unauthenticated users to.
        default_authenticated_route: The route to redirect authenticated users
            to when they access the login page.
        cookie_secure: Whether to set the Secure flag on cookies (requires HTTPS).
        enabled: Whether the middleware is enabled.
    """
    if public_routes is not None:
        _config["public_routes"] = public_routes
    if public_prefixes is not None:
        _config["public_prefixes"] = public_prefixes
    _config["login_route"] = login_route
    _config["default_authenticated_route"] = default_authenticated_route
    _config["cookie_secure"] = cookie_secure
    _config["enabled"] = enabled


def set_auth_cookie(response: Response, session_id: str) -> Response:
    """Set the HttpOnly authentication cookie on a response.

    Args:
        response: The response to set the cookie on.
        session_id: The session ID to store in the cookie.

    Returns:
        The response with the cookie set.
    """
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=session_id,
        max_age=AUTH_COOKIE_MAX_AGE,
        path=AUTH_COOKIE_PATH,
        samesite=AUTH_COOKIE_SAMESITE,
        secure=_config["cookie_secure"],
        httponly=AUTH_COOKIE_HTTPONLY,
    )
    return response


def clear_auth_cookie(response: Response) -> Response:
    """Clear the authentication cookie from a response.

    Args:
        response: The response to clear the cookie from.

    Returns:
        The response with the cookie cleared.
    """
    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path=AUTH_COOKIE_PATH,
    )
    return response


def is_safe_redirect_url(url: str) -> bool:
    """Validate that a URL is safe to redirect to.

    Prevents open redirect attacks by ensuring the URL is:
    - A relative path (starts with /)
    - Not a protocol-relative URL (//)
    - Not containing path traversal (..)
    - Not containing a protocol (://)

    Args:
        url: The URL to validate.

    Returns:
        True if the URL is safe to redirect to, False otherwise.
    """
    if not url:
        return False

    # Must be relative path
    if not url.startswith("/"):
        return False

    # No protocol-relative URLs
    if url.startswith("//"):
        return False

    # No protocol injection
    if "://" in url:
        return False

    # No path traversal
    if ".." in url:
        return False

    # Validate with urlparse for extra safety
    parsed = urlparse(url)
    if parsed.scheme or parsed.netloc:
        return False

    return True


def _validate_session(session_id: str) -> Optional["LocalUser"]:
    """Validate a session ID and return the associated user.

    Args:
        session_id: The session ID to validate.

    Returns:
        The LocalUser if the session is valid, None otherwise.
    """
    if not session_id:
        return None

    try:
        import reflex as rx
        from sqlmodel import Session, select
        from reflex.model import get_engine

        from .auth_session import LocalAuthSession
        from .user import LocalUser

        engine = get_engine()
        with Session(engine) as db_session:
            result = db_session.exec(
                select(LocalUser, LocalAuthSession).where(
                    LocalAuthSession.session_id == session_id,
                    LocalAuthSession.expiration >= datetime.datetime.now(datetime.timezone.utc),
                    LocalUser.id == LocalAuthSession.user_id,
                    LocalUser.enabled == True,
                )
            ).first()

            if result:
                user, _ = result
                return user

    except Exception as e:
        # Log error but don't expose details
        logger.warning("Session validation error: %s", type(e).__name__)

    return None


class AuthMiddleware:
    """ASGI Middleware for server-side authentication.

    This middleware:
    1. Validates the HttpOnly session cookie on each request
    2. Redirects unauthenticated users to the login page
    3. Redirects authenticated users away from the login page
    4. Preserves the original URL in a ?next= parameter

    Usage:
        app = rx.App(
            api_transformer=AuthMiddleware,
        )
    """

    def __init__(self, app: ASGIApp):
        """Initialize the middleware.

        Args:
            app: The ASGI app to wrap.
        """
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle an incoming request.

        Args:
            scope: The ASGI scope.
            receive: The receive callable.
            send: The send callable.
        """
        # Only handle HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if middleware is enabled
        if not _config["enabled"]:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = request.url.path
        login_route = _config["login_route"]

        # Handle login page specially (before public route check)
        # This allows redirecting authenticated users away from login
        if path == login_route:
            session_id = request.cookies.get(AUTH_COOKIE_NAME)
            user = _validate_session(session_id) if session_id else None

            if user is not None:
                # Authenticated user on login - redirect to dashboard
                redirect_url = _config["default_authenticated_route"]
                response = RedirectResponse(url=redirect_url, status_code=303)
                await response(scope, receive, send)
                return
            # Not authenticated on login page - allow through
            await self.app(scope, receive, send)
            return

        # Allow public routes and static files (except login, handled above)
        if self._is_public(path):
            await self.app(scope, receive, send)
            return

        # Get session from HttpOnly cookie
        session_id = request.cookies.get(AUTH_COOKIE_NAME)

        # Validate session
        user = _validate_session(session_id) if session_id else None
        is_authenticated = user is not None

        # Protected routes - require authentication
        if not is_authenticated:
            response = self._create_login_redirect(path)
            await response(scope, receive, send)
            return

        # Authenticated - serve the page
        await self.app(scope, receive, send)

    def _is_public(self, path: str) -> bool:
        """Check if a path is public (doesn't require authentication).

        Args:
            path: The path to check.

        Returns:
            True if the path is public, False otherwise.
        """
        # Exact match with public routes
        if path in _config["public_routes"]:
            return True

        # Prefix match
        for prefix in _config["public_prefixes"]:
            if path.startswith(prefix):
                return True

        # File extension match
        for ext in DEFAULT_FILE_EXTENSIONS:
            if path.endswith(ext):
                return True

        return False

    def _create_login_redirect(self, original_path: str) -> RedirectResponse:
        """Create a redirect response to the login page.

        Args:
            original_path: The path the user was trying to access.

        Returns:
            A redirect response to the login page.
        """
        login_route = _config["login_route"]

        if is_safe_redirect_url(original_path) and original_path != login_route:
            next_param = quote(original_path, safe="")
            return RedirectResponse(
                url=f"{login_route}?next={next_param}",
                status_code=303
            )

        return RedirectResponse(url=login_route, status_code=303)
