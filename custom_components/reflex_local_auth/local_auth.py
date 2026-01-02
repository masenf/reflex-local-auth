"""
Authentication data is stored in the LocalAuthState class so that all substates can
access it for verifying access to event handlers and computed vars.

Your app may inherit from LocalAuthState, or it may access it via the `get_state` API.

Security Model:
    - localStorage: Used for Reflex's internal WebSocket auth and state hydration
    - HttpOnly Cookie: Managed by API endpoints (/api/auth/*) for server-side validation

    The HttpOnly cookie is set/cleared by the API endpoints, NOT by Reflex state.
    This provides true XSS protection as JavaScript cannot access HttpOnly cookies.

    For full security, use the API endpoints for login/logout:
    - POST /api/auth/login - Sets HttpOnly cookie
    - POST /api/auth/logout - Clears HttpOnly cookie
    - GET /api/auth/me - Check authentication status
"""

from __future__ import annotations

import datetime
from typing import Optional

import reflex as rx
from sqlmodel import select

from .auth_session import LocalAuthSession
from .user import LocalUser

AUTH_TOKEN_LOCAL_STORAGE_KEY = "_auth_token"
DEFAULT_AUTH_SESSION_EXPIRATION_DELTA = datetime.timedelta(days=7)
DEFAULT_AUTH_REFRESH_DELTA = datetime.timedelta(minutes=10)


class LocalAuthState(rx.State):
    """Base authentication state for Reflex applications.

    This class manages authentication tokens in localStorage for Reflex's
    internal WebSocket authentication and state hydration.

    For server-side protection with HttpOnly cookies, use the API endpoints
    (/api/auth/*) which set cookies that JavaScript cannot access.

    See also: setup_auth_api() and AuthMiddleware for full security.
    """

    # The auth_token is stored in local storage to persist across tab and browser sessions.
    auth_token: str = rx.LocalStorage(name=AUTH_TOKEN_LOCAL_STORAGE_KEY)

    @rx.var(
        cache=True,
        interval=DEFAULT_AUTH_REFRESH_DELTA,
        initial_value=LocalUser(id=-1),
    )
    def authenticated_user(self) -> LocalUser:
        """The currently authenticated user, or a dummy user if not authenticated.

        Returns:
            A LocalUser instance with id=-1 if not authenticated, or the LocalUser instance
            corresponding to the currently authenticated user.
        """
        with rx.session() as session:
            result = session.exec(
                select(LocalUser, LocalAuthSession).where(
                    LocalAuthSession.session_id == self.auth_token,
                    LocalAuthSession.expiration
                    >= datetime.datetime.now(datetime.timezone.utc),
                    LocalUser.id == LocalAuthSession.user_id,
                ),
            ).first()
            if result:
                user, session = result
                return user
        return LocalUser(id=-1)  # type: ignore

    @rx.var(
        cache=True,
        interval=DEFAULT_AUTH_REFRESH_DELTA,
        initial_value=False,
    )
    def is_authenticated(self) -> bool:
        """Whether the current user is authenticated.

        Returns:
            True if the authenticated user has a positive user ID, False otherwise.
        """
        return (
            self.authenticated_user.id is not None and self.authenticated_user.id >= 0
        )

    @rx.event
    def do_logout(self):
        """Destroy LocalAuthSessions associated with the auth_token.

        This method deletes the session from the database and clears localStorage.

        Note: For full security with HttpOnly cookies, also call POST /api/auth/logout
        to clear the HttpOnly cookie that JavaScript cannot access.
        """
        with rx.session() as session:
            for auth_session in session.exec(
                select(LocalAuthSession).where(
                    LocalAuthSession.session_id == self.auth_token
                )
            ).all():
                session.delete(auth_session)
            session.commit()
        # Clear localStorage token
        self.auth_token = ""

    def _login(
        self,
        user_id: int,
        expiration_delta: datetime.timedelta = DEFAULT_AUTH_SESSION_EXPIRATION_DELTA,
    ) -> None:
        """Create an LocalAuthSession for the given user_id.

        If the auth_token is already associated with an LocalAuthSession, it will be
        logged out first.

        Note: This method sets the localStorage token for Reflex state compatibility.
        For full security with HttpOnly cookies, use POST /api/auth/login instead,
        which sets an HttpOnly cookie that JavaScript cannot access.

        Args:
            user_id: The user ID to associate with the LocalAuthSession.
            expiration_delta: The amount of time before the LocalAuthSession expires.
        """
        self.do_logout()
        if user_id < 0:
            return
        self.auth_token = self.auth_token or self.router.session.client_token
        with rx.session() as session:
            session.add(
                LocalAuthSession(  # type: ignore
                    user_id=user_id,
                    session_id=self.auth_token,
                    expiration=datetime.datetime.now(datetime.timezone.utc)
                    + expiration_delta,
                )
            )
            session.commit()
