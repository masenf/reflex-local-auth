"""Login state and authentication logic."""

from __future__ import annotations

import asyncio
from typing import Any

import reflex as rx
from sqlmodel import select

from . import routes
from .local_auth import LocalAuthState
from .user import LocalUser


class LoginState(LocalAuthState):
    """Handle login form submission and redirect to proper routes after authentication."""

    error_message: str = ""
    redirect_to: str = ""

    @rx.event
    async def on_submit(self, form_data: dict[str, Any]):
        """Handle login form on_submit.

        The database lookup and bcrypt password check run in a worker thread to
        avoid blocking the event loop.

        Args:
            form_data: A dict of form fields and values.
        """
        self.error_message = ""
        username = form_data["username"]
        password = form_data["password"]
        user = await asyncio.to_thread(_get_user_by_username, username)
        if user is not None and not user.enabled:
            self.error_message = "This account is disabled."
            return rx.set_value("password", "")
        if (
            user is not None
            and user.id is not None
            and user.enabled
            and password
            and await user.averify(password)
        ):
            # mark the user as logged in
            await self._login(user.id)
        else:
            self.error_message = "There was a problem logging in, please try again."
            return rx.set_value("password", "")
        self.error_message = ""
        return LoginState.redir()  # type: ignore

    @rx.event
    def redir(self):
        """Redirect to the redirect_to route if logged in, or to the login page if not."""
        if not self.is_hydrated:
            # wait until after hydration to ensure auth_token is known
            return LoginState.redir()  # type: ignore
        current_route = self.router.url.path
        if not self.is_authenticated and current_route != routes.LOGIN_ROUTE:
            self.redirect_to = current_route
            return rx.redirect(routes.LOGIN_ROUTE)
        elif self.is_authenticated and current_route == routes.LOGIN_ROUTE:
            return rx.redirect(self.redirect_to or "/")


def _get_user_by_username(username: str) -> LocalUser | None:
    """Look up a LocalUser by username (blocking).

    Args:
        username: The username to look up.

    Returns:
        The matching LocalUser, or None.
    """
    with rx.session() as session:
        return session.exec(
            select(LocalUser).where(LocalUser.username == username)
        ).one_or_none()


def require_login(page: rx.app.ComponentCallable) -> rx.app.ComponentCallable:
    """Decorator to require authentication before rendering a page.

    If the user is not authenticated, then redirect to the login page.

    Args:
        page: The page to wrap.

    Returns:
        The wrapped page component.
    """

    def protected_page():
        return rx.fragment(
            rx.cond(
                LoginState.is_hydrated & LoginState.is_authenticated,  # type: ignore
                page(),
                rx.center(
                    # When this text mounts, it will redirect to the login page
                    rx.text("Loading...", on_mount=LoginState.redir),
                ),
            )
        )

    protected_page.__name__ = page.__name__
    return protected_page
