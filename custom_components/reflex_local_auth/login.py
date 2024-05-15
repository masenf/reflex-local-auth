"""Login state and authentication logic."""
from __future__ import annotations

from typing import ClassVar

import reflex as rx
from sqlmodel import select

from . import routes
from .local_auth import LOCAL_AUTH_PROVIDER, LocalAuthState
from .user import LocalUser


class LoginState(rx.ReflexAuthProvider):
    """Handle login form submission and redirect to proper routes after authentication."""
    _reflex_auth_provider: ClassVar[str] = LOCAL_AUTH_PROVIDER

    error_message: str = ""
    redirect_to: str = ""

    async def on_submit(self, form_data) -> rx.event.EventSpec:
        """Handle login form on_submit.

        Args:
            form_data: A dict of form fields and values.
        """
        self.error_message = ""
        username = form_data["username"]
        password = form_data["password"]
        with rx.session() as session:
            user = session.exec(
                select(LocalUser).where(LocalUser.username == username)
            ).one_or_none()
        if user is not None and not user.enabled:
            self.error_message = "This account is disabled."
            return rx.set_value("password", "")
        if (
            user is not None
            and user.id is not None
            and user.enabled
            and password
            and user.verify(password)
        ):
            # mark the user as logged in
            auth_state = await self.get_state(rx.ReflexAuthState)
            auth_state._login(foreign_user_id=str(user.id), provider=LOCAL_AUTH_PROVIDER)
        else:
            self.error_message = "There was a problem logging in, please try again."
            return rx.set_value("password", "")
        self.error_message = ""
        return LoginState.redir()  # type: ignore

    async def redir(self) -> rx.event.EventSpec | None:
        """Redirect to the redirect_to route if logged in, or to the login page if not."""
        if not self.is_hydrated:
            # wait until after hydration to ensure auth_token is known
            return LoginState.redir()  # type: ignore
        auth_state = await self.get_state(rx.ReflexAuthState)
        page = self.router.page.path
        if not auth_state.is_authenticated and page != routes.LOGIN_ROUTE:
            self.redirect_to = self.router.page.raw_path
            return rx.redirect(routes.LOGIN_ROUTE)
        elif auth_state.is_authenticated and page == routes.LOGIN_ROUTE:
            return rx.redirect(self.redirect_to or "/")

    async def _validate_user(self) -> bool:
        # If the user logged in and their session is active, then they are valid.
        local_auth_state = await self.get_state(LocalAuthState)
        return local_auth_state.authenticated_local_user.enabled

    @classmethod
    def get_login_component(cls) -> rx.Component:
        """Get the login component for the login page."""
        return rx.button("Login with Username and Password", on_click=cls.redir)


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
                rx.ReflexAuthState.is_authenticated,  # type: ignore
                page(),
                rx.center(
                    # When this text mounts, it will redirect to the login page
                    rx.text("Loading...", on_mount=LoginState.redir),
                ),
            )
        )

    protected_page.__name__ = page.__name__
    return protected_page
