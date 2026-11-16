"""New user registration validation and database logic."""

from __future__ import annotations

import asyncio
from typing import Any

import reflex as rx
from reflex.event import EventSpec
from sqlmodel import select

from . import routes
from .local_auth import LocalAuthState
from .user import LocalUser

POST_REGISTRATION_DELAY = 0.5


class RegistrationState(LocalAuthState):
    """Handle registration form submission and redirect to login page after registration."""

    success: bool = False
    error_message: str = ""
    new_user_id: int = -1

    async def _validate_fields(
        self, username, password, confirm_password
    ) -> EventSpec | list[EventSpec] | None:
        if not username:
            self.error_message = "Username cannot be empty"
            return rx.set_focus("username")
        if await asyncio.to_thread(_username_exists, username):
            self.error_message = (
                f"Username {username} is already registered. Try a different name"
            )
            return [rx.set_value("username", ""), rx.set_focus("username")]
        if not password:
            self.error_message = "Password cannot be empty"
            return rx.set_focus("password")
        if password != confirm_password:
            self.error_message = "Passwords do not match"
            return [
                rx.set_value("confirm_password", ""),
                rx.set_focus("confirm_password"),
            ]

    async def _register_user(self, username, password) -> None:
        password_hash = await LocalUser.ahash_password(password)
        new_user_id = await asyncio.to_thread(_create_user, username, password_hash)
        if new_user_id is not None:
            self.new_user_id = new_user_id

    @rx.event
    async def handle_registration(
        self,
        form_data: dict[str, Any],
    ):
        """Handle registration form on_submit.

        Set error_message appropriately based on validation results. Database
        access and password hashing run in a worker thread to avoid blocking the
        event loop.

        Subclasses extending this handler must ``await`` it.

        Args:
            form_data: A dict of form fields and values.
        """
        username = form_data["username"]
        password = form_data["password"]
        validation_errors = await self._validate_fields(
            username, password, form_data["confirm_password"]
        )
        if validation_errors:
            self.new_user_id = -1
            return validation_errors
        await self._register_user(username, password)
        return type(self).successful_registration

    @rx.event
    def set_success(self, success: bool):
        """Set the success flag.

        Args:
            success: Whether the registration was successful.
        """
        self.success = success

    @rx.event
    async def successful_registration(
        self,
    ):
        # Set success and redirect to login page after a brief delay.
        self.error_message = ""
        self.new_user_id = -1
        self.success = True
        yield
        await asyncio.sleep(POST_REGISTRATION_DELAY)
        yield [rx.redirect(routes.LOGIN_ROUTE), type(self).set_success(False)]

    @rx.event
    def redir(self):
        """Redirect to the registration form."""
        return rx.redirect(routes.REGISTER_ROUTE)


def _username_exists(username: str) -> bool:
    """Check whether a username is already registered (blocking).

    Args:
        username: The username to check.

    Returns:
        True if a LocalUser with this username exists.
    """
    with rx.session() as session:
        return (
            session.exec(
                select(LocalUser).where(LocalUser.username == username)
            ).one_or_none()
            is not None
        )


def _create_user(username: str, password_hash: bytes) -> int | None:
    """Create a new enabled LocalUser (blocking).

    Args:
        username: The new user's username.
        password_hash: The bcrypt hash of the new user's password.

    Returns:
        The new user's id.
    """
    with rx.session() as session:
        new_user = LocalUser()  # type: ignore
        new_user.username = username
        new_user.password_hash = password_hash
        new_user.enabled = True
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return new_user.id
