"""New user registration validation and database logic."""
from __future__ import annotations

import asyncio

import reflex as rx

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

    def _validate_fields(
        self, username, password, confirm_password
    ) -> rx.event.EventSpec | list[rx.event.EventSpec] | None:
        if not username:
            self.error_message = "Username cannot be empty"
            return rx.set_focus("username")
        with rx.session() as session:
            existing_user = session.exec(
                select(LocalUser).where(LocalUser.username == username)
            ).one_or_none()
        if existing_user is not None:
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

    def _register_user(self, username, password) -> None:
        with rx.session() as session:
            # Create the new user and add it to the database.
            new_user = LocalUser()  # type: ignore
            new_user.username = username
            new_user.password_hash = LocalUser.hash_password(password)
            new_user.enabled = True
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            self.new_user_id = new_user.id

    def handle_registration(
        self, form_data
    ) -> rx.event.EventSpec | list[rx.event.EventSpec]:
        """Handle registration form on_submit.

        Set error_message appropriately based on validation results.

        Args:
            form_data: A dict of form fields and values.
        """
        username = form_data["username"]
        password = form_data["password"]
        validation_errors = self._validate_fields(
            username, password, form_data["confirm_password"]
        )
        if validation_errors:
            self.new_user_id = -1
            return validation_errors
        self._register_user(username, password)
        return type(self).successful_registration

    async def successful_registration(self):
        # Set success and redirect to login page after a brief delay.
        self.error_message = ""
        self.new_user_id = -1
        self.success = True
        yield
        await asyncio.sleep(POST_REGISTRATION_DELAY)
        yield [rx.redirect(routes.LOGIN_ROUTE), RegistrationState.set_success(False)]

    def redir(self):
        """Redirect to the registration form."""
        return rx.redirect(routes.REGISTER_ROUTE)
