"""An example registration page that can be used as-is.

app.add_page(
    reflex_local_auth.pages.register_page,
    route=reflex_local_auth.routes.REGISTER_ROUTE,
    title="Register",
)
"""
import reflex as rx

from .. import routes
from ..registration import RegistrationState
from .components import input_100w, MIN_WIDTH, PADDING_TOP


def register_error() -> rx.Component:
    """Render the registration error message."""
    return rx.cond(
        RegistrationState.error_message != "",
        rx.callout(
            RegistrationState.error_message,
            icon="alert_triangle",
            color_scheme="red",
            role="alert",
            width="100%",
        ),
    )


def register_form() -> rx.Component:
    """Render the registration form."""
    return rx.form(
        rx.vstack(
            rx.heading("Create an account", size="7"),
            register_error(),
            rx.text("Username"),
            input_100w("username"),
            rx.text("Password"),
            input_100w("password", type="password"),
            rx.text("Confirm Password"),
            input_100w("confirm_password", type="password"),
            rx.button("Sign up", width="100%"),
            rx.center(
                rx.link("Login", on_click=lambda: rx.redirect(routes.LOGIN_ROUTE)),
                width="100%",
            ),
            min_width=MIN_WIDTH,
        ),
        on_submit=RegistrationState.handle_registration,
    )


def register_page() -> rx.Component:
    """Render the registration page.

    Returns:
        A reflex component.
    """

    return rx.center(
        rx.cond(
            RegistrationState.success,
            rx.vstack(
                rx.text("Registration successful!"),
            ),
            rx.card(register_form()),
        ),
        padding_top=PADDING_TOP,
    )
