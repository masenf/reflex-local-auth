"""An example login page that can be used as-is.

app.add_page(
    reflex_local_auth.pages.login_page,
    route=reflex_local_auth.routes.LOGIN_ROUTE,
    title="Login",
)
"""
import reflex as rx

from ..login import LoginState
from ..registration import RegistrationState
from .components import input_100w, MIN_WIDTH, PADDING_TOP


def login_error() -> rx.Component:
    """Render the login error message."""
    return rx.cond(
        LoginState.error_message != "",
        rx.callout(
            LoginState.error_message,
            icon="alert_triangle",
            color_scheme="red",
            role="alert",
            width="100%",
        ),
    )


def login_form() -> rx.Component:
    """Render the login form."""
    return rx.form(
        rx.vstack(
            rx.heading("Login into your Account", size="7"),
            login_error(),
            rx.text("Username"),
            input_100w("username"),
            rx.text("Password"),
            input_100w("password", type="password"),
            rx.button("Sign in", width="100%"),
            rx.center(
                rx.link("Register", on_click=RegistrationState.redir),
                width="100%",
            ),
            min_width=MIN_WIDTH,
        ),
        on_submit=LoginState.on_submit,
    )


def login_page() -> rx.Component:
    """Render the login page.

    Returns:
        A reflex component.
    """

    return rx.center(
        rx.cond(
            LoginState.is_hydrated,  # type: ignore
            rx.card(login_form()),
        ),
        padding_top=PADDING_TOP,
    )
