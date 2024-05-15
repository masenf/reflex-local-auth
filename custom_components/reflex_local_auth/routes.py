from __future__ import annotations

import reflex as rx


LOGIN_ROUTE = "/login"
REGISTER_ROUTE = "/register"


def set_login_route(route: str) -> None:
    """Set the login route.

    Args:
        route: The route to set as the login route.
    """
    global LOGIN_ROUTE
    LOGIN_ROUTE = route


def set_register_route(route: str) -> None:
    """Set the register route.

    Args:
        route: The route to set as the register route.
    """
    global REGISTER_ROUTE
    REGISTER_ROUTE = route


def add_routes(app: rx.App):
    """Add the local auth routes to the app with default settings.
    
    Args:
        app: The reflex app to add the routes to.
    """
    from . import pages

    app.add_page(
        pages.login_page,
        route=LOGIN_ROUTE,
        title="Login",
        description="Login via reflex-local-auth.",
    )

    app.add_page(
        pages.register_page,
        route=REGISTER_ROUTE,
        title="Register",
        description="Register for reflex-local-auth.",
    )