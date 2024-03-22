from __future__ import annotations

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
