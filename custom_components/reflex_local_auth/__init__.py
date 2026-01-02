import logging

from . import pages, routes
from .local_auth import LocalAuthState
from .login import LoginState, require_login
from .middleware import (
    AuthMiddleware,
    configure_middleware,
    set_auth_cookie,
    clear_auth_cookie,
    is_safe_redirect_url,
)
from .auth_api import (
    setup_auth_api,
    auth_router,
)
from .registration import RegistrationState
from .routes import set_login_route, set_register_route
from .user import LocalUser

# Configure default logging handler
logging.getLogger("reflex_local_auth").addHandler(logging.NullHandler())

__all__ = [
    # Auth State
    "LocalAuthState",
    "LocalUser",
    "LoginState",
    "RegistrationState",
    # Middleware
    "AuthMiddleware",
    "configure_middleware",
    "set_auth_cookie",
    "clear_auth_cookie",
    "is_safe_redirect_url",
    # Auth API (Professional)
    "setup_auth_api",
    "auth_router",
    # Pages and Routes
    "pages",
    "require_login",
    "routes",
    "set_login_route",
    "set_register_route",
]
