"""
Authentication data is stored in the LocalAuthState class so that all substates can
access it for verifying access to event handlers and computed vars.

Your app may inherit from LocalAuthState, or it may access it via the `get_state` API.
"""
from __future__ import annotations

from sqlmodel import select

import reflex as rx

from .user import LocalUser


LOCAL_AUTH_PROVIDER = "reflex-local-auth"


class LocalAuthState(rx.ReflexAuthState):

    @rx.cached_var
    def authenticated_local_user(self) -> LocalUser:
        """The currently authenticated user, or a dummy user if not authenticated.

        Returns:
            A LocalUser instance with id=-1 if not authenticated, or the LocalUser instance
            corresponding to the currently authenticated user.
        """
        if self.authenticated_user.provider == LOCAL_AUTH_PROVIDER:
            with rx.session() as session:
                result = session.exec(
                    select(LocalUser).where(
                        LocalUser.id == int(self.authenticated_user.foreign_user_id),
                    ),
                ).first()
                if result is not None:
                    return result
        return LocalUser(id=-1)  # type: ignore