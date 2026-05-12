from __future__ import annotations

import bcrypt
from sqlmodel import Field, SQLModel, String


class LocalUser(
    SQLModel,
    table=True,  # type: ignore
):
    """A local User model with bcrypt password hashing."""

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(
        unique=True,
        nullable=False,
        index=True,
        sa_type=String(255),  # pyright: ignore[reportArgumentType]
    )
    password_hash: bytes = Field(nullable=False)
    enabled: bool = False

    @staticmethod
    def hash_password(secret: str) -> bytes:
        """Hash the secret using bcrypt.

        Args:
            secret: The password to hash.

        Returns:
            The hashed password.
        """
        return bcrypt.hashpw(
            password=secret.encode("utf-8"),
            salt=bcrypt.gensalt(),
        )

    def verify(self, secret: str) -> bool:
        """Validate the user's password.

        Args:
            secret: The password to check.

        Returns:
            True if the hashed secret matches this user's password_hash.
        """
        return bcrypt.checkpw(
            password=secret.encode("utf-8"),
            hashed_password=self.password_hash,
        )

    def dict(self, *args, **kwargs) -> dict:
        """Return a dictionary representation of the user."""
        d = super().model_dump(*args, **kwargs)
        # Never return the hash when serializing to the frontend.
        d.pop("password_hash", None)
        return d
