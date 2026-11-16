from __future__ import annotations

import asyncio

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

    @classmethod
    async def ahash_password(cls, secret: str) -> bytes:
        """Hash the secret using bcrypt in a worker thread.

        bcrypt is deliberately slow, so this keeps it off the event loop.

        Args:
            secret: The password to hash.

        Returns:
            The hashed password.
        """
        return await asyncio.to_thread(cls.hash_password, secret)

    async def averify(self, secret: str) -> bool:
        """Validate the user's password in a worker thread.

        bcrypt is deliberately slow, so this keeps it off the event loop.

        Args:
            secret: The password to check.

        Returns:
            True if the hashed secret matches this user's password_hash.
        """
        return await asyncio.to_thread(self.verify, secret)

    def model_dump(self, *args, **kwargs) -> dict:
        """Return a dictionary representation of the user."""
        d = super().model_dump(*args, **kwargs)
        # Never return the hash when serializing to the frontend.
        d.pop("password_hash", None)
        return d
