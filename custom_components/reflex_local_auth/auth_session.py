import datetime

from sqlmodel import Column, DateTime, Field, SQLModel, String, func


class LocalAuthSession(
    SQLModel,
    table=True,  # type: ignore
):
    """Correlate a session_id with an arbitrary user_id."""

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, nullable=False)
    session_id: str = Field(
        unique=True,
        index=True,
        nullable=False,
        sa_type=String(255),  # pyright: ignore[reportArgumentType]
    )
    expiration: datetime.datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), server_default=func.now(), nullable=False
        ),
    )
