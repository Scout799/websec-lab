"""Database models for the controlled victim application."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask_login import UserMixin
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from websec_lab.extensions import db


def utc_now() -> datetime:
    return datetime.now(UTC)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(default=utc_now)

    account: Mapped[Account] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    sent_transfers: Mapped[list[Transfer]] = relationship(
        foreign_keys="Transfer.sender_id", back_populates="sender"
    )
    received_transfers: Mapped[list[Transfer]] = relationship(
        foreign_keys="Transfer.recipient_id", back_populates="recipient"
    )
    grants: Mapped[list[AuthorizationGrant]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Account(db.Model):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    balance_cents: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now, onupdate=utc_now)

    user: Mapped[User] = relationship(back_populates="account")


class Transfer(db.Model):
    __tablename__ = "transfers"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    amount_cents: Mapped[int] = mapped_column(Integer)
    note: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="completed", index=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now, index=True)

    sender: Mapped[User] = relationship(foreign_keys=[sender_id], back_populates="sent_transfers")
    recipient: Mapped[User] = relationship(
        foreign_keys=[recipient_id], back_populates="received_transfers"
    )


class AuthorizationGrant(db.Model):
    __tablename__ = "authorization_grants"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    client_name: Mapped[str] = mapped_column(String(80))
    scope: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    user: Mapped[User] = relationship(back_populates="grants")


class ConfirmationToken(db.Model):
    """Server-side single-use token binding one confirmation page render
    to exactly one submission of a sensitive action."""

    __tablename__ = "confirmation_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    action: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utc_now)
    consumed_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(80), index=True)
    outcome: Mapped[str] = mapped_column(String(20), index=True)
    details: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(default=utc_now, index=True)

    user: Mapped[User | None] = relationship(back_populates="audit_logs")

    def details_dict(self) -> dict[str, Any]:
        import json

        value = json.loads(self.details)
        return value if isinstance(value, dict) else {}
