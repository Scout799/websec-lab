"""Transactional business operations for the victim application."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import delete, select

from websec_lab.extensions import db
from websec_lab.victim.models import (
    Account,
    AuditLog,
    AuthorizationGrant,
    Transfer,
    User,
)


class BusinessRuleError(ValueError):
    """Raised when a requested lab operation violates a business rule."""


SEED_USERS = (
    ("alice", "alice@example.test", "alice-lab", 100_000),
    ("bob", "bob@example.test", "bob-lab", 25_000),
    ("merchant", "merchant@example.test", "merchant-lab", 50_000),
)


def record_audit(
    action: str,
    outcome: str,
    *,
    user: User | None = None,
    details: dict[str, object] | None = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=None if user is None else user.id,
        action=action,
        outcome=outcome,
        details=json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
    )
    db.session.add(entry)
    return entry


def seed_lab_data() -> int:
    """Create deterministic synthetic users without duplicating existing rows."""

    created = 0
    for username, email, password, balance_cents in SEED_USERS:
        existing = db.session.scalar(select(User).where(User.username == username))
        if existing is not None:
            continue
        user = User(username=username, email=email, password_hash="")
        user.set_password(password)
        user.account = Account(balance_cents=balance_cents)
        db.session.add(user)
        created += 1
    db.session.commit()
    return created


def initialize_database(*, reset: bool = False) -> int:
    if reset:
        db.drop_all()
    db.create_all()
    return seed_lab_data()


def update_email(user: User, new_email: str) -> None:
    normalized = new_email.strip().lower()
    owner = db.session.scalar(select(User).where(User.email == normalized))
    if owner is not None and owner.id != user.id:
        raise BusinessRuleError("该邮箱已被其他测试账户使用。")

    previous = user.email
    user.email = normalized
    record_audit(
        "profile.email_changed",
        "success",
        user=user,
        details={"previous": previous, "current": normalized},
    )
    db.session.commit()


def amount_to_cents(amount: Decimal) -> int:
    cents = int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if cents <= 0:
        raise BusinessRuleError("转账金额必须大于 0。")
    return cents


def perform_transfer(sender: User, recipient_username: str, amount: Decimal, note: str) -> Transfer:
    recipient = db.session.scalar(
        select(User).where(User.username == recipient_username.strip().lower())
    )
    if recipient is None:
        raise BusinessRuleError("收款测试账户不存在。")
    if recipient.id == sender.id:
        raise BusinessRuleError("不能向自己转账。")
    if sender.account is None or recipient.account is None:
        raise BusinessRuleError("测试账户缺少余额账户。")

    amount_cents = amount_to_cents(amount)
    if sender.account.balance_cents < amount_cents:
        record_audit(
            "transfer.created",
            "rejected",
            user=sender,
            details={"recipient": recipient.username, "amount_cents": amount_cents},
        )
        db.session.commit()
        raise BusinessRuleError("测试账户余额不足。")

    sender.account.balance_cents -= amount_cents
    recipient.account.balance_cents += amount_cents
    transfer = Transfer(
        sender_id=sender.id,
        recipient_id=recipient.id,
        amount_cents=amount_cents,
        note=note.strip(),
        status="completed",
    )
    db.session.add(transfer)
    record_audit(
        "transfer.created",
        "success",
        user=sender,
        details={"recipient": recipient.username, "amount_cents": amount_cents},
    )
    db.session.commit()
    return transfer


def create_grant(user: User, client_name: str, scope: str) -> AuthorizationGrant:
    grant = AuthorizationGrant(
        user_id=user.id,
        client_name=client_name.strip(),
        scope=scope.strip(),
        active=True,
    )
    db.session.add(grant)
    record_audit(
        "authorization.granted",
        "success",
        user=user,
        details={"client_name": grant.client_name, "scope": grant.scope},
    )
    db.session.commit()
    return grant


def revoke_grant(user: User, grant_id: int) -> AuthorizationGrant:
    grant = db.session.scalar(
        select(AuthorizationGrant).where(
            AuthorizationGrant.id == grant_id,
            AuthorizationGrant.user_id == user.id,
        )
    )
    if grant is None:
        raise BusinessRuleError("授权记录不存在。")
    if grant.active:
        grant.active = False
        grant.revoked_at = datetime.now(UTC)
        record_audit(
            "authorization.revoked",
            "success",
            user=user,
            details={"grant_id": grant.id, "client_name": grant.client_name},
        )
        db.session.commit()
    return grant


def delete_user_activity(user: User) -> None:
    """Delete synthetic transfers and grants while keeping the lab identity usable."""

    db.session.execute(
        delete(Transfer).where((Transfer.sender_id == user.id) | (Transfer.recipient_id == user.id))
    )
    db.session.execute(delete(AuthorizationGrant).where(AuthorizationGrant.user_id == user.id))
    db.session.execute(delete(AuditLog).where(AuditLog.user_id == user.id))
    record_audit("user.activity_deleted", "success", user=user)
    db.session.commit()
