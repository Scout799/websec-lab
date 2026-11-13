from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import select

from websec_lab.extensions import db
from websec_lab.victim.models import AuditLog, AuthorizationGrant, Transfer, User
from websec_lab.victim.services import (
    BusinessRuleError,
    create_grant,
    delete_user_activity,
    perform_transfer,
    revoke_grant,
    seed_lab_data,
    update_email,
)


def get_user(username: str) -> User:
    user = db.session.scalar(select(User).where(User.username == username))
    assert user is not None
    return user


def test_seed_data_is_deterministic(victim_app: Flask) -> None:
    with victim_app.app_context():
        assert seed_lab_data() == 0
        users = db.session.scalars(select(User).order_by(User.username)).all()
        assert [user.username for user in users] == ["alice", "bob", "merchant"]
        assert get_user("alice").check_password("alice-lab") is True
        assert get_user("alice").check_password("wrong") is False


def test_transfer_updates_balances_and_records_evidence(victim_app: Flask) -> None:
    with victim_app.app_context():
        alice = get_user("alice")
        bob = get_user("bob")

        transfer = perform_transfer(alice, "bob", Decimal("12.34"), "test transfer")

        assert transfer.amount_cents == 1234
        assert alice.account.balance_cents == 98_766
        assert bob.account.balance_cents == 26_234
        assert db.session.scalar(select(db.func.count(Transfer.id))) == 1
        audit = db.session.scalar(select(AuditLog).where(AuditLog.action == "transfer.created"))
        assert audit is not None
        assert audit.outcome == "success"
        assert audit.details_dict()["amount_cents"] == 1234


def test_transfer_rejects_invalid_business_cases(victim_app: Flask) -> None:
    with victim_app.app_context():
        alice = get_user("alice")
        original_balance = alice.account.balance_cents

        with pytest.raises(BusinessRuleError, match="自己"):
            perform_transfer(alice, "alice", Decimal("1.00"), "")
        with pytest.raises(BusinessRuleError, match="不存在"):
            perform_transfer(alice, "missing", Decimal("1.00"), "")
        with pytest.raises(BusinessRuleError, match="余额不足"):
            perform_transfer(alice, "bob", Decimal("1001.00"), "")

        assert alice.account.balance_cents == original_balance
        rejected = db.session.scalar(select(AuditLog).where(AuditLog.outcome == "rejected"))
        assert rejected is not None


def test_profile_email_must_remain_unique(victim_app: Flask) -> None:
    with victim_app.app_context():
        alice = get_user("alice")
        update_email(alice, "ALICE.NEW@EXAMPLE.TEST")
        assert alice.email == "alice.new@example.test"

        with pytest.raises(BusinessRuleError, match="已被"):
            update_email(alice, "bob@example.test")


def test_grant_revoke_and_activity_cleanup(victim_app: Flask) -> None:
    with victim_app.app_context():
        alice = get_user("alice")
        grant = create_grant(alice, "Calendar Demo", "profile:read")
        assert grant.active is True

        revoke_grant(alice, grant.id)
        assert grant.active is False
        assert grant.revoked_at is not None

        perform_transfer(alice, "bob", Decimal("2.50"), "cleanup")
        delete_user_activity(alice)

        assert db.session.scalar(select(db.func.count(Transfer.id))) == 0
        assert db.session.scalar(select(db.func.count(AuthorizationGrant.id))) == 0
        entries = db.session.scalars(select(AuditLog).where(AuditLog.user_id == alice.id)).all()
        assert [entry.action for entry in entries] == ["user.activity_deleted"]
