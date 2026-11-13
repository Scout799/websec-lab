"""Local-only quick-action pages used as clickjacking targets.

These intentionally minimal confirmation pages exist so the attacker
scenarios have a stable, single-button victim surface whose business
effect can be verified through the test API. They are only registered
in ``local_only`` environments and never contain real user data.

The active defense profile (M5) controls their behavior: two-stage
confirmation, server-side one-time tokens and a re-authentication
gate can each be toggled from ``config/defense.yaml`` without touching
this module's callers.
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import delete, select, update

from websec_lab.defense import DefenseProfile
from websec_lab.extensions import db
from websec_lab.victim.forms import QuickGrantForm, QuickReauthForm, QuickTransferForm
from websec_lab.victim.models import ConfirmationToken, User
from websec_lab.victim.services import (
    BusinessRuleError,
    create_grant,
    perform_transfer,
    record_audit,
)

lab_blueprint = Blueprint("victim_lab", __name__, url_prefix="/lab")

QUICK_TRANSFER_DEFAULT_CENTS = 123
QUICK_TRANSFER_MAX_CENTS = 50_000
QUICK_TRANSFER_NOTE = "快捷转账实验"
# The attacker pages tag each technique with a short ASCII note so the victim's
# transfer history itself says which attack produced the entry ("S5
# frame-busting"). Anything that does not match the tag shape is ignored.
NOTE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
REAUTH_SESSION_KEY = "victim_auth_at"


def _defense() -> DefenseProfile:
    return current_app.config["DEFENSE"]


def _issue_confirmation_token(action: str) -> str:
    """Create a fresh single-use token for the current confirm page render."""

    db.session.execute(
        delete(ConfirmationToken).where(
            ConfirmationToken.user_id == current_user.id,
            ConfirmationToken.action == action,
            ConfirmationToken.consumed_at.isnot(None),
        )
    )
    token = uuid.uuid4().hex
    db.session.add(ConfirmationToken(user_id=current_user.id, token=token, action=action))
    db.session.commit()
    return token


def _consume_confirmation_token(action: str, supplied: str) -> bool:
    """Atomically consume a token; returns False on replay or mismatch."""

    if not supplied:
        return False
    result = db.session.execute(
        update(ConfirmationToken)
        .where(
            ConfirmationToken.token == supplied,
            ConfirmationToken.user_id == current_user.id,
            ConfirmationToken.action == action,
            ConfirmationToken.consumed_at.is_(None),
        )
        .values(consumed_at=datetime.now(UTC))
    )
    db.session.commit()
    return result.rowcount == 1


def _reauthentication_expired() -> bool:
    ttl = _defense().reauth_ttl_seconds
    if ttl is None:
        return False
    auth_at = session.get(REAUTH_SESSION_KEY)
    if not isinstance(auth_at, int | float):
        return True
    return (time.time() - auth_at) > ttl


@lab_blueprint.before_request
def require_local_only() -> None:
    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)


@lab_blueprint.before_request
def gate_reauthentication():  # type: ignore[no-untyped-def]
    if request.endpoint == "victim_lab.reauth":
        return None
    if _reauthentication_expired():
        return redirect(url_for("victim_lab.reauth", next=request.full_path))
    return None


@lab_blueprint.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():  # type: ignore[no-untyped-def]
    form = QuickReauthForm()
    target = request.values.get("next", "")
    if not target.startswith("/lab/"):
        target = url_for("victim_lab.quick_transfer")

    if form.validate_on_submit():
        if current_user.check_password(form.password.data):
            session[REAUTH_SESSION_KEY] = time.time()
            record_audit(
                "lab.reauth.success",
                "success",
                user=current_user,
                details={"target": target},
            )
            db.session.commit()
            return redirect(target)
        record_audit("lab.reauth.success", "rejected", user=current_user)
        db.session.commit()
        flash("密码错误，请重新验证。", "error")
    return render_template("victim/lab_reauth.html", form=form, next_target=target)


def _display_amount(amount_cents: int) -> str:
    return f"¥{(Decimal(amount_cents) / 100).quantize(Decimal('0.01'))}"


def _resolve_recipient(requested: str) -> tuple[User | None, str]:
    recipient_name = requested.strip().lower() or "bob"
    recipient = db.session.scalar(select(User).where(User.username == recipient_name))
    if recipient is not None and recipient.id != current_user.id:
        return recipient, recipient_name

    # Fall back to a seeded account that differs from the current user so the
    # confirmation page always shows a valid cross-account transfer.
    for fallback_name in ("bob", "merchant", "alice"):
        if fallback_name == current_user.username:
            continue
        fallback = db.session.scalar(select(User).where(User.username == fallback_name))
        if fallback is not None:
            return fallback, fallback_name
    return None, recipient_name


def _resolve_amount_cents(raw: int | None) -> int:
    amount_cents = QUICK_TRANSFER_DEFAULT_CENTS if raw is None else raw
    return max(1, min(amount_cents, QUICK_TRANSFER_MAX_CENTS))


def _resolve_note() -> str:
    """Ledger note for this transfer: the attacker's short technique tag.

    Every scenario books a different amount and a different tag, so the
    victim's own history distinguishes "S5 frame-busting" from "S2 overlay"
    instead of showing one indistinguishable row per attack.
    """

    raw = (request.args.get("note") or "").strip()
    if raw and NOTE_PATTERN.fullmatch(raw):
        return raw
    return QUICK_TRANSFER_NOTE


@lab_blueprint.route("/quick-transfer", methods=["GET", "POST"])
@login_required
def quick_transfer():  # type: ignore[no-untyped-def]
    form = QuickTransferForm()
    profile = _defense()

    recipient, recipient_name = _resolve_recipient(request.args.get("recipient", "bob"))
    amount_cents = _resolve_amount_cents(request.args.get("amount_cents", type=int))
    ledger_note = _resolve_note()

    show_details = profile.confirm_mode == "reconfirm" and request.args.get("stage") != "2"

    if request.method == "POST":
        if profile.one_time_token and not _consume_confirmation_token(
            "quick_transfer", request.form.get("confirm_token", "")
        ):
            record_audit(
                "lab.quick_transfer.token_rejected",
                "rejected",
                user=current_user,
                details={"recipient": recipient_name, "amount_cents": amount_cents},
            )
            db.session.commit()
            flash("确认令牌无效或已被使用。", "error")
            return render_template(
                "victim/lab_quick_transfer.html",
                form=form,
                completed=None,
                recipient=recipient_name,
                amount_cents=amount_cents,
                amount_display=_display_amount(amount_cents),
                balance_display=_display_amount(current_user.account.balance_cents),
                ledger_note=ledger_note,
                show_details=False,
                confirm_token=_issue_confirmation_token("quick_transfer"),
            )

        try:
            completed = perform_transfer(
                current_user,
                recipient_name,
                Decimal(amount_cents) / 100,
                ledger_note,
            )
        except BusinessRuleError as exc:
            flash(str(exc), "error")
        else:
            record_audit(
                "lab.quick_transfer.executed",
                "success",
                user=current_user,
                details={
                    "transfer_id": completed.id,
                    "recipient": recipient_name,
                    "amount_cents": amount_cents,
                },
            )
            db.session.commit()
            return render_template(
                "victim/lab_quick_transfer.html",
                form=None,
                completed=completed,
                recipient=recipient_name,
                amount_cents=amount_cents,
                amount_display=_display_amount(amount_cents),
                balance_display=_display_amount(current_user.account.balance_cents),
                ledger_note=ledger_note,
                show_details=False,
                confirm_token="",
            )

    return render_template(
        "victim/lab_quick_transfer.html",
        form=form,
        completed=None,
        recipient=recipient_name,
        amount_cents=amount_cents,
        amount_display=_display_amount(amount_cents),
        balance_display=_display_amount(current_user.account.balance_cents),
        ledger_note=ledger_note,
        show_details=show_details,
        confirm_token=(
            _issue_confirmation_token("quick_transfer")
            if profile.one_time_token and not show_details
            else ""
        ),
    )


@lab_blueprint.route("/quick-grant", methods=["GET", "POST"])
@login_required
def quick_grant():  # type: ignore[no-untyped-def]
    form = QuickGrantForm()
    profile = _defense()

    client_name = request.args.get("client", "Lab Partner Demo", type=str).strip()
    client_name = client_name[:60] or "Lab Partner Demo"

    show_details = profile.confirm_mode == "reconfirm" and request.args.get("stage") != "2"

    if request.method == "POST":
        if profile.one_time_token and not _consume_confirmation_token(
            "quick_grant", request.form.get("confirm_token", "")
        ):
            record_audit(
                "lab.quick_grant.token_rejected",
                "rejected",
                user=current_user,
                details={"client_name": client_name},
            )
            db.session.commit()
            flash("确认令牌无效或已被使用。", "error")
            return render_template(
                "victim/lab_quick_grant.html",
                form=form,
                completed=None,
                client_name=client_name,
                show_details=False,
                confirm_token=_issue_confirmation_token("quick_grant"),
            )

        grant = create_grant(current_user, client_name, "profile:read")
        record_audit(
            "lab.quick_grant.executed",
            "success",
            user=current_user,
            details={"grant_id": grant.id, "client_name": client_name},
        )
        db.session.commit()
        return render_template(
            "victim/lab_quick_grant.html",
            form=None,
            completed=grant,
            client_name=client_name,
            show_details=False,
            confirm_token="",
        )

    return render_template(
        "victim/lab_quick_grant.html",
        form=form,
        completed=None,
        client_name=client_name,
        show_details=show_details,
        confirm_token=(
            _issue_confirmation_token("quick_grant")
            if profile.one_time_token and not show_details
            else ""
        ),
    )
