"""Embeddable components the victim exposes to authorized partners (M4).

Unlike the quick-action lab pages, these components carry no sensitive
controls: they are read-only summary views that a partner site may frame
when the active defense profile allowlists the partner origin.
"""

from __future__ import annotations

from decimal import Decimal

from flask import Blueprint, abort, current_app, render_template
from flask_login import current_user, login_required
from sqlalchemy import or_, select

from websec_lab.extensions import db
from websec_lab.victim.models import Transfer

embed_blueprint = Blueprint("victim_embed", __name__, url_prefix="/embed")


@embed_blueprint.before_request
def require_local_only() -> None:
    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)


def _display_amount(amount_cents: int) -> str:
    return f"¥{(Decimal(amount_cents) / 100).quantize(Decimal('0.01'))}"


@embed_blueprint.get("/profile-card")
@login_required
def profile_card():  # type: ignore[no-untyped-def]
    latest = db.session.scalars(
        select(Transfer)
        .where(
            or_(
                Transfer.sender_id == current_user.id,
                Transfer.recipient_id == current_user.id,
            )
        )
        .order_by(Transfer.id.desc())
        .limit(1)
    ).first()
    return render_template(
        "victim/embed_profile_card.html",
        username=current_user.username,
        balance_display=_display_amount(current_user.account.balance_cents),
        latest=latest,
        latest_display=_display_amount(latest.amount_cents) if latest else None,
    )
