"""User-facing routes for the controlled victim application."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import or_, select

from websec_lab import __version__
from websec_lab.extensions import db
from websec_lab.victim.forms import (
    DeleteDataForm,
    GrantForm,
    LoginForm,
    LogoutForm,
    ProfileForm,
    RevokeGrantForm,
    TransferForm,
)
from websec_lab.victim.lab_routes import REAUTH_SESSION_KEY
from websec_lab.victim.models import AuditLog, AuthorizationGrant, Transfer, User
from websec_lab.victim.services import (
    BusinessRuleError,
    create_grant,
    delete_user_activity,
    perform_transfer,
    record_audit,
    revoke_grant,
    update_email,
)

victim_blueprint = Blueprint("victim", __name__)


@victim_blueprint.app_context_processor
def inject_layout_context() -> dict[str, object]:
    return {"logout_form": LogoutForm(), "app_version": __version__}


@victim_blueprint.get("/")
def index():  # type: ignore[no-untyped-def]
    if current_user.is_authenticated:
        return redirect(url_for("victim.dashboard"))
    return render_template("victim/landing.html")


def _safe_login_next() -> str | None:
    """Only allow loopback/*.test absolute URLs or site-relative paths.

    The demo flow sends the user to the login page with ``next`` pointing
    back at the attacker demo page, so cross-origin returns must be allowed
    — but only to other local lab origins, never open redirects.
    """

    from urllib.parse import urlsplit

    candidate = request.args.get("next", "").strip()
    if not candidate:
        return None
    if not candidate.startswith(("http://", "https://", "/")):
        return None
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower()
    if not host:
        return candidate if candidate.startswith("/") else None
    is_local = (
        host in ("127.0.0.1", "localhost", "::1")
        or host.endswith(".test")
        or host == "test"
    )
    return candidate if is_local else None


@victim_blueprint.route("/login", methods=["GET", "POST"])
def login():  # type: ignore[no-untyped-def]
    next_url = _safe_login_next()
    if current_user.is_authenticated:
        return redirect(next_url or url_for("victim.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        user = db.session.scalar(select(User).where(User.username == username))
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            session[REAUTH_SESSION_KEY] = time.time()
            record_audit(
                "session.login",
                "success",
                user=user,
                details={"remote_addr": request.remote_addr or "unknown"},
            )
            db.session.commit()
            flash("已登录本地测试账户。", "success")
            return redirect(next_url or url_for("victim.dashboard"))

        record_audit(
            "session.login",
            "rejected",
            details={"username": username, "remote_addr": request.remote_addr or "unknown"},
        )
        db.session.commit()
        flash("用户名或密码错误。", "error")
    return render_template("victim/login.html", form=form)


@victim_blueprint.post("/logout")
@login_required
def logout():  # type: ignore[no-untyped-def]
    form = LogoutForm()
    if not form.validate_on_submit():
        flash("退出请求验证失败。", "error")
        return redirect(url_for("victim.dashboard"))
    user = current_user
    record_audit("session.logout", "success", user=user)
    db.session.commit()
    logout_user()
    flash("已退出测试账户。", "success")
    return redirect(url_for("victim.index"))


@victim_blueprint.get("/dashboard")
@login_required
def dashboard():  # type: ignore[no-untyped-def]
    recent_transfers = db.session.scalars(
        select(Transfer)
        .where(
            or_(
                Transfer.sender_id == current_user.id,
                Transfer.recipient_id == current_user.id,
            )
        )
        .order_by(Transfer.created_at.desc())
        .limit(5)
    ).all()
    active_grants = db.session.scalar(
        select(db.func.count(AuthorizationGrant.id)).where(
            AuthorizationGrant.user_id == current_user.id,
            AuthorizationGrant.active.is_(True),
        )
    )
    return render_template(
        "victim/dashboard.html",
        recent_transfers=recent_transfers,
        active_grants=active_grants or 0,
    )


@victim_blueprint.route("/profile", methods=["GET", "POST"])
@login_required
def profile():  # type: ignore[no-untyped-def]
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        try:
            update_email(current_user, form.email.data)
        except BusinessRuleError as exc:
            flash(str(exc), "error")
        else:
            flash("邮箱已更新。", "success")
            return redirect(url_for("victim.profile"))
    return render_template("victim/profile.html", form=form)


@victim_blueprint.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():  # type: ignore[no-untyped-def]
    form = TransferForm()
    if form.validate_on_submit():
        try:
            completed = perform_transfer(
                current_user,
                form.recipient_username.data,
                form.amount.data,
                form.note.data or "",
            )
        except BusinessRuleError as exc:
            flash(str(exc), "error")
        else:
            flash(f"模拟转账 #{completed.id} 已完成。", "success")
            return redirect(url_for("victim.transfer_history"))
    return render_template("victim/transfer.html", form=form)


@victim_blueprint.get("/transfers")
@login_required
def transfer_history():  # type: ignore[no-untyped-def]
    transfers = db.session.scalars(
        select(Transfer)
        .where(
            or_(
                Transfer.sender_id == current_user.id,
                Transfer.recipient_id == current_user.id,
            )
        )
        .order_by(Transfer.created_at.desc())
    ).all()
    return render_template("victim/transfers.html", transfers=transfers)


@victim_blueprint.route("/authorizations", methods=["GET", "POST"])
@login_required
def authorizations():  # type: ignore[no-untyped-def]
    form = GrantForm()
    if form.validate_on_submit():
        create_grant(current_user, form.client_name.data, form.scope.data)
        flash("第三方应用权限已记录。", "success")
        return redirect(url_for("victim.authorizations"))

    grants = db.session.scalars(
        select(AuthorizationGrant)
        .where(AuthorizationGrant.user_id == current_user.id)
        .order_by(AuthorizationGrant.created_at.desc())
    ).all()
    return render_template(
        "victim/authorizations.html",
        form=form,
        revoke_form=RevokeGrantForm(),
        grants=grants,
    )


@victim_blueprint.post("/authorizations/<int:grant_id>/revoke")
@login_required
def revoke_authorization(grant_id: int):  # type: ignore[no-untyped-def]
    form = RevokeGrantForm()
    if not form.validate_on_submit():
        flash("撤销请求验证失败。", "error")
        return redirect(url_for("victim.authorizations"))
    try:
        revoke_grant(current_user, grant_id)
    except BusinessRuleError as exc:
        flash(str(exc), "error")
    else:
        flash("授权已撤销。", "success")
    return redirect(url_for("victim.authorizations"))


@victim_blueprint.route("/delete-data", methods=["GET", "POST"])
@login_required
def delete_data():  # type: ignore[no-untyped-def]
    form = DeleteDataForm()
    if form.validate_on_submit():
        if form.confirmation.data != "DELETE":
            flash("请输入 DELETE 进行确认。", "error")
        else:
            delete_user_activity(current_user)
            flash("实验活动数据已清理，测试账户仍然保留。", "success")
            return redirect(url_for("victim.dashboard"))
    return render_template("victim/delete_data.html", form=form)


@victim_blueprint.get("/audit-log")
@login_required
def audit_log():  # type: ignore[no-untyped-def]
    entries = db.session.scalars(
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
    ).all()
    return render_template("victim/audit_log.html", entries=entries)


@victim_blueprint.get("/healthz")
def healthz():  # type: ignore[no-untyped-def]
    return {
        "status": "ok",
        "service": "victim",
        "version": __version__,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@victim_blueprint.get("/readyz")
def readyz():  # type: ignore[no-untyped-def]
    try:
        db.session.execute(select(db.func.count(User.id))).scalar_one()
    except Exception:  # pragma: no cover - exercised by deployment failures
        return {"status": "not-ready", "service": "victim", "database": "unavailable"}, 503
    return {"status": "ready", "service": "victim", "database": "available"}
