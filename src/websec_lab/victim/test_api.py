"""Local-only state API used by future automated attack experiments."""

from __future__ import annotations

import hmac

from flask import Blueprint, abort, current_app, jsonify, request
from sqlalchemy import or_, select

from websec_lab.extensions import db
from websec_lab.victim.models import AuditLog, AuthorizationGrant, Transfer, User
from websec_lab.victim.services import initialize_database

test_api_blueprint = Blueprint("test_api", __name__, url_prefix="/api/test")


def _require_test_access() -> None:
    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)
    supplied = request.headers.get("X-Websec-Test-Token", "")
    expected = str(current_app.config["TEST_API_TOKEN"])
    if not hmac.compare_digest(supplied, expected):
        abort(403)


@test_api_blueprint.before_request
def protect_test_api() -> None:
    _require_test_access()


@test_api_blueprint.get("/state/<username>")
def state(username: str):  # type: ignore[no-untyped-def]
    user = db.session.scalar(select(User).where(User.username == username.lower()))
    if user is None:
        return {"error": "unknown test user"}, 404

    transfers = db.session.scalars(
        select(Transfer)
        .where(or_(Transfer.sender_id == user.id, Transfer.recipient_id == user.id))
        .order_by(Transfer.id)
    ).all()
    grants = db.session.scalars(
        select(AuthorizationGrant)
        .where(AuthorizationGrant.user_id == user.id)
        .order_by(AuthorizationGrant.id)
    ).all()
    audit_count = db.session.scalar(
        select(db.func.count(AuditLog.id)).where(AuditLog.user_id == user.id)
    )

    return jsonify(
        {
            "user": {"id": user.id, "username": user.username, "email": user.email},
            "account": {"balance_cents": user.account.balance_cents},
            "transfers": [
                {
                    "id": item.id,
                    "sender": item.sender.username,
                    "recipient": item.recipient.username,
                    "amount_cents": item.amount_cents,
                    "note": item.note,
                    "status": item.status,
                }
                for item in transfers
            ],
            "grants": [
                {
                    "id": item.id,
                    "client_name": item.client_name,
                    "scope": item.scope,
                    "active": item.active,
                }
                for item in grants
            ],
            "audit_count": audit_count or 0,
        }
    )


@test_api_blueprint.post("/reset")
def reset():  # type: ignore[no-untyped-def]
    created = initialize_database(reset=True)
    return {"status": "reset", "seed_users_created": created}


def _origin_of(url: str) -> str:
    """scheme://host:port, lowercased, default ports filled in."""

    from urllib.parse import urlsplit

    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}"


def _blocks_framing(profile, ancestor: str) -> tuple[bool, str]:  # type: ignore[no-untyped-def]
    """Would this profile's headers stop `ancestor` from framing the victim?

    Only used for demo/audit feedback, so it covers the shapes the lab's
    profiles actually use (XFO DENY/SAMEORIGIN, frame-ancestors none/self/
    allowlist). The authoritative verdict remains the browser probe.
    """

    xfo = (profile.xfo or "").strip().upper()
    if xfo == "DENY":
        return True, "X-Frame-Options: DENY"
    if xfo == "SAMEORIGIN":
        return True, "X-Frame-Options: SAMEORIGIN（攻击方与目标不同源）"

    sources = profile.csp_frame_ancestors
    if sources is None:
        return False, ""
    values = [sources] if isinstance(sources, str) else list(sources)
    if not values:
        return False, ""

    ancestor_origin = _origin_of(ancestor)
    ancestor_host = ancestor_origin.split("://", 1)[1].split(":", 1)[0]

    # Explicit allowlist entries win, but compare full origins: a hostname
    # substring match would treat partner:5300 as "allowing" attacker:5200.
    for raw in values:
        token = str(raw).strip().strip("'").lower()
        if token == "*":
            return False, ""
        if token in ("self", "none"):
            continue
        if token.startswith("http") and _origin_of(token) == ancestor_origin:
            return False, ""
        if token.startswith("*.") and ancestor_host.endswith(token[1:]):
            return False, ""

    for raw in values:
        token = str(raw).strip().strip("'").lower()
        if token == "none":
            return True, "CSP frame-ancestors 'none'"
        if token == "self":
            return True, "CSP frame-ancestors 'self'（攻击方与目标不同源）"
    return True, "CSP frame-ancestors 白名单未包含攻击方"


@test_api_blueprint.get("/defense")
def get_defense():  # type: ignore[no-untyped-def]
    """Current defense profile name (demo/audit convenience, token protected)."""

    profile = current_app.config["DEFENSE"]
    payload: dict[str, object] = {"profile": profile.name}
    ancestor = (request.args.get("ancestor") or "").strip().rstrip("/")
    if ancestor:
        blocked, reason = _blocks_framing(profile, ancestor)
        payload["blocks_framing"] = blocked
        payload["block_reason"] = reason
    return payload


@test_api_blueprint.post("/defense")
def set_defense():  # type: ignore[no-untyped-def]
    """Hot-swap the defense profile without restarting the service.

    Response-header defenses and business-layer rules apply immediately;
    cookie attributes of already-issued sessions keep their original flags
    (documented limitation — for the demo flow only headers/business matter).
    """

    from websec_lab.defense import expand_partner_origins, resolve_active_profile

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("profile", "")).strip()
    try:
        profile = resolve_active_profile(override=name or None)
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller
        return {"error": "unknown_profile", "detail": str(exc)}, 400
    profile = expand_partner_origins(profile, list(current_app.config["PARTNER_EMBED_ORIGINS"]))
    current_app.config["DEFENSE"] = profile
    return {"status": "ok", "profile": profile.name}
