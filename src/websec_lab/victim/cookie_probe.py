"""Read-only, local-lab session observation endpoint for SameSite experiments."""

from flask import Blueprint, current_app, render_template, request
from flask_login import current_user

cookie_probe_blueprint = Blueprint("cookie_probe", __name__, url_prefix="/cookie-lab")


@cookie_probe_blueprint.get("/session")
def session_probe():
    observation = {
        "authenticated": current_user.is_authenticated,
        "session_cookie_present": current_app.config["SESSION_COOKIE_NAME"] in request.cookies,
        "sec_fetch_site": request.headers.get("Sec-Fetch-Site"),
        "scheme": request.scheme,
        "host": request.host,
        "samesite": current_app.config["SESSION_COOKIE_SAMESITE"],
        "secure_cookie": current_app.config["SESSION_COOKIE_SECURE"],
        "username": current_user.username if current_user.is_authenticated else None,
    }
    return render_template("victim/cookie_probe.html", observation=observation)
