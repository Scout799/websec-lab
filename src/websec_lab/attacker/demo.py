"""Split-screen demo mode: make the clickjacking story self-explanatory.

The demo page shows the attacker lure on the left and the victim account
(queried live through the lab's test API) on the right, with an automatic
narration timeline in between. Because the browser cannot call the victim
test API cross-origin, this blueprint proxies it server-side under the
same origin whitelist the scenarios already use.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import requests
from flask import Blueprint, abort, current_app, jsonify, render_template, request, url_for

from websec_lab.attacker.scenarios import (
    OVERLAY,
    ScenarioParamError,
    parse_run_params,
)

demo_blueprint = Blueprint("demo", __name__, url_prefix="/demo")

DEMO_USERS = ("alice", "bob", "merchant")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
STATE_POLL_TIMEOUT_SECONDS = 4.0


def _allowed_origins() -> list[str]:
    return list(current_app.config["ATTACKER_VICTIM_ORIGINS"])


def _demo_token() -> str:
    return str(current_app.config.get("DEMO_STATE_TOKEN") or "local-lab-only")


def _request_host() -> str:
    return (urlsplit(request.host_url).hostname or "").lower()


def _same_host_victim_origin(allowed_origins: list[str]) -> str:
    """Embed the victim under the same hostname the demo was opened with.

    The victim session cookie is scoped to its host, so a demo opened at
    ``http://localhost:5200`` cannot share a session with an iframe pointing
    at ``http://127.0.0.1:5100``. The login form rendered inside that iframe
    then posts without its cookie and Flask-WTF rejects it with
    ``400 Bad Request: The CSRF session token is missing`` — the attack looks
    broken even though the credentials were right. Prefer the loopback alias
    that matches the request so the demo and the iframe stay on one site.
    """

    default_origin = allowed_origins[0]
    host = _request_host()
    if host not in LOOPBACK_HOSTS:
        return default_origin
    for origin in allowed_origins:
        if (urlsplit(origin).hostname or "").lower() == host:
            return origin.rstrip("/")
    return default_origin


@demo_blueprint.get("/")
def index():  # type: ignore[no-untyped-def]
    return render_template("attacker/demo_index.html")


@demo_blueprint.get("/cursor")
def cursor_demo():  # type: ignore[no-untyped-def]
    """Cursorjacking: the pointer the user sees is not where the click lands.

    Deliberately kept outside the S1-S7 scenario registry: it is a perception
    demo that does not need an iframe and has no victim business state, so it
    must not be counted as one of the seven attack variants.
    """

    return render_template("attacker/cursor_demo.html")


@demo_blueprint.get("/classic")
def classic():  # type: ignore[no-untyped-def]
    """The split-screen demo for the classic transparent overlay attack."""

    allowed_origins = _allowed_origins()
    args = request.args.to_dict()
    if not args.get("origin"):
        args["origin"] = _same_host_victim_origin(allowed_origins)
    try:
        params = parse_run_params(OVERLAY, args, allowed_origins)
    except ScenarioParamError as exc:
        return jsonify({"error": "invalid_demo_params", "detail": str(exc)}), 400
    return render_template(
        "attacker/demo_classic.html",
        params=params,
        victim_login_url=f"{params.victim_base}/login",
        # Coming back from the login page must restore the demo exactly as it
        # was left (透视/defense/amount), otherwise the presenter has to set
        # the scene up again after logging in.
        demo_return_url=url_for("demo.classic", _external=True, **args),
        report_token=str(current_app.config["ATTACKER_REPORT_TOKEN"]),
    )


def _proxy_victim_api(path: str) -> tuple[dict, int]:
    origin = (request.args.get("origin") or "").strip().rstrip("/")
    if origin not in _allowed_origins():
        return {"error": "invalid_origin", "detail": "origin not allowed"}, 400
    upstream_origin = current_app.config.get("DEMO_INTERNAL_ORIGINS", {}).get(origin, origin)
    try:
        upstream = requests.get(
            f"{upstream_origin}{path}",
            headers={"X-Websec-Test-Token": _demo_token()},
            timeout=STATE_POLL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {
            "error": "victim_unreachable",
            "detail": f"cannot reach {origin}: {exc.__class__.__name__}",
        }, 502
    try:
        payload = upstream.json()
    except ValueError:
        return {"error": "victim_invalid_response"}, 502
    return payload, upstream.status_code


@demo_blueprint.get("/api/state")
def victim_state():  # type: ignore[no-untyped-def]
    """Proxy the victim test-state API so the demo page stays same-origin."""

    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)
    username = (request.args.get("username") or "alice").strip().lower()
    if username not in DEMO_USERS:
        return {"error": "invalid_user", "detail": "demo tracks lab users only"}, 400
    payload, status = _proxy_victim_api(f"/api/test/state/{username}")
    return jsonify(payload), status


@demo_blueprint.post("/api/reset")
def victim_reset():  # type: ignore[no-untyped-def]
    """One-click clean slate before repeating the demo."""

    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)
    origin = (request.args.get("origin") or "").strip().rstrip("/")
    if origin not in _allowed_origins():
        return {"error": "invalid_origin"}, 400
    upstream_origin = current_app.config.get("DEMO_INTERNAL_ORIGINS", {}).get(origin, origin)
    try:
        upstream = requests.post(
            f"{upstream_origin}/api/test/reset",
            headers={"X-Websec-Test-Token": _demo_token()},
            timeout=STATE_POLL_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        return {"error": "victim_unreachable", "detail": str(exc)}, 502
    return jsonify({"status": "reset", "victim_status": upstream.status_code})


@demo_blueprint.route("/api/defense", methods=["GET", "POST"])
def victim_defense():  # type: ignore[no-untyped-def]
    """Proxy the victim's defense hot-swap endpoint (no terminal needed).

    GET  returns the active profile name; POST {"profile": "..."} swaps it.
    """

    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)
    origin = (request.args.get("origin") or "").strip().rstrip("/")
    if origin not in _allowed_origins():
        return {"error": "invalid_origin"}, 400
    upstream_origin = current_app.config.get("DEMO_INTERNAL_ORIGINS", {}).get(origin, origin)
    try:
        if request.method == "POST":
            upstream = requests.post(
                f"{upstream_origin}/api/test/defense",
                json=request.get_json(silent=True) or {},
                headers={"X-Websec-Test-Token": _demo_token()},
                timeout=STATE_POLL_TIMEOUT_SECONDS,
            )
        else:
            # Pass the ancestor through so the victim can answer "would this
            # profile block that origin?" instead of only naming the profile.
            upstream = requests.get(
                f"{upstream_origin}/api/test/defense",
                params={"ancestor": request.args.get("ancestor", "")},
                headers={"X-Websec-Test-Token": _demo_token()},
                timeout=STATE_POLL_TIMEOUT_SECONDS,
            )
    except requests.RequestException as exc:
        return {"error": "victim_unreachable", "detail": str(exc)}, 502
    try:
        payload = upstream.json()
    except ValueError:
        return {"error": "victim_invalid_response"}, 502
    return jsonify(payload), upstream.status_code


def init_demo_config(app):  # type: ignore[no-untyped-def]
    """Attach demo-specific config defaults before the app serves requests."""

    app.config.setdefault("DEMO_STATE_TOKEN", os.getenv("WEBSEC_TEST_API_TOKEN", "local-lab-only"))
    return app
