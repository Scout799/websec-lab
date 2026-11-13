"""Victim application factory."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, current_app
from flask_wtf.csrf import CSRFError

from websec_lab.config import LabSettings, load_settings
from websec_lab.defense import DefenseProfile, expand_partner_origins, resolve_active_profile
from websec_lab.extensions import csrf, db, login_manager, migrate
from websec_lab.victim.embed_routes import embed_blueprint
from websec_lab.victim.lab_routes import lab_blueprint
from websec_lab.victim.models import User
from websec_lab.victim.routes import victim_blueprint
from websec_lab.victim.test_api import test_api_blueprint


def _apply_defense_headers(response, profile: DefenseProfile):  # type: ignore[no-untyped-def]
    if profile.xfo:
        response.headers.set("X-Frame-Options", profile.xfo)
    for extra in profile.xfo_extra:
        response.headers.add("X-Frame-Options", extra)

    csp_value = profile.csp_header_value()
    if csp_value is not None:
        response.headers.set(profile.csp_header_name(), csp_value)
    for raw in profile.csp_extra_raw:
        response.headers.add(profile.csp_header_name(), raw)

    if profile.coop:
        response.headers.set("Cross-Origin-Opener-Policy", profile.coop)
    return response


def create_app(
    settings: LabSettings | None = None,
    test_config: dict[str, object] | None = None,
) -> Flask:
    """Create the stateful victim web application."""

    resolved_settings = settings or load_settings()
    service = resolved_settings.service("victim")
    package_root = Path(__file__).resolve().parents[1]

    resolved_settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    resolved_settings.log_dir.mkdir(parents=True, exist_ok=True)

    profile_override = None
    if test_config and "DEFENSE_PROFILE" in test_config:
        profile_override = str(test_config["DEFENSE_PROFILE"])
        test_config = {k: v for k, v in test_config.items() if k != "DEFENSE_PROFILE"}
    defense = resolve_active_profile(override=profile_override)

    # T0507: expand the `partner` source token into the concrete partner
    # origins declared by lab.yaml, so the allowlist follows the environment.
    partner_service = resolved_settings.service("partner")
    partner_embed_origins = [
        partner_service.public_origin.rstrip("/"),
        f"http://127.0.0.1:{partner_service.port}",
        f"http://localhost:{partner_service.port}",
    ]
    defense = expand_partner_origins(defense, partner_embed_origins)

    app = Flask(
        __name__,
        template_folder=str(package_root / "templates"),
        static_folder=str(package_root / "static"),
    )
    app.config.update(
        SECRET_KEY=os.getenv("WEBSEC_SECRET_KEY", "local-lab-secret-change-me"),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{resolved_settings.database_path.as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SERVICE_NAME=service.name,
        SERVICE_DISPLAY_NAME=service.display_name,
        SERVICE_PURPOSE=service.purpose,
        LAB_ENVIRONMENT=resolved_settings.environment,
        LAB_LOCAL_ONLY=resolved_settings.local_only,
        TEST_API_TOKEN=os.getenv("WEBSEC_TEST_API_TOKEN", "local-lab-only"),
        SESSION_COOKIE_NAME="websec_victim_session",
        SESSION_COOKIE_HTTPONLY=defense.cookie_httponly,
        SESSION_COOKIE_SAMESITE=defense.cookie_samesite,
        SESSION_COOKIE_SECURE=defense.cookie_secure,
        WTF_CSRF_TIME_LIMIT=None,
        DEFENSE=defense,
        PARTNER_EMBED_ORIGINS=partner_embed_origins,
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    migrate.init_app(
        app, db, directory=str(resolved_settings.source_path.parents[1] / "migrations")
    )
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "victim.login"
    login_manager.login_message = "请先登录测试账户。"
    login_manager.login_message_category = "warning"

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):  # type: ignore[no-untyped-def]
        """Explain a rejected login instead of showing a bare "Bad Request".

        The demo renders the victim login page inside an iframe, so that copy
        can go stale after the user logs in elsewhere, and a browser that
        withholds the session cookie leaves the form without its token. The
        submission is still rejected — the status stays 400 — but the presenter
        sees the login form plus the reason rather than an opaque error page.
        """

        from flask import flash, render_template, request

        from websec_lab.victim.forms import LoginForm

        if request.endpoint == "victim.login":
            flash("登录页已过期（浏览器没有带回会话 cookie），请重新打开登录页再试。", "error")
            return render_template("victim/login.html", form=LoginForm()), 400
        return error.get_response()

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        if not user_id.isdigit():
            return None
        return db.session.get(User, int(user_id))

    @app.after_request
    def add_baseline_headers(response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Referrer-Policy", "same-origin" if resolved_settings.trusted_proxy else "no-referrer"
        )
        response.headers.setdefault("Cache-Control", "no-store")
        response = _apply_defense_headers(response, current_app.config["DEFENSE"])
        if app.config["LAB_LOCAL_ONLY"]:
            from flask import request

            from websec_lab.victim.telemetry import RUN_PATTERN

            run = request.args.get("lab_run", "")
            if RUN_PATTERN.fullmatch(run):
                for header in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
                    values = response.headers.getlist(header)
                    if values:
                        response.headers.set(
                            header, values[0] + f"; report-uri /telemetry/csp?run_id={run}"
                        )
                        for value in values[1:]:
                            response.headers.add(header, value)
            if response.mimetype == "text/html" and response.status_code == 200:
                body = response.get_data(as_text=True)
                response.set_data(
                    body.replace("</body>", '<script src="/telemetry/client.js"></script></body>')
                )
        return response

    app.register_blueprint(victim_blueprint)
    app.register_blueprint(lab_blueprint)
    app.register_blueprint(embed_blueprint)
    app.register_blueprint(test_api_blueprint)
    csrf.exempt(test_api_blueprint)
    if app.config["LAB_LOCAL_ONLY"]:
        from websec_lab.auditor.dynamic.probe_routes import probe_blueprint
        from websec_lab.victim.cookie_probe import cookie_probe_blueprint
        from websec_lab.victim.telemetry import SignalStore, telemetry_blueprint

        app.register_blueprint(cookie_probe_blueprint)
        app.register_blueprint(probe_blueprint)
        app.register_blueprint(telemetry_blueprint)
        app.extensions["signal_store"] = SignalStore()
        csrf.exempt(telemetry_blueprint)
    return app
