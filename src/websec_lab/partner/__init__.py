"""Partner application factory (M4: legitimate embedding origin).

The partner is an authorized business origin that embeds victim-provided
components — the "compatibility" side of the defense matrix: a correct
CSP allowlist must keep the partner working while blocking the attacker.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template, request

from websec_lab.config import LabSettings, load_settings


def create_app(
    settings: LabSettings | None = None,
    test_config: dict[str, object] | None = None,
) -> Flask:
    """Create the partner application with its embed pages."""

    resolved_settings = settings or load_settings()
    service = resolved_settings.service("partner")
    victim = resolved_settings.service("victim")
    package_root = Path(__file__).resolve().parents[1]

    app = Flask(
        __name__,
        template_folder=str(package_root / "templates"),
        static_folder=str(package_root / "static"),
    )
    app.config.update(
        SERVICE_NAME=service.name,
        SERVICE_DISPLAY_NAME=service.display_name,
        SERVICE_PURPOSE=service.purpose,
        LAB_ENVIRONMENT=resolved_settings.environment,
        LAB_LOCAL_ONLY=resolved_settings.local_only,
        PARTNER_ORIGIN=service.public_origin,
        VICTIM_ORIGIN=victim.public_origin,
        VICTIM_LOOPBACK=f"http://127.0.0.1:{victim.port}",
    )
    if test_config:
        app.config.update(test_config)

    @app.after_request
    def add_baseline_headers(response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/")
    def home():  # type: ignore[no-untyped-def]
        return render_template("partner/home.html")

    @app.get("/wallet")
    def wallet():  # type: ignore[no-untyped-def]
        # The wallet embeds the victim-provided profile component. The victim
        # origin is configurable so tests can point it at an ephemeral port.
        victim_origin = str(app.config.get("WALLET_VICTIM_ORIGIN") or app.config["VICTIM_ORIGIN"])
        return render_template("partner/wallet.html", victim_origin=victim_origin)

    @app.get("/healthz")
    def healthz():  # type: ignore[no-untyped-def]
        from websec_lab import __version__

        return {"status": "ok", "service": "partner", "version": __version__}

    @app.get("/payment")
    def payment():
        from websec_lab.victim.telemetry import RUN_PATTERN

        run = request.args.get("lab_run", "")
        if run and not RUN_PATTERN.fullmatch(run):
            abort(400)
        return render_template(
            "partner/payment.html", victim_origin=app.config["VICTIM_ORIGIN"], lab_run=run
        )

    @app.get("/readyz")
    def readyz():  # type: ignore[no-untyped-def]
        return {
            "status": "ready",
            "service": "partner",
            "local_only": resolved_settings.local_only,
        }

    from websec_lab.auditor.dynamic.probe_routes import probe_blueprint

    app.register_blueprint(probe_blueprint)
    return app
