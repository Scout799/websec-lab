"""Shared Flask application factory used by all lab services."""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask, jsonify, render_template

from websec_lab import __version__
from websec_lab.config import LabSettings, load_settings


def create_service_app(service_name: str, settings: LabSettings | None = None) -> Flask:
    """Create a small service shell with consistent diagnostics."""

    resolved_settings = settings or load_settings()
    service = resolved_settings.service(service_name)

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SERVICE_NAME=service.name,
        SERVICE_DISPLAY_NAME=service.display_name,
        SERVICE_PURPOSE=service.purpose,
        LAB_ENVIRONMENT=resolved_settings.environment,
        LAB_LOCAL_ONLY=resolved_settings.local_only,
    )

    @app.after_request
    def add_baseline_headers(response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/")
    def index():  # type: ignore[no-untyped-def]
        return render_template(
            "index.html",
            project_name=resolved_settings.project_name,
            service=service,
            environment=resolved_settings.environment,
            version=__version__,
        )

    @app.get("/healthz")
    def healthz():  # type: ignore[no-untyped-def]
        return jsonify(
            {
                "status": "ok",
                "service": service.name,
                "version": __version__,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    @app.get("/readyz")
    def readyz():  # type: ignore[no-untyped-def]
        return jsonify(
            {
                "status": "ready",
                "service": service.name,
                "local_only": resolved_settings.local_only,
                "configuration": resolved_settings.source_path.name,
            }
        )

    return app
