"""Auditor application factory (M6: static analysis, M7: probe harness)."""

from __future__ import annotations

from flask import Flask

from websec_lab.auditor.audit_console import console_blueprint
from websec_lab.auditor.dynamic.probe_routes import probe_blueprint
from websec_lab.auditor.routes import analyzer_blueprint
from websec_lab.config import LabSettings
from websec_lab.web import create_service_app


def create_app(
    settings: LabSettings | None = None,
    test_config: dict[str, object] | None = None,
) -> Flask:
    """Create the auditor service: shared shell + analyzer API + probe harness."""

    app = create_service_app("auditor", settings=settings)
    if test_config:
        app.config.update(test_config)
    app.register_blueprint(analyzer_blueprint)
    app.register_blueprint(probe_blueprint)
    app.register_blueprint(console_blueprint)
    return app
