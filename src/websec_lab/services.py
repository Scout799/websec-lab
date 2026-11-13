"""Service application registry."""

from __future__ import annotations

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from websec_lab.config import LabSettings, load_settings
from websec_lab.web import create_service_app


def _create_app(service_name: str, settings: LabSettings | None = None) -> Flask:
    """Create one of the four registered lab services."""

    if service_name not in {"victim", "attacker", "partner", "auditor"}:
        raise ValueError(f"Unsupported service: {service_name}")
    if service_name == "victim":
        from websec_lab.victim import create_app as create_victim_app

        return create_victim_app(settings=settings)
    if service_name == "attacker":
        from websec_lab.attacker import create_app as create_attacker_app

        return create_attacker_app(settings=settings)
    if service_name == "auditor":
        from websec_lab.auditor import create_app as create_auditor_app

        return create_auditor_app(settings=settings)
    if service_name == "partner":
        from websec_lab.partner import create_app as create_partner_app

        return create_partner_app(settings=settings)
    return create_service_app(service_name, settings=settings)


def create_app(service_name: str, settings: LabSettings | None = None) -> Flask:
    resolved = settings or load_settings()
    app = _create_app(service_name, resolved)
    if resolved.trusted_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    return app
