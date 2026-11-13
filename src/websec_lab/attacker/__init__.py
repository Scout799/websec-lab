"""Attacker application factory.

The attacker service hosts the clickjacking scenario pages and the
split-screen demo mode. It is a core safety property of this lab that
those pages can only ever be served from a ``local_only`` configuration,
so the factory refuses to start otherwise.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, render_template

from websec_lab.attacker.demo import demo_blueprint, init_demo_config
from websec_lab.attacker.routes import attacker_blueprint
from websec_lab.attacker.runstore import RunStore
from websec_lab.attacker.scenarios import allowed_victim_origins
from websec_lab.config import ConfigurationError, LabSettings, load_settings


def create_app(
    settings: LabSettings | None = None,
    test_config: dict[str, object] | None = None,
) -> Flask:
    """Create the local-only attacker application."""

    resolved_settings = settings or load_settings()
    if not resolved_settings.local_only:
        raise ConfigurationError(
            "The attacker application can only run in a local_only lab environment."
        )

    service = resolved_settings.service("attacker")
    victim = resolved_settings.service("victim")
    package_root = Path(__file__).resolve().parents[1]

    app = Flask(
        __name__,
        template_folder=str(package_root / "templates"),
        static_folder=str(package_root / "static"),
    )
    # The demo proxies victim state server-side, so every origin the demo may
    # embed must resolve to the address the victim actually listens on. Both
    # loopback aliases are mapped: the page may be opened as either one, and
    # `localhost` can resolve to ::1 where the dev server does not listen.
    demo_internal_origins = {
        f"http://{host}:{victim.port}": f"http://127.0.0.1:{victim.port}"
        for host in ("127.0.0.1", "localhost")
    }
    if resolved_settings.trusted_proxy:
        demo_internal_origins[victim.public_origin] = f"http://127.0.0.1:{victim.port}"

    app.config.update(
        SERVICE_NAME=service.name,
        SERVICE_DISPLAY_NAME=service.display_name,
        SERVICE_PURPOSE=service.purpose,
        LAB_ENVIRONMENT=resolved_settings.environment,
        LAB_LOCAL_ONLY=resolved_settings.local_only,
        ATTACKER_VICTIM_ORIGINS=allowed_victim_origins(victim.public_origin, victim.port),
        ATTACKER_REPORT_TOKEN=os.getenv("WEBSEC_TEST_API_TOKEN", "local-lab-only"),
        RUN_JOURNAL_PATH=str(resolved_settings.artifact_dir / "attacker" / "runs.jsonl"),
        DEMO_INTERNAL_ORIGINS=demo_internal_origins,
    )
    if test_config:
        app.config.update(test_config)

    journal_path = Path(str(app.config["RUN_JOURNAL_PATH"]))
    if not journal_path.is_absolute():
        journal_path = resolved_settings.source_path.parents[1] / journal_path
    app.extensions["websec_attacker_runs"] = RunStore(journal_path=journal_path)

    @app.after_request
    def add_baseline_headers(response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.register_blueprint(attacker_blueprint)
    app.register_blueprint(demo_blueprint)
    init_demo_config(app)

    @app.get("/cookie-lab")
    def cookie_lab():
        return render_template("attacker/cookie_lab.html", victim_origin=victim.public_origin)

    from websec_lab.auditor.dynamic.probe_routes import probe_blueprint

    app.register_blueprint(probe_blueprint)
    from websec_lab.attacker.window_lab import window_blueprint

    app.register_blueprint(window_blueprint)
    return app
