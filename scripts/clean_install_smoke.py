"""Exercise the installed wheel's resources with isolated, disposable storage."""

import json
import tempfile
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path

from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.services import create_app
from websec_lab.victim.services import seed_lab_data


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix="websec-install-") as tmp:
        root = Path(tmp)
        settings = replace(
            load_settings(),
            database_path=root / "test.sqlite3",
            artifact_dir=root / "artifacts",
            log_dir=root / "logs",
        )
        for service, route in [
            ("victim", "/login"),
            ("attacker", "/"),
            ("partner", "/payment"),
            ("auditor", "/"),
        ]:
            app = create_app(service, settings)
            if service == "victim":
                with app.app_context():
                    db.create_all()
                    seed_lab_data()
            response = app.test_client().get(route)
            assert response.status_code == 200, (service, response.status_code)
            assert b"<!doctype html>" in response.data.lower()
            assert app.test_client().get("/healthz").status_code == 200
            checks.append({"service": service, "route": route, "status": 200})
            if service == "victim":
                with app.app_context():
                    db.session.remove()
                    db.engine.dispose()
    print(
        json.dumps(
            {
                "installed_version": version("websec-clickjacking-lab"),
                "checks": checks,
                "passed": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
