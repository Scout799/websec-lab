import itertools
from dataclasses import replace
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app
from websec_lab.victim.services import seed_lab_data


@pytest.fixture
def victim_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Create victim apps under a chosen defense profile with isolated DBs."""

    counter = itertools.count()
    created: list[Flask] = []

    def make(profile: str = "none", local_only: bool | None = None) -> Flask:
        settings = replace(
            load_settings(),
            database_path=tmp_path / f"victim-{profile}-{next(counter)}.sqlite3",
        )
        test_config: dict[str, object] = {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "TEST_API_TOKEN": "test-token",
            "WTF_CSRF_ENABLED": False,
            "DEFENSE_PROFILE": profile,
        }
        if local_only is not None:
            test_config["LAB_LOCAL_ONLY"] = local_only
        app = create_app(settings=settings, test_config=test_config)
        with app.app_context():
            db.create_all()
            seed_lab_data()
        created.append(app)
        return app

    yield make

    for app in created:
        with app.app_context():
            db.session.remove()
            db.drop_all()


@pytest.fixture
def victim_app(victim_factory) -> Flask:
    return victim_factory("none")


@pytest.fixture
def victim_client(victim_app: Flask) -> FlaskClient:
    return victim_app.test_client()


@pytest.fixture
def login(victim_client: FlaskClient):  # type: ignore[no-untyped-def]
    def perform(username: str = "alice", password: str = "alice-lab"):
        return victim_client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    return perform


@pytest.fixture
def attacker_app(tmp_path: Path) -> Flask:
    from websec_lab.attacker import create_app as create_attacker_app

    settings = replace(load_settings(), local_only=True, artifact_dir=tmp_path / "artifacts")
    return create_attacker_app(
        settings=settings,
        test_config={
            "TESTING": True,
            "ATTACKER_REPORT_TOKEN": "test-token",
            "RUN_JOURNAL_PATH": tmp_path / "artifacts" / "attacker" / "runs.jsonl",
        },
    )


@pytest.fixture
def attacker_client(attacker_app: Flask) -> FlaskClient:
    return attacker_app.test_client()
