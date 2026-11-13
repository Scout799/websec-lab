"""Tests for the M4 legitimate-embedding scenario (partner + victim component)."""

from flask import Flask
from flask.testing import FlaskClient

from websec_lab.config import load_settings
from websec_lab.partner import create_app as create_partner_app


def test_partner_wallet_embeds_victim_component(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    settings = replace(load_settings())
    app = create_partner_app(settings=settings, test_config={"TESTING": True})
    client = app.test_client()

    wallet = client.get("/wallet")
    body = wallet.get_data(as_text=True)

    assert wallet.status_code == 200
    assert 'id="bank-component"' in body
    assert 'src="http://127.0.0.1:5100/embed/profile-card"' in body


def test_partner_wallet_honors_victim_origin_override(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_partner_app(
        test_config={"TESTING": True, "WALLET_VICTIM_ORIGIN": "http://127.0.0.1:9911"}
    )
    body = app.test_client().get("/wallet").get_data(as_text=True)

    assert 'src="http://127.0.0.1:9911/embed/profile-card"' in body


def test_embed_component_requires_login(victim_client: FlaskClient) -> None:
    response = victim_client.get("/embed/profile-card")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_embed_component_shows_readonly_summary(login, victim_client: FlaskClient) -> None:
    login()
    victim_client.post("/lab/quick-transfer")

    response = victim_client.get("/embed/profile-card")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'data-embed="profile-card"' in body
    assert "alice" in body
    assert "¥998.77" in body
    # A legitimate component must not carry actionable controls.
    assert "<form" not in body
    assert "<button" not in body


def test_embed_component_hidden_outside_local_only(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from dataclasses import replace

    from websec_lab.extensions import db
    from websec_lab.victim import create_app as create_victim_app
    from websec_lab.victim.services import seed_lab_data

    settings = replace(load_settings(), database_path=tmp_path / "off.sqlite3")
    app = create_victim_app(
        settings=settings,
        test_config={
            "TESTING": True,
            "SECRET_KEY": "s",
            "LAB_LOCAL_ONLY": False,
            "WTF_CSRF_ENABLED": False,
        },
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()
    client = app.test_client()
    client.post("/login", data={"username": "alice", "password": "alice-lab"})

    assert client.get("/embed/profile-card").status_code == 404

    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_allowlist_header_includes_configured_partner_origin(victim_factory) -> None:  # type: ignore[no-untyped-def]
    app: Flask = victim_factory("csp-partner-allowlist")
    response = app.test_client().get("/login")

    header = response.headers.get("Content-Security-Policy", "")
    assert "'self'" in header
    assert "http://127.0.0.1:5300" in header
    assert "http://localhost:5300" in header
    # The attacker origin must stay absent.
    assert "attacker" not in header
