from dataclasses import replace

from flask import Flask
from flask.testing import FlaskClient

from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.models import AuditLog
from websec_lab.victim.services import seed_lab_data

TEST_TOKEN_HEADERS = {"X-Websec-Test-Token": "test-token"}


def _state(client: FlaskClient, username: str = "alice") -> dict:
    response = client.get(f"/api/test/state/{username}", headers=TEST_TOKEN_HEADERS)
    assert response.status_code == 200
    return response.get_json()


def test_quick_transfer_requires_login(victim_client: FlaskClient) -> None:
    response = victim_client.get("/lab/quick-transfer")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_quick_transfer_confirmation_page(login, victim_client: FlaskClient) -> None:
    login()
    page = victim_client.get("/lab/quick-transfer")

    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "确认转账" in body
    assert "¥1.23" in body
    assert "收款账户：bob" in body
    assert 'data-quick-page="transfer"' in body


def test_quick_transfer_post_executes_transfer(login, victim_client: FlaskClient) -> None:
    login()
    response = victim_client.post("/lab/quick-transfer")

    assert response.status_code == 200
    assert "转账已完成 #1" in response.get_data(as_text=True)

    state = _state(victim_client)
    assert state["account"]["balance_cents"] == 100_000 - 123
    assert len(state["transfers"]) == 1
    assert state["transfers"][0]["amount_cents"] == 123
    assert state["transfers"][0]["recipient"] == "bob"


def test_quick_transfer_records_the_attacker_technique_tag(
    login, victim_client: FlaskClient
) -> None:
    """Each scenario tags its transfer so the ledger names the technique."""

    login()
    victim_client.post("/lab/quick-transfer?amount_cents=555&note=S5%20frame-busting")

    state = _state(victim_client)
    assert state["transfers"][0]["amount_cents"] == 555
    assert state["transfers"][0]["note"] == "S5 frame-busting"


def test_quick_transfer_ignores_a_malformed_technique_tag(
    login, victim_client: FlaskClient
) -> None:
    login()
    victim_client.post("/lab/quick-transfer?note=%3Cscript%3Ealert(1)%3C%2Fscript%3E")

    state = _state(victim_client)
    assert state["transfers"][0]["note"] == "快捷转账实验"


def test_quick_transfer_records_lab_audit(
    login, victim_client: FlaskClient, victim_app: Flask
) -> None:
    login()
    victim_client.post("/lab/quick-transfer")

    with victim_app.app_context():
        actions = db.session.scalars(
            db.select(AuditLog.action).where(AuditLog.action == "lab.quick_transfer.executed")
        ).all()
    assert actions == ["lab.quick_transfer.executed"]


def test_quick_transfer_amount_is_clamped_to_maximum(login, victim_client: FlaskClient) -> None:
    login()
    response = victim_client.post("/lab/quick-transfer?amount_cents=999999")

    assert response.status_code == 200
    state = _state(victim_client)
    assert state["transfers"][0]["amount_cents"] == 50_000
    assert state["account"]["balance_cents"] == 100_000 - 50_000


def test_quick_transfer_minimum_amount_is_one_cent(login, victim_client: FlaskClient) -> None:
    login()
    victim_client.post("/lab/quick-transfer?amount_cents=0")

    state = _state(victim_client)
    assert state["transfers"][0]["amount_cents"] == 1


def test_quick_transfer_self_recipient_falls_back_to_bob(login, victim_client: FlaskClient) -> None:
    login()
    page = victim_client.get("/lab/quick-transfer?recipient=alice")

    assert "收款账户：bob" in page.get_data(as_text=True)


def test_quick_transfer_default_recipient_avoids_current_user(victim_client: FlaskClient) -> None:
    victim_client.post("/login", data={"username": "bob", "password": "bob-lab"})

    page = victim_client.get("/lab/quick-transfer")

    assert "收款账户：merchant" in page.get_data(as_text=True)


def test_quick_transfer_insufficient_balance_keeps_form(victim_client: FlaskClient) -> None:
    victim_client.post("/login", data={"username": "bob", "password": "bob-lab"})
    response = victim_client.post(
        "/lab/quick-transfer?recipient=merchant&amount_cents=50000", follow_redirects=True
    )

    body = response.get_data(as_text=True)
    assert "余额不足" in body
    assert "确认转账" in body
    assert "转账已完成" not in body
    state = _state(victim_client, "bob")
    assert state["transfers"] == []
    assert state["account"]["balance_cents"] == 25_000


def test_quick_grant_post_creates_authorization(login, victim_client: FlaskClient) -> None:
    login()
    response = victim_client.post("/lab/quick-grant")

    assert response.status_code == 200
    assert "已授权 #1" in response.get_data(as_text=True)

    state = _state(victim_client)
    assert len(state["grants"]) == 1
    assert state["grants"][0]["active"] is True
    assert state["grants"][0]["client_name"] == "Lab Partner Demo"


def test_lab_pages_hidden_outside_local_only(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = replace(load_settings(), database_path=tmp_path / "lab-off.sqlite3")
    app = create_victim_app(
        settings=settings,
        test_config={
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "LAB_LOCAL_ONLY": False,
            "WTF_CSRF_ENABLED": False,
        },
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()

    client = app.test_client()
    client.post("/login", data={"username": "alice", "password": "alice-lab"})

    assert client.get("/lab/quick-transfer").status_code == 404
    assert client.get("/lab/quick-grant").status_code == 404

    with app.app_context():
        db.session.remove()
        db.drop_all()
