import pytest

from websec_lab.services import create_app


@pytest.mark.parametrize("service_name", ["attacker", "auditor"])
def test_service_homepage_and_health_endpoints(service_name: str) -> None:
    app = create_app(service_name)
    app.config.update(TESTING=True)

    with app.test_client() as client:
        homepage = client.get("/")
        health = client.get("/healthz")
        readiness = client.get("/readyz")

    assert homepage.status_code == 200
    assert service_name.encode() in homepage.data.lower()
    assert homepage.headers["X-Content-Type-Options"] == "nosniff"
    assert health.status_code == 200
    assert health.get_json()["service"] == service_name
    assert health.get_json()["status"] == "ok"
    assert readiness.get_json()["status"] == "ready"
    assert readiness.get_json()["local_only"] is True


def test_partner_service_pages_and_health() -> None:
    app = create_app("partner")
    app.config.update(TESTING=True)

    with app.test_client() as client:
        home = client.get("/")
        wallet = client.get("/wallet")
        health = client.get("/healthz")
        readiness = client.get("/readyz")

    assert home.status_code == 200
    assert "惠生活服务" in home.get_data(as_text=True)

    wallet_body = wallet.get_data(as_text=True)
    assert wallet.status_code == 200
    assert 'id="bank-component"' in wallet_body
    assert "/embed/profile-card" in wallet_body

    assert health.get_json()["service"] == "partner"
    assert readiness.get_json()["status"] == "ready"
    assert readiness.get_json()["local_only"] is True


def test_unknown_service_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported service"):
        create_app("unknown")
