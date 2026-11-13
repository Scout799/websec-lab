"""Tests for the split-screen demo mode (attacker /demo)."""

from types import SimpleNamespace

import pytest
from flask.testing import FlaskClient

from websec_lab.attacker import demo as demo_module


def test_demo_index_lists_entry_point(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/demo/")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert "分屏演示模式" in body
    assert "开始经典演示" in body


def test_cursor_demo_renders_as_a_standalone_example(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/demo/cursor")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'id="cursor-decoy"' in body
    assert 'id="cursor-target"' in body
    assert "光标劫持" in body
    assert "cursor: none + 假光标 + 固定位移" in body


def test_cursor_demo_is_not_part_of_the_scenario_registry(attacker_client: FlaskClient) -> None:
    """It is a perception demo, so it must not turn seven scenarios into eight."""

    page = attacker_client.get("/demo/")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert "cursorjacking" in body or "光标劫持" in body


def test_demo_classic_renders_split_screen(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/demo/classic", base_url="http://127.0.0.1:5200")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'id="decoy-button"' in body
    assert 'src="http://127.0.0.1:5100/lab/quick-transfer' in body
    assert 'id="victim-frame"' in body
    assert "事件解说" in body
    assert "受害者账户实况" in body
    assert "透视：关" in body
    assert "重置演示数据" in body


def test_demo_classic_keeps_the_loopback_alias_it_was_opened_with(
    attacker_client: FlaskClient,
) -> None:
    """A localhost page must embed a localhost victim.

    Cookies are host-scoped: mixing localhost:5200 with an iframe on
    127.0.0.1:5100 drops the victim session inside the iframe, so the login
    form there answers 400 "CSRF session token is missing".
    """

    page = attacker_client.get("/demo/classic", base_url="http://localhost:5200")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'src="http://localhost:5100/lab/quick-transfer' in body
    assert 'href="http://localhost:5100/login?next=' in body
    assert "127.0.0.1:5100" not in body


def test_demo_login_link_keeps_current_demo_state(attacker_client: FlaskClient) -> None:
    page = attacker_client.get(
        "/demo/classic?debug=1&opacity=0.5", base_url="http://127.0.0.1:5200"
    )
    body = page.get_data(as_text=True)

    assert "debug%3D1" in body
    assert "opacity%3D0.5" in body


def test_demo_classic_rejects_foreign_origin(attacker_client: FlaskClient) -> None:
    response = attacker_client.get("/demo/classic", query_string={"origin": "https://evil.example"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_demo_params"


def test_demo_state_rejects_unknown_user(attacker_client: FlaskClient) -> None:
    response = attacker_client.get(
        "/demo/api/state", query_string={"origin": "http://127.0.0.1:5100", "username": "root"}
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_user"


def test_demo_state_rejects_foreign_origin(attacker_client: FlaskClient) -> None:
    response = attacker_client.get(
        "/demo/api/state", query_string={"origin": "http://192.168.1.5:5100", "username": "alice"}
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_origin"


def test_demo_state_reports_unreachable_victim(
    attacker_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic: simulate the upstream connection failing instead of
    # relying on port 5100 being unused (a live lab victim breaks that).
    def failing_get(url, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        raise demo_module.requests.ConnectionError("connection refused")

    monkeypatch.setattr(demo_module.requests, "get", failing_get)
    response = attacker_client.get(
        "/demo/api/state", query_string={"origin": "http://127.0.0.1:5100", "username": "alice"}
    )
    assert response.status_code == 502
    assert response.get_json()["error"] == "victim_unreachable"


class _FakeUpstream:
    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.url = ""
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._payload


def test_demo_state_proxies_victim_payload(
    attacker_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_get(url, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        return _FakeUpstream(payload={"account": {"balance_cents": 99000}})

    monkeypatch.setattr(demo_module.requests, "get", fake_get)
    response = attacker_client.get(
        "/demo/api/state", query_string={"origin": "http://127.0.0.1:5100", "username": "alice"}
    )

    assert response.status_code == 200
    assert response.get_json() == {"account": {"balance_cents": 99000}}
    assert captured["url"] == "http://127.0.0.1:5100/api/test/state/alice"
    assert captured["headers"]["X-Websec-Test-Token"] == "local-lab-only"


def test_demo_reset_proxies_victim(
    attacker_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        captured["url"] = url
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(demo_module.requests, "post", fake_post)
    response = attacker_client.post(
        "/demo/api/reset", query_string={"origin": "http://localhost:5100"}
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "reset"
    # The page may be opened as localhost, but the server-side proxy always
    # dials the address the victim listens on so an IPv6-only localhost can
    # never turn the demo into "victim unreachable".
    assert captured["url"] == "http://127.0.0.1:5100/api/test/reset"


def test_demo_reset_rejects_foreign_origin(attacker_client: FlaskClient) -> None:
    response = attacker_client.post(
        "/demo/api/reset", query_string={"origin": "http://x.example:1"}
    )
    assert response.status_code == 400
