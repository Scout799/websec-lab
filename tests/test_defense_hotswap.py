"""Tests for runtime defense hot-swap (victim endpoint + demo proxy)."""

from types import SimpleNamespace

import pytest
from flask.testing import FlaskClient

from websec_lab.attacker import demo as demo_module

TEST_TOKEN_HEADERS = {"X-Websec-Test-Token": "test-token"}


def test_hot_swap_changes_headers_without_restart(victim_client: FlaskClient) -> None:
    victim_client.post("/login", data={"username": "alice", "password": "alice-lab"})

    before = victim_client.get("/login")
    assert before.headers.get("X-Frame-Options") is None

    switched = victim_client.post(
        "/api/test/defense",
        json={"profile": "xfo-deny"},
        headers=TEST_TOKEN_HEADERS,
    )
    assert switched.status_code == 200
    assert switched.get_json()["profile"] == "xfo-deny"

    after = victim_client.get("/login")
    assert after.headers.get("X-Frame-Options") == "DENY"

    # Switch back and confirm the header disappears again.
    victim_client.post("/api/test/defense", json={"profile": "none"}, headers=TEST_TOKEN_HEADERS)
    restored = victim_client.get("/login")
    assert restored.headers.get("X-Frame-Options") is None


def test_hot_swap_reports_current_profile(victim_client: FlaskClient) -> None:
    response = victim_client.get("/api/test/defense", headers=TEST_TOKEN_HEADERS)
    assert response.get_json()["profile"] == "none"


def test_defense_endpoint_says_whether_it_blocks_a_given_ancestor(
    victim_client: FlaskClient,
) -> None:
    """Scenario pages ask this before claiming "the click does nothing"."""

    open_profile = victim_client.get(
        "/api/test/defense",
        query_string={"ancestor": "http://127.0.0.1:5200"},
        headers=TEST_TOKEN_HEADERS,
    ).get_json()
    assert open_profile["blocks_framing"] is False

    victim_client.post(
        "/api/test/defense", json={"profile": "xfo-deny"}, headers=TEST_TOKEN_HEADERS
    )
    blocked = victim_client.get(
        "/api/test/defense",
        query_string={"ancestor": "http://127.0.0.1:5200"},
        headers=TEST_TOKEN_HEADERS,
    ).get_json()
    assert blocked["blocks_framing"] is True
    assert "X-Frame-Options" in blocked["block_reason"]

    victim_client.post("/api/test/defense", json={"profile": "none"}, headers=TEST_TOKEN_HEADERS)


def test_allowlist_blocks_attacker_but_allows_partner(victim_client: FlaskClient) -> None:
    """A partner:5300 entry must not be read as "allows 127.0.0.1:5200"."""

    victim_client.post(
        "/api/test/defense", json={"profile": "csp-partner-allowlist"}, headers=TEST_TOKEN_HEADERS
    )

    attacker = victim_client.get(
        "/api/test/defense",
        query_string={"ancestor": "http://127.0.0.1:5200"},
        headers=TEST_TOKEN_HEADERS,
    ).get_json()
    assert attacker["blocks_framing"] is True

    partner = victim_client.get(
        "/api/test/defense",
        query_string={"ancestor": "http://127.0.0.1:5300"},
        headers=TEST_TOKEN_HEADERS,
    ).get_json()
    assert partner["blocks_framing"] is False

    victim_client.post("/api/test/defense", json={"profile": "none"}, headers=TEST_TOKEN_HEADERS)


def test_hot_swap_rejects_unknown_profile(victim_client: FlaskClient) -> None:
    response = victim_client.post(
        "/api/test/defense", json={"profile": "fort-knox"}, headers=TEST_TOKEN_HEADERS
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "unknown_profile"


def test_hot_swap_requires_token(victim_client: FlaskClient) -> None:
    response = victim_client.post("/api/test/defense", json={"profile": "xfo-deny"})
    assert response.status_code == 403


def test_demo_defense_proxy_rejects_foreign_origin(attacker_client: FlaskClient) -> None:
    response = attacker_client.post(
        "/demo/api/defense",
        json={"profile": "xfo-deny"},
        query_string={"origin": "http://x.example:1"},
    )
    assert response.status_code == 400


def test_demo_defense_proxy_passes_through(
    attacker_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["json"] = json
        return SimpleNamespace(
            status_code=200, json=lambda: {"status": "ok", "profile": "xfo-deny"}
        )

    monkeypatch.setattr(demo_module.requests, "post", fake_post)
    response = attacker_client.post(
        "/demo/api/defense",
        json={"profile": "xfo-deny"},
        query_string={"origin": "http://127.0.0.1:5100"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "profile": "xfo-deny"}
    assert captured["url"] == "http://127.0.0.1:5100/api/test/defense"
    assert captured["json"] == {"profile": "xfo-deny"}
