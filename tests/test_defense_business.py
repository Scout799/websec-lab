"""Business-layer defense tests: reconfirm, one-time token, reauth, busting."""

import re
import time

from flask.testing import FlaskClient

TEST_TOKEN_HEADERS = {"X-Websec-Test-Token": "test-token"}
TOKEN_PATTERN = re.compile(r'name="confirm_token" value="([0-9a-f]+)"')


def _client(victim_factory, profile: str) -> FlaskClient:
    client = victim_factory(profile).test_client()
    response = client.post("/login", data={"username": "alice", "password": "alice-lab"})
    assert response.status_code == 302
    return client


def _state(client: FlaskClient) -> dict:
    response = client.get("/api/test/state/alice", headers=TEST_TOKEN_HEADERS)
    return response.get_json()


# ---- reconfirm (T0510) ----


def test_reconfirm_shows_details_before_confirm(victim_factory) -> None:
    client = _client(victim_factory, "confirm-reconfirm")

    details = client.get("/lab/quick-transfer")
    body = details.get_data(as_text=True)
    assert "进入确认" in body
    assert 'data-stage="details"' in body
    assert 'name="submit"' not in body

    confirm = client.get("/lab/quick-transfer?stage=2")
    assert 'data-stage="confirm"' in confirm.get_data(as_text=True)
    assert "确认转账" in confirm.get_data(as_text=True)


def test_reconfirm_details_click_does_not_transfer(victim_factory) -> None:
    client = _client(victim_factory, "confirm-reconfirm")

    client.get("/lab/quick-transfer")
    client.get("/lab/quick-transfer?stage=2&recipient=bob&amount_cents=123")

    state = _state(client)
    assert state["transfers"] == []
    assert state["account"]["balance_cents"] == 100_000


def test_reconfirm_normal_user_flow_still_works(victim_factory) -> None:
    client = _client(victim_factory, "confirm-reconfirm")

    response = client.post("/lab/quick-transfer", follow_redirects=True)

    assert "转账已完成 #1" in response.get_data(as_text=True)
    assert _state(client)["account"]["balance_cents"] == 100_000 - 123


# ---- one-time token (T0511) ----


def test_token_flow_single_use(victim_factory) -> None:
    client = _client(victim_factory, "confirm-token")

    page = client.get("/lab/quick-transfer")
    match = TOKEN_PATTERN.search(page.get_data(as_text=True))
    assert match is not None
    token = match.group(1)

    accepted = client.post("/lab/quick-transfer", data={"confirm_token": token})
    assert "转账已完成 #1" in accepted.get_data(as_text=True)

    replay_page = client.get("/lab/quick-transfer")
    replay_token = TOKEN_PATTERN.search(replay_page.get_data(as_text=True)).group(1)

    replayed = client.post("/lab/quick-transfer", data={"confirm_token": replay_token})
    assert "转账已完成 #2" in replayed.get_data(as_text=True)
    assert _state(client)["account"]["balance_cents"] == 100_000 - 246


def test_token_replay_is_rejected(victim_factory) -> None:
    client = _client(victim_factory, "confirm-token")

    page = client.get("/lab/quick-transfer")
    token = TOKEN_PATTERN.search(page.get_data(as_text=True)).group(1)

    client.post("/lab/quick-transfer", data={"confirm_token": token})
    replay = client.post("/lab/quick-transfer", data={"confirm_token": token})

    assert "确认令牌无效或已被使用" in replay.get_data(as_text=True)
    state = _state(client)
    assert len(state["transfers"]) == 1
    assert state["account"]["balance_cents"] == 100_000 - 123


def test_token_missing_is_rejected(victim_factory) -> None:
    client = _client(victim_factory, "confirm-token")

    rejected = client.post("/lab/quick-transfer", data={})

    assert "确认令牌无效或已被使用" in rejected.get_data(as_text=True)
    assert _state(client)["transfers"] == []


def test_no_token_hidden_field_without_profile(victim_factory) -> None:
    client = _client(victim_factory, "none")

    page = client.get("/lab/quick-transfer")

    assert "confirm_token" not in page.get_data(as_text=True)


# ---- reauth (T0512) ----


def test_reauth_gate_redirects_when_stale(victim_factory) -> None:
    client = _client(victim_factory, "reauth")

    with client.session_transaction() as session_state:
        session_state["victim_auth_at"] = time.time() - 10_000

    response = client.get("/lab/quick-transfer")

    assert response.status_code == 302
    assert "/lab/reauth" in response.headers["Location"]
    assert _state(client)["transfers"] == []


def test_reauth_requires_correct_password(victim_factory) -> None:
    client = _client(victim_factory, "reauth")
    with client.session_transaction() as session_state:
        session_state["victim_auth_at"] = time.time() - 10_000

    wrong = client.post(
        "/lab/reauth",
        data={"password": "wrong-password"},
        query_string={"next": "/lab/quick-transfer"},
        follow_redirects=True,
    )
    assert "密码错误" in wrong.get_data(as_text=True)

    ok = client.post(
        "/lab/reauth",
        data={"password": "alice-lab"},
        query_string={"next": "/lab/quick-transfer"},
        follow_redirects=True,
    )
    assert "快捷转账确认" in ok.get_data(as_text=True)
    assert 'data-stage="confirm"' in ok.get_data(as_text=True)


def test_reauth_not_required_within_ttl(victim_factory) -> None:
    client = _client(victim_factory, "reauth")

    response = client.get("/lab/quick-transfer")

    assert response.status_code == 200
    assert 'data-stage="confirm"' in response.get_data(as_text=True)


def test_reauth_next_is_restricted_to_lab_paths(victim_factory) -> None:
    client = _client(victim_factory, "reauth")
    with client.session_transaction() as session_state:
        session_state["victim_auth_at"] = time.time() - 10_000

    response = client.post(
        "/lab/reauth",
        data={"password": "alice-lab"},
        query_string={"next": "https://evil.example/steal"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/lab/")


# ---- hardened combination + frame-busting (T0513/14) ----


def test_hardened_profile_combines_all_business_defenses(victim_factory) -> None:
    client = _client(victim_factory, "business-hardened")

    with client.session_transaction() as session_state:
        session_state["victim_auth_at"] = time.time() - 10_000

    gated = client.get("/lab/quick-transfer")
    assert "/lab/reauth" in gated.headers.get("Location", "")

    client.post(
        "/lab/reauth",
        data={"password": "alice-lab"},
        query_string={"next": "/lab/quick-transfer"},
    )
    details = client.get("/lab/quick-transfer")
    assert 'data-stage="details"' in details.get_data(as_text=True)

    page = client.get("/lab/quick-transfer?stage=2")
    token = TOKEN_PATTERN.search(page.get_data(as_text=True)).group(1)
    accepted = client.post("/lab/quick-transfer", data={"confirm_token": token})

    assert "转账已完成 #1" in accepted.get_data(as_text=True)
    assert _state(client)["account"]["balance_cents"] == 100_000 - 123


def test_frame_busting_snippet_only_present_when_enabled(victim_factory) -> None:
    defended = _client(victim_factory, "frame-busting")
    baseline = _client(victim_factory, "none")

    defended_page = defended.get("/lab/quick-transfer").get_data(as_text=True)
    baseline_page = baseline.get("/lab/quick-transfer").get_data(as_text=True)

    assert "window.top.location" in defended_page
    assert "window.top.location" not in baseline_page


def test_frame_busting_applies_to_main_site_too(victim_factory) -> None:
    client = _client(victim_factory, "frame-busting")

    dashboard = client.get("/dashboard").get_data(as_text=True)

    assert "window.top.location" in dashboard


def test_hidden_busting_snippet_only_present_when_enabled(victim_factory) -> None:
    defended = _client(victim_factory, "frame-busting-hidden")
    baseline = _client(victim_factory, "none")

    body = defended.get("/lab/quick-transfer").get_data(as_text=True)
    assert "display: none" in body
    assert "window.top === window.self" in body
    assert "window.top.location" not in body

    baseline_body = baseline.get("/lab/quick-transfer").get_data(as_text=True)
    assert "display: none" not in baseline_body


def test_grant_page_respects_token_and_reconfirm(victim_factory) -> None:
    client = _client(victim_factory, "confirm-token")

    page = client.get("/lab/quick-grant")
    token = TOKEN_PATTERN.search(page.get_data(as_text=True)).group(1)

    client.post("/lab/quick-grant", data={"confirm_token": token})
    replay = client.post("/lab/quick-grant", data={"confirm_token": token})

    assert "确认令牌无效或已被使用" in replay.get_data(as_text=True)
    state = _state(client)
    assert len(state["grants"]) == 1
