"""Set-Cookie attribute tests for the M5 cookie defense profiles."""

import pytest


def _session_cookie(victim_factory, profile: str) -> str:
    app = victim_factory(profile)
    client = app.test_client()
    response = client.post("/login", data={"username": "alice", "password": "alice-lab"})
    assert response.status_code == 302

    cookies = [
        header
        for header in response.headers.getlist("Set-Cookie")
        if header.startswith("websec_victim_session=")
    ]
    assert len(cookies) == 1
    return cookies[0]


@pytest.mark.parametrize(
    ("profile", "samesite", "secure"),
    [
        ("none", "Lax", False),
        ("xfo-deny", "Lax", False),
        ("samesite-strict", "Strict", False),
        ("samesite-none", "None", False),
        ("cookie-hardened", "Strict", True),
    ],
)
def test_cookie_attributes_follow_profile(
    victim_factory, profile: str, samesite: str, secure: bool
) -> None:
    cookie = _session_cookie(victim_factory, profile)

    assert f"SameSite={samesite}" in cookie
    assert "HttpOnly" in cookie
    if secure:
        assert "Secure" in cookie
    else:
        assert "Secure" not in cookie


def test_httponly_always_enforced(victim_factory) -> None:
    for profile in ("none", "cookie-hardened", "samesite-none"):
        cookie = _session_cookie(victim_factory, profile)
        assert "HttpOnly" in cookie, profile
