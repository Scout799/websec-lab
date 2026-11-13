"""Response-header snapshot tests for the M5 defense profiles."""

import pytest
from flask.testing import FlaskClient

ENFORCING_CSP = "Content-Security-Policy"
REPORTING_CSP = "Content-Security-Policy-Report-Only"


def _login_page(victim_factory, profile: str) -> FlaskClient:
    app = victim_factory(profile)
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    return response


@pytest.mark.parametrize(
    ("profile", "xfo", "csp"),
    [
        ("none", None, None),
        ("xfo-deny", "DENY", None),
        ("xfo-sameorigin", "SAMEORIGIN", None),
        ("csp-none", None, "frame-ancestors 'none'"),
        ("csp-self", None, "frame-ancestors 'self'"),
        (
            "csp-partner-allowlist",
            None,
            # The `partner` token is expanded from lab.yaml at app startup:
            # public origin (loopback in the default config) + localhost twin.
            "frame-ancestors 'self' http://127.0.0.1:5300 http://localhost:5300",
        ),
        (
            "xfo-csp-consistent",
            "SAMEORIGIN",
            "frame-ancestors 'self'",
        ),
        (
            "xfo-csp-conflict",
            "DENY",
            "frame-ancestors http://attacker.test:5200 https://same.victim.test:8443",
        ),
    ],
)
def test_header_snapshots(victim_factory, profile: str, xfo: str | None, csp: str | None) -> None:
    response = _login_page(victim_factory, profile)

    if xfo is None:
        assert response.headers.getlist("X-Frame-Options") == []
    else:
        assert response.headers.getlist("X-Frame-Options") == [xfo]

    if csp is None:
        assert response.headers.getlist(ENFORCING_CSP) == []
    else:
        assert response.headers.getlist(ENFORCING_CSP) == [csp]


def test_headers_apply_to_every_response(victim_factory) -> None:
    app = victim_factory("xfo-deny")
    client = app.test_client()

    for path in ("/login", "/healthz", "/api/test/state/alice"):
        response = client.get(path, headers={"X-Websec-Test-Token": "test-token"})
        assert response.headers.get("X-Frame-Options") == "DENY", path


def test_report_only_uses_report_header(victim_factory) -> None:
    response = _login_page(victim_factory, "csp-report-only")

    assert response.headers.getlist(REPORTING_CSP) == ["frame-ancestors 'none'"]
    assert response.headers.getlist(ENFORCING_CSP) == []


def test_duplicate_xfo_profile_emits_two_headers(victim_factory) -> None:
    response = _login_page(victim_factory, "broken-duplicate-xfo")

    assert response.headers.getlist("X-Frame-Options") == ["SAMEORIGIN", "SAMEORIGIN"]


def test_invalid_xfo_value_is_passed_through_verbatim(victim_factory) -> None:
    response = _login_page(victim_factory, "broken-invalid-xfo")

    assert response.headers.get("X-Frame-Options") == "ALLOW-FROM http://partner.test:5300"


def test_wide_csp_wildcard_is_passed_through(victim_factory) -> None:
    response = _login_page(victim_factory, "broken-wide-csp")

    assert response.headers.getlist(ENFORCING_CSP) == ["frame-ancestors *"]


def test_duplicate_csp_profile_emits_two_policies(victim_factory) -> None:
    response = _login_page(victim_factory, "broken-duplicate-csp")

    assert response.headers.getlist(ENFORCING_CSP) == [
        "frame-ancestors 'none'",
        "frame-ancestors 'self' http://partner.test:5300",
    ]


def test_coop_profile_sets_opener_policy(victim_factory) -> None:
    response = _login_page(victim_factory, "coop-same-origin")

    assert response.headers.get("Cross-Origin-Opener-Policy") == "same-origin"


def test_baseline_headers_are_not_regressed(victim_factory) -> None:
    response = _login_page(victim_factory, "xfo-deny")

    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("Cache-Control") == "no-store"
