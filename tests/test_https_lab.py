"""Configuration and app-level checks for the separate HTTPS deployment."""

import json
import re
from dataclasses import replace

import pytest

from websec_lab.auditor.origins import parse_origin
from websec_lab.config import load_settings
from websec_lab.experiments.samesite import PROFILES, SameSiteCase, business_effect_matches
from websec_lab.extensions import db
from websec_lab.https_lab import HOSTS, HTTPS_CONFIG, browser_arguments, nginx_configuration
from websec_lab.services import create_app
from websec_lab.victim.services import seed_lab_data


def test_https_configuration_keeps_backends_on_loopback():
    settings = load_settings(HTTPS_CONFIG)
    assert settings.trusted_proxy is True
    assert settings.database_path != load_settings().database_path
    assert all(s.host == "127.0.0.1" for s in settings.services.values())
    assert all(s.public_origin.startswith("https://") for s in settings.services.values())


def test_nginx_hosts_tls_and_private_control_endpoint():
    config = nginx_configuration()
    for host in HOSTS:
        assert host in config
    assert "listen 127.0.0.1:8443 ssl" in config
    assert "ssl_protocols TLSv1.2 TLSv1.3" in config
    assert "proxy_set_header X-Forwarded-Proto https" in config
    assert config.count("location /__lab/ { return 404; }") == 4
    assert "return 421" in config
    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        assert f"{name}_temp_path logs/" in config


def test_browser_arguments_do_not_ignore_tls_errors():
    args = browser_arguments()
    assert any("host-resolver-rules" in arg for arg in args)
    assert all(
        "ignore-certificate" not in arg and "disable-web-security" not in arg for arg in args
    )


def test_schemeful_same_site_and_subdomain_control():
    target = parse_origin("https://victim.test:8443")
    assert target.same_site(parse_origin("https://same.victim.test:8443"))
    assert not target.same_origin(parse_origin("https://same.victim.test:8443"))
    assert not target.same_site(parse_origin("https://attacker.test:8443"))
    assert not target.same_site(parse_origin("http://victim.test:8443"))


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("relation", ["same-site", "cross-site"])
@pytest.mark.parametrize("policy", ["allow", "block"])
def test_samesite_expected_matrix(profile, relation, policy):
    case = SameSiteCase("chrome", profile, relation, policy, 1)
    cookie, secure = PROFILES[profile]
    expected = secure and (relation == "same-site" or (cookie == "None" and policy == "allow"))
    assert case.expected_authenticated is expected
    expected_top_level = secure and (relation == "same-site" or cookie in {"Lax", "None"})
    assert case.expected_top_level_authenticated is expected_top_level


@pytest.mark.parametrize(
    "expected,count_delta,balance_delta,matches",
    [
        (True, 1, -123, True),
        (True, 0, 0, False),
        (False, 0, 0, True),
        (False, 1, 0, False),
        (False, 0, -123, False),
        (False, 1, -123, False),
    ],
)
def test_business_checks_reject_partial_or_unexpected_mutations(
    expected, count_delta, balance_delta, matches
):
    assert business_effect_matches(expected, count_delta, balance_delta) is matches


@pytest.mark.parametrize("profile", PROFILES)
def test_https_profiles_preserve_cookie_attributes(victim_factory, profile):
    response = (
        victim_factory(profile)
        .test_client()
        .post(
            "/login",
            data={"username": "alice", "password": "alice-lab"},
            base_url="https://victim.test:8443",
        )
    )
    cookie = response.headers["Set-Cookie"]
    same_site, secure = PROFILES[profile]
    assert f"SameSite={same_site}" in cookie
    assert ("; Secure" in cookie) is secure
    assert "Domain=" not in cookie


def test_session_probe_reports_state_without_cookie_value(victim_client, login):
    assert login().status_code == 200
    response = victim_client.get("/cookie-lab/session", headers={"Sec-Fetch-Site": "same-site"})
    match = re.search(r'<pre id="session-observation">(.*?)</pre>', response.text, re.S)
    observation = json.loads(match.group(1))
    assert observation["authenticated"] is True
    assert observation["session_cookie_present"] is True
    assert observation["sec_fetch_site"] == "same-site"
    assert "cookie_value" not in observation


def test_session_probe_not_available_outside_local_lab(victim_factory):
    assert (
        victim_factory(local_only=False).test_client().get("/cookie-lab/session").status_code == 404
    )


def test_https_partner_uses_configured_public_origin():
    app = create_app("partner", load_settings(HTTPS_CONFIG))
    body = app.test_client().get("/wallet").text
    assert 'src="https://victim.test:8443/embed/profile-card"' in body


def test_forwarded_https_login_preserves_csrf_validation(tmp_path):
    settings = replace(load_settings(HTTPS_CONFIG), database_path=tmp_path / "csrf.sqlite3")
    app = create_app("victim", settings)
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        seed_lab_data()
    client = app.test_client()
    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "victim.test:8443"}
    page = client.get("/login", base_url="https://victim.test:8443", headers=headers)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text).group(1)
    assert page.headers["Referrer-Policy"] == "same-origin"
    missing = client.post(
        "/login",
        data={"username": "alice", "password": "alice-lab"},
        base_url="https://victim.test:8443",
        headers=headers,
    )
    assert missing.status_code == 400
    response = client.post(
        "/login",
        data={"username": "alice", "password": "alice-lab", "csrf_token": token},
        base_url="https://victim.test:8443",
        headers={**headers, "Referer": "https://victim.test:8443/login"},
    )
    assert response.status_code == 302
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
