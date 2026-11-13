"""Unit tests for the M6 parsers, origin matching and rules catalog."""

import pytest

from websec_lab.auditor.analyzer import analyze_response
from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.origins import (
    Origin,
    matches_frame_ancestor_source,
    parse_origin,
    registrable_domain,
)
from websec_lab.auditor.parsers import (
    parse_csp,
    parse_set_cookies,
    parse_xfo,
)
from websec_lab.auditor.rules import RULES, Finding, risk_score

TARGET = parse_origin("http://victim.test:5100/lab/quick-transfer")
ATTACKER = parse_origin("http://attacker.test:5200")
PARTNER = parse_origin("http://partner.test:5300")


@pytest.mark.parametrize(
    ("headers", "allowed", "blocked_by"),
    [
        ({"x-frame-options": "DENY", "content-security-policy": "frame-ancestors *"}, True, ()),
        (
            {"x-frame-options": "SAMEORIGIN", "content-security-policy": "frame-ancestors 'none'"},
            False,
            ("csp",),
        ),
        (
            {"x-frame-options": "DENY", "content-security-policy-report-only": "frame-ancestors *"},
            False,
            ("xfo",),
        ),
        (
            {"x-frame-options": "DENY", "content-security-policy": "script-src 'none'"},
            False,
            ("xfo",),
        ),
    ],
)
def test_csp_precedence_over_xfo(headers, allowed, blocked_by):
    result = analyze_response(HeaderMap(headers), (), str(TARGET), [str(ATTACKER)])
    assert result.decisions[0].allowed is allowed
    assert result.decisions[0].blocked_by == blocked_by


def test_redirected_self_uses_final_response_origin() -> None:
    result = analyze_response(
        HeaderMap({"content-security-policy": "frame-ancestors 'self'"}),
        (),
        "http://victim.test:5100/redirect",
        ["http://partner.test:5300"],
        final_url="http://partner.test:5300/final",
    )
    assert result.decisions[0].allowed is True


# ---- HeaderMap (T0602) ----


def test_header_map_normalizes_names_and_splits_commas() -> None:
    headers = HeaderMap(
        {"X-Frame-Options": "DENY", "Content-Security-Policy": ["frame-ancestors 'none'", "a, b"]}
    )

    assert headers.getlist("x-frame-options") == ["DENY"]
    assert headers.getlist("content-security-policy") == [
        "frame-ancestors 'none'",
        "a",
        "b",
    ]
    assert headers.first("x-frame-options") == "DENY"
    assert headers.has("CONTENT-SECURITY-POLICY") is True
    assert headers.getlist("missing") == []


def test_header_map_preserves_duplicate_order() -> None:
    headers = HeaderMap({"x-frame-options": ["SAMEORIGIN", "SAMEORIGIN"]})

    assert headers.getlist("X-Frame-Options") == ["SAMEORIGIN", "SAMEORIGIN"]


# ---- origin parsing and matching (T0605) ----


def test_parse_origin_fills_default_ports() -> None:
    assert parse_origin("http://victim.test") == Origin("http", "victim.test", 80)
    assert parse_origin("https://victim.test") == Origin("https", "victim.test", 443)
    assert parse_origin("http://victim.test:5100/x?y=1") == Origin("http", "victim.test", 5100)


def test_parse_origin_rejects_non_http_urls() -> None:
    with pytest.raises(ValueError):
        parse_origin("ftp://victim.test/file")
    with pytest.raises(ValueError):
        parse_origin("/relative/only")


def test_registrable_domain_last_two_labels() -> None:
    assert registrable_domain("victim.test") == "victim.test"
    assert registrable_domain("a.b.victim.test") == "victim.test"


def test_same_site_vs_same_origin() -> None:
    other_port = parse_origin("http://victim.test:9999")
    assert TARGET.same_site(other_port) is True
    assert TARGET.same_origin(other_port) is False
    assert TARGET.same_site(ATTACKER) is False


@pytest.mark.parametrize(
    ("source", "ancestor", "expected"),
    [
        ("'self'", TARGET, True),
        ("'self'", ATTACKER, False),
        ("http://victim.test:5100", TARGET, True),
        ("http://victim.test:5100", parse_origin("http://victim.test:5200"), False),
        ("http://victim.test", parse_origin("http://victim.test:5200"), False),
        ("http://victim.test", parse_origin("http://victim.test:80"), True),
        ("http://victim.test:*", parse_origin("http://victim.test:5200"), True),
        ("http://victim.test:invalid", TARGET, False),
        ("https:", parse_origin("https://any.host"), True),
        ("https:", TARGET, False),
        ("http://*.test", PARTNER, False),
        ("http://*.test:*", PARTNER, True),
        ("http://*.test", parse_origin("http://test"), False),
        ("*", ATTACKER, True),
        ("http://victim.test:5100/deep/path", TARGET, True),  # path ignored
    ],
)
def test_frame_ancestor_source_matching(source: str, ancestor: Origin, expected: bool) -> None:
    assert matches_frame_ancestor_source(source, ancestor, TARGET) is expected


# ---- XFO parser (T0603) ----


def test_parse_xfo_absent_returns_none() -> None:
    assert parse_xfo(HeaderMap({})) is None


def test_parse_xfo_flags() -> None:
    policy = parse_xfo(HeaderMap({"x-frame-options": ["ALLOW-FROM http://p.test", "Bogus"]}))

    assert policy is not None
    assert policy.duplicates is True
    assert policy.obsolete_allow_from is True
    assert policy.invalid_values == ("Bogus",)
    assert policy.effective_value is None


def test_parse_xfo_effective_value_uses_first_valid() -> None:
    policy = parse_xfo(HeaderMap({"x-frame-options": ["Bogus", "DENY"]}))

    assert policy is not None
    assert policy.effective_value == "deny"


# ---- CSP parser (T0604) ----


def test_parse_csp_separates_enforcing_and_report_only() -> None:
    analysis = parse_csp(
        HeaderMap(
            {
                "content-security-policy": ["frame-ancestors 'none'"],
                "content-security-policy-report-only": ["frame-ancestors 'self'"],
            }
        )
    )

    assert analysis.has_enforcing_frame_ancestors is True
    assert len(analysis.enforcing) == 1
    assert len(analysis.report_only) == 1
    assert analysis.allows(ATTACKER, TARGET) is False
    assert analysis.allows(TARGET, TARGET) is False  # 'none' allows nothing


def test_parse_csp_multiple_policies_intersect() -> None:
    analysis = parse_csp(
        HeaderMap(
            {
                "content-security-policy": [
                    "frame-ancestors 'self' http://partner.test:5300",
                    "frame-ancestors 'self'",
                ]
            }
        )
    )

    assert analysis.allows(PARTNER, TARGET) is False  # blocked by second policy
    assert analysis.allows(TARGET, TARGET) is True


def test_parse_csp_policy_without_frame_ancestors_allows_all() -> None:
    analysis = parse_csp(HeaderMap({"content-security-policy": ["script-src 'self'"]}))

    assert analysis.has_enforcing_frame_ancestors is False
    assert analysis.allows(ATTACKER, TARGET) is True


def test_parse_csp_mixed_none_is_malformed() -> None:
    analysis = parse_csp(
        HeaderMap({"content-security-policy": ["frame-ancestors 'none' http://partner.test:5300"]})
    )

    policy = analysis.enforcing[0]
    assert policy.malformed is True
    assert policy.allows(PARTNER, TARGET) is True


def test_parse_csp_duplicate_directive_is_ignored_and_flagged() -> None:
    analysis = parse_csp(
        HeaderMap(
            {"content-security-policy": ["frame-ancestors 'self'; frame-ancestors http://p.test"]}
        )
    )

    policy = analysis.enforcing[0]
    assert policy.malformed is True
    assert policy.sources == ("'self'",)


# ---- Set-Cookie parser (T0609) ----


def test_parse_set_cookies_extracts_attributes_case_insensitively() -> None:
    cookies = parse_set_cookies(["sid=1; httponly; samesite=strict; SECURE", "raw-no-separator"])

    assert len(cookies) == 1
    assert cookies[0].name == "sid"
    assert cookies[0].http_only is True
    assert cookies[0].secure is True
    assert cookies[0].same_site == "Strict"


def test_parse_set_cookies_flags_none_without_secure() -> None:
    cookies = parse_set_cookies(["sid=1; SameSite=None; HttpOnly"])

    assert cookies[0].same_site_none_without_secure is True


# ---- rules catalog and risk score (T0610/T0615) ----


def test_rule_catalog_integrity() -> None:
    ids = sorted(RULES)
    assert len(ids) == len(set(ids))
    assert ids[0] == "WS001"
    for rule in RULES.values():
        assert rule.severity in {"info", "low", "medium", "high"}
        assert rule.remediation.strip()


def test_risk_score_grades_and_caps() -> None:
    empty = risk_score([])
    assert empty["score"] == 0
    assert empty["grade"] == "info"

    single_high = risk_score([Finding.from_rule("WS001", "evidence")])
    assert single_high["score"] == 40
    assert single_high["grade"] == "high"

    capped = risk_score(
        [
            Finding.from_rule("WS001", "a"),
            Finding.from_rule("WS007", "b"),
            Finding.from_rule("WS002", "c"),
        ]
    )
    assert capped["score"] == 100
    assert capped["grade"] == "critical"
    assert capped["contributions"][0] == {"rule_id": "WS001", "weight": 40}
