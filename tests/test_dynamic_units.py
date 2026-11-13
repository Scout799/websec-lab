"""Unit tests for M7 data structures, harness page and session resolution."""

import pytest
from flask.testing import FlaskClient

from websec_lab.auditor import create_app as create_auditor_app
from websec_lab.auditor.dynamic.models import (
    ClickjackingResult,
    DynamicAuditResult,
    FrameCheckResult,
    LoginResult,
)
from websec_lab.auditor.dynamic.session import (
    VIEWPORT_PROFILES,
    BrowserSession,
    BrowserSessionError,
    resolve_browser,
)


@pytest.fixture
def auditor_client() -> FlaskClient:
    app = create_auditor_app(test_config={"TESTING": True})
    return app.test_client()


# ---- unified result structures (T0716) ----


def test_result_serialization_and_summary(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = DynamicAuditResult(
        run_id="abc123",
        target_url="http://victim.test:5100/lab/quick-transfer",
        probe_origin="http://127.0.0.1:64000",
        login=LoginResult(performed=True, username="alice", success=True),
        framing=FrameCheckResult(
            ancestor="http://127.0.0.1:64000",
            verdict="blocked",
            blocked_by=["xfo"],
            signals={"iframe_loads_observed": 1},
            screenshot="x/framing_probe.png",
        ),
        clickjacking=ClickjackingResult(
            clicked=True,
            iframe_reloaded=False,
            sensitive_action_triggered=False,
            state_before={"transfers": 0},
            state_after={"transfers": 0},
        ),
    )

    payload = result.as_dict()

    assert payload["framing"]["verdict"] == "blocked"
    assert payload["clickjacking"]["sensitive_action_triggered"] is False
    assert payload["summary"] == {
        "framing_verdict": "blocked",
        "framing_blocked_by": ["xfo"],
        "clickjacking_triggered": False,
        "run_ok": True,
    }
    assert result.framing_blocked is True

    written = result.to_json_file(tmp_path / "result.json")
    assert written.exists()


def test_empty_result_summary_defaults() -> None:
    result = DynamicAuditResult(run_id="x", target_url="http://victim.test/x")

    payload = result.as_dict()

    assert payload["framing"] is None
    assert payload["summary"]["framing_verdict"] is None
    assert payload["summary"]["run_ok"] is True


# ---- probe harness (T0704/T0705) ----


def test_harness_renders_visible_variant(auditor_client: FlaskClient) -> None:
    page = auditor_client.get(
        "/probe/embed",
        query_string={"target": "http://victim.test:5100/lab/quick-transfer"},
    )
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'src="http://victim.test:5100/lab/quick-transfer"' in body
    assert 'class="visible-frame"' in body


def test_harness_renders_overlay_variant(auditor_client: FlaskClient) -> None:
    page = auditor_client.get(
        "/probe/embed",
        query_string={
            "target": "http://victim.test:5100/lab/quick-transfer",
            "variant": "overlay",
            "decoy": "点击领取",
        },
    )
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'id="decoy-button"' in body
    assert "点击领取" in body
    assert 'class="visible-frame"' not in body


def test_harness_rejects_non_local_targets(auditor_client: FlaskClient) -> None:
    page = auditor_client.get("/probe/embed", query_string={"target": "https://real.example.com/"})

    assert page.status_code == 400


def test_harness_rejects_unknown_variant(auditor_client: FlaskClient) -> None:
    page = auditor_client.get(
        "/probe/embed",
        query_string={"target": "http://victim.test:5100/x", "variant": "ghost"},
    )

    assert page.status_code == 400


# ---- session resolution (T0702/T0713/T0714) ----


def test_resolve_browser_rejects_unknown_channel() -> None:
    with pytest.raises(BrowserSessionError, match="Unsupported browser channel"):
        resolve_browser("safari")


def test_viewport_profiles_exist() -> None:
    assert set(VIEWPORT_PROFILES) == {"desktop", "mobile"}
    assert VIEWPORT_PROFILES["mobile"]["is_mobile"] is True


def test_session_rejects_unknown_viewport() -> None:
    with pytest.raises(BrowserSessionError, match="viewport"):
        BrowserSession(viewport_profile="tablet")


def test_resolve_chrome_when_available() -> None:
    from websec_lab.browser import discover_browsers

    if not any(item.channel == "chrome" for item in discover_browsers()):
        pytest.skip("No local Chrome installation")
    resolved = resolve_browser("chrome")
    assert resolved.engine == "chromium"
    assert resolved.executable


def test_framing_markers_ignore_report_only_messages() -> None:
    from websec_lab.auditor.dynamic.collectors import framing_block_markers

    enforcing = framing_block_markers(
        [
            "Refused to display 'http://v.test/' in a frame because it set "
            "'X-Frame-Options' to 'deny'.",
            "Framing 'http://v.test/' violates the following CSP directive.",
        ]
    )
    assert "xfo" in enforcing

    # Report-Only violations carry the same wording but must not count:
    # nothing was actually blocked.
    report_only = framing_block_markers(
        [
            # Chrome's actual Report-Only wording (hyphenated, observed live).
            "Framing 'http://v.test/' violates the following report-only "
            "Content Security Policy directive: \"frame-ancestors 'none'\".",
        ]
    )
    assert report_only == []


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "Framing 'http://v.test/' violates the following Content Security Policy "
            "directive: frame-ancestors 'none'.",
            ["csp"],
        ),
        (
            "Loading script violates the following Content Security Policy "
            "directive: script-src 'none'.",
            [],
        ),
        (
            "Framing violates the following report only Content Security Policy "
            "directive: frame-ancestors 'none'.",
            [],
        ),
        ("Load denied by X-Frame-Options: http://v.test/ does not permit framing.", ["xfo"]),
    ],
)
def test_framing_markers_require_enforcing_frame_policy(message, expected) -> None:
    from websec_lab.auditor.dynamic.collectors import framing_block_markers

    assert framing_block_markers([message]) == expected


@pytest.mark.parametrize("unexpected", [False, True])
def test_frame_busting_does_not_click_visible_target(monkeypatch, unexpected) -> None:
    from unittest.mock import Mock

    from websec_lab.auditor.dynamic import runner

    page = Mock()
    page.url = (
        "https://other.test/" if unexpected else "https://victim.test:8443/lab/quick-transfer"
    )
    collector = Mock()
    collector.screenshot.return_value = "evidence.png"
    monkeypatch.setattr(runner, "_wait_title_loads", lambda *args: -1)
    config = runner.DynamicAuditConfig(target_url="https://victim.test:8443/lab/quick-transfer")
    args = (page, "https://same.victim.test:8443", config.target_url, collector, config)
    if unexpected:
        with pytest.raises(runner.AuditStepError, match="unexpected origin"):
            runner._check_clickjacking(*args)
    else:
        result = runner._check_clickjacking(*args)
        assert result.clicked is False
        assert "frame-busting" in result.note
        assert result.sensitive_action_triggered is None
    page.locator.assert_not_called()
    page.mouse.click.assert_not_called()
