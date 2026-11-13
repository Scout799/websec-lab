"""Real-browser regressions for source alignment, evidence and policy precedence."""

import threading
from contextlib import contextmanager
from dataclasses import replace

import pytest
from flask import Response
from werkzeug.serving import make_server

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import run_combined_audit, write_html_report, write_markdown_report
from websec_lab.browser import discover_browsers
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app
from websec_lab.victim.services import seed_lab_data

CHANNELS = [b.channel for b in discover_browsers() if b.channel in {"chrome", "msedge"}]
pytestmark = pytest.mark.skipif(not CHANNELS, reason="No local Chromium-family browser installed")


@contextmanager
def live_victim(tmp_path, profile="none", headers=None):
    settings = replace(load_settings(), database_path=tmp_path / "regression.sqlite3")
    app = create_app(
        settings=settings,
        test_config={
            "DEFENSE_PROFILE": profile,
            "TEST_API_TOKEN": "regression-token",
        },
    )

    @app.get("/regression/unavailable")
    def unavailable():
        return Response("Service unavailable", status=503)

    @app.get("/regression/script-policy")
    def script_policy():
        return Response(
            '<p>Loaded document</p><script>console.log("blocked")</script>',
            headers={"Content-Security-Policy": "script-src 'none'"},
        )

    if headers:

        @app.after_request
        def policy(response):
            for name, value in headers.items():
                response.headers[name] = value
            return response

    with app.app_context():
        db.create_all()
        seed_lab_data()
    server = make_server("127.0.0.1", 0, app)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


@pytest.mark.parametrize("channel", CHANNELS or ["chrome"])
def test_actual_origin_and_csp_override_xfo(tmp_path, channel):
    with live_victim(
        tmp_path,
        headers={
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors http://127.0.0.1:*",
        },
    ) as origin:
        report = run_combined_audit(
            f"{origin}/login",
            ["http://localhost:5200"],
            browser_channel=channel,
            evidence_root=tmp_path / "evidence",
            poll_timeout_s=2,
        )
        assert report.static["decisions"][0]["allowed"] is False
        assert report.probe_static["decisions"][0]["allowed"] is True
        assert report.dynamic["framing"]["verdict"] == "allowed"
        assert report.consistency["agree"] is True
        assert report.consistency["source_matches_request"] is False
        assert report.overall["verdict"] == "embeddable"
        assert report.dynamic["errors"] == []


@pytest.mark.parametrize(
    "profile,verdict",
    [
        ("none", "vulnerable"),
        ("xfo-deny", "protected"),
        ("confirm-reconfirm", "partial"),
    ],
)
def test_combined_business_verdict_and_report_formats(tmp_path, profile, verdict):
    with live_victim(tmp_path, profile) as origin:
        report = run_combined_audit(
            f"{origin}/lab/quick-transfer",
            ["http://127.0.0.1:5200"],
            click=True,
            login=LoginConfig(origin, "alice", "alice-lab"),
            state_check=StateCheckConfig(origin, "alice", "regression-token"),
            evidence_root=tmp_path / "evidence",
            poll_timeout_s=2,
        )
        assert report.overall["verdict"] == verdict
        assert report.consistency["agree"] is True
        assert report.consistency["response_basis"] == "browser_document_response"
        assert report.dynamic["errors"] == []
        assert "实际测试祖先链" in write_markdown_report(report, tmp_path / "report.md").read_text(
            encoding="utf-8"
        )
        html = write_html_report(report, tmp_path / "report.html").read_text(encoding="utf-8")
        assert "data:image/png;base64," in html
        assert report.overall["label"] in html


def test_load_event_on_503_cannot_prove_embeddability(tmp_path):
    with live_victim(tmp_path) as origin:
        report = run_combined_audit(
            f"{origin}/regression/unavailable",
            ["http://127.0.0.1:5200"],
            evidence_root=tmp_path / "evidence",
            poll_timeout_s=2,
        )
        assert report.dynamic["framing"]["signals"]["iframe_loads_observed"] >= 1
        assert report.dynamic["framing"]["verdict"] == "unknown"
        assert report.consistency["agree"] is None
        assert report.overall["verdict"] == "inconclusive"


def test_script_csp_violation_does_not_mean_frame_blocked(tmp_path):
    with live_victim(tmp_path) as origin:
        report = run_combined_audit(
            f"{origin}/regression/script-policy",
            ["http://127.0.0.1:5200"],
            evidence_root=tmp_path / "evidence",
            poll_timeout_s=2,
        )
        assert report.dynamic["csp_violations"]
        assert report.dynamic["framing"]["blocked_by"] == []
        assert report.dynamic["framing"]["verdict"] == "allowed"
        assert report.overall["verdict"] == "embeddable"


@pytest.mark.parametrize(
    "sources,verdict",
    [
        ("http://127.0.0.1", "blocked"),
        ("http://127.0.0.1:*", "allowed"),
        ("'none' http://127.0.0.1:*", "allowed"),
    ],
)
def test_csp_source_semantics_match_browser(tmp_path, sources, verdict):
    with live_victim(
        tmp_path,
        headers={
            "Content-Security-Policy": f"frame-ancestors {sources}",
        },
    ) as origin:
        report = run_combined_audit(
            f"{origin}/login",
            ["http://127.0.0.1:5200"],
            evidence_root=tmp_path / "evidence",
            poll_timeout_s=2,
        )
        assert report.dynamic["framing"]["verdict"] == verdict
        assert report.consistency["static_framing"] == verdict
        assert report.consistency["agree"] is True
