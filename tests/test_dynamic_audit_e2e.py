"""End-to-end dynamic audit tests with a real browser (T0717).

These tests start a real victim (werkzeug thread) plus the in-process probe
harness, then execute the full dynamic audit chain: login with saved
session, multi-signal framing verdict, coordinate click, business-state
verification and evidence persistence. They are skipped when no local
Chromium-family browser is installed.
"""

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from websec_lab.auditor.dynamic import (
    DynamicAuditConfig,
    LoginConfig,
    StateCheckConfig,
    run_dynamic_audit,
)
from websec_lab.browser import discover_browsers
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

pytestmark = pytest.mark.skipif(
    not [item for item in discover_browsers() if item.channel in {"chrome", "msedge"}],
    reason="No local Chromium-family browser installed",
)


def _start_victim(tmp_path: Path, profile: str) -> tuple[int, object]:
    settings = replace(load_settings(), database_path=tmp_path / f"v-{profile}.sqlite3")
    app = create_victim_app(
        settings=settings,
        test_config={"DEFENSE_PROFILE": profile, "TEST_API_TOKEN": "test-token"},
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port), server


def _audit_config(tmp_path: Path, origin: str, click: bool) -> DynamicAuditConfig:
    return DynamicAuditConfig(
        target_url=f"{origin}/lab/quick-transfer",
        clickjacking=click,
        login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
        state_check=(
            StateCheckConfig(victim_origin=origin, username="alice", token="test-token")
            if click
            else None
        ),
        evidence_root=tmp_path / "evidence",
        poll_timeout_s=8.0,
    )


@pytest.mark.parametrize(
    ("profile", "expected_verdict", "expected_triggered"),
    [
        ("none", "allowed", True),
        ("xfo-deny", "blocked", False),
    ],
)
def test_full_dynamic_audit(
    tmp_path: Path, profile: str, expected_verdict: str, expected_triggered: bool
) -> None:
    port, server = _start_victim(tmp_path, profile)
    try:
        origin = f"http://127.0.0.1:{port}"
        result = run_dynamic_audit(_audit_config(tmp_path, origin, click=True))

        # Login succeeded and the session state was persisted (T0703).
        assert result.login.performed is True
        assert result.login.success is True
        assert result.login.storage_state

        # Multi-signal framing verdict matches the profile (T0704/T0709).
        assert result.framing is not None
        assert result.framing.verdict == expected_verdict, result.framing.signals
        if expected_verdict == "blocked":
            assert "xfo" in result.framing.blocked_by

        # Coordinate click + business state verification (T0710).
        assert result.clickjacking is not None
        assert result.clickjacking.clicked is True
        assert result.clickjacking.sensitive_action_triggered is expected_triggered
        if expected_triggered:
            assert result.clickjacking.state_after["transfers"] == 1
            assert result.clickjacking.state_before["transfers"] == 0

        # Evidence persisted (T0711/T0715/T0716).
        evidence_dir = Path(result.evidence_dir)
        assert (evidence_dir / "result.json").exists()
        assert (evidence_dir / "framing_probe.png").exists()
        assert (evidence_dir / "clickjacking_before.png").exists()
        assert (evidence_dir / "clickjacking_after.png").exists()
        assert (evidence_dir / "console_log.json").exists()
        assert (evidence_dir / "network_log.json").exists()
        assert result.console_count > 0
        assert result.errors == []
    finally:
        server.shutdown()


def test_audit_without_login_for_public_target(tmp_path: Path) -> None:
    port, server = _start_victim(tmp_path, "csp-none")
    try:
        config = DynamicAuditConfig(
            target_url=f"http://127.0.0.1:{port}/login",
            clickjacking=False,
            login=None,
            evidence_root=tmp_path / "evidence-public",
            poll_timeout_s=8.0,
        )
        result = run_dynamic_audit(config)

        assert result.login.performed is False
        # The login page redirects to itself (302 chain recorded in network log);
        # the embed of the final login page is blocked by CSP 'none'.
        assert result.framing is not None
        assert result.framing.verdict == "blocked"
        assert "csp" in result.framing.blocked_by
        assert result.errors == []
    finally:
        server.shutdown()


def test_legitimate_source_passes_allowlist(tmp_path: Path) -> None:
    """T0705: a harness bound to the allowlisted partner origin is allowed in."""

    port, server = _start_victim(tmp_path, "csp-partner-allowlist")
    try:
        origin = f"http://127.0.0.1:{port}"
        config = DynamicAuditConfig(
            target_url=f"{origin}/lab/quick-transfer",
            clickjacking=False,
            login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
            evidence_root=tmp_path / "evidence-legit",
            poll_timeout_s=8.0,
            harness_port=5300,
        )
        result = run_dynamic_audit(config)

        assert result.framing is not None
        assert result.framing.verdict == "allowed"
        assert result.framing.blocked_by == []
        assert result.probe_origin == "http://127.0.0.1:5300"
        assert result.errors == []
    finally:
        server.shutdown()
