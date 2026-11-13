"""Unified result data structures for dynamic audits (T0716).

Every dynamic audit produces one :class:`DynamicAuditResult` that serializes
to JSON; all evidence (screenshots, console log, network log, page snapshot)
is written into a per-run evidence directory and referenced by path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class FrameCheckResult:
    """Verdict for embedding the target from one ancestor origin."""

    ancestor: str
    verdict: str  # "allowed" | "blocked" | "unknown"
    blocked_by: list[str] = field(default_factory=list)  # subset of {"xfo", "csp"}
    signals: dict[str, object] = field(default_factory=dict)
    screenshot: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "ancestor": self.ancestor,
            "verdict": self.verdict,
            "blocked_by": list(self.blocked_by),
            "signals": dict(self.signals),
            "screenshot": self.screenshot,
        }


@dataclass(slots=True)
class ClickjackingResult:
    """Outcome of a coordinate click against the overlay harness."""

    clicked: bool
    iframe_reloaded: bool
    sensitive_action_triggered: bool | None
    state_before: dict[str, object] | None = None
    state_after: dict[str, object] | None = None
    screenshot_before: str | None = None
    screenshot_after: str | None = None
    note: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "clicked": self.clicked,
            "iframe_reloaded": self.iframe_reloaded,
            "sensitive_action_triggered": self.sensitive_action_triggered,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "screenshot_before": self.screenshot_before,
            "screenshot_after": self.screenshot_after,
            "note": self.note,
        }


@dataclass(slots=True)
class LoginResult:
    performed: bool
    username: str | None = None
    storage_state: str | None = None
    final_url: str | None = None
    success: bool | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "performed": self.performed,
            "username": self.username,
            "storage_state": self.storage_state,
            "final_url": self.final_url,
            "success": self.success,
        }


@dataclass(slots=True)
class DynamicAuditResult:
    """Everything produced by one dynamic audit run."""

    run_id: str
    target_url: str
    final_url: str | None = None
    probe_origin: str | None = None
    started_at: str = field(default_factory=_utc_now_iso)
    finished_at: str | None = None
    browser: dict[str, object] = field(default_factory=dict)
    viewport: dict[str, object] = field(default_factory=dict)
    login: LoginResult = field(default_factory=lambda: LoginResult(performed=False))
    framing: FrameCheckResult | None = None
    clickjacking: ClickjackingResult | None = None
    # Interactive elements a hijacked click could land on, with their boxes.
    hijack_points: list[dict[str, object]] = field(default_factory=list)
    hijack_screenshot: str | None = None
    evidence_dir: str | None = None
    evidence_files: list[str] = field(default_factory=list)
    console_count: int = 0
    network_count: int = 0
    csp_violations: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def framing_blocked(self) -> bool | None:
        if self.framing is None:
            return None
        return self.framing.verdict == "blocked"

    def summary(self) -> dict[str, object]:
        return {
            "framing_verdict": self.framing.verdict if self.framing else None,
            "framing_blocked_by": self.framing.blocked_by if self.framing else [],
            "clickjacking_triggered": (
                self.clickjacking.sensitive_action_triggered if self.clickjacking else None
            ),
            "run_ok": not self.errors,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "target_url": self.target_url,
            "final_url": self.final_url,
            "probe_origin": self.probe_origin,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "browser": dict(self.browser),
            "viewport": dict(self.viewport),
            "login": self.login.as_dict(),
            "framing": self.framing.as_dict() if self.framing else None,
            "clickjacking": self.clickjacking.as_dict() if self.clickjacking else None,
            "hijack_points": list(self.hijack_points),
            "hijack_screenshot": self.hijack_screenshot,
            "evidence_dir": self.evidence_dir,
            "evidence_files": list(self.evidence_files),
            "console_count": self.console_count,
            "network_count": self.network_count,
            "csp_violations": list(self.csp_violations),
            "page_errors": list(self.page_errors),
            "errors": list(self.errors),
            "summary": self.summary(),
        }

    def to_json_file(self, path: Path) -> Path:
        path.write_text(json.dumps(self.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path
