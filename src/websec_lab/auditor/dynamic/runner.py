"""Dynamic audit orchestration (T0703/T0704/T0705/T0709/T0710/T0715).

One call to :func:`run_dynamic_audit` drives a real browser through the
full dynamic verification chain — optional victim login with a saved
session, an embed probe with multi-signal framing verdict, an optional
coordinate-click check whose effect is confirmed against the victim's
local state API — and returns the unified result structure with all
evidence written to disk.
"""

from __future__ import annotations

import threading
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import Page
from werkzeug.serving import make_server

from websec_lab.auditor.dynamic.collectors import (
    EvidenceCollector,
    framing_block_markers,
)
from websec_lab.auditor.dynamic.models import (
    ClickjackingResult,
    DynamicAuditResult,
    FrameCheckResult,
    LoginResult,
)
from websec_lab.auditor.dynamic.session import BrowserSession
from websec_lab.auditor.hijack_points import capture_highlighted_points, scan_hijackable_elements
from websec_lab.auditor.origins import parse_origin
from websec_lab.config import repository_root
from websec_lab.transport import is_lab_https, local_get

DEFAULT_EVIDENCE_ROOT = repository_root() / "artifacts" / "auditor"


class AuditStepError(RuntimeError):
    """Raised when one audit step fails after retries (T0715)."""


@dataclass(slots=True)
class LoginConfig:
    origin: str
    username: str
    password: str


@dataclass(slots=True)
class StateCheckConfig:
    victim_origin: str
    username: str
    token: str


@dataclass(slots=True)
class DynamicAuditConfig:
    target_url: str
    clickjacking: bool = False
    login: LoginConfig | None = None
    state_check: StateCheckConfig | None = None
    browser_channel: str = "chrome"
    viewport_profile: str = "desktop"
    headless: bool = True
    trace: bool = False
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT
    step_timeout_ms: int = 20_000
    poll_timeout_s: float = 10.0
    retries: int = 1
    decoy_text: str = "立即领取"
    harness_port: int = 0
    probe_origin: str | None = None
    scenario: str = "overlay"


def _resolve_evidence_root(root: Path) -> Path:
    return root if root.is_absolute() else root.resolve()


def _start_harness(port: int = 0) -> tuple[str, object]:
    """Serve the auditor probe harness on a loopback port.

    A fixed port lets the harness impersonate a specific lab origin (for
    example the partner loopback origin present in allowlist profiles),
    which is how legitimate-source embedding is verified dynamically.
    """

    from websec_lab.auditor import create_app as create_auditor_app

    app = create_auditor_app(test_config={"TESTING": True})
    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{server.port}", server


def _retryable(action, attempts: int, step: str):  # type: ignore[no-untyped-def]
    last_error: Exception | None = None
    for _ in range(max(1, attempts)):
        try:
            return action()
        except Exception as exc:  # noqa: BLE001 - step failures are recorded
            last_error = exc
    raise AuditStepError(f"{step} failed after {attempts} attempt(s)") from last_error


def _wait_title_loads(page: Page, minimum: int, timeout_s: float) -> int:
    """Poll the harness title ('loads:N') until the target frame loaded."""

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            title = page.title()
            if title.startswith("loads:"):
                count = int(title.split(":", 1)[1])
                if count >= minimum:
                    return count
        except Exception:  # pragma: no cover - transient during navigation
            pass
        time.sleep(0.2)
    return -1


def _victim_state(check: StateCheckConfig) -> dict[str, int]:
    response = local_get(
        f"{check.victim_origin}/api/test/state/{check.username}",
        headers={"X-Websec-Test-Token": check.token},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    return {
        "transfers": len(payload["transfers"]),
        "grants": len(payload["grants"]),
        "balance_cents": payload["account"]["balance_cents"],
    }


def _state_changed(before: dict[str, int], after: dict[str, int]) -> bool:
    return before != after


def _perform_login(page: Page, config: LoginConfig, timeout_ms: int) -> str:
    page.goto(f"{config.origin}/login", wait_until="domcontentloaded")
    page.get_by_label("用户名").fill(config.username)
    page.get_by_label("密码").fill(config.password)
    page.get_by_role("button", name="登录").click()
    page.get_by_role("heading", name=f"你好，{config.username}").wait_for(timeout=timeout_ms)
    return page.url


def _check_framing(
    page: Page,
    probe_origin: str,
    target_url: str,
    collector: EvidenceCollector,
    config: DynamicAuditConfig,
) -> FrameCheckResult:
    console_before = len(collector.console)
    documents_before = len(collector.documents)
    page.goto(
        f"{probe_origin}/probe/embed?target={quote(target_url)}&variant=visible",
        wait_until="domcontentloaded",
    )
    loads = _wait_title_loads(page, 1, config.poll_timeout_s)
    console_texts = [entry.text for entry in collector.console[console_before:]]
    blocked_by = framing_block_markers(console_texts)

    # iframe load fires even for blocked/error documents. Inspect the actual
    # child document through Playwright and require a successful HTTP response.
    document = None
    loaded_url = None
    for frame in page.frames:
        if frame == page.main_frame or not frame.url.startswith(("http://", "https://")):
            continue
        try:
            if frame.evaluate("document.readyState") not in {"interactive", "complete"}:
                continue
        except Exception:
            continue
        loaded_url = frame.url
        document = next(
            (
                item
                for item in reversed(collector.documents[documents_before:])
                if item["url"] == frame.url
            ),
            None,
        )
        if document is not None:
            break

    if blocked_by:
        verdict = "blocked"
    elif document is not None and 200 <= int(document["status"]) < 300:
        verdict = "allowed"
    elif _busted_out(page, probe_origin):
        # A frame-busting script navigated the top window away from the
        # harness: embedding itself succeeded, the countermeasure fired
        # afterwards, so the framing verdict is "allowed".
        verdict = "allowed"
    else:
        verdict = "unknown"

    screenshot = collector.screenshot("framing_probe")
    policy_response = document or next(
        (
            item
            for item in reversed(collector.documents[documents_before:])
            if parse_origin(str(item["url"])) == parse_origin(target_url)
            and not 300 <= int(item["status"]) < 400
        ),
        None,
    )
    signals = {
        "iframe_loads_observed": max(loads, 0),
        "load_signal_timed_out": loads < 0,
        "busted_out": verdict == "allowed" and loads < 0,
        "console_block_markers": blocked_by,
        "csp_violations": len(collector.csp_violations),
        "loaded_frame_url": loaded_url,
        "document_response": policy_response,
    }
    return FrameCheckResult(
        ancestor=probe_origin,
        verdict=verdict,
        blocked_by=blocked_by,
        signals=signals,
        screenshot=screenshot,
    )


def _busted_out(page: Page, probe_origin: str) -> bool:
    """True when the harness page was navigated away by the embedded page."""

    try:
        return not page.url.startswith(probe_origin)
    except Exception:  # pragma: no cover - page may be mid-navigation
        return False


def _scan_hijack_points(
    page: Page,
    config: DynamicAuditConfig,
    collector: EvidenceCollector,
) -> tuple[list[dict[str, object]], str | None]:
    """Open the target top-level and record where a hijacked click would land."""

    page.goto(config.target_url, wait_until="load", timeout=config.step_timeout_ms)
    points = scan_hijackable_elements(page)
    if not points:
        return [], None
    screenshot = Path(collector.evidence_dir) / "hijack_points.png"
    captured = capture_highlighted_points(page, points, screenshot)
    return points, str(screenshot) if captured else None


def _align_click_to_target(page: Page, decoy_box: dict[str, float]) -> bool:
    """Shift the probe iframe so the victim's action button sits under the decoy.

    The harness centres the iframe on the decoy, but the victim's submit button
    is not at the page centre (header + card layout), so a centred click lands
    on empty space and every audit reported "clicked, no business change".
    """

    frame = None
    for candidate in page.frames:
        if candidate is page.main_frame:
            continue
        if "/lab/" in candidate.url:
            frame = candidate
            break
    if frame is None:
        return False

    handle = None
    for selector in ("#submit", "button[type=submit]", "button"):
        with suppress(Exception):
            handle = frame.query_selector(selector)
        if handle is not None:
            break
    if handle is None:
        return False

    box = handle.bounding_box()
    if box is None:
        return False

    target_x = decoy_box["x"] + decoy_box["width"] / 2
    target_y = decoy_box["y"] + decoy_box["height"] / 2
    dx = target_x - (box["x"] + box["width"] / 2)
    dy = target_y - (box["y"] + box["height"] / 2)
    if abs(dx) < 2 and abs(dy) < 2:
        return True

    page.evaluate(
        """([shiftX, shiftY]) => {
            const frame = document.getElementById('target-frame');
            if (!frame) return;
            frame.style.transform = 'translate(' + shiftX + 'px,' + shiftY + 'px)';
        }""",
        [dx, dy],
    )
    page.wait_for_timeout(150)
    return True


def _check_clickjacking(
    page: Page,
    probe_origin: str,
    target_url: str,
    collector: EvidenceCollector,
    config: DynamicAuditConfig,
) -> ClickjackingResult:
    state_before: dict[str, int] | None = None
    if config.state_check is not None:
        state_before = _victim_state(config.state_check)

    if config.scenario not in {"overlay", "clip", "multistep"}:
        raise ValueError(f"Unsupported click scenario: {config.scenario}")
    targets = (
        [target_url.replace("/lab/quick-transfer", "/lab/quick-grant"), target_url]
        if config.scenario == "multistep"
        else [target_url]
    )
    screenshot_before = None
    loads = 0
    clicked = False
    busted_out = False
    for index, step_target in enumerate(targets):
        variant = "clip" if config.scenario == "clip" else "overlay"
        page.goto(
            f"{probe_origin}/probe/embed?target={quote(step_target)}"
            f"&variant={variant}&opacity=0.01&decoy={quote(config.decoy_text)}",
            wait_until="load",
        )
        _wait_title_loads(page, 1, config.poll_timeout_s)
        if index == 0:
            screenshot_before = collector.screenshot("clickjacking_before")
        if _busted_out(page, probe_origin):
            # Navigating the top page removes the misleading interface. Do not
            # click the now-visible bank page or classify this as a tool error.
            if parse_origin(page.url) != parse_origin(step_target):
                raise AuditStepError("probe navigated to an unexpected origin")
            busted_out = True
            break
        decoy = page.locator("#decoy-button")
        if not decoy.count():
            raise AuditStepError("decoy button not found in attack harness")
        decoy.scroll_into_view_if_needed()
        box = decoy.bounding_box()
        if box is None:
            raise AuditStepError("decoy button has no rendered geometry")
        if is_lab_https(target_url):
            page.wait_for_timeout(1_200)
        _align_click_to_target(page, box)
        box = decoy.bounding_box() or box
        page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        clicked = True
        page.wait_for_timeout(750)
        with suppress(Exception):
            loads = int(page.title().split(":", 1)[1])
    screenshot_after = collector.screenshot("clickjacking_after")

    state_after: dict[str, int] | None = None
    if config.state_check is not None:
        state_after = _victim_state(config.state_check)

    triggered: bool | None = None
    if state_before is not None and state_after is not None:
        triggered = _state_changed(state_before, state_after)

    return ClickjackingResult(
        clicked=clicked,
        iframe_reloaded=loads >= 2,
        sensitive_action_triggered=triggered,
        state_before=state_before,
        state_after=state_after,
        screenshot_before=screenshot_before,
        screenshot_after=screenshot_after,
        note=(
            "frame-busting navigated the top page; misleading interface removed before click"
            if busted_out
            else (
                f"scenario={config.scenario}; steps={len(targets)}; frame content reloaded"
                if loads >= 2
                else "no in-frame submission observed after the click"
            )
        ),
    )


def run_dynamic_audit(config: DynamicAuditConfig) -> DynamicAuditResult:
    """Execute one dynamic audit and persist all evidence."""

    run_id = uuid.uuid4().hex[:12]
    evidence_dir = _resolve_evidence_root(config.evidence_root) / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    result = DynamicAuditResult(
        run_id=run_id,
        target_url=config.target_url,
        evidence_dir=str(evidence_dir),
    )

    harness_origin = ""
    harness_server = None
    session: BrowserSession | None = None

    def _fail(step: str, error: Exception) -> None:
        result.errors.append(f"{step}: {error!r}")
        if collector is not None:
            with suppress(Exception):
                collector.preserve_failure(step, error)

    collector: EvidenceCollector | None = None

    try:
        if config.probe_origin is not None:
            from websec_lab.auditor.fetch import is_local_target

            if not is_local_target(config.probe_origin):
                raise ValueError("Probe must be a local lab origin")
            harness_origin = config.probe_origin.rstrip("/")
        elif is_lab_https(config.target_url):
            harness_origin = "https://audit.test:8443"
        else:
            harness_origin, harness_server = _start_harness(config.harness_port)
        result.probe_origin = harness_origin

        session = BrowserSession(
            channel=config.browser_channel,
            viewport_profile=config.viewport_profile,
            headless=config.headless,
            trace_enabled=config.trace,
            https_lab=is_lab_https(config.target_url),
        )
        session.start()
        page = session.page
        page.set_default_timeout(config.step_timeout_ms)
        result.browser = {
            **session.resolved.describe(),
            "headless": config.headless,
            "version": session.version,
        }
        result.viewport = session.viewport_description()

        collector = EvidenceCollector(page=page, evidence_dir=evidence_dir)

        # Optional login with persisted session state (T0703).
        if config.login is not None:
            try:
                final_url = _retryable(
                    lambda: _perform_login(page, config.login, config.step_timeout_ms),
                    config.retries,
                    "login",
                )
                storage_state = collector.save_storage_state()
                result.login = LoginResult(
                    performed=True,
                    username=config.login.username,
                    storage_state=storage_state,
                    final_url=final_url,
                    success=True,
                )
            except Exception as exc:  # noqa: BLE001
                _fail("login", exc)
                result.login = LoginResult(
                    performed=True, username=config.login.username, success=False
                )

        # Framing probe with multi-signal verdict (T0704/T0705/T0709).
        if not result.errors:
            try:
                result.framing = _retryable(
                    lambda: _check_framing(
                        page, harness_origin, config.target_url, collector, config
                    ),
                    config.retries,
                    "framing_probe",
                )
            except Exception as exc:  # noqa: BLE001
                _fail("framing_probe", exc)

        # Coordinate click + business-state verification (T0710).
        if config.clickjacking and not result.errors:
            try:
                result.clickjacking = _retryable(
                    lambda: _check_clickjacking(
                        page, harness_origin, config.target_url, collector, config
                    ),
                    config.retries,
                    "clickjacking",
                )
            except Exception as exc:  # noqa: BLE001
                _fail("clickjacking", exc)

        # Locate the concrete elements a hijacked click would land on.
        if not result.errors:
            try:
                result.hijack_points, result.hijack_screenshot = _retryable(
                    lambda: _scan_hijack_points(page, config, collector),
                    config.retries,
                    "hijack_points",
                )
            except Exception as exc:  # noqa: BLE001
                _fail("hijack_points", exc)

        if config.trace:
            session.stop_tracing(evidence_dir / "trace.zip")
            result.evidence_files.append("trace.zip")

    except Exception as exc:  # noqa: BLE001 - browser/harness startup failures
        _fail("startup", exc)
    finally:
        if collector is not None:
            try:
                collector.dump_logs()
                result.evidence_files.extend(
                    sorted(path.name for path in evidence_dir.iterdir() if path.is_file())
                )
                result.console_count = len(collector.console)
                result.network_count = len(collector.network)
                result.csp_violations = list(collector.csp_violations)
                result.page_errors = list(collector.page_errors)
            except Exception:  # pragma: no cover - evidence dump is best-effort
                pass
        if session is not None:
            session.close()
        if harness_server is not None:
            harness_server.shutdown()

    from datetime import UTC, datetime

    result.finished_at = datetime.now(UTC).isoformat()
    result.to_json_file(evidence_dir / "result.json")
    result.evidence_files = sorted(set(result.evidence_files) | {"result.json"})
    return result
