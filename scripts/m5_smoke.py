"""Real-browser attack/defense matrix smoke test for the M5 profiles.

For each defense profile the script starts a fresh victim+attacker pair,
logs in with the real local Chrome, runs the matching attacker scenario,
and verifies through the victim test API whether the sensitive action
actually happened. This is the M3 attack baseline re-run under defense.

Usage:
    python scripts/m5_smoke.py [--case NAME ...]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

from m3_smoke import LabServers, click_decoy_center, current_run_id, login_victim
from playwright.sync_api import Browser, Page, sync_playwright

from websec_lab.browser import discover_browsers


def open_run(page: Page, lab: LabServers, scenario: str, extra: str = "") -> None:
    page.goto(
        f"{lab.attacker_origin}/scenarios/{scenario}/run" f"?origin={lab.victim_origin}{extra}"
    )


def transfer_count(lab: LabServers) -> int:
    return len(lab.victim_state()["transfers"])


def click_decoy_when_ready(page: Page, expect_victim_button: bool) -> None:
    """Click the decoy once; optionally wait for the victim button first."""

    if expect_victim_button:
        page.frame_locator("#victim-frame").get_by_role("button", name="确认转账").wait_for(
            state="visible"
        )
    else:
        # Blocked frames never render victim content; give the frame a moment
        # to settle so the click lands on the (empty) iframe, not before it.
        page.wait_for_selector("#victim-frame")
        page.wait_for_timeout(800)
    click_decoy_center(page)
    page.wait_for_timeout(1_000)


FRAME_BLOCK_MARKERS = (
    "Refused to display",  # X-Frame-Options blocking
    "violates the following Content Security Policy",  # frame-ancestors blocking
)


def _frame_blocked(console_messages: list[str]) -> bool:
    return any(any(marker in text for marker in FRAME_BLOCK_MARKERS) for text in console_messages)


def run_probe_case(page: Page, lab: LabServers, expected: str) -> None:
    # Chromium's in-page contentDocument signal cannot distinguish a blocked
    # frame from a loaded cross-origin one (both null), so the verdict here
    # combines the probe event with console messages captured by the driver —
    # the same multi-signal approach the M7 auditor will formalize.
    console_messages: list[str] = []
    page.on("console", lambda message: console_messages.append(message.text))
    open_run(page, lab, "probe", "&path=/lab/quick-transfer")
    event = lab.wait_for_event(current_run_id(page), "probe_result")

    deadline = time.monotonic() + 10
    refused = _frame_blocked(console_messages)
    while not refused and time.monotonic() < deadline:
        time.sleep(0.25)
        refused = _frame_blocked(console_messages)

    framing = "blocked" if refused else ("allowed" if event.get("onload") else "unknown")
    assert framing == expected, (framing, event, console_messages)
    print(f"  probe verdict={framing} console-confirmed")


# ---- individual defense cases ----


def case_baseline(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=True)
    assert transfer_count(lab) == 1
    print("  overlay attack succeeded (baseline): transfers=1")


def case_xfo_deny(page: Page, lab: LabServers) -> None:
    run_probe_case(page, lab, "blocked")
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=False)
    assert transfer_count(lab) == 0
    print("  overlay attack blocked: transfers=0")


def case_csp_none(page: Page, lab: LabServers) -> None:
    run_probe_case(page, lab, "blocked")
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=False)
    assert transfer_count(lab) == 0
    print("  overlay attack blocked: transfers=0")


def case_csp_allowlist(page: Page, lab: LabServers) -> None:
    # The attacker origin is deliberately absent from the partner allowlist.
    run_probe_case(page, lab, "blocked")
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=False)
    assert transfer_count(lab) == 0
    print("  attacker not in allowlist, overlay blocked: transfers=0")


def case_xfo_csp_conflict(page: Page, lab: LabServers) -> None:
    # XFO DENY still blocks even though CSP names the attacker origin.
    run_probe_case(page, lab, "blocked")
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=False)
    assert transfer_count(lab) == 0
    print("  conflicting headers still block: transfers=0")


def case_csp_report_only(page: Page, lab: LabServers) -> None:
    run_probe_case(page, lab, "allowed")
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=True)
    assert transfer_count(lab) == 1
    print("  report-only does NOT block: transfers=1 (documented limitation)")


def case_confirm_reconfirm(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "overlay", "&amount_cents=123")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("link", name="进入确认").wait_for(state="visible")
    click_decoy_center(page)
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")
    assert transfer_count(lab) == 0
    print("  first click only reached details stage: transfers=0")


def case_confirm_token(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "overlay", "&amount_cents=123")
    click_decoy_when_ready(page, expect_victim_button=True)
    assert transfer_count(lab) == 1
    print("  live click submits the valid token once: transfers=1 (documented limitation)")


def case_business_hardened(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "overlay", "&amount_cents=123")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("link", name="进入确认").wait_for(state="visible")
    click_decoy_center(page)
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")
    assert transfer_count(lab) == 0
    print("  hardened flow stops the single click: transfers=0")


def case_frame_busting(page: Page, lab: LabServers) -> None:
    console_messages: list[str] = []
    page.on("console", lambda message: console_messages.append(message.text))
    open_run(page, lab, "overlay", "&amount_cents=123")
    page.wait_for_timeout(2_500)

    if page.url.startswith(lab.victim_origin):
        # The busting navigation succeeded: the attacker page is gone.
        assert transfer_count(lab) == 0
        print("  busting navigated the top frame away: transfers=0")
        return

    # Modern Chrome blocks cross-origin top-level navigation without a user
    # gesture, silently neutralizing the classic busting script; the attack
    # continues, which is exactly why XFO/CSP are required.
    gesture_blocked = any(
        "top-level navigation" in text or "Unsafe attempt" in text for text in console_messages
    )
    click_decoy_when_ready(page, expect_victim_button=True)
    assert transfer_count(lab) == 1
    print(
        f"  classic busting neutralized by browser gesture policy (blocked_msg={gesture_blocked}): "
        "transfers=1 (documented limitation)"
    )


def case_frame_busting_hidden(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "overlay", "&amount_cents=123")
    page.wait_for_selector("#victim-frame")
    page.wait_for_timeout(800)  # reveal script keeps the framed page hidden
    click_decoy_center(page)
    page.wait_for_timeout(1_000)

    assert page.url.startswith(lab.attacker_origin)
    assert transfer_count(lab) == 0
    print("  hidden busting kept the victim page invisible: transfers=0")


def case_bust_sandbox_bypass(page: Page, lab: LabServers) -> None:
    open_run(page, lab, "bust", "&amount_cents=123")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")

    sandbox_attr = page.get_attribute("#victim-frame", "sandbox") or ""
    assert "allow-forms" in sandbox_attr and "allow-same-origin" in sandbox_attr, sandbox_attr
    assert "allow-scripts" not in sandbox_attr, sandbox_attr

    click_decoy_center(page)
    frame.get_by_text("转账已完成 #").wait_for()
    assert transfer_count(lab) == 1
    print("  sandboxed iframe neutralized busting: transfers=1 (bypass confirmed)")


CASES: dict[str, tuple[str, object]] = {
    "baseline-none": ("none", case_baseline),
    "xfo-deny": ("xfo-deny", case_xfo_deny),
    "csp-none": ("csp-none", case_csp_none),
    "csp-partner-allowlist": ("csp-partner-allowlist", case_csp_allowlist),
    "xfo-csp-conflict": ("xfo-csp-conflict", case_xfo_csp_conflict),
    "csp-report-only": ("csp-report-only", case_csp_report_only),
    "confirm-reconfirm": ("confirm-reconfirm", case_confirm_reconfirm),
    "confirm-token": ("confirm-token", case_confirm_token),
    "business-hardened": ("business-hardened", case_business_hardened),
    "frame-busting": ("frame-busting", case_frame_busting),
    "frame-busting-hidden": ("frame-busting-hidden", case_frame_busting_hidden),
    "bust-sandbox-bypass": ("frame-busting", case_bust_sandbox_bypass),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        metavar="NAME",
        help="Run only the named case(s); repeatable. Default runs all.",
    )
    args = parser.parse_args()
    unknown = set(args.cases or []) - set(CASES)
    if unknown:
        raise SystemExit(f"Unknown cases: {', '.join(sorted(unknown))}")
    selected = {name: CASES[name] for name in (args.cases or CASES)}

    installed = [item for item in discover_browsers() if item.channel in {"chrome", "msedge"}]
    if not installed:
        raise SystemExit("No local Chromium-family browser is available")
    selected_browser = installed[0]

    with sync_playwright() as playwright:
        browser: Browser = playwright.chromium.launch(
            executable_path=str(selected_browser.executable_path), headless=True
        )
        for name, (profile, handler) in selected.items():
            workspace = Path(tempfile.mkdtemp(prefix=f"websec-m5-{name}-"))
            lab = LabServers(workspace, defense_profile=profile)
            lab.reset_victim()
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.set_default_timeout(20_000)
            print(f"case={name} defense={profile}")
            try:
                login_victim(page, lab.victim_origin)
                handler(page, lab)
            finally:
                context.close()
        browser.close()

    print("m5 smoke: all defense cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
