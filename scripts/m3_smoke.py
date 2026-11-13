"""Real-browser smoke test for the M3 clickjacking scenarios.

Starts the victim and attacker services on ephemeral loopback ports,
drives them with the local Chrome installation, and verifies that the
overlay / clip / multistep scenarios actually change victim business
state while the probe scenario reports the framing verdict.

Usage:
    python scripts/m3_smoke.py
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

import requests
from playwright.sync_api import Page, sync_playwright
from werkzeug.serving import make_server

from websec_lab.attacker import create_app as create_attacker_app
from websec_lab.browser import discover_browsers
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

TEST_TOKEN = "local-lab-only"
ALIGNMENT_TOLERANCE_PX = 15
POLL_TIMEOUT_SECONDS = 10


class LabServers:
    """Victim + attacker running on ephemeral loopback ports in threads."""

    def __init__(self, workspace: Path, defense_profile: str | None = None) -> None:
        base_settings = load_settings()
        victim_cfg = base_settings.service("victim")
        attacker_cfg = base_settings.service("attacker")

        victim_settings = replace(base_settings, database_path=workspace / "victim.sqlite3")
        victim_test_config: dict[str, object] = {}
        if defense_profile is not None:
            victim_test_config["DEFENSE_PROFILE"] = defense_profile
        self.victim_app = create_victim_app(
            settings=victim_settings, test_config=victim_test_config
        )
        with self.victim_app.app_context():
            db.create_all()
            seed_lab_data()

        vport = self._free_port()
        self.victim_origin = f"http://127.0.0.1:{vport}"
        patched_services = dict(base_settings.services)
        patched_services["victim"] = replace(
            victim_cfg, host="127.0.0.1", port=vport, public_origin=self.victim_origin
        )
        attacker_settings = replace(
            base_settings,
            services=patched_services,
            artifact_dir=workspace / "artifacts",
            source_path=base_settings.source_path,
        )
        attacker_port_cfg = replace(attacker_cfg, host="127.0.0.1")
        patched_services["attacker"] = attacker_port_cfg
        self.attacker_app = create_attacker_app(
            settings=replace(attacker_settings, services=patched_services),
            test_config={
                "ATTACKER_REPORT_TOKEN": TEST_TOKEN,
                "RUN_JOURNAL_PATH": workspace / "artifacts" / "attacker" / "runs.jsonl",
            },
        )

        self.victim_server = make_server("127.0.0.1", vport, self.victim_app)
        aport = self._free_port()
        self.attacker_origin = f"http://127.0.0.1:{aport}"
        self.attacker_server = make_server("127.0.0.1", aport, self.attacker_app)

        self.threads = [
            threading.Thread(target=self.victim_server.serve_forever, daemon=True),
            threading.Thread(target=self.attacker_server.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    @staticmethod
    def _free_port() -> int:
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def victim_state(self, username: str = "alice") -> dict:
        response = requests.get(
            f"{self.victim_origin}/api/test/state/{username}",
            headers={"X-Websec-Test-Token": TEST_TOKEN},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def reset_victim(self) -> None:
        response = requests.post(
            f"{self.victim_origin}/api/test/reset",
            headers={"X-Websec-Test-Token": TEST_TOKEN},
            timeout=10,
        )
        response.raise_for_status()

    def run_events(self, run_id: str) -> list[dict]:
        response = requests.get(f"{self.attacker_origin}/api/runs/{run_id}", timeout=10)
        response.raise_for_status()
        return response.json()["events"]

    def wait_for_event(self, run_id: str, event_type: str) -> dict:
        deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            for event in self.run_events(run_id):
                if event.get("type") == event_type:
                    return event
            time.sleep(0.25)
        raise TimeoutError(f"event {event_type!r} not reported for run {run_id}")


def current_run_id(page: Page) -> str:
    return page.evaluate(
        "() => document.querySelectorAll('.run-chip')[1].textContent.replace(/[^0-9a-f]/g, '')"
    )


def alignment_drift(page: Page) -> tuple[float, float]:
    return page.evaluate("""() => {
            const frame = document.getElementById('victim-frame');
            const decoy = document.getElementById('decoy-button');
            const f = frame.getBoundingClientRect();
            const d = decoy.getBoundingClientRect();
            return [Math.abs(f.left + f.width / 2 - (d.left + d.width / 2)),
                    Math.abs(f.top + f.height / 2 - (d.top + d.height / 2))];
        }""")


def click_decoy_center(page: Page) -> None:
    box = page.locator("#decoy-button").bounding_box()
    assert box is not None
    page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)


def login_victim(page: Page, victim_origin: str) -> None:
    page.goto(f"{victim_origin}/login", wait_until="networkidle")
    page.get_by_label("用户名").fill("alice")
    page.get_by_label("密码").fill("alice-lab")
    page.get_by_role("button", name="登录").click()
    page.get_by_role("heading", name="你好，alice").wait_for()


def run_overlay(page: Page, lab: LabServers) -> None:
    page.goto(
        f"{lab.attacker_origin}/scenarios/overlay/run?origin={lab.victim_origin}&amount_cents=123"
    )
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")

    drift_x, drift_y = alignment_drift(page)
    assert drift_x <= ALIGNMENT_TOLERANCE_PX and drift_y <= ALIGNMENT_TOLERANCE_PX, (
        f"overlay misaligned: dx={drift_x}, dy={drift_y}"
    )

    click_decoy_center(page)
    frame.get_by_text("转账已完成 #").wait_for()

    run_id = current_run_id(page)
    lab.wait_for_event(run_id, "run_complete")
    state = lab.victim_state()
    assert len(state["transfers"]) == 1, state["transfers"]
    assert state["transfers"][0]["amount_cents"] == 123
    assert state["account"]["balance_cents"] == 100_000 - 123
    print("overlay=ok transfer_created=1 balance=99877")


def run_clip(page: Page, lab: LabServers) -> None:
    page.goto(
        f"{lab.attacker_origin}/scenarios/clip/run?origin={lab.victim_origin}&amount_cents=456"
    )
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")

    window_box = page.locator("#clip-window").bounding_box()
    decoy_box = page.locator("#decoy-button").bounding_box()
    assert window_box is not None and decoy_box is not None
    dx = abs(window_box["x"] + window_box["width"] / 2 - (decoy_box["x"] + decoy_box["width"] / 2))
    dy = abs(
        window_box["y"] + window_box["height"] / 2 - (decoy_box["y"] + decoy_box["height"] / 2)
    )
    assert dx <= ALIGNMENT_TOLERANCE_PX and dy <= ALIGNMENT_TOLERANCE_PX, (
        f"clip window misaligned: dx={dx}, dy={dy}"
    )

    click_decoy_center(page)
    frame.get_by_text("转账已完成 #").wait_for()

    state = lab.victim_state()
    assert len(state["transfers"]) == 2, state["transfers"]
    assert state["transfers"][1]["amount_cents"] == 456
    print("clip=ok transfer_created=2")


def run_multistep(page: Page, lab: LabServers) -> None:
    page.goto(f"{lab.attacker_origin}/scenarios/multistep/run?origin={lab.victim_origin}")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认授权").wait_for(state="visible")

    click_decoy_center(page)
    frame.get_by_role("button", name="确认转账").wait_for(state="visible", timeout=15_000)
    page.get_by_text("第 2 步 / 共 2 步").wait_for()

    click_decoy_center(page)
    frame.get_by_text("转账已完成 #").wait_for()

    run_id = current_run_id(page)
    lab.wait_for_event(run_id, "run_complete")
    state = lab.victim_state()
    assert len(state["grants"]) == 1, state["grants"]
    assert len(state["transfers"]) == 3, state["transfers"]
    assert state["account"]["balance_cents"] == 100_000 - 123 - 456 - 789
    print("multistep=ok grants=1 transfers=3")


def run_probe(page: Page, lab: LabServers) -> None:
    # In-page contentDocument signals are inconclusive in Chromium (null for
    # both cross-origin content and blocked frames), so the verdict combines
    # the reported onload signal with the driver-captured console messages.
    console_messages: list[str] = []
    page.on("console", lambda message: console_messages.append(message.text))
    page.goto(
        f"{lab.attacker_origin}/scenarios/probe/run?origin={lab.victim_origin}&path=/lab/quick-transfer"
    )
    event = lab.wait_for_event(current_run_id(page), "probe_result")

    blocked = any(
        "Refused to display" in text or "violates the following Content Security Policy" in text
        for text in console_messages
    )
    framing = "blocked" if blocked else ("allowed" if event.get("onload") else "unknown")
    assert framing == "allowed", (framing, event, console_messages)
    print("probe=ok verdict=allowed console-confirmed")


def run_scroll(page: Page, lab: LabServers) -> None:
    page.goto(f"{lab.attacker_origin}/scenarios/scroll/run?origin={lab.victim_origin}")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认转账").wait_for(state="attached")

    decoy = page.locator("#decoy-button")
    decoy.scroll_into_view_if_needed()
    decoy.wait_for(state="visible")
    page.wait_for_timeout(300)  # let the scroll listener realign the overlay

    box = decoy.bounding_box()
    assert box is not None
    page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    frame.get_by_text("转账已完成 #").wait_for()

    state = lab.victim_state()
    assert len(state["transfers"]) == 4, state["transfers"]
    print("scroll=ok transfer_created=4")


def run_tap(browser, lab: LabServers) -> None:  # type: ignore[no-untyped-def]
    mobile = browser.new_context(
        viewport={"width": 390, "height": 844},
        device_scale_factor=3,
        has_touch=True,
        is_mobile=True,
    )
    page = mobile.new_page()
    page.set_default_timeout(20_000)
    page.goto(f"{lab.victim_origin}/login", wait_until="networkidle")
    page.get_by_label("用户名").fill("alice")
    page.get_by_label("密码").fill("alice-lab")
    page.get_by_role("button", name="登录").click()
    page.get_by_role("heading", name="你好，alice").wait_for()

    page.goto(f"{lab.attacker_origin}/scenarios/tap/run?origin={lab.victim_origin}")
    frame = page.frame_locator("#victim-frame")
    frame.get_by_role("button", name="确认转账").wait_for(state="visible")

    box = page.locator("#decoy-button").bounding_box()
    assert box is not None
    page.touchscreen.tap(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    frame.get_by_text("转账已完成 #").wait_for()

    state = lab.victim_state()
    assert len(state["transfers"]) == 5, state["transfers"]
    print("tap=ok transfer_created=5 mobile_touch")
    mobile.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-data", action="store_true", help="Skip final victim reset")
    args = parser.parse_args()

    installed = [item for item in discover_browsers() if item.channel in {"chrome", "msedge"}]
    if not installed:
        raise SystemExit("No local Chromium-family browser is available")
    selected = installed[0]

    workspace = Path(tempfile.mkdtemp(prefix="websec-m3-smoke-"))
    lab = LabServers(workspace)
    lab.reset_victim()

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(selected.executable_path), headless=True
            )
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.set_default_timeout(20_000)

            login_victim(page, lab.victim_origin)
            print(f"login=ok victim={lab.victim_origin}")

            run_overlay(page, lab)
            run_clip(page, lab)
            run_multistep(page, lab)
            run_scroll(page, lab)
            run_tap(browser, lab)
            run_probe(page, lab)

            browser.close()
    finally:
        if not args.keep_data:
            lab.reset_victim()

    print(f"browser={selected.name}")
    print("m3 smoke: all scenarios passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
