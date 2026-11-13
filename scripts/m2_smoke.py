"""Run a real-browser smoke test for the M2 victim workflows."""

from __future__ import annotations

import argparse

import requests
from playwright.sync_api import sync_playwright

from websec_lab.browser import discover_browsers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5100")
    parser.add_argument("--test-token", default="local-lab-only")
    args = parser.parse_args()

    headers = {"X-Websec-Test-Token": args.test_token}
    reset = requests.post(f"{args.base_url}/api/test/reset", headers=headers, timeout=10)
    reset.raise_for_status()

    installed = [item for item in discover_browsers() if item.channel in {"chrome", "msedge"}]
    if not installed:
        raise SystemExit("No local Chromium-family browser is available")
    selected = installed[0]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(selected.executable_path), headless=True
        )
        page = browser.new_page()
        page.goto(f"{args.base_url}/login", wait_until="networkidle")
        page.get_by_label("用户名").fill("alice")
        page.get_by_label("密码").fill("alice-lab")
        page.get_by_role("button", name="登录").click()
        page.get_by_role("heading", name="你好，alice").wait_for()

        page.goto(f"{args.base_url}/transfer", wait_until="networkidle")
        page.get_by_label("收款账户").fill("bob")
        page.get_by_label("金额").fill("1.23")
        page.get_by_label("备注").fill("M2 browser smoke")
        page.get_by_role("button", name="确认转账").click()
        page.get_by_text("模拟转账 #1 已完成。").wait_for()
        browser.close()

    state = requests.get(
        f"{args.base_url}/api/test/state/alice", headers=headers, timeout=10
    ).json()
    if state["account"]["balance_cents"] != 99_877:
        raise SystemExit(f"Unexpected balance after browser transfer: {state['account']}")
    print(f"browser={selected.name}")
    print("login=ok")
    print("transfer=ok")
    print(f"balance_cents={state['account']['balance_cents']}")

    cleanup = requests.post(f"{args.base_url}/api/test/reset", headers=headers, timeout=10)
    cleanup.raise_for_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
