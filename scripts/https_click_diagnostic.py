"""Compare transparent cross-site iframe hit testing without changing browser security."""

import json
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

from websec_lab.browser import discover_browsers
from websec_lab.experiments.samesite import _internal_state
from websec_lab.https_lab import HttpsLab, browser_arguments


def main():
    output = Path("artifacts/verification/2026-11-04-https/click-diagnostic")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    session = requests.Session()
    session.trust_env = False
    with HttpsLab("https-samesite-none"), sync_playwright() as playwright:
        chrome = next(b for b in discover_browsers() if b.channel == "chrome")
        browser = playwright.chromium.launch(
            executable_path=str(chrome.executable_path), headless=True, args=browser_arguments()
        )
        try:
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.goto("https://victim.test:8443/login")
            page.get_by_label("用户名").fill("alice")
            page.get_by_label("密码").fill("alice-lab")
            page.get_by_role("button", name="登录").click()
            page.get_by_role("heading", name="你好，alice").wait_for()
            messages = []
            responses = []
            page.on("console", lambda m: messages.append(m.text))
            page.on(
                "response",
                lambda r: (
                    responses.append({"url": r.url, "status": r.status})
                    if r.request.method == "POST" and "/lab/quick-transfer" in r.url
                    else None
                ),
            )
            for opacity in (0, 0.01, 0.35, 1):
                messages.clear()
                responses.clear()
                before = _internal_state(session)
                page.goto(
                    "https://attacker.test:8443/scenarios/overlay/run?opacity=" + str(opacity),
                    wait_until="load",
                )
                target = page.frame_locator("#victim-frame").locator("body")
                target.evaluate("""body => {
                    for (const type of ['pointerdown', 'pointerup', 'click']) {
                        body.addEventListener(type, e => console.debug(JSON.stringify({
                            event: type, tag: e.target.tagName, trusted: e.isTrusted,
                            x: e.clientX, y: e.clientY
                        })), true);
                    }
                }""")
                decoy = page.locator("#decoy-button")
                decoy.scroll_into_view_if_needed()
                box = decoy.bounding_box()
                page.wait_for_timeout(1_500)
                page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                page.wait_for_timeout(1_000)
                after = _internal_state(session)
                row = {
                    "opacity": opacity,
                    "transfer_delta": len(after["transfers"]) - len(before["transfers"]),
                    "messages": list(messages),
                    "post_responses": list(responses),
                }
                rows.append(row)
                print(json.dumps(row, ensure_ascii=True), flush=True)
                page.screenshot(path=str(output / f"opacity-{opacity}.png"), full_page=True)
        finally:
            browser.close()
    (output / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
