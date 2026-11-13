"""Open a local lab page with an installed browser through Playwright."""

from __future__ import annotations

import argparse

from playwright.sync_api import sync_playwright

from websec_lab.browser import discover_browsers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5100/healthz")
    args = parser.parse_args()

    browsers = discover_browsers()
    chromium_family = [item for item in browsers if item.channel in {"chrome", "msedge"}]
    if not chromium_family:
        raise SystemExit("No local Chromium-family browser is available")

    selected = chromium_family[0]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(selected.executable_path),
            headless=True,
        )
        page = browser.new_page()
        response = page.goto(args.url, wait_until="domcontentloaded")
        if response is None or not response.ok:
            status = None if response is None else response.status
            raise SystemExit(f"Browser smoke test failed with HTTP status {status}")
        print(f"browser={selected.name}")
        print(f"url={page.url}")
        print(f"status={response.status}")
        print(f"body={page.locator('body').inner_text()}")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
