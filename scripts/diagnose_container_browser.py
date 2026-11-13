"""Inspect lab cookie decisions without exporting cookie values."""

import json

from websec_lab.auditor.dynamic.session import BrowserSession


def main():
    observations = []
    with BrowserSession(https_lab=True) as browser:
        page = browser.page
        cdp = browser.context.new_cdp_session(page)
        cdp.send("Network.enable")
        cdp.on(
            "Network.requestWillBeSentExtraInfo",
            lambda data: observations.append(
                [
                    {"name": item["cookie"]["name"], "blocked": item["blockedReasons"]}
                    for item in data.get("associatedCookies", [])
                ]
            ),
        )
        page.goto("https://victim.test:8443/login")
        page.get_by_label("用户名").fill("alice")
        page.get_by_label("密码").fill("alice-lab")
        page.get_by_role("button", name="登录").click()
        page.get_by_role("heading", name="你好，alice").wait_for()
        cookies = [
            {k: v for k, v in item.items() if k != "value"} for item in browser.context.cookies()
        ]
        page.goto(
            "https://partner.test:8443/probe/embed?target=https%3A%2F%2Fvictim.test%3A8443%2Fembed%2Fprofile-card&variant=visible",
            wait_until="load",
        )
        page.wait_for_timeout(2000)
        print(
            json.dumps(
                dict(
                    browser=browser.version,
                    cookies=cookies,
                    frames=[f.url for f in page.frames],
                    associated_cookies=observations,
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
