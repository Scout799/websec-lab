"""Verify public scenario pages at their default parameters, including resize."""

import json
import tempfile
from pathlib import Path

from websec_lab.auditor.dynamic.session import BrowserSession
from websec_lab.experiments.final_matrix import VICTIM, reset, state
from websec_lab.https_lab import HttpsLab
from websec_lab.transport import lab_session

ROOT = Path(__file__).resolve().parents[1]


def main():
    output = ROOT / "artifacts/finalization/manual-ui"
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="websec-ui-") as tmp, lab_session() as session:
        for profile in ("https-samesite-none", "csp-none"):
            with HttpsLab(profile, Path(tmp) / f"{profile}.sqlite3"):
                for channel in ("chrome", "msedge", "firefox"):
                    scenarios = (
                        ("overlay", "clip", "multistep")
                        if profile == "https-samesite-none"
                        else ("overlay",)
                    )
                    for scenario in scenarios:
                        reset(session)
                        before = state(session)
                        with BrowserSession(channel=channel, https_lab=True) as browser:
                            page = browser.page
                            page.goto(VICTIM + "/login")
                            page.get_by_label("用户名").fill("alice")
                            page.get_by_label("密码").fill("alice-lab")
                            page.get_by_role("button", name="登录").click()
                            page.get_by_role("heading", name="你好，alice").wait_for()
                            page.goto(
                                f"https://attacker.test:8443/scenarios/{scenario}/run",
                                wait_until="load",
                            )
                            page.set_viewport_size({"width": 1100, "height": 760})
                            page.wait_for_timeout(700)
                            page.set_viewport_size({"width": 1280, "height": 900})
                            page.wait_for_timeout(1500)
                            for step in range(2 if scenario == "multistep" else 1):
                                decoy = page.locator("#decoy-button")
                                decoy.scroll_into_view_if_needed()
                                box = decoy.bounding_box()
                                page.mouse.click(
                                    box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                                )
                                page.wait_for_timeout(1600)
                                if scenario == "multistep" and step == 0:
                                    assert "第 2 步" in page.locator("#decoy-hint").inner_text()
                            page.screenshot(
                                path=str(output / f"{profile}-{channel}-{scenario}.png")
                            )
                        after = state(session)
                        delta = {key: after[key] - before[key] for key in before}
                        expected = int(profile == "https-samesite-none")
                        assert delta["transfers"] == expected, (channel, scenario, delta)
                        assert delta["grants"] == int(scenario == "multistep") * expected
                        assert delta["balance_cents"] == -123 * expected
                        rows.append(
                            dict(
                                profile=profile,
                                browser=channel,
                                scenario=scenario,
                                default_parameters=True,
                                resized=True,
                                delta=delta,
                                passed=True,
                            )
                        )
    (output / "summary.json").write_text(
        json.dumps(dict(passed=True, cases=rows), indent=2), encoding="utf-8"
    )
    print(json.dumps(dict(passed=True, cases=len(rows)), indent=2))


if __name__ == "__main__":
    main()
