"""Real HTTPS SameSite matrix with cookie, authentication and business evidence."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

from websec_lab.browser import discover_browsers
from websec_lab.https_lab import CA, PORT, HttpsLab, browser_arguments

PROFILES = {
    "https-samesite-strict": ("Strict", True),
    "https-samesite-lax": ("Lax", True),
    "https-samesite-none": ("None", True),
    "samesite-none": ("None", False),
}
COOKIE_NAME = "websec_victim_session"


@dataclass
class SameSiteCase:
    browser: str
    profile: str
    relation: str
    third_party_policy: str
    repeat: int

    @property
    def expected_authenticated(self) -> bool:
        same_site, secure = PROFILES[self.profile]
        if same_site == "None" and not secure:
            return False
        if self.relation == "same-site":
            return True
        return self.third_party_policy == "allow" and same_site == "None"

    @property
    def top_origin(self) -> str:
        host = "same.victim.test" if self.relation == "same-site" else "attacker.test"
        return f"https://{host}:{PORT}"

    @property
    def expected_top_level_authenticated(self) -> bool:
        same_site, secure = PROFILES[self.profile]
        return secure and (self.relation == "same-site" or same_site != "Strict")


def _internal_state(session: requests.Session) -> dict:
    response = session.get(
        "http://127.0.0.1:15100/api/test/state/alice",
        headers={"X-Websec-Test-Token": "local-lab-only"},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def business_effect_matches(expected: bool, transfer_delta: int, balance_delta: int) -> bool:
    if expected:
        return transfer_delta == 1 and balance_delta == -123
    return transfer_delta == 0 and balance_delta == 0


def run_case(case: SameSiteCase, out: Path, executable: Path) -> dict:
    row = {
        **asdict(case),
        "expected_authenticated": case.expected_authenticated,
        "top_origin": case.top_origin,
        "victim_origin": f"https://victim.test:{PORT}",
        "ok": False,
    }
    label = f"{case.browser}-{case.profile}-{case.relation}-{case.third_party_policy}-{case.repeat}"
    evidence = out / "evidence" / label
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="websec-cookie-browser-") as temporary:
        user_dir = Path(temporary)
        (user_dir / "Default").mkdir()
        # Use a fresh regular profile rather than changing the user's browser.
        (user_dir / "Default/Preferences").write_text(
            json.dumps(
                {
                    "profile": {
                        "cookie_controls_mode": 0 if case.third_party_policy == "allow" else 1,
                        "block_third_party_cookies": case.third_party_policy == "block",
                    }
                }
            ),
            encoding="utf-8",
        )
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                str(user_dir),
                executable_path=str(executable),
                headless=True,
                args=browser_arguments(),
                viewport={"width": 1280, "height": 900},
                ignore_https_errors=False,
            )
            try:
                page = context.pages[0] if context.pages else context.new_page()
                page.set_default_timeout(12_000)
                cdp = context.new_cdp_session(page)
                cdp.send("Network.enable")
                cdp.send(
                    "Network.setCookieControls",
                    {
                        "enableThirdPartyCookieRestriction": case.third_party_policy == "block",
                        "disableThirdPartyCookieMetadata": True,
                        "disableThirdPartyCookieHeuristics": True,
                    },
                )
                cookie_requests = []
                rejected_cookies = []

                def request_extra(event):
                    # Save reasons/booleans only; do not export session values.
                    cookies = [
                        item
                        for item in event.get("associatedCookies", [])
                        if item.get("cookie", {}).get("name") == COOKIE_NAME
                    ]
                    if cookies:
                        cookie_requests.append(
                            {
                                "request_id": event["requestId"],
                                "cookies": [
                                    {
                                        "name": COOKIE_NAME,
                                        "blocked_reasons": item.get("blockedReasons", []),
                                    }
                                    for item in cookies
                                ],
                            }
                        )

                def response_extra(event):
                    for item in event.get("blockedCookies", []):
                        rejected_cookies.append({"blocked_reasons": item.get("blockedReasons", [])})

                cdp.on("Network.requestWillBeSentExtraInfo", request_extra)
                cdp.on("Network.responseReceivedExtraInfo", response_extra)
                victim = row["victim_origin"]
                response = page.goto(f"{victim}/login", wait_until="networkidle")
                assert response and response.status == 200
                assert page.evaluate("isSecureContext") is True
                row["browser_version"] = cdp.send("Browser.getVersion")["product"]
                row["tls_verified"] = True
                row["cdp_cookie_controls"] = case.third_party_policy
                initial_cookies = context.cookies(victim)
                stored = next((c for c in initial_cookies if c["name"] == COOKIE_NAME), None)
                row["cookie_stored"] = stored is not None
                row["cookie_attributes"] = (
                    {k: stored[k] for k in ("sameSite", "secure", "httpOnly", "domain")}
                    if stored
                    else None
                )
                if stored:
                    page.get_by_label("用户名").fill("alice")
                    page.get_by_label("密码").fill("alice-lab")
                    page.get_by_role("button", name="登录").click()
                    page.get_by_role("heading", name="你好，alice").wait_for()
                    row["top_level_login"] = True
                else:
                    row["top_level_login"] = False
                    assert PROFILES[case.profile] == ("None", False), "Unexpected cookie rejection"

                cookie_requests.clear()
                page.goto(f"{case.top_origin}/cookie-lab", wait_until="networkidle")
                observation_text = (
                    page.frame_locator("#session-frame")
                    .locator("#session-observation")
                    .inner_text()
                )
                observation = json.loads(observation_text)
                row["session_observation"] = observation
                row["authenticated"] = observation["authenticated"]
                row["session_cookie_sent"] = observation["session_cookie_present"]
                row["cookie_network_evidence"] = list(cookie_requests)
                row["rejected_cookies"] = rejected_cookies
                assert observation["scheme"] == "https"
                assert observation["sec_fetch_site"] == case.relation
                page.screenshot(path=str(evidence / "session.png"), full_page=True)

                session = requests.Session()
                session.trust_env = False
                before = _internal_state(session)
                row["attack_opacity"] = 0.01
                page.goto(
                    f"{case.top_origin}/scenarios/overlay/run?opacity={row['attack_opacity']}",
                    wait_until="load",
                )
                # Wait for the actual UI and embedded response. Telemetry fetches
                # are not a reliable page-readiness signal for this experiment.
                page.wait_for_function(
                    "document.querySelector('#run-status').textContent.includes('对齐完成')"
                )
                embedded = page.frame_locator("#victim-frame")
                embedded.locator("[data-quick-page='transfer'], input[name='username']").wait_for()
                decoy = page.locator("#decoy-button")
                decoy.scroll_into_view_if_needed()
                box = decoy.bounding_box()
                assert box is not None
                click_x, click_y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                row["click_point"] = {"x": click_x, "y": click_y}
                row["click_surface"] = page.evaluate(
                    "([x, y]) => document.elementFromPoint(x, y)?.id", [click_x, click_y]
                )
                assert row["click_surface"] == "victim-frame", "Click missed transparent frame"
                if observation["authenticated"]:
                    target_box = embedded.locator(".quick-card .button").bounding_box()
                    row["target_button_box"] = target_box
                    assert target_box is not None
                    assert target_box["x"] <= click_x <= target_box["x"] + target_box["width"]
                    assert target_box["y"] <= click_y <= target_box["y"] + target_box["height"]
                # Flush a rendered frame before sending OS-style coordinates,
                # including the cross-site iframe's separate renderer process.
                page.screenshot(path=str(evidence / "before-click.png"), full_page=True)
                # A settled layout models a user reading the decoy. Chromium
                # can discard input sent immediately after a frame is moved.
                row["pre_click_settle_ms"] = 1_200
                page.wait_for_timeout(row["pre_click_settle_ms"])
                page.mouse.click(click_x, click_y)
                page.wait_for_timeout(1_000)
                after = _internal_state(session)
                row["transfer_delta"] = len(after["transfers"]) - len(before["transfers"])
                row["balance_delta_cents"] = (
                    after["account"]["balance_cents"] - before["account"]["balance_cents"]
                )
                row["attack_triggered"] = (
                    row["transfer_delta"] == 1 and row["balance_delta_cents"] == -123
                )
                page.screenshot(path=str(evidence / "attack.png"), full_page=True)
                # Follow a real link, preserving the initiating site's relation.
                # page.goto(victim) would model address-bar navigation instead.
                page.goto(f"{case.top_origin}/cookie-lab", wait_until="load")
                page.locator("#top-level-probe").click()
                top_observation = json.loads(page.locator("#session-observation").inner_text())
                row["top_level_observation"] = top_observation
                row["top_level_authenticated"] = top_observation["authenticated"]
                row["expected_top_level_authenticated"] = case.expected_top_level_authenticated
                assert top_observation["sec_fetch_site"] == case.relation
                page.screenshot(path=str(evidence / "top-level.png"), full_page=True)
                expected = case.expected_authenticated
                row["ok"] = (
                    row["authenticated"] is expected
                    and row["session_cookie_sent"] is expected
                    and business_effect_matches(
                        expected, row["transfer_delta"], row["balance_delta_cents"]
                    )
                    and row["top_level_authenticated"] is case.expected_top_level_authenticated
                    and top_observation["session_cookie_present"]
                    is case.expected_top_level_authenticated
                )
                if PROFILES[case.profile] == ("None", False):
                    row["ok"] = row["ok"] and any(
                        "SameSiteNoneInsecure" in item["blocked_reasons"]
                        for item in rejected_cookies
                    )
            except Exception as error:
                row["error"] = repr(error)
            finally:
                context.close()
    (evidence / "result.json").write_text(
        json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return row


def run_matrix(
    out: Path, repeats: int = 3, channels: tuple[str, ...] = ("chrome", "msedge")
) -> dict:
    installed = {b.channel: b.executable_path for b in discover_browsers()}
    for channel in channels:
        if channel not in installed:
            raise RuntimeError(f"Requested browser not installed: {channel}")
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    start = time.monotonic()
    for profile in PROFILES:
        with HttpsLab(profile):
            for channel in channels:
                for policy in ("allow", "block"):
                    for relation in ("same-site", "cross-site"):
                        for repeat in range(1, repeats + 1):
                            case = SameSiteCase(channel, profile, relation, policy, repeat)
                            row = run_case(case, out, installed[channel])
                            rows.append(row)
                            print(
                                f"{channel} {profile} {relation} third-party={policy} "
                                f"repeat={repeat} expected={case.expected_authenticated} "
                                f"actual={row.get('authenticated')} "
                                f"attack={row.get('attack_triggered')} ok={row['ok']}",
                                flush=True,
                            )
                            (out / "results.json").write_text(
                                json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
                            )
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "repeats": repeats,
        "rows": len(rows),
        "passed": sum(r["ok"] for r in rows),
        "failed": sum(not r["ok"] for r in rows),
        "duration_s": round(time.monotonic() - start, 2),
        "ca_file": str(CA),
        "https_port": PORT,
        "browser_versions": sorted({r.get("browser_version", "unavailable") for r in rows}),
        "certificate_errors_ignored": False,
        "host_mapping": "dedicated browser resolver rules",
        "cookie_controls": "isolated regular profile preferences + CDP Network.setCookieControls",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    fields = [
        "browser",
        "profile",
        "relation",
        "third_party_policy",
        "repeat",
        "expected_authenticated",
        "authenticated",
        "session_cookie_sent",
        "attack_triggered",
        "transfer_delta",
        "balance_delta_cents",
        "top_level_authenticated",
        "expected_top_level_authenticated",
        "ok",
        "error",
    ]
    with (out / "results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# HTTPS SameSite实验结果",
        "",
        f"- 实验数：{len(rows)}，通过：{summary['passed']}，失败：{summary['failed']}",
        "- TLS证书验证保持开启。每例使用独立浏览器配置。",
        "",
        "| 浏览器 | 配置 | 关系 | 第三方Cookie | 重复 | 会话Cookie | 已登录 | 操作触发 "
        "| 顶层GET登录态 | 通过 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            "| "
            + " | ".join(
                str(r.get(k, "—"))
                for k in [
                    "browser",
                    "profile",
                    "relation",
                    "third_party_policy",
                    "repeat",
                    "session_cookie_sent",
                    "authenticated",
                    "attack_triggered",
                    "top_level_authenticated",
                    "ok",
                ]
            )
            + " |"
        )
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("artifacts/samesite-https"))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--browser", choices=["chrome", "msedge", "both"], default="both")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("repeats must be positive")
    channels = ("chrome", "msedge") if args.browser == "both" else (args.browser,)
    summary = run_matrix(args.out, args.repeats, channels)
    print(json.dumps(summary, indent=2))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
