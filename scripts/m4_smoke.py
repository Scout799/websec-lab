"""M4 smoke: legitimate embedding vs blocking vs multi-level nesting.

Starts a real partner site plus victims under different defense profiles
and verifies, with a real browser, the three compatibility semantics:

1. allowlist profile → the partner wallet's embedded bank component loads;
2. deny-all profile → the same component is blocked (compatibility cost);
3. multi-level nesting → an unauthorized outer page embedding the partner
   wallet still cannot get the bank component (frame-ancestors checks the
   whole ancestor chain).

Usage:
    python scripts/m4_smoke.py
"""

from __future__ import annotations

import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from websec_lab.browser import discover_browsers
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.partner import create_app as create_partner_app
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_victim(workspace: Path, profile: str, partner_port: int) -> int:
    """Start a victim whose allowlist expansion covers the actual partner port."""

    base = load_settings()
    partner_cfg = base.service("partner")
    settings = replace(
        base,
        database_path=workspace / "victim.sqlite3",
        services={
            **base.services,
            "partner": replace(
                partner_cfg,
                port=partner_port,
                public_origin=f"http://127.0.0.1:{partner_port}",
            ),
        },
    )
    app = create_victim_app(
        settings=settings,
        test_config={"DEFENSE_PROFILE": profile, "TEST_API_TOKEN": "test-token"},
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def start_partner(victim_origin: str, port: int = 0) -> int:
    app = create_partner_app(test_config={"TESTING": True, "WALLET_VICTIM_ORIGIN": victim_origin})
    server = make_server("127.0.0.1", port, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def _component_loaded(page, timeout_ms: int = 12_000) -> bool:  # type: ignore[no-untyped-def]
    """True if the bank component rendered inside the partner wallet."""

    try:
        page.frame_locator("#bank-component").get_by_text("账户余额", exact=False).wait_for(
            state="visible", timeout=timeout_ms
        )
        return True
    except Exception:
        return False


def main() -> int:
    browser_path = [item for item in discover_browsers() if item.channel == "chrome"]
    if not browser_path:
        raise SystemExit("No local Chromium-family browser available")
    executable = browser_path[0].executable_path

    failures: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=str(executable), headless=True)

        # Case 1+2: allowlist keeps the partner working, deny-all breaks it.
        for profile, expected in (("csp-partner-allowlist", True), ("xfo-deny", False)):
            workspace = Path(tempfile.mkdtemp(prefix=f"websec-m4-{profile}-"))
            partner_port = _free_port()
            vport = start_victim(workspace, profile, partner_port)
            victim_origin = f"http://127.0.0.1:{vport}"
            pport = start_partner(victim_origin, port=partner_port)

            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.goto(f"{victim_origin}/login")
            page.get_by_label("用户名").fill("alice")
            page.get_by_label("密码").fill("alice-lab")
            page.get_by_role("button", name="登录").click()
            page.get_by_role("heading", name="你好，alice").wait_for()

            page.goto(f"http://127.0.0.1:{pport}/wallet")
            loaded = _component_loaded(page)
            ok = loaded is expected
            status = "ok" if ok else "FAIL"
            print(f"profile={profile:<24} loaded={loaded} expected={expected} -> {status}")
            if not ok:
                failures.append(f"{profile}: component loaded={loaded}, expected {expected}")
            context.close()

        # Case 3: multi-level nesting — an outer page (harness-like, served by
        # the partner app itself under an unauthorized path is not enough; we
        # need a THIRD origin) embeds the partner wallet. We host the outer
        # page on a second partner server instance (different port = different
        # origin) whose wallet embeds the victim as usual.
        workspace = Path(tempfile.mkdtemp(prefix="websec-m4-multi-"))
        partner_port = _free_port()
        vport = start_victim(workspace, "csp-partner-allowlist", partner_port)
        victim_origin = f"http://127.0.0.1:{vport}"
        pport = start_partner(victim_origin, port=partner_port)
        # The outer page must be a genuinely unauthorized ORIGIN. A data-URL
        # or set_content page would inherit the victim origin (and pass as
        # 'self'), so we serve the outer page from the auditor probe harness
        # instead: harness origin -> partner wallet -> bank component.
        from websec_lab.auditor import create_app as create_auditor_app

        outer_app = create_auditor_app(test_config={"TESTING": True})
        outer_server = make_server("127.0.0.1", 0, outer_app)
        threading.Thread(target=outer_server.serve_forever, daemon=True).start()
        outer_origin = f"http://127.0.0.1:{outer_server.port}"

        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        # Log in on the victim origin first so the component has a session.
        page.goto(f"{victim_origin}/login")
        page.get_by_label("用户名").fill("alice")
        page.get_by_label("密码").fill("alice-lab")
        page.get_by_role("button", name="登录").click()
        page.get_by_role("heading", name="你好，alice").wait_for()

        from urllib.parse import quote

        page.goto(
            f"{outer_origin}/probe/embed?target={quote(f'http://127.0.0.1:{pport}/wallet')}"
            "&variant=visible"
        )
        page.wait_for_timeout(3_000)
        harness_frame = page.frame_locator("#target-frame")
        try:
            bank_visible = (
                harness_frame.frame_locator("#bank-component")
                .get_by_text("账户余额", exact=False)
                .is_visible(timeout=4_000)
            )
        except Exception:
            bank_visible = False

        ok = bank_visible is False
        status = "ok" if ok else "FAIL"
        print(f"multi-level unauthorized outer origin bank_visible={bank_visible} -> {status}")
        if not ok:
            failures.append("multi-level: bank component visible under unauthorized ancestor")
        context.close()
        browser.close()

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        raise SystemExit(1)
    print("m4 smoke: legitimate embedding semantics verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
