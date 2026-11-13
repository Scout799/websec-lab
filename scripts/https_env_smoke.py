"""Verify gateway TLS/SNI/routes and unmodified browser certificate trust."""

import json
import ssl
from pathlib import Path

from playwright.sync_api import sync_playwright

from websec_lab.browser import discover_browsers
from websec_lab.https_lab import HOSTS, PORT, browser_arguments, https_get


def main() -> int:
    results = {"gateway": [], "browsers": []}
    expected = {
        "victim.test": "victim",
        "attacker.test": "attacker",
        "same.victim.test": "attacker",
        "partner.test": "partner",
        "audit.test": "auditor",
    }
    for host in HOSTS:
        status, response = https_get(host)
        route_matches = f'"service":"{expected[host]}"' in response.replace(" ", "")
        private_status, _ = https_get(host, "/__lab/shutdown")
        row = {
            "host": host,
            "status": status,
            "route_matches": route_matches,
            "private_control_status": private_status,
            "tls_chain_and_hostname_verified": True,
        }
        results["gateway"].append(row)
        assert status == 200 and route_matches and private_status == 404, row
    assert https_get("victim.test", request_host="unlisted.test")[0] == 421
    results["unknown_host_rejected"] = True
    try:
        https_get("unlisted.test")
    except ssl.SSLCertVerificationError:
        results["wrong_sni_certificate_rejected"] = True
    else:
        raise AssertionError("Certificate hostname validation was not enforced")
    with sync_playwright() as playwright:
        for installation in discover_browsers():
            if installation.channel not in {"chrome", "msedge"}:
                continue
            browser = playwright.chromium.launch(
                executable_path=str(installation.executable_path),
                headless=True,
                args=browser_arguments(),
            )
            row = {
                "channel": installation.channel,
                "version": browser.version,
                "tls_verified": False,
                "ignore_https_errors": False,
            }
            try:
                page = browser.new_page(ignore_https_errors=False)
                response = page.goto(f"https://victim.test:{PORT}/login", timeout=10_000)
                row["tls_verified"] = response.status == 200 and page.evaluate("isSecureContext")
            except Exception as error:
                row["error"] = str(error).splitlines()[0]
            finally:
                browser.close()
            results["browsers"].append(row)
    results["ready_for_samesite_matrix"] = bool(results["browsers"]) and all(
        row["tls_verified"] for row in results["browsers"]
    )
    out = Path("artifacts/verification/2026-11-04-https/environment.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(results, indent=2, ensure_ascii=True))
    return 0 if results["ready_for_samesite_matrix"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
