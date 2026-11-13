"""M6 smoke: the static analyzer fetches live victims under each M5 profile.

Starts a fresh victim per defense profile, points the auditor's fetch-mode
analyzer at it, and checks that the static verdicts match the expectations
already validated dynamically by ``m5_smoke``. This closes the loop
between static prediction and the defense matrix.

Usage:
    python scripts/m6_smoke.py
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from werkzeug.serving import make_server

from websec_lab.auditor import create_app as create_auditor_app
from websec_lab.auditor.analyzer import analyze_response
from websec_lab.auditor.fetch import fetch_response
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

ATTACKER_ANCESTOR = "http://127.0.0.1:5200"

# profile -> (expected allowed for attacker ancestor, expected rule subset)
EXPECTED: dict[str, tuple[bool, set[str]]] = {
    "none": (True, {"WS001"}),
    "xfo-deny": (False, set()),
    "xfo-sameorigin": (False, set()),
    "csp-none": (False, set()),
    "csp-self": (False, set()),
    "csp-partner-allowlist": (False, set()),
    "xfo-csp-consistent": (False, {"WS012"}),
    "xfo-csp-conflict": (False, {"WS005"}),
    "broken-invalid-xfo": (True, {"WS004", "WS001"}),
    "broken-duplicate-xfo": (False, {"WS003"}),
    "broken-wide-csp": (True, {"WS007"}),
    "broken-duplicate-csp": (False, {"WS006"}),
    "csp-report-only": (True, {"WS008", "WS001"}),
}


def start_victim(workspace: Path, profile: str) -> int:
    settings = replace(load_settings(), database_path=workspace / "victim.sqlite3")
    app = create_victim_app(settings=settings, test_config={"DEFENSE_PROFILE": profile})
    with app.app_context():
        db.create_all()
        seed_lab_data()
    server = make_server("127.0.0.1", 0, app)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Dump every result as JSON")
    args = parser.parse_args()

    # Build the auditor app once so the corpus/API path also gets exercised.
    auditor_app = create_auditor_app(test_config={"TESTING": True})
    failures: list[str] = []

    for profile, (expected_allowed, expected_rules) in EXPECTED.items():
        workspace = Path(tempfile.mkdtemp(prefix=f"websec-m6-{profile}-"))
        port = start_victim(workspace, profile)
        target = f"http://127.0.0.1:{port}/login"

        fetched = fetch_response(target)
        result = analyze_response(
            headers=fetched.headers,
            set_cookies=fetched.set_cookies,
            target_url=target,
            ancestors=[ATTACKER_ANCESTOR],
            redirect_chain=fetched.redirect_chain,
            final_url=fetched.final_url,
        )

        decision = result.decisions[0]
        fired = {finding.rule_id for finding in result.findings}
        ok_allowed = decision.allowed is expected_allowed
        ok_rules = expected_rules <= fired

        # Cross-check the same analysis through the service API (fetch mode).
        with auditor_app.test_client() as client:
            api = client.get(
                "/api/analyze",
                query_string={"url": target, "ancestor": ATTACKER_ANCESTOR},
            )
            api_payload = api.get_json()
        ok_api = api.status_code == 200 and (
            api_payload["decisions"][0]["allowed"] is expected_allowed
        )

        status = "ok" if (ok_allowed and ok_rules and ok_api) else "FAIL"
        verdict = "allowed" if decision.allowed else "blocked"
        print(
            f"profile={profile:<26} static={verdict:<8} rules={sorted(fired)} "
            f"risk={result.risk['score']:<3} api={ok_api} -> {status}"
        )
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        if status == "FAIL":
            failures.append(
                f"{profile}: expected allowed={expected_allowed} rules⊇{sorted(expected_rules)}, "
                f"got allowed={decision.allowed} rules={sorted(fired)} api_ok={ok_api} "
                f"detail={decision.detail}"
            )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        raise SystemExit(1)

    print("m6 smoke: static verdicts match the defense matrix on all profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
