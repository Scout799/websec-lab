"""M7 smoke: full dynamic audits across the M5 defense matrix.

For each profile the script starts a fresh victim, runs the complete
dynamic audit chain (login with saved session, multi-signal framing
verdict, coordinate click, business-state verification, evidence dump)
and checks the outcomes against the expectations already established by
the M5 (real attack) and M6 (static) smokes. One case additionally runs
on a mobile viewport and one with tracing enabled to prove those paths.

Usage:
    python scripts/m7_smoke.py
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

from werkzeug.serving import make_server

from websec_lab.auditor.dynamic import (
    DynamicAuditConfig,
    LoginConfig,
    StateCheckConfig,
    run_dynamic_audit,
)
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

# profile -> (framing verdict, blocked_by subset, clickjacking triggered)
EXPECTED: dict[str, tuple[str, set[str], bool]] = {
    "none": ("allowed", set(), True),
    "xfo-deny": ("blocked", {"xfo"}, False),
    "csp-none": ("blocked", {"csp"}, False),
    "csp-partner-allowlist": ("blocked", {"csp"}, False),
    "confirm-reconfirm": ("allowed", set(), False),
    "confirm-token": ("allowed", set(), True),
    "frame-busting-hidden": ("allowed", set(), False),
}


def start_victim(workspace: Path, profile: str) -> int:
    settings = replace(load_settings(), database_path=workspace / "victim.sqlite3")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Dump each result as JSON")
    args = parser.parse_args()

    evidence_root = Path(tempfile.mkdtemp(prefix="websec-m7-"))
    failures: list[str] = []

    for index, (profile, (verdict, blocked_by, triggered)) in enumerate(EXPECTED.items()):
        workspace = Path(tempfile.mkdtemp(prefix=f"websec-m7-{profile}-"))
        port = start_victim(workspace, profile)
        origin = f"http://127.0.0.1:{port}"

        config = DynamicAuditConfig(
            target_url=f"{origin}/lab/quick-transfer",
            clickjacking=True,
            login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
            state_check=StateCheckConfig(
                victim_origin=origin, username="alice", token="test-token"
            ),
            evidence_root=evidence_root,
            poll_timeout_s=8.0,
            viewport_profile="mobile" if profile == "none" else "desktop",
            trace=index == 0,  # one traced run proves the trace pipeline
        )
        result = run_dynamic_audit(config)

        ok_framing = (
            result.framing is not None
            and result.framing.verdict == verdict
            and blocked_by <= set(result.framing.blocked_by)
        )
        ok_click = (
            result.clickjacking is not None
            and result.clickjacking.sensitive_action_triggered is triggered
        )
        ok_login = result.login.success is True
        ok_evidence = (Path(result.evidence_dir) / "result.json").exists()
        ok = ok_framing and ok_click and ok_login and ok_evidence and not result.errors

        view = result.viewport.get("profile", "?")
        click = result.clickjacking.sensitive_action_triggered if result.clickjacking else None
        print(
            f"profile={profile:<24} framing={verdict:<8} click_triggered={click} "
            f"viewport={view} login={ok_login} evidence=ok -> {'ok' if ok else 'FAIL'}"
        )
        if args.json:
            print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
        if not ok:
            signals = result.framing.signals if result.framing else None
            failures.append(
                f"{profile}: framing={ok_framing} click={ok_click} login={ok_login} "
                f"errors={result.errors} signals={signals}"
            )

    # Verify the traced run actually produced a trace archive.
    trace_files = list(evidence_root.glob("*/trace.zip"))
    if not trace_files:
        failures.append("no trace.zip produced by the traced run")

    # Legitimate-source embedding (T0705): bind the harness to the partner
    # loopback origin that the allowlist profile permits — the same profile
    # blocked the ephemeral harness origin above.
    workspace = Path(tempfile.mkdtemp(prefix="websec-m7-legit-"))
    port = start_victim(workspace, "csp-partner-allowlist")
    origin = f"http://127.0.0.1:{port}"
    legit = run_dynamic_audit(
        DynamicAuditConfig(
            target_url=f"{origin}/lab/quick-transfer",
            clickjacking=False,
            login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
            state_check=StateCheckConfig(
                victim_origin=origin, username="alice", token="test-token"
            ),
            evidence_root=evidence_root,
            poll_timeout_s=8.0,
            harness_port=5300,
        )
    )
    legit_ok = legit.framing is not None and legit.framing.verdict == "allowed" and not legit.errors
    legit_verdict = legit.framing.verdict if legit.framing else "?"
    print(
        f"profile=csp-partner-allowlist      framing={legit_verdict} "
        f"harness=127.0.0.1:5300 (legit origin) -> {'ok' if legit_ok else 'FAIL'}"
    )
    if not legit_ok:
        failures.append(f"legitimate source: verdict={legit_verdict} errors={legit.errors}")

    # CLI smoke: websec-lab audit against one blocked profile.
    workspace = Path(tempfile.mkdtemp(prefix="websec-m7-cli-"))
    port = start_victim(workspace, "xfo-deny")
    from websec_lab import cli

    cli_exit = cli.main(
        [
            "audit",
            f"http://127.0.0.1:{port}/login",
            "--no-login",
            "--json",
        ]
    )
    if cli_exit != 0:
        failures.append(f"CLI audit exited with {cli_exit}")
    else:
        print("cli_audit=ok (xfo-deny /login)")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        raise SystemExit(1)

    print("m7 smoke: dynamic audits match expectations on all profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
