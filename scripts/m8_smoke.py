"""M8 smoke: combined audit reports across defense profiles.

For each profile the script starts a fresh victim, runs the combined
audit (static M6 + dynamic M7 in one call) and verifies the three report
formats land on disk with the expected verdict and embedded evidence.

Usage:
    python scripts/m8_smoke.py
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

from werkzeug.serving import make_server

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import (
    run_combined_audit,
    write_html_report,
    write_json_report,
    write_markdown_report,
)
from websec_lab.config import load_settings
from websec_lab.extensions import db
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

# profile -> expected overall verdict
EXPECTED: dict[str, str] = {
    "none": "vulnerable",
    "xfo-deny": "protected",
    "confirm-reconfirm": "partial",
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
    parser.add_argument("--out", type=Path, help="Keep reports and evidence in this directory")
    args = parser.parse_args()
    reports_root = args.out or Path(tempfile.mkdtemp(prefix="websec-m8-"))
    failures: list[str] = []

    for profile, expected_verdict in EXPECTED.items():
        workspace = Path(tempfile.mkdtemp(prefix=f"websec-m8-{profile}-"))
        port = start_victim(workspace, profile)
        origin = f"http://127.0.0.1:{port}"

        report = run_combined_audit(
            target_url=f"{origin}/lab/quick-transfer",
            ancestors=["http://127.0.0.1:5200"],
            click=True,
            login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
            state_check=StateCheckConfig(
                victim_origin=origin, username="alice", token="test-token"
            ),
            evidence_root=reports_root,
            poll_timeout_s=8.0,
        )

        out_dir = reports_root / f"{profile}-report"
        json_path = write_json_report(report, out_dir / "report.json")
        md_path = write_markdown_report(report, out_dir / "report.md")
        html_path = write_html_report(report, out_dir / "report.html")

        ok_verdict = report.overall["verdict"] == expected_verdict
        ok_consistency = report.consistency["agree"] is True
        ok_files = all(
            path.exists() and path.stat().st_size > 0 for path in (json_path, md_path, html_path)
        )
        html = html_path.read_text(encoding="utf-8")
        ok_evidence = "data:image/png;base64," in html and "攻击前" in html

        status = "ok" if ok_verdict and ok_consistency and ok_files and ok_evidence else "FAIL"
        print(
            f"profile={profile:<18} verdict={report.overall['verdict']:<12} "
            f"agree={report.consistency['agree']} files={ok_files} "
            f"screenshots_embedded={ok_evidence} -> {status}"
        )
        if status == "FAIL":
            failures.append(
                f"{profile}: verdict={report.overall['verdict']} "
                f"agree={report.consistency['agree']} files={ok_files} evidence={ok_evidence} "
                f"errors={report.dynamic.get('errors')}"
            )

    # Show where the sample reports live for the course deliverable.
    sample = reports_root / "none-report"
    print(f"sample reports: {sample}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        raise SystemExit(1)
    print("m8 smoke: combined reports generated and verified for all profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
