"""Two automated end-to-end demonstrations; this is not a human presentation rehearsal."""

import json
import tempfile
from pathlib import Path

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import run_combined_audit, write_html_report, write_json_report
from websec_lab.https_lab import HttpsLab

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / "artifacts/finalization/rehearsals"
    directory.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix="websec-rehearse-") as tmp:
        for round_number, browser in enumerate(("chrome", "firefox"), 1):
            for profile in ("https-samesite-none", "csp-none", "https-partner-allowlist"):
                with HttpsLab(profile, Path(tmp) / f"{round_number}-{profile}.sqlite3"):
                    origin = "https://victim.test:8443"
                    config = dict(
                        login=LoginConfig(origin, "alice", "alice-lab"),
                        browser_channel=browser,
                        poll_timeout_s=2,
                        evidence_root=directory / f"round-{round_number}" / profile,
                    )
                    report = run_combined_audit(
                        origin + "/lab/quick-transfer",
                        ["https://attacker.test:8443"],
                        click=True,
                        state_check=StateCheckConfig(origin, "alice", "local-lab-only"),
                        probe_origin="https://attacker.test:8443",
                        **config,
                    )
                    expected = "vulnerable" if profile == "https-samesite-none" else "protected"
                    assert report.overall["verdict"] == expected, report.overall
                    assert not report.dynamic["errors"]
                    write_json_report(report, directory / f"round-{round_number}-{profile}.json")
                    write_html_report(report, directory / f"round-{round_number}-{profile}.html")
                    if profile == "https-partner-allowlist":
                        partner = run_combined_audit(
                            origin + "/embed/profile-card",
                            ["https://partner.test:8443"],
                            probe_origin="https://partner.test:8443",
                            **config,
                        )
                        assert partner.overall["verdict"] == "embeddable"
                        assert (
                            "/embed/profile-card"
                            in partner.dynamic["framing"]["signals"]["loaded_frame_url"]
                        )
                    cases.append(
                        dict(
                            round=round_number,
                            browser=browser,
                            profile=profile,
                            verdict=expected,
                            passed=True,
                        )
                    )
    result = dict(
        automated_only=True, human_presentations_rehearsed=False, passed=True, cases=cases
    )
    (directory / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
