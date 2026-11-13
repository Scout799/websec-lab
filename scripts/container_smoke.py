"""Real Linux/container smoke: verified TLS, browser trust and partner isolation."""

import json

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import run_combined_audit, write_json_report
from websec_lab.config import repository_root
from websec_lab.https_lab import HOSTS, https_get


def main():
    for host in HOSTS:
        assert https_get(host)[0] == 200
    target = "https://victim.test:8443/lab/quick-transfer"
    report = run_combined_audit(
        target,
        ["https://attacker.test:8443"],
        click=True,
        login=LoginConfig("https://victim.test:8443", "alice", "alice-lab"),
        state_check=StateCheckConfig("https://victim.test:8443", "alice", "local-lab-only"),
        probe_origin="https://attacker.test:8443",
        poll_timeout_s=2,
    )
    assert report.overall["verdict"] == "protected", report.as_dict()
    partner = run_combined_audit(
        "https://victim.test:8443/embed/profile-card",
        ["https://partner.test:8443"],
        login=LoginConfig("https://victim.test:8443", "alice", "alice-lab"),
        probe_origin="https://partner.test:8443",
        poll_timeout_s=2,
    )
    write_json_report(partner, repository_root() / "artifacts/container-partner.json")
    write_json_report(report, repository_root() / "artifacts/container-attack.json")
    assert partner.overall["verdict"] == "embeddable", partner.as_dict()
    assert "/embed/profile-card" in partner.dynamic["framing"]["signals"]["loaded_frame_url"]
    print(
        json.dumps(
            {
                "gateway_hosts": len(HOSTS),
                "attack": report.overall["verdict"],
                "partner": partner.overall["verdict"],
                "browser": partner.dynamic["browser"],
            }
        )
    )


if __name__ == "__main__":
    main()
