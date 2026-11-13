import json

import pytest

from websec_lab import cli


def test_config_command_prints_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["config"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["project_name"] == "WebSec Clickjacking Lab"
    assert payload["local_only"] is True
    assert set(payload["services"]) == {"victim", "attacker", "partner", "auditor"}


def test_run_command_uses_service_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class FakeApp:
        def run(self, **kwargs: object) -> None:
            calls.update(kwargs)

    monkeypatch.setattr(cli, "create_app", lambda *_args, **_kwargs: FakeApp())

    exit_code = cli.main(["run", "victim"])

    assert exit_code == 0
    assert calls == {
        "host": "127.0.0.1",
        "port": 5100,
        "debug": False,
        "use_reloader": False,
    }


def test_run_command_accepts_network_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class FakeApp:
        def run(self, **kwargs: object) -> None:
            calls.update(kwargs)

    monkeypatch.setattr(cli, "create_app", lambda *_args, **_kwargs: FakeApp())

    cli.main(["run", "auditor", "--host", "127.0.0.2", "--port", "5499", "--debug"])

    assert calls["host"] == "127.0.0.2"
    assert calls["port"] == 5499
    assert calls["debug"] is True


def test_doctor_reports_discovered_browsers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeBrowser:
        def as_dict(self) -> dict[str, str]:
            return {"name": "Test Browser", "executable_path": "test.exe"}

    monkeypatch.setattr(cli, "discover_browsers", lambda: [FakeBrowser()])

    exit_code = cli.main(["doctor"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["browsers"][0]["name"] == "Test Browser"


def test_parser_rejects_an_unknown_service() -> None:
    with pytest.raises(SystemExit):
        cli.main(["run", "unknown"])


@pytest.mark.parametrize("verdict,code", [("inconclusive", 1), ("embeddable", 0)])
def test_audit_report_exit_status_matches_evidence(monkeypatch, tmp_path, verdict, code) -> None:
    from websec_lab.auditor import report as report_module

    report = report_module.CombinedReport(run_id="cli-regression", target_url="http://v.test/")
    report.dynamic = {
        "framing": None,
        "clickjacking": None,
        "errors": ["browser unavailable"] if code else [],
    }
    report.overall = {"verdict": verdict, "label": report_module.VERDICT_LABELS[verdict]}
    monkeypatch.setattr(report_module, "run_combined_audit", lambda **_kwargs: report)
    result = cli.main(["audit-report", "http://v.test/", "--no-login", "--out", str(tmp_path)])
    assert result == code
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
