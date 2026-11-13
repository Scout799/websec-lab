"""Unit tests for the combined audit report (M8)."""

import json
from pathlib import Path

import pytest

from websec_lab.auditor import report as report_module
from websec_lab.auditor.dynamic.models import (
    ClickjackingResult,
    DynamicAuditResult,
    FrameCheckResult,
)
from websec_lab.auditor.fetch import FetchedResponse
from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.report import (
    VERDICT_LABELS,
    CombinedReport,
    _compute_consistency,
    _overall_verdict,
    run_combined_audit,
    write_html_report,
    write_json_report,
    write_markdown_report,
)


def _report() -> CombinedReport:
    return CombinedReport(
        run_id="abc123",
        target_url="http://victim.test:5100/lab/quick-transfer",
        static={
            "findings": [
                {
                    "rule_id": "WS001",
                    "severity": "high",
                    "title": "无任何嵌入防护",
                    "evidence": "no headers",
                    "remediation": "add XFO/CSP",
                }
            ],
            "headers": {"x-frame-options": []},
            "permission_matrix": [
                {"origin": "http://attacker.test:5200", "allowed": True, "blocked_by": []}
            ],
            "risk": {"score": 40, "grade": "high"},
        },
        dynamic={
            "framing": {"verdict": "allowed", "blocked_by": []},
            "clickjacking": {
                "sensitive_action_triggered": True,
                "iframe_reloaded": True,
            },
        },
        consistency=_compute_consistency("allowed", "allowed"),
        overall={
            "verdict": "vulnerable",
            "label": VERDICT_LABELS["vulnerable"],
            "static_risk": {"score": 40, "grade": "high"},
            "clickjacking_triggered": True,
        },
    )


def test_consistency_matrix() -> None:
    agree = _compute_consistency("blocked", "blocked")
    assert agree["agree"] is True
    assert "一致" in agree["note"]

    disagree = _compute_consistency("allowed", "blocked")
    assert disagree["agree"] is False
    assert "不一致" in disagree["note"]

    missing = _compute_consistency(None, "blocked")
    assert missing["agree"] is None


@pytest.mark.parametrize(
    ("static", "dynamic", "triggered", "expected"),
    [
        ("allowed", "allowed", True, "vulnerable"),
        ("blocked", "allowed", True, "vulnerable"),
        ("blocked", "blocked", False, "protected"),
        ("allowed", "blocked", None, "protected"),
        ("allowed", "allowed", False, "partial"),
        ("blocked", "allowed", None, "embeddable"),
        ("allowed", "allowed", None, "embeddable"),
        ("blocked", None, None, "inconclusive"),
        ("allowed", None, None, "inconclusive"),
        ("allowed", "unknown", False, "inconclusive"),
        (None, None, None, "inconclusive"),
    ],
)
def test_overall_verdict_branches(static, dynamic, triggered, expected) -> None:
    assert _overall_verdict(static, dynamic, triggered) == expected


@pytest.mark.parametrize(
    "static,dynamic", [(None, "blocked"), ("unknown", "unknown"), ("allowed", "unknown")]
)
def test_unknown_is_not_consistency(static, dynamic) -> None:
    assert _compute_consistency(static, dynamic)["agree"] is None


def _stub_audit(monkeypatch, *, errors=None, observed_response=True, raise_browser=False):
    """Use different unauthenticated/authenticated policies and ancestor origins."""
    target = "http://127.0.0.1:5100/lab/quick-transfer"
    probe = "http://127.0.0.1:65432"
    monkeypatch.setattr(
        report_module,
        "fetch_response",
        lambda _url: FetchedResponse(
            target,
            "http://127.0.0.1:5100/login",
            200,
            HeaderMap({"X-Frame-Options": "DENY"}),
            (),
        ),
    )
    signals = {}
    if observed_response:
        signals["document_response"] = {
            "url": target,
            "status": 200,
            "headers": {"content-security-policy": [f"frame-ancestors {probe}"]},
        }
    result = DynamicAuditResult(
        run_id="stub",
        target_url=target,
        probe_origin=probe,
        framing=FrameCheckResult(ancestor=probe, verdict="allowed", signals=signals),
        clickjacking=ClickjackingResult(True, False, False),
        errors=errors or [],
    )
    captured = {}

    def dynamic(config):
        captured["config"] = config
        if raise_browser:
            raise RuntimeError("browser unavailable")
        return result

    monkeypatch.setattr(report_module, "run_dynamic_audit", dynamic)
    return target, result, captured


def test_consistency_uses_actual_origin_and_browser_response(monkeypatch) -> None:
    target, _, captured = _stub_audit(monkeypatch)
    report = run_combined_audit(target, ancestors=["http://127.0.0.1:5200"])

    assert report.static["decisions"][0]["allowed"] is False
    assert report.probe_static["decisions"][0]["allowed"] is True
    assert report.consistency["agree"] is True
    assert report.consistency["source_matches_request"] is False
    assert report.consistency["observed_ancestors"] == ["http://127.0.0.1:65432"]
    assert report.consistency["response_basis"] == "browser_document_response"
    assert report.overall["verdict"] == "partial"
    assert captured["config"].evidence_root is not None


@pytest.mark.parametrize("raise_browser", [False, True])
def test_dynamic_failure_cannot_produce_definitive_verdict(monkeypatch, tmp_path, raise_browser):
    target, _, _ = _stub_audit(monkeypatch, errors=["click failed"], raise_browser=raise_browser)
    report = run_combined_audit(target, ancestors=["http://127.0.0.1:5200"])

    assert report.overall["verdict"] == "inconclusive"
    assert report.consistency["agree"] is None
    md = write_markdown_report(report, tmp_path / "failed.md").read_text(encoding="utf-8")
    html = write_html_report(report, tmp_path / "failed.html").read_text(encoding="utf-8")
    assert "动态审计错误" in md and "动态审计错误" in html


def test_missing_browser_headers_do_not_confirm_consistency(monkeypatch) -> None:
    target, _, _ = _stub_audit(monkeypatch, observed_response=False)
    report = run_combined_audit(target, ancestors=["http://127.0.0.1:5200"])
    assert report.consistency["agree"] is None
    assert report.consistency["response_basis"] == "unauthenticated_http_fetch"


def test_harness_port_and_evidence_root_forwarded(monkeypatch, tmp_path) -> None:
    target, _, captured = _stub_audit(monkeypatch)
    run_combined_audit(target, [], evidence_root=tmp_path, harness_port=54321)
    assert captured["config"].harness_port == 54321
    assert captured["config"].evidence_root == tmp_path


def test_json_writer_roundtrip(tmp_path: Path) -> None:
    path = write_json_report(_report(), tmp_path / "out" / "report.json")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "abc123"
    assert payload["overall"]["verdict"] == "vulnerable"
    assert payload["consistency"]["agree"] is True


def test_markdown_writer_contains_sections(tmp_path: Path) -> None:
    path = write_markdown_report(_report(), tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")

    assert "WebSec 点击劫持审计报告" in text
    assert "静态 / 动态一致性" in text
    assert "WS001" in text
    assert "来源权限矩阵" in text
    assert "✅" in text


def test_html_writer_is_self_contained(tmp_path: Path) -> None:
    path = write_html_report(_report(), tmp_path / "report.html")
    html = path.read_text(encoding="utf-8")

    assert VERDICT_LABELS["vulnerable"] in html
    assert "WS001" in html
    assert "verdict vulnerable" in html
    assert html.startswith("<!doctype html>")
    # No external references: everything must live in this one file.
    assert 'src="http' not in html
    assert "<link" not in html


def test_html_writer_without_dynamic_section(tmp_path: Path) -> None:
    report = CombinedReport(run_id="x", target_url="http://victim.test:5100/login")
    report.static = {"findings": [], "headers": {}, "permission_matrix": []}
    report.consistency = _compute_consistency("blocked", None)
    report.overall = {"verdict": "protected", "label": "当前策略有效阻断点击劫持"}

    path = write_html_report(report, tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")

    assert "protected" in html
    assert "风险发现" not in html


def test_html_handles_explicit_null_click_result(tmp_path: Path) -> None:
    report = _report()
    report.dynamic["clickjacking"] = None
    assert "未执行" in write_html_report(report, tmp_path / "null.html").read_text(encoding="utf-8")
