"""Combined audit reports merging static (M6) and dynamic (M7) results (M8).

One call runs both analyzers against the same target, computes the
static/dynamic consistency verdict, and renders JSON / Markdown / HTML
deliverables. The HTML report is self-contained: screenshots are embedded
as base64 so a single file can be attached to the course report or opened
anywhere as evidence.
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from websec_lab.auditor.analyzer import AnalysisResult, analyze_response
from websec_lab.auditor.dynamic.models import DynamicAuditResult
from websec_lab.auditor.dynamic.runner import (
    DynamicAuditConfig,
    LoginConfig,
    StateCheckConfig,
    run_dynamic_audit,
)
from websec_lab.auditor.fetch import fetch_response
from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.origins import parse_origin
from websec_lab.transport import local_get

VERDICT_LABELS = {
    "vulnerable": "本次测试已验证敏感操作被触发",
    "protected": "本次测试来源的 iframe 嵌入被浏览器阻断",
    "partial": "页面可嵌入，本次点击未触发敏感操作，原因尚未确定",
    "embeddable": "页面可嵌入，尚未验证敏感操作是否可被触发",
    "inconclusive": "证据不足，无法下结论",
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class CombinedReport:
    run_id: str
    target_url: str
    created_at: str = field(default_factory=_utc_now)
    static: dict[str, object] = field(default_factory=dict)
    probe_static: dict[str, object] = field(default_factory=dict)
    dynamic: dict[str, object] | None = None
    consistency: dict[str, object] = field(default_factory=dict)
    overall: dict[str, object] = field(default_factory=dict)
    evidence: dict[str, str] = field(default_factory=dict)  # name -> path
    signals: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "target_url": self.target_url,
            "created_at": self.created_at,
            "static": self.static,
            "probe_static": self.probe_static,
            "dynamic": self.dynamic,
            "consistency": dict(self.consistency),
            "overall": dict(self.overall),
            "evidence": dict(self.evidence),
            "signals": self.signals,
        }


def _static_framing_verdict(static: AnalysisResult) -> str | None:
    if not static.decisions:
        return None
    return "allowed" if static.decisions[0].allowed else "blocked"


def _compute_consistency(
    static_verdict: str | None, dynamic_verdict: str | None
) -> dict[str, object]:
    if static_verdict not in {"allowed", "blocked"} or dynamic_verdict not in {
        "allowed",
        "blocked",
    }:
        agree = None
    else:
        agree = static_verdict == dynamic_verdict
    return {
        "static_framing": static_verdict,
        "dynamic_framing": dynamic_verdict,
        "agree": agree,
        "note": (
            "静态响应头判定与真实浏览器嵌入行为一致"
            if agree
            else (
                "静态与动态判定不一致，需要人工核查（例如 Report-Only 或依赖会话的行为差异）"
                if agree is False
                else "缺少一侧结果，无法比对"
            )
        ),
    }


def _overall_verdict(
    static_verdict: str | None,
    dynamic_verdict: str | None,
    click_triggered: bool | None,
) -> str:
    if click_triggered is True:
        return "vulnerable"
    if dynamic_verdict == "blocked":
        return "protected"
    if click_triggered is False and dynamic_verdict == "allowed":
        return "partial"
    if dynamic_verdict == "allowed":
        return "embeddable"
    # A static prediction alone cannot prove either exploitability or protection.
    return "inconclusive"


def run_combined_audit(
    target_url: str,
    ancestors: list[str],
    click: bool = False,
    login: LoginConfig | None = None,
    state_check: StateCheckConfig | None = None,
    browser_channel: str = "chrome",
    viewport_profile: str = "desktop",
    evidence_root: Path | None = None,
    poll_timeout_s: float = 10.0,
    harness_port: int = 0,
    probe_origin: str | None = None,
    scenario: str = "overlay",
) -> CombinedReport:
    """Run static + dynamic audits on one target and merge the evidence."""

    run_id = uuid.uuid4().hex[:12]
    report = CombinedReport(run_id=run_id, target_url=target_url)

    # ---- static pass (M6) ----
    fetched = fetch_response(target_url)
    static_result = analyze_response(
        headers=fetched.headers,
        set_cookies=fetched.set_cookies,
        target_url=target_url,
        ancestors=ancestors,
        redirect_chain=fetched.redirect_chain,
        final_url=fetched.final_url,
    )
    report.static = static_result.as_dict()

    static_verdict = _static_framing_verdict(static_result)

    # ---- dynamic pass (M7) ----
    dynamic_result: DynamicAuditResult | None = None
    try:
        config = DynamicAuditConfig(
            target_url=target_url,
            clickjacking=click,
            login=login,
            state_check=state_check,
            browser_channel=browser_channel,
            viewport_profile=viewport_profile,
            poll_timeout_s=poll_timeout_s,
            harness_port=harness_port,
            probe_origin=probe_origin,
            scenario=scenario,
        )
        if evidence_root is not None:
            config.evidence_root = evidence_root
        dynamic_result = run_dynamic_audit(config)
        report.dynamic = dynamic_result.as_dict()
    except Exception as exc:  # noqa: BLE001 - dynamic audit is best-effort here
        report.dynamic = {"errors": [repr(exc)]}

    dynamic_verdict = None
    click_triggered: bool | None = None
    if dynamic_result is not None and dynamic_result.framing is not None:
        dynamic_verdict = dynamic_result.framing.verdict
        if dynamic_result.clickjacking is not None:
            click_triggered = dynamic_result.clickjacking.sensitive_action_triggered

    # Retain the caller's requested chain in `static`, but compare the browser
    # only with a prediction for its ACTUAL origin and document response.
    probe_verdict = None
    probe_origin = dynamic_result.probe_origin if dynamic_result is not None else None
    response_basis = "unavailable"
    if probe_origin and dynamic_result.framing is not None:
        response = dynamic_result.framing.signals.get("document_response")
        if response:
            observed_url = str(response["url"])
            observed_headers = HeaderMap(response["headers"])
            observed_cookies = tuple(observed_headers.getlist("set-cookie"))
            response_basis = "browser_document_response"
        else:
            observed_url = fetched.final_url
            observed_headers = fetched.headers
            observed_cookies = fetched.set_cookies
            response_basis = "unauthenticated_http_fetch"
        probe_analysis = analyze_response(
            headers=observed_headers,
            set_cookies=observed_cookies,
            target_url=target_url,
            ancestors=[probe_origin],
            final_url=observed_url,
        )
        report.probe_static = probe_analysis.as_dict()
        probe_verdict = _static_framing_verdict(probe_analysis)

    report.consistency = _compute_consistency(probe_verdict, dynamic_verdict)
    requested_chain = [str(parse_origin(origin)) for origin in ancestors]
    observed_chain = [str(parse_origin(probe_origin))] if probe_origin else []
    report.consistency.update(
        requested_ancestors=requested_chain,
        observed_ancestors=observed_chain,
        requested_static_framing=static_verdict,
        source_matches_request=requested_chain == observed_chain,
        response_basis=response_basis,
    )
    if response_basis != "browser_document_response":
        report.consistency["agree"] = None
        report.consistency["note"] = "未取得浏览器文档响应，静态预测仅供参考，未确认一致性"
    errors = (report.dynamic or {}).get("errors") or []
    if errors:
        report.consistency["agree"] = None
        report.consistency["note"] = "动态审计未完整完成，不能确认一致性"
    verdict = (
        "inconclusive"
        if errors
        else _overall_verdict(probe_verdict, dynamic_verdict, click_triggered)
    )
    report.overall = {
        "verdict": verdict,
        "label": VERDICT_LABELS[verdict],
        "static_risk": static_result.risk,
        "clickjacking_triggered": click_triggered,
        "scope": "仅针对报告中的实际来源、浏览器及本次测试操作，不代表所有攻击均已排除",
    }

    if dynamic_result is not None and dynamic_result.evidence_dir:
        for name in (
            "framing_probe.png",
            "clickjacking_before.png",
            "clickjacking_after.png",
            "hijack_points.png",
            "console_log.json",
            "result.json",
        ):
            candidate = Path(dynamic_result.evidence_dir) / name
            if candidate.exists():
                report.evidence[name] = str(candidate)

    marker = parse_qs(urlsplit(target_url).query).get("lab_run", [""])[0]
    if marker and state_check is not None:
        try:
            response = local_get(
                f"{state_check.victim_origin}/telemetry/runs/{marker}",
                headers={"X-Websec-Test-Token": state_check.token},
                timeout=5,
            )
            response.raise_for_status()
            report.signals = response.json()
        except Exception as exc:
            report.signals = {"error": str(exc)}
    return report


# ---------------------------------------------------------------------------
# writers
# ---------------------------------------------------------------------------


def write_json_report(report: CombinedReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_markdown_report(report: CombinedReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    static = report.static
    dynamic = report.dynamic or {}
    overall = report.overall
    consistency = report.consistency

    lines: list[str] = []
    lines.append("# WebSec 点击劫持审计报告")
    lines.append("")
    lines.append(f"- 运行编号：`{report.run_id}`")
    lines.append(f"- 目标：`{report.target_url}`")
    lines.append(f"- 生成时间：{report.created_at}")
    lines.append(
        f"- **总体结论：{overall.get('label', '-')}（verdict: {overall.get('verdict')}）**"
    )
    if overall.get("static_risk"):
        risk = overall["static_risk"]
        lines.append(f"- 静态风险评分：**{risk.get('score')}（{risk.get('grade')}）**")
    lines.append("")

    lines.append("## 静态 / 动态一致性")
    lines.append("")
    lines.append("| 静态判定 | 动态判定 | 一致 |")
    lines.append("|---|---|---|")
    agree = consistency.get("agree")
    agree_text = {"true": "✅", "false": "❌"}.get(str(agree).lower(), "—")
    lines.append(
        f"| {consistency.get('static_framing') or '-'} "
        f"| {consistency.get('dynamic_framing') or '-'} | {agree_text} |"
    )
    lines.append("")
    lines.append(f"> {consistency.get('note', '')}")
    lines.append(f"- 请求的祖先链：{consistency.get('requested_ancestors', [])}")
    lines.append(f"- 实际测试祖先链：{consistency.get('observed_ancestors', [])}")
    lines.append(f"- 对照响应来源：{consistency.get('response_basis', 'unavailable')}")
    lines.append(f"- 结论范围：{overall.get('scope', '')}")
    lines.append("")

    lines.append("## 动态验证结果")
    lines.append("")
    framing = dynamic.get("framing")
    if framing:
        lines.append(
            f"- 嵌入判定：**{framing.get('verdict')}**"
            f"（阻断机制：{', '.join(framing.get('blocked_by') or []) or '-'}）"
        )
    click = dynamic.get("clickjacking")
    if click:
        triggered = click.get("sensitive_action_triggered")
        lines.append(
            f"- 坐标点击验证：敏感操作被触发 = "
            f"**{'是 ⚠️' if triggered else '否' if triggered is False else '未执行'}**"
            f"（点击后观察到 iframe 重载：{'是' if click.get('iframe_reloaded') else '否'}）"
        )
    for error in dynamic.get("errors") or []:
        lines.append(f"- 动态审计错误：{error}")
    if not framing and not click and not dynamic.get("errors"):
        lines.append("未取得动态审计结果。")
    lines.append("")

    if report.signals.get("analysis"):
        analysis = report.signals["analysis"]
        lines.extend(
            [
                "## 双通道观察",
                "",
                "| CSP报告 | 交互启发式 | 联合观察 | 风险 |",
                "|---|---|---|---|",
                f"| {analysis.get('csp_detected')} | {analysis.get('interaction_detected')} "
                f"| {analysis.get('fused_detected')} | {analysis.get('risk')} |",
                "",
                f"事件数：{analysis.get('event_count')}；"
                f"可疑点击数：{analysis.get('suspicious_click_count')}。",
                "信号用于定位可疑交互；敏感操作是否执行以独立业务状态为准。",
                "",
            ]
        )
    lines.append("## 静态分析发现")
    lines.append("")
    findings = static.get("findings") or []
    if findings:
        lines.append("| 规则 | 等级 | 说明 | 证据 | 修复建议 |")
        lines.append("|---|---|---|---|---|")
        for finding in findings:
            lines.append(
                f"| {finding['rule_id']} | {finding['severity']} "
                f"| {finding['title']} | {finding['evidence']} | {finding['remediation']} |"
            )
    else:
        lines.append("未触发任何规则。")
    lines.append("")

    lines.append("## 响应头与来源权限矩阵")
    lines.append("")
    headers = static.get("headers") or {}
    lines.append("```json")
    lines.append(json.dumps(headers, indent=2, ensure_ascii=False))
    lines.append("```")
    lines.append("")
    matrix = static.get("permission_matrix") or []
    if matrix:
        lines.append("| 来源 | 允许嵌入 | 阻断机制 |")
        lines.append("|---|---|---|")
        for row in matrix:
            lines.append(
                f"| {row['origin']} | {'✅' if row['allowed'] else '❌'} "
                f"| {', '.join(row['blocked_by']) or '-'} |"
            )
        lines.append("")

    if report.evidence:
        lines.append("## 证据文件")
        lines.append("")
        for name, evidence_path in report.evidence.items():
            lines.append(f"- `{name}` → `{evidence_path}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_report(report: CombinedReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    html = _render_html(report)
    path.write_text(html, encoding="utf-8")
    return path


def _image_data_uri(path_str: str) -> str | None:
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_file():
        return None
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _render_html(report: CombinedReport) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("auditor/report.html")

    dynamic = report.dynamic or {}
    screenshots = {
        "framing_probe": _image_data_uri(report.evidence.get("framing_probe.png", "")),
        "clickjacking_before": _image_data_uri(report.evidence.get("clickjacking_before.png", "")),
        "clickjacking_after": _image_data_uri(report.evidence.get("clickjacking_after.png", "")),
        "hijack_points": _image_data_uri(report.evidence.get("hijack_points.png", "")),
    }
    console_tail: list[dict] = []
    console_path = Path(report.evidence.get("console_log.json", ""))
    if console_path.is_file():
        try:
            console_tail = json.loads(console_path.read_text(encoding="utf-8"))[-15:]
        except (OSError, ValueError):
            console_tail = []

    return template.render(
        report=report,
        static=report.static,
        dynamic=dynamic,
        overall=report.overall,
        consistency=report.consistency,
        findings=report.static.get("findings") or [],
        matrix=report.static.get("permission_matrix") or [],
        hijack_points=dynamic.get("hijack_points") or [],
        screenshots=screenshots,
        console_tail=console_tail,
        risk=report.overall.get("static_risk") or {},
    )
