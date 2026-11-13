"""M9 experiment runner: execute the matrix and emit data + charts.

Every case runs against a freshly started victim (and, for legitimate-
embedding cases, a partner site) so experiments never share state; the
attack cases reuse the combined M8 audit so each row carries both the
static verdict and the real-browser outcome with full evidence.
"""

from __future__ import annotations

import csv
import json
import platform
import sys
import tempfile
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import run_combined_audit
from websec_lab.config import load_settings
from websec_lab.experiments.charts import (
    attack_outcome_chart,
    metric_cards_chart,
    write_chart,
)
from websec_lab.experiments.matrix import ExperimentCase, ExperimentSpec
from websec_lab.experiments.metrics import ExperimentRow, compute_metrics
from websec_lab.extensions import db
from websec_lab.partner import create_app as create_partner_app
from websec_lab.victim import create_app as create_victim_app
from websec_lab.victim.services import seed_lab_data

TEST_TOKEN = "test-token"


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_victim(workspace: Path, profile: str, partner_port: int | None) -> int:
    base = load_settings()
    services = dict(base.services)
    if partner_port is not None:
        partner_cfg = base.service("partner")
        services["partner"] = replace(
            partner_cfg,
            port=partner_port,
            public_origin=f"http://127.0.0.1:{partner_port}",
        )
    settings = replace(base, database_path=workspace / "victim.sqlite3", services=services)
    app = create_victim_app(
        settings=settings,
        test_config={"DEFENSE_PROFILE": profile, "TEST_API_TOKEN": TEST_TOKEN},
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()
    server_host = "127.0.0.1"
    from werkzeug.serving import make_server

    server = make_server(server_host, 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def _start_partner(victim_origin: str, port: int) -> int:
    from werkzeug.serving import make_server

    app = create_partner_app(test_config={"TESTING": True, "WALLET_VICTIM_ORIGIN": victim_origin})
    server = make_server("127.0.0.1", port, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def _run_attack_case(
    case: ExperimentCase, spec: ExperimentSpec, evidence_root: Path, browser_channel: str
) -> tuple[ExperimentRow, dict[str, object]]:
    workspace = Path(tempfile.mkdtemp(prefix=f"websec-m9-{case.case_id}-"))
    vport = _start_victim(workspace, case.profile, partner_port=None)
    origin = f"http://127.0.0.1:{vport}"

    started = time.monotonic()
    report = run_combined_audit(
        target_url=f"{origin}{spec.target_path}",
        ancestors=["http://127.0.0.1:5200"],
        click=True,
        login=LoginConfig(origin=origin, username="alice", password="alice-lab"),
        state_check=StateCheckConfig(victim_origin=origin, username="alice", token=TEST_TOKEN),
        browser_channel=browser_channel,
        viewport_profile=case.viewport,
        evidence_root=evidence_root,
        poll_timeout_s=8.0,
        scenario=case.scenario,
    )
    duration = round(time.monotonic() - started, 2)

    consistency = report.consistency
    static_framing = consistency.get("static_framing")
    dynamic_framing = consistency.get("dynamic_framing")
    row = ExperimentRow(
        case_id=case.case_id,
        kind="attack",
        profile=case.profile,
        scenario=case.scenario,
        viewport=case.viewport,
        repeat=case.repeat,
        static_framing=static_framing,
        dynamic_framing=dynamic_framing,
        attack_triggered=report.overall.get("clickjacking_triggered"),
        agree=consistency.get("agree"),
        static_flagged_vulnerable=(
            static_framing == "allowed" if static_framing in {"allowed", "blocked"} else None
        ),
        duration_s=duration,
        ok=not (report.dynamic or {}).get("errors"),
        detail=report.overall.get("verdict", ""),
    )
    return row, report.as_dict()


def _run_legit_case(case: ExperimentCase) -> ExperimentRow:
    from playwright.sync_api import sync_playwright

    from websec_lab.browser import discover_browsers

    workspace = Path(tempfile.mkdtemp(prefix=f"websec-m9-{case.case_id}-"))
    partner_port = _free_port()
    vport = _start_victim(workspace, case.profile, partner_port)
    victim_origin = f"http://127.0.0.1:{vport}"
    pport = _start_partner(victim_origin, partner_port)

    installed = [item for item in discover_browsers() if item.channel in {"chrome", "msedge"}]
    if not installed:
        return ExperimentRow(
            case_id=case.case_id,
            kind="legit",
            profile=case.profile,
            scenario=case.scenario,
            viewport=case.viewport,
            repeat=case.repeat,
            ok=False,
            detail="no local browser",
        )

    started = time.monotonic()
    loaded = False
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(installed[0].executable_path), headless=True
        )
        page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
        try:
            page.goto(f"{victim_origin}/login")
            page.get_by_label("用户名").fill("alice")
            page.get_by_label("密码").fill("alice-lab")
            page.get_by_role("button", name="登录").click()
            page.get_by_role("heading", name="你好，alice").wait_for()
            page.goto(f"http://127.0.0.1:{pport}/wallet")
            try:
                page.frame_locator("#bank-component").get_by_text("账户余额", exact=False).wait_for(
                    state="visible", timeout=12_000
                )
                loaded = True
            except Exception:
                loaded = False
        finally:
            browser.close()

    return ExperimentRow(
        case_id=case.case_id,
        kind="legit",
        profile=case.profile,
        scenario=case.scenario,
        viewport=case.viewport,
        repeat=case.repeat,
        partner_embed_loaded=loaded,
        duration_s=round(time.monotonic() - started, 2),
        ok=True,
        detail="loaded" if loaded else "blocked",
    )


CSV_COLUMNS = [
    "case_id",
    "kind",
    "profile",
    "scenario",
    "viewport",
    "repeat",
    "static_framing",
    "dynamic_framing",
    "attack_triggered",
    "agree",
    "static_flagged_vulnerable",
    "partner_embed_loaded",
    "duration_s",
    "ok",
    "detail",
]


def _write_csv(rows: list[ExperimentRow], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_dict())
    return path


def _write_summary_markdown(
    metrics: dict[str, object],
    environment: dict[str, object],
    rows: list[ExperimentRow],
    chart_files: list[str],
    path: Path,
) -> Path:
    lines: list[str] = []
    lines.append("# M9 实验结果摘要")
    lines.append("")
    lines.append(f"- 生成时间：{environment.get('finished_at')}")
    lines.append(f"- 浏览器：{environment.get('browser')}")
    lines.append(f"- Python：{environment.get('python')} · 平台：{environment.get('platform')}")
    totals = metrics.get("totals", {})
    lines.append(
        f"- 实验总数：{totals.get('rows')}（攻击 {totals.get('attack_rows')} / "
        f"合法嵌入 {totals.get('legit_rows')}）"
    )
    lines.append("")

    lines.append("## 核心指标")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    for key, label in (
        ("attack_success_rate", "总体攻击成功率"),
        ("illegal_embed_block_rate", "非法嵌入阻断率"),
        ("static_dynamic_consistency", "静态/动态一致率"),
        ("legit_embed_pass_rate", "合法嵌入通过率（白名单）"),
        ("legit_broken_under_deny_all", "全拒策略下合法业务受损率"),
    ):
        value = metrics.get(key)
        display = f"{value * 100:.1f}%" if isinstance(value, float) else "—"
        lines.append(f"| {label} | {display} |")
    detection = metrics.get("detection", {})
    if isinstance(detection, dict):
        rate = detection.get("detection_rate")
        display = f"{rate * 100:.1f}%" if isinstance(rate, float) else "—"
        lines.append(f"| 静态检测率（TP/(TP+FN)） | {display} |")
        lines.append(
            f"| 混淆矩阵 TP/FP/FN/TN | "
            f"{detection.get('true_positive')}/{detection.get('false_positive')}"
            f"/{detection.get('false_negative')}/{detection.get('true_negative')} |"
        )
    timing = metrics.get("timing", {})
    if isinstance(timing, dict):
        lines.append(f"| 平均单例耗时 | {timing.get('avg_case_seconds')} s |")
    lines.append("")

    lines.append("## 各防御配置的攻击结果")
    lines.append("")
    lines.append("| 防御 profile | 攻击实验数 | 嵌入被阻断 | 未证实触发 | 攻击成功 |")
    lines.append("|---|---|---|---|---|")
    for profile, stats in (metrics.get("per_profile") or {}).items():
        cases = stats["cases"]
        blocked = stats["dynamic_blocked"]
        triggered = stats["attack_triggered"]
        lines.append(
            f"| `{profile}` | {cases} | {blocked} | {cases - blocked - triggered} | {triggered} |"
        )
    lines.append("")

    if chart_files:
        lines.append("## 图表")
        lines.append("")
        for chart in chart_files:
            lines.append(f"![{chart}]({chart})")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def run_experiments(
    spec: ExperimentSpec,
    out_dir: Path,
    browser_channel: str = "chrome",
    quiet: bool = False,
) -> dict[str, object]:
    """Execute the whole matrix and write results, metrics and charts."""

    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_root = out_dir / "evidence"
    rows: list[ExperimentRow] = []
    raw_reports: list[dict[str, object]] = []
    started_at = datetime.now(UTC).isoformat()

    for case in spec.expand():
        if not quiet:
            print(f"case {case.case_id} ...", flush=True)
        if case.kind == "attack":
            row, report_payload = _run_attack_case(case, spec, evidence_root, browser_channel)
            rows.append(row)
            raw_reports.append({"case_id": case.case_id, "report": report_payload})
        else:
            rows.append(_run_legit_case(case))

    metrics = compute_metrics(rows)

    first_browser = next(
        (
            (payload["report"].get("dynamic") or {}).get("browser")  # type: ignore[union-attr]
            for payload in raw_reports
            if (payload["report"].get("dynamic") or {}).get("browser")
        ),
        {},
    )
    environment = {
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "spec": str(spec.source_path),
        "browser": first_browser,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "repeats": spec.repeats,
        "notes": list(spec.notes),
    }

    csv_path = _write_csv(rows, out_dir / "results.csv")
    (out_dir / "results.json").write_text(
        json.dumps([row.as_dict() for row in rows], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    chart_files: list[str] = []
    attack_chart = write_chart(
        attack_outcome_chart(
            metrics.get("per_profile") or {},  # type: ignore[arg-type]
            int(metrics.get("totals", {}).get("attack_rows") or 0),  # type: ignore[union-attr]
        ),
        out_dir / "attack_outcomes.svg",
    )
    cards_chart = write_chart(metric_cards_chart(metrics), out_dir / "metric_cards.svg")
    chart_files = [attack_chart.name, cards_chart.name]

    summary = {
        "environment": environment,
        "metrics": metrics,
        "rows": [row.as_dict() for row in rows],
        "outputs": {
            "csv": str(csv_path),
            "charts": chart_files,
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    _write_summary_markdown(metrics, environment, rows, chart_files, out_dir / "summary.md")

    if not quiet:
        print(f"rows={len(rows)} -> {out_dir}")
    return summary
