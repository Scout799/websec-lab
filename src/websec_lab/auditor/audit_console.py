"""Browser-facing audit console (M6/M7), so the audit can be run without a CLI.

The auditor service used to be API-only: operators had to know the CLI and then
find the generated HTML on disk. This page runs the same combined audit and
serves the resulting report, keeping every artifact where the CLI would put it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from websec_lab.auditor.dynamic.runner import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import (
    run_combined_audit,
    write_html_report,
    write_json_report,
    write_markdown_report,
)
from websec_lab.config import load_settings
from websec_lab.transport import is_lab_https

console_blueprint = Blueprint("audit_console", __name__)

RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{6,32}$")
DEFAULT_TARGET = "http://127.0.0.1:5100/lab/quick-transfer"
MAX_RECENT = 8
DEFENSE_CHOICES = (
    "keep",
    "none",
    "xfo-deny",
    "xfo-sameorigin",
    "csp-none",
    "csp-self",
    "csp-partner-allowlist",
    "confirm-reconfirm",
    "business-hardened",
)


def _victim_headers() -> dict[str, str]:
    return {"X-Websec-Test-Token": os.getenv("WEBSEC_TEST_API_TOKEN", "local-lab-only")}


def _current_defense() -> str:
    import requests

    victim = load_settings().service("victim")
    try:
        response = requests.get(
            f"http://127.0.0.1:{victim.port}/api/test/defense",
            headers=_victim_headers(),
            timeout=3,
        )
        return str(response.json().get("profile", "unknown"))
    except Exception:  # noqa: BLE001 - display only
        return "unknown"


def _apply_defense(name: str) -> str | None:
    """Hot-swap the victim's defense profile before running the audit."""

    import requests

    victim = load_settings().service("victim")
    try:
        response = requests.post(
            f"http://127.0.0.1:{victim.port}/api/test/defense",
            json={"profile": name},
            headers=_victim_headers(),
            timeout=5,
        )
    except Exception as exc:  # noqa: BLE001
        return f"无法切换防御档位：{type(exc).__name__}"
    if response.status_code != 200:
        return f"切换防御档位失败（HTTP {response.status_code}）"
    return None


def _reports_root() -> Path:
    return load_settings().artifact_dir / "reports"


def _recent_reports() -> list[dict[str, str]]:
    root = _reports_root()
    if not root.is_dir():
        return []
    entries = []
    for directory in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not directory.is_dir() or not (directory / "report.html").is_file():
            continue
        entries.append(
            {
                "run_id": directory.name,
                "target": _report_target(directory),
                "when": _report_time(directory),
            }
        )
        if len(entries) >= MAX_RECENT:
            break
    return entries


def _report_target(directory: Path) -> str:
    try:
        import json

        payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        return str(payload.get("target_url") or "")
    except Exception:  # noqa: BLE001 - listing must not fail the page
        return ""


def _report_time(directory: Path) -> str:
    try:
        import json

        payload = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        return str(payload.get("created_at") or "")
    except Exception:  # noqa: BLE001
        return ""


@console_blueprint.get("/audit")
def audit_form():  # type: ignore[no-untyped-def]
    settings = load_settings()
    victim = settings.service("victim")
    attacker = settings.service("attacker")
    last_run = (request.args.get("run_id") or "").strip()
    return render_template(
        "auditor/audit.html",
        default_target=DEFAULT_TARGET,
        default_ancestor=f"http://127.0.0.1:{attacker.port}",
        default_login_origin=f"http://127.0.0.1:{victim.port}",
        victim_port=victim.port,
        recent=_recent_reports(),
        last_run=last_run if RUN_ID_PATTERN.fullmatch(last_run) else "",
        defense_choices=DEFENSE_CHOICES,
        current_defense=_current_defense(),
        error=None,
    )


@console_blueprint.post("/audit")
def audit_run():  # type: ignore[no-untyped-def]
    settings = load_settings()
    target = (request.form.get("target") or "").strip()
    ancestor = (request.form.get("ancestor") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    with_click = request.form.get("click") == "on"
    defense = (request.form.get("defense") or "keep").strip()

    victim = settings.service("victim")
    attacker = settings.service("attacker")
    default_target = DEFAULT_TARGET
    default_ancestor = f"http://127.0.0.1:{attacker.port}"
    default_login_origin = f"http://127.0.0.1:{victim.port}"

    def fail(message: str):  # type: ignore[no-untyped-def]
        return (
            render_template(
                "auditor/audit.html",
                default_target=target or default_target,
                default_ancestor=ancestor or default_ancestor,
                default_login_origin=default_login_origin,
                victim_port=victim.port,
                recent=_recent_reports(),
                last_run="",
                defense_choices=DEFENSE_CHOICES,
                current_defense=_current_defense(),
                error=message,
            ),
            400,
        )

    if not target:
        return fail("请填写要审计的目标 URL。")
    if not (is_lab_https(target) or target.startswith(("http://127.0.0.1", "http://localhost"))):
        return fail("审计器只允许本地目标（loopback 或 *.test）。")
    if defense in DEFENSE_CHOICES and defense != "keep":
        problem = _apply_defense(defense)
        if problem:
            return fail(problem)

    login = None
    if username and password:
        login = LoginConfig(origin=default_login_origin, username=username, password=password)
    state_check = None
    if with_click:
        state_check = StateCheckConfig(
            victim_origin=default_login_origin,
            username=username or "alice",
            token=str(current_app.config.get("TEST_API_TOKEN", "local-lab-only")),
        )

    try:
        report = run_combined_audit(
            target_url=target,
            ancestors=[ancestor or default_ancestor],
            click=with_click,
            login=login,
            state_check=state_check,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        return fail(f"审计执行失败：{type(exc).__name__}: {exc}")

    out_dir = _reports_root() / report.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json_report(report, out_dir / "report.json")
    write_markdown_report(report, out_dir / "report.md")
    write_html_report(report, out_dir / "report.html")
    return redirect(url_for("audit_console.audit_form", run_id=report.run_id))


@console_blueprint.get("/audit/state")
def audit_live_state():  # type: ignore[no-untyped-def]
    """Live victim ledger for the console panel (server-side, token preserved).

    Mirrors what the split-screen demo shows: after a hijacked click, the new
    transfer shows up here on the next poll without opening the victim page.
    """

    import requests

    settings = load_settings()
    victim = settings.service("victim")
    username = (request.args.get("username") or "alice").strip().lower()
    if not username.isalnum():
        return {"error": "invalid_user"}, 400
    token = os.getenv("WEBSEC_TEST_API_TOKEN", "local-lab-only")
    try:
        upstream = requests.get(
            f"http://127.0.0.1:{victim.port}/api/test/state/{username}",
            headers={"X-Websec-Test-Token": token},
            timeout=4,
        )
    except requests.RequestException as exc:
        return {"error": "victim_unreachable", "detail": type(exc).__name__}, 502
    try:
        payload = upstream.json()
    except ValueError:
        return {"error": "victim_invalid_response"}, 502
    return payload, upstream.status_code


@console_blueprint.get("/audit/<run_id>")
def audit_report(run_id: str):  # type: ignore[no-untyped-def]
    if not RUN_ID_PATTERN.fullmatch(run_id):
        abort(404)
    report_path = _reports_root() / run_id / "report.html"
    if not report_path.is_file():
        abort(404)
    return send_file(report_path, mimetype="text/html")
