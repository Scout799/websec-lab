"""Command-line entry point for local development."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from websec_lab.browser import discover_browsers
from websec_lab.config import LabSettings, load_settings, repository_root
from websec_lab.services import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="websec-lab", description="WebSec local lab CLI")
    parser.add_argument("--config", help="Path to a lab YAML configuration file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run one local service")
    run_parser.add_argument("service", choices=("victim", "attacker", "partner", "auditor"))
    run_parser.add_argument("--host", help="Override the configured bind host")
    run_parser.add_argument("--port", type=int, help="Override the configured port")
    run_parser.add_argument("--debug", action="store_true")

    subparsers.add_parser("config", help="Print the validated effective configuration")
    subparsers.add_parser("doctor", help="Check the local development environment")

    database_parser = subparsers.add_parser("db", help="Manage the victim database")
    database_parser.add_argument("action", choices=("upgrade", "seed", "reset"))
    database_parser.add_argument(
        "--yes", action="store_true", help="Confirm destructive reset operations"
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Run the static framing-policy analyzer on a local target"
    )
    analyze_parser.add_argument("url", help="Target URL (loopback or *.test only)")
    analyze_parser.add_argument(
        "--ancestor",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Embedding ancestor origin, repeatable, outermost first",
    )
    analyze_parser.add_argument("--json", action="store_true", help="Print the full JSON result")

    audit_parser = subparsers.add_parser(
        "audit", help="Run a dynamic browser audit against a local target"
    )
    audit_parser.add_argument("url", help="Target URL (loopback or *.test only)")
    audit_parser.add_argument(
        "--click", action="store_true", help="Also run the clickjacking click check"
    )
    audit_parser.add_argument(
        "--login-user", default="alice", help="Victim account for the audit login"
    )
    audit_parser.add_argument(
        "--login-pass", default="alice-lab", help="Victim password for the audit login"
    )
    audit_parser.add_argument(
        "--no-login", action="store_true", help="Skip the victim login (public targets)"
    )
    audit_parser.add_argument(
        "--login-origin", help="Victim origin for login (default: loopback from config)"
    )
    audit_parser.add_argument(
        "--state-origin", help="Victim origin for state checks (default: loopback from config)"
    )
    audit_parser.add_argument(
        "--test-token", default="local-lab-only", help="Token for the victim test API"
    )
    audit_parser.add_argument(
        "--browser", default="chrome", choices=("chrome", "msedge", "firefox")
    )
    audit_parser.add_argument("--viewport", default="desktop", choices=("desktop", "mobile"))
    audit_parser.add_argument("--trace", action="store_true", help="Record a Playwright trace")
    audit_parser.add_argument("--probe-origin", help="Actual local origin serving /probe/embed")
    audit_parser.add_argument(
        "--scenario", choices=["overlay", "clip", "multistep"], default="overlay"
    )
    audit_parser.add_argument("--json", action="store_true", help="Print the full JSON result")

    report_parser = subparsers.add_parser(
        "audit-report",
        help="Run static + dynamic audits on one target and write combined reports",
    )
    report_parser.add_argument("url", help="Target URL (loopback or *.test only)")
    report_parser.add_argument(
        "--ancestor",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="Embedding ancestor origin (repeatable)",
    )
    report_parser.add_argument(
        "--click", action="store_true", help="Include the clickjacking check"
    )
    report_parser.add_argument("--login-user", default="alice")
    report_parser.add_argument("--login-pass", default="alice-lab")
    report_parser.add_argument("--no-login", action="store_true")
    report_parser.add_argument("--login-origin")
    report_parser.add_argument("--state-origin")
    report_parser.add_argument("--probe-origin")
    report_parser.add_argument(
        "--scenario", choices=["overlay", "clip", "multistep"], default="overlay"
    )
    report_parser.add_argument(
        "--signals", action="store_true", help="Record CSP and interaction channels"
    )
    report_parser.add_argument("--test-token", default="local-lab-only")
    report_parser.add_argument(
        "--browser", default="chrome", choices=("chrome", "msedge", "firefox")
    )
    report_parser.add_argument("--viewport", default="desktop", choices=("desktop", "mobile"))
    report_parser.add_argument(
        "--out", default=None, help="Output directory (default: artifacts/reports/<run_id>)"
    )

    experiments_parser = subparsers.add_parser(
        "experiments", help="Run the M9 experiment matrix and generate metrics/charts"
    )
    experiments_parser.add_argument(
        "--spec", default=None, help="Experiment spec YAML (default: config/experiments.yaml)"
    )
    experiments_parser.add_argument(
        "--out",
        default=None,
        help="Output directory (default: artifacts/experiments/<timestamp>)",
    )
    return parser


def settings_as_dict(settings: LabSettings) -> dict[str, object]:
    return {
        "project_name": settings.project_name,
        "environment": settings.environment,
        "local_only": settings.local_only,
        "configuration": str(settings.source_path),
        "services": {
            name: {
                "host": service.host,
                "port": service.port,
                "public_origin": service.public_origin,
            }
            for name, service in settings.services.items()
        },
        "storage": {
            "database_path": str(settings.database_path),
            "artifact_dir": str(settings.artifact_dir),
            "log_dir": str(settings.log_dir),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings(args.config)

    if args.command == "config":
        from websec_lab.defense import load_defense_settings

        defense = load_defense_settings()
        payload = settings_as_dict(settings)
        payload["defense"] = {
            "active_profile": defense.active_profile().name,
            "default_profile": defense.default_profile,
            "source": str(defense.source_path),
            "available_profiles": sorted(defense.profiles),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if args.command == "doctor":
        browsers = [browser.as_dict() for browser in discover_browsers()]
        payload = {
            "status": "ok" if browsers else "warning",
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "configuration": str(settings.source_path),
            "local_only": settings.local_only,
            "browsers": browsers,
            "notes": (
                []
                if browsers
                else ["No supported system browser found; install Playwright browser binaries."]
            ),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if args.command == "db":
        if args.action == "reset" and not args.yes:
            print("Refusing to reset without --yes", file=sys.stderr)
            return 2

        from flask_migrate import upgrade

        from websec_lab.extensions import db
        from websec_lab.victim.services import seed_lab_data

        app = create_app("victim", settings=settings)
        migrations = repository_root() / "migrations"
        with app.app_context():
            if args.action == "reset":
                db.drop_all()
            if args.action in {"upgrade", "reset"}:
                upgrade(directory=str(migrations))
            created = seed_lab_data()
        print(
            json.dumps(
                {"status": "ok", "action": args.action, "seed_users_created": created},
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "analyze":
        from websec_lab.auditor.analyzer import analyze_response
        from websec_lab.auditor.fetch import FetchError, fetch_response

        try:
            fetched = fetch_response(args.url)
        except FetchError as exc:
            print(f"Fetch failed: {exc}", file=sys.stderr)
            return 2

        result = analyze_response(
            headers=fetched.headers,
            set_cookies=fetched.set_cookies,
            target_url=args.url,
            ancestors=args.ancestor,
            redirect_chain=fetched.redirect_chain,
            final_url=fetched.final_url,
        )
        if args.json:
            print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
            return 0

        print(f"target: {result.final_url} (redirects: {len(result.redirect_chain)})")
        for decision in result.decisions:
            verdict = "ALLOWED" if decision.allowed else "BLOCKED"
            mechanisms = ",".join(decision.blocked_by) if decision.blocked_by else "-"
            print(f"decision: {decision.origin} -> {verdict} (blocked_by: {mechanisms})")
        if result.findings:
            print("findings:")
            for finding in result.findings:
                summary = f"  [{finding.rule_id}][{finding.severity}] {finding.title}"
                print(f"{summary} - {finding.evidence}")
        else:
            print("findings: none")
        print(f"risk: {result.risk['score']} ({result.risk['grade']})")
        return 0

    if args.command == "audit":
        from websec_lab.auditor.dynamic import (
            DynamicAuditConfig,
            LoginConfig,
            StateCheckConfig,
            run_dynamic_audit,
        )

        victim_service = settings.service("victim")
        from websec_lab.transport import is_lab_https

        default_origin = (
            "https://victim.test:8443"
            if is_lab_https(args.url)
            else f"http://127.0.0.1:{victim_service.port}"
        )
        login_origin = args.login_origin or default_origin
        state_origin = args.state_origin or default_origin

        login = None
        if not args.no_login:
            login = LoginConfig(
                origin=login_origin, username=args.login_user, password=args.login_pass
            )
        state_check = None
        if args.click:
            state_check = StateCheckConfig(
                victim_origin=state_origin,
                username=args.login_user,
                token=args.test_token,
            )

        result = run_dynamic_audit(
            DynamicAuditConfig(
                target_url=args.url,
                clickjacking=args.click,
                login=login,
                state_check=state_check,
                browser_channel=args.browser,
                viewport_profile=args.viewport,
                trace=args.trace,
                probe_origin=args.probe_origin,
                scenario=args.scenario,
            )
        )

        if args.json:
            print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
            return 0

        print(f"run_id: {result.run_id}")
        print(f"target: {result.target_url}")
        print(f"probe_origin: {result.probe_origin}")
        if result.framing:
            verdict = result.framing.verdict
            mechanisms = ",".join(result.framing.blocked_by) or "-"
            print(f"framing: {verdict} (blocked_by: {mechanisms})")
        if result.clickjacking:
            triggered = result.clickjacking.sensitive_action_triggered
            print(f"clickjacking: sensitive_action_triggered={triggered}")
            print(f"  iframe_reloaded={result.clickjacking.iframe_reloaded}")
        print(f"login_performed: {result.login.performed} success={result.login.success}")
        print(f"console_entries: {result.console_count} network_entries: {result.network_count}")
        print(f"evidence_dir: {result.evidence_dir}")
        if result.errors:
            print("errors:")
            for error in result.errors:
                print(f"  - {error}")
            return 1
        return 0

    if args.command == "audit-report":
        if args.signals:
            import uuid
            from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

            parts = urlsplit(args.url)
            query = dict(parse_qsl(parts.query))
            query["lab_run"] = uuid.uuid4().hex
            args.url = urlunsplit(parts._replace(query=urlencode(query)))
        from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
        from websec_lab.auditor.report import (
            CombinedReport,
            run_combined_audit,
            write_html_report,
            write_json_report,
            write_markdown_report,
        )

        victim_service = settings.service("victim")
        from websec_lab.transport import is_lab_https

        default_origin = (
            "https://victim.test:8443"
            if is_lab_https(args.url)
            else f"http://127.0.0.1:{victim_service.port}"
        )
        login_origin = args.login_origin or default_origin
        state_origin = args.state_origin or default_origin

        login = None
        if not args.no_login:
            login = LoginConfig(
                origin=login_origin, username=args.login_user, password=args.login_pass
            )
        state_check = None
        if args.click:
            state_check = StateCheckConfig(
                victim_origin=state_origin,
                username=args.login_user,
                token=args.test_token,
            )

        report: CombinedReport = run_combined_audit(
            target_url=args.url,
            ancestors=args.ancestor or ["http://127.0.0.1:5200"],
            click=args.click,
            login=login,
            state_check=state_check,
            browser_channel=args.browser,
            viewport_profile=args.viewport,
            probe_origin=args.probe_origin,
            scenario=args.scenario,
        )

        out_dir = Path(args.out) if args.out else Path("artifacts") / "reports" / report.run_id
        json_path = write_json_report(report, out_dir / "report.json")
        md_path = write_markdown_report(report, out_dir / "report.md")
        html_path = write_html_report(report, out_dir / "report.html")

        print(f"run_id: {report.run_id}")
        print(f"verdict: {report.overall['verdict']} - {report.overall['label']}")
        consistency = report.consistency
        print(
            f"consistency: static={consistency.get('static_framing')} "
            f"dynamic={consistency.get('dynamic_framing')} agree={consistency.get('agree')}"
        )
        triggered = report.overall.get("clickjacking_triggered")
        if triggered is not None:
            print(f"clickjacking_triggered: {triggered}")
        print(f"json:     {json_path}")
        print(f"markdown: {md_path}")
        print(f"html:     {html_path}")
        return 1 if report.overall["verdict"] == "inconclusive" else 0

    if args.command == "experiments":
        from websec_lab.experiments import load_experiment_spec, run_experiments

        spec = load_experiment_spec(args.spec)
        default_out = Path("artifacts") / "experiments" / datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = Path(args.out) if args.out else default_out

        summary = run_experiments(spec, out_dir)
        metrics = summary["metrics"]

        print(f"rows: {metrics['totals']['rows']}")
        print(f"attack_success_rate:        {metrics['attack_success_rate']}")
        print(f"illegal_embed_block_rate:   {metrics['illegal_embed_block_rate']}")
        print(f"static_dynamic_consistency: {metrics['static_dynamic_consistency']}")
        print(f"legit_embed_pass_rate:      {metrics['legit_embed_pass_rate']}")
        print(f"outputs: {out_dir}")
        return 0

    service = settings.service(args.service)
    app = create_app(args.service, settings=settings)
    app.run(
        host=args.host or service.host,
        port=args.port or service.port,
        debug=args.debug,
        use_reloader=False,
    )
    return 0
