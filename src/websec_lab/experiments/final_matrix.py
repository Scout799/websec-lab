"""Final HTTPS experiment suite: three attacks, three browsers and dual-channel ablations."""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.dynamic.session import BrowserSession
from websec_lab.auditor.report import run_combined_audit, write_html_report, write_json_report
from websec_lab.config import repository_root
from websec_lab.https_lab import HttpsLab
from websec_lab.transport import lab_session

VICTIM = "https://victim.test:8443"
ATTACKER = "https://same.victim.test:8443"
TOKEN = "local-lab-only"
WINDOW_PROFILES = {
    "none",
    "xfo-deny",
    "csp-none",
    "https-partner-allowlist",
    "coop-same-origin",
    "business-hardened",
}
LEGIT_PROFILES = {"csp-partner-allowlist", "https-partner-allowlist", "xfo-deny", "csp-self"}


def state(session) -> dict:
    response = session.get(
        "http://127.0.0.1:15100/api/test/state/alice",
        headers={"X-Websec-Test-Token": TOKEN},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "transfers": len(data["transfers"]),
        "grants": len(data["grants"]),
        "balance_cents": data["account"]["balance_cents"],
    }


def reset(session):
    response = session.post(
        "http://127.0.0.1:15100/api/test/reset", headers={"X-Websec-Test-Token": TOKEN}, timeout=15
    )
    response.raise_for_status()


def signals(session, run: str) -> dict:
    response = session.get(
        f"{VICTIM}/telemetry/runs/{run}", headers={"X-Websec-Test-Token": TOKEN}, timeout=5
    )
    response.raise_for_status()
    return response.json()


def _deltas(row: dict, before: dict, after: dict):
    for key in ("transfers", "grants", "balance_cents"):
        row[key + "_delta"] = after[key] - before[key]
    row["attack_triggered"] = before != after
    row["full_sequence_completed"] = row["transfers_delta"] == 1 and row["grants_delta"] == 1
    row["business_valid"] = (
        row["transfers_delta"] in (0, 1)
        and row["grants_delta"] in (0, 1)
        and row["balance_cents_delta"] == -123 * row["transfers_delta"]
    )


def audit_case(row: dict, directory: Path, session) -> dict:
    run = row["run_id"]
    legit = row["kind"] == "legit"
    target = f"{VICTIM}{'/embed/profile-card' if legit else '/lab/quick-transfer'}?lab_run={run}"
    origin = (
        "https://partner.test:8443"
        if legit or row["scenario"] == "legitimate-embedded-payment"
        else ATTACKER
    )
    before = state(session)
    report = run_combined_audit(
        target,
        [origin],
        click=not legit,
        login=(
            None if row["profile"] == "samesite-none" else LoginConfig(VICTIM, "alice", "alice-lab")
        ),
        state_check=StateCheckConfig(VICTIM, "alice", TOKEN),
        browser_channel=row["browser"],
        viewport_profile=row["viewport"],
        evidence_root=directory / "browser",
        probe_origin=origin,
        scenario=(
            row["scenario"] if row["scenario"] in {"overlay", "clip", "multistep"} else "overlay"
        ),
        poll_timeout_s=2,
    )
    after = state(session)
    _deltas(row, before, after)
    dynamic = report.dynamic or {}
    frame = dynamic.get("framing") or {}
    row.update(
        static_framing=report.consistency.get("static_framing"),
        dynamic_framing=frame.get("verdict"),
        agree=report.consistency.get("agree"),
        overall=report.overall["verdict"],
        browser_version=dynamic.get("browser", {}).get("version"),
        ok=not dynamic.get("errors")
        and frame.get("verdict") in {"allowed", "blocked"}
        and row["business_valid"],
    )
    if legit:
        loaded_url = frame.get("signals", {}).get("loaded_frame_url") or ""
        row["functional"] = (
            frame.get("verdict") == "allowed" and "/embed/profile-card" in loaded_url
        )
    row["errors"] = dynamic.get("errors", [])
    evidence = report.signals or signals(session, run)
    row["channels"] = evidence.get("analysis", {})
    (directory / "signals.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    write_json_report(report, directory / "report.json")
    # A compact self-contained report for each distinct profile/scenario is
    # sufficient; screenshots and JSON are preserved for every repetition.
    if row["repeat"] == 1 and row["browser"] == "chrome":
        write_html_report(report, directory / "report.html")
    return row


def window_or_normal_case(row: dict, directory: Path, session) -> dict:
    run = row["run_id"]
    target = f"{VICTIM}/lab/quick-transfer?lab_run={run}"
    before = state(session)
    with BrowserSession(channel=row["browser"], https_lab=True) as browser:
        page = browser.page
        row["browser_version"] = browser.version
        page.goto(f"{VICTIM}/login")
        page.get_by_label("用户名").fill("alice")
        page.get_by_label("密码").fill("alice-lab")
        page.get_by_role("button", name="登录").click()
        page.get_by_role("heading", name="你好，alice").wait_for()
        if row["kind"] == "window":
            page.goto(f"https://attacker.test:8443/window-lab?lab_run={run}")
            with page.expect_popup() as prepared:
                page.locator("#prepare").click()
            victim = prepared.value
            victim.set_viewport_size({"width": 800, "height": 600})
            victim.wait_for_load_state("load")
            page.bring_to_front()
            with page.expect_popup() as induced:
                page.locator("#launch").click()
            popup = induced.value
            popup.set_viewport_size({"width": 800, "height": 600})
            popup.wait_for_load_state("load")
            box = popup.locator("#window-decoy").bounding_box()
            x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
            popup.screenshot(path=str(directory / "decoy.png"))
            victim.screenshot(path=str(directory / "target-before.png"))
            started = time.monotonic()
            with popup.expect_event("close"):
                try:
                    popup.mouse.click(x, y)
                except Exception:
                    if not popup.is_closed():
                        raise
            victim.bring_to_front()
            time.sleep(0.10)
            row["interval_ms"] = round((time.monotonic() - started) * 1000, 2)
            victim.mouse.click(x, y)
            victim.wait_for_timeout(600)
            victim.screenshot(path=str(directory / "target-after.png"))
            row["input_model"] = (
                "two trusted page-coordinate clicks; popup closed by first mousedown"
            )
        else:
            if row["scenario"] == "legitimate-embedded-payment":
                page.goto(f"https://partner.test:8443/payment?lab_run={run}", wait_until="load")
                page.wait_for_timeout(1_200)
                page.screenshot(path=str(directory / "normal-before.png"))
                page.frame_locator("#payment-component").locator(
                    ".quick-card input[type=submit]"
                ).click()
                row["normal_context"] = (
                    "Partner displays recipient bob and amount 123 cents; visible bank confirmation"
                )
            else:
                page.goto(target, wait_until="load")
            if row["scenario"] == "fast-focus-normal":
                another = browser.context.new_page()
                another.goto("https://attacker.test:8443/")
                another.bring_to_front()
                page.bring_to_front()
            else:
                page.wait_for_timeout(1_200)
            if row["scenario"] != "legitimate-embedded-payment":
                page.locator(".quick-card input[type=submit]").click()
            page.wait_for_timeout(600)
            page.screenshot(path=str(directory / "normal-after.png"))
        after = state(session)
    _deltas(row, before, after)
    evidence = signals(session, run)
    row["channels"] = evidence["analysis"]
    row["ok"] = row["business_valid"]
    (directory / "signals.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return row


def summarize(rows: list[dict]) -> dict:
    attacks = [r for r in rows if r["kind"] in {"attack", "window"} and r["ok"]]
    normal = [r for r in rows if r["kind"] == "normal" and r["ok"]]
    ablations = {}
    for channel in ("csp_detected", "interaction_detected", "fused_detected"):
        hits = sum(r["channels"].get(channel, False) for r in attacks)
        fp = sum(r["channels"].get(channel, False) for r in normal)
        successful = [r for r in attacks if r["attack_triggered"]]
        ablations[channel] = {
            "detected_attempts": hits,
            "attempts": len(attacks),
            "successful_attack_detections": sum(
                r["channels"].get(channel, False) for r in successful
            ),
            "successful_attacks": len(successful),
            "false_positives": fp,
            "normal_controls": len(normal),
        }
    return {
        "rows": len(rows),
        "passed": sum(r["ok"] for r in rows),
        "failed": sum(not r["ok"] for r in rows),
        "ablations": ablations,
    }


def save(rows: list[dict], output: Path, metadata: dict):
    (output / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = {**metadata, **summarize(rows)}
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if rows:
        fields = list(dict.fromkeys(k for row in rows for k in row))
        with (output / "results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fields)
            writer.writeheader()
            writer.writerows(
                {
                    k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                    for k, v in r.items()
                }
                for r in rows
            )


def run(
    output: Path,
    profiles: list[str],
    browsers: list[str],
    repeats: int,
    extras: bool = True,
    only_kind: str | None = None,
) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    metadata = {
        "started_at": datetime.now(UTC).isoformat(),
        "profiles": profiles,
        "browsers": browsers,
        "repeats": repeats,
        "tls_verification": True,
        "attack_origin": ATTACKER,
        "run_scope": "local synthetic lab",
        "state_isolation": "fresh database per profile, reset before every case",
    }
    rows = []
    with tempfile.TemporaryDirectory(prefix="websec-final-") as temporary, lab_session() as session:
        for profile in profiles:
            with HttpsLab(profile, Path(temporary) / f"{profile}.sqlite3"):
                cases = [("attack", s, "desktop") for s in ("overlay", "clip", "multistep")]
                if extras and profile in LEGIT_PROFILES:
                    cases.append(("legit", "partner-embed", "desktop"))
                if extras and profile in WINDOW_PROFILES:
                    cases.append(("window", "consecutive-window-clicks", "desktop"))
                if extras and profile == "https-samesite-none":
                    cases.extend(
                        [
                            ("normal", "direct-normal", "desktop"),
                            ("normal", "fast-focus-normal", "desktop"),
                        ]
                    )
                if extras and profile == "https-partner-allowlist":
                    cases.append(("normal", "legitimate-embedded-payment", "desktop"))
                if extras and profile in {"none", "xfo-deny", "business-hardened"}:
                    cases.extend(("attack", s, "mobile") for s in ("overlay", "clip", "multistep"))
                for channel in browsers:
                    for kind, scenario, viewport in cases:
                        if only_kind and kind != only_kind:
                            continue
                        for repeat in range(1, repeats + 1):
                            reset(session)
                            label = f"{channel}-{profile}-{kind}-{scenario}-{viewport}-{repeat}"
                            row = {
                                "case_id": label,
                                "run_id": uuid.uuid4().hex,
                                "browser": channel,
                                "profile": profile,
                                "kind": kind,
                                "scenario": scenario,
                                "viewport": viewport,
                                "repeat": repeat,
                                "ok": False,
                            }
                            directory = output / "evidence" / label
                            directory.mkdir(parents=True, exist_ok=True)
                            started = time.monotonic()
                            try:
                                if kind in {"attack", "legit"}:
                                    audit_case(row, directory, session)
                                else:
                                    window_or_normal_case(row, directory, session)
                            except Exception as error:
                                row["errors"] = [repr(error)]
                            row["duration_s"] = round(time.monotonic() - started, 3)
                            rows.append(row)
                            (directory / "result.json").write_text(
                                json.dumps(row, indent=2), encoding="utf-8"
                            )
                            save(rows, output, metadata)
                            print(
                                f"{len(rows)} {label} ok={row['ok']} "
                                f"action={row.get('attack_triggered')} "
                                f"frame={row.get('dynamic_framing')} "
                                f"errors={row.get('errors', [])}",
                                flush=True,
                            )
    metadata["finished_at"] = datetime.now(UTC).isoformat()
    save(rows, output, metadata)
    return {**metadata, **summarize(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("artifacts/final-matrix"))
    parser.add_argument("--profiles", nargs="+")
    parser.add_argument(
        "--browsers",
        nargs="+",
        choices=["chrome", "msedge", "firefox"],
        default=["chrome", "msedge", "firefox"],
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--no-extras", action="store_true")
    parser.add_argument("--only-kind", choices=["attack", "legit", "normal", "window"])
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("repeats must be positive")
    profiles = args.profiles or list(
        yaml.safe_load((repository_root() / "config/defense.yaml").read_text(encoding="utf-8"))[
            "profiles"
        ]
    )
    summary = run(
        args.out, profiles, args.browsers, args.repeats, not args.no_extras, args.only_kind
    )
    print(json.dumps(summary, indent=2))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
