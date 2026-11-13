"""Merge retained runs, independently verify evidence, and make presentation data."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import matplotlib
import yaml

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/final-results"
DELIVERY = ROOT / "deliverables"
SOURCES = [
    "artifacts/final-matrix-v2",
    "artifacts/final-frame-busting-recheck",
    "artifacts/final-controls",
    "artifacts/final-origin-controls",
]


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def expected_ids(profiles):
    ids = set()
    for profile in profiles:
        cases = [("attack", s, "desktop") for s in ("overlay", "clip", "multistep")]
        if profile in {"csp-partner-allowlist", "https-partner-allowlist", "xfo-deny", "csp-self"}:
            cases.append(("legit", "partner-embed", "desktop"))
        if profile in {
            "none",
            "xfo-deny",
            "csp-none",
            "https-partner-allowlist",
            "coop-same-origin",
            "business-hardened",
        }:
            cases.append(("window", "consecutive-window-clicks", "desktop"))
        if profile == "https-samesite-none":
            cases.extend(("normal", s, "desktop") for s in ("direct-normal", "fast-focus-normal"))
        if profile == "https-partner-allowlist":
            cases.append(("normal", "legitimate-embedded-payment", "desktop"))
        if profile in {"none", "xfo-deny", "business-hardened"}:
            cases.extend(("attack", s, "mobile") for s in ("overlay", "clip", "multistep"))
        for browser in ("chrome", "msedge", "firefox"):
            for kind, scenario, viewport in cases:
                for repeat in (1, 2, 3):
                    ids.add(f"{browser}-{profile}-{kind}-{scenario}-{viewport}-{repeat}")
    return ids


def check_csv(path, rows):
    with path.open(encoding="utf-8-sig", newline="") as handle:
        actual = list(csv.DictReader(handle))
    assert len(actual) == len(rows), path
    for csv_row, row in zip(actual, rows, strict=True):
        for key, value in row.items():
            encoded = (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
            assert csv_row[key] == ("" if value is None else encoded), (path, row["case_id"], key)


def validate(row):
    directory = ROOT / row["evidence_dir"]
    original = load(directory / "result.json")
    assert all(row[k] == v for k, v in original.items())
    assert row["ok"] and not row.get("errors"), row["case_id"]
    assert row["browser_version"] != "unavailable"
    dt, dg, db = (row[k] for k in ("transfers_delta", "grants_delta", "balance_cents_delta"))
    assert dt in (0, 1) and dg in (0, 1) and db == -123 * dt
    assert row["attack_triggered"] == bool(dt or dg)
    assert row["full_sequence_completed"] == (dt == dg == 1)
    assert row["business_valid"]
    if row["kind"] in {"attack", "legit"}:
        report = load(directory / "report.json")
        dynamic = report["dynamic"]
        assert not dynamic["errors"]
        assert dynamic["framing"]["verdict"] in {"allowed", "blocked"}
        click = dynamic.get("clickjacking")
        if click and click.get("state_before"):
            before, after = click["state_before"], click["state_after"]
            assert [after[k] - before[k] for k in ("transfers", "grants", "balance_cents")] == [
                dt,
                dg,
                db,
            ]
    evidence = load(directory / "signals.json")
    assert evidence["analysis"] == row["channels"]
    events = evidence["events"]
    assert all(event["run_id"] == row["run_id"] for event in events)
    assert all("?" not in event.get("path", "") for event in events)
    csp = any(e["channel"] == "csp" and e.get("directive") == "frame-ancestors" for e in events)
    interaction = any(
        e["channel"] == "interaction"
        and e.get("type") == "click"
        and e.get("trusted")
        and e.get("sensitive")
        and (e.get("in_frame") or 0 <= e.get("since_focus_ms", -1) < 300)
        for e in events
    )
    assert row["channels"]["csp_detected"] == csp
    assert row["channels"]["interaction_detected"] == interaction
    assert row["channels"]["fused_detected"] == (csp or interaction)
    pictures = list(directory.rglob("*.png"))
    assert pictures and all(p.stat().st_size > 100 for p in pictures)
    return len(pictures)


def stats(rows):
    attacks = [r for r in rows if r["kind"] in {"attack", "window"}]
    successful = [r for r in attacks if r["attack_triggered"]]
    normal = [r for r in rows if r["kind"] == "normal"]
    ablations = {}
    for key in ("csp_detected", "interaction_detected", "fused_detected"):
        ablations[key] = dict(
            detected_attempts=sum(r["channels"][key] for r in attacks),
            attempts=len(attacks),
            successful_attack_detections=sum(r["channels"][key] for r in successful),
            successful_attacks=len(successful),
            false_positives=sum(r["channels"][key] for r in normal),
            normal_controls=len(normal),
        )
    profile_stats = {}
    for profile in dict.fromkeys(r["profile"] for r in rows):
        desktop = [
            r
            for r in rows
            if r["profile"] == profile and r["kind"] == "attack" and r["viewport"] == "desktop"
        ]
        overlay = [r for r in desktop if r["scenario"] == "overlay"]
        multi = [r for r in desktop if r["scenario"] == "multistep"]
        profile_stats[profile] = dict(
            desktop_actions=sum(r["attack_triggered"] for r in desktop),
            desktop_n=len(desktop),
            desktop_transfers=sum(r["transfers_delta"] for r in desktop),
            overlay_transfers=sum(r["transfers_delta"] for r in overlay),
            overlay_n=len(overlay),
            multistep_full=sum(r["full_sequence_completed"] for r in multi),
            multistep_n=len(multi),
        )
    legit = {}
    for profile in sorted({r["profile"] for r in rows if r["kind"] == "legit"}):
        subset = [r for r in rows if r["profile"] == profile and r["kind"] == "legit"]
        legit[profile] = dict(
            n=len(subset),
            allowed=sum(r["dynamic_framing"] == "allowed" for r in subset),
            functional=sum(r["functional"] for r in subset),
        )
    browsers = {}
    for browser in ("chrome", "msedge", "firefox"):
        subset = [
            r
            for r in rows
            if r["browser"] == browser and r["kind"] == "attack" and r["viewport"] == "desktop"
        ]
        browsers[browser] = dict(
            n=len(subset),
            actions=sum(r["attack_triggered"] for r in subset),
            versions=sorted({r["browser_version"] for r in rows if r["browser"] == browser}),
        )
    compared = [r for r in rows if isinstance(r.get("agree"), bool)]
    return dict(
        rows=len(rows),
        passed=len(rows),
        failed=0,
        profiles=len(profile_stats),
        kinds=dict(Counter(r["kind"] for r in rows)),
        ablations=ablations,
        profile_stats=profile_stats,
        legitimate=legit,
        browsers=browsers,
        consistency=dict(agree=sum(r["agree"] for r in compared), n=len(compared)),
    )


def figures(rows, summary):
    directory = DELIVERY / "figures"
    directory.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 11, "axes.spines.top": False, "axes.spines.right": False})

    def save(fig, name):
        fig.tight_layout()
        for ext in ("png", "svg"):
            fig.savefig(directory / f"{name}.{ext}", dpi=170, bbox_inches="tight")
        plt.close(fig)

    profiles = list(summary["profile_stats"])
    fig, ax = plt.subplots(figsize=(12, 10))
    values = [summary["profile_stats"][p]["desktop_actions"] for p in profiles]
    ax.barh(profiles, values, color="#2563eb")
    ax.set(xlabel="Cases with any business change (27 desktop attempts / profile)", xlim=(0, 30))
    ax.invert_yaxis()
    for y, value in enumerate(values):
        ax.text(value + 0.3, y, f"{value}/27", va="center", fontsize=9)
    save(fig, "defense-comparison")
    import numpy as np

    fig, ax = plt.subplots(figsize=(7, 12))
    values = [
        [
            sum(
                r["attack_triggered"]
                for r in rows
                if r["kind"] == "attack"
                and r["viewport"] == "desktop"
                and r["browser"] == b
                and r["profile"] == p
            )
            for b in ("chrome", "msedge", "firefox")
        ]
        for p in profiles
    ]
    ax.imshow(np.array(values), cmap="Blues", vmin=0, vmax=9, aspect="auto")
    ax.set_xticks(range(3), ["Chrome", "Edge", "Firefox"])
    ax.set_yticks(range(len(profiles)), profiles)
    for y, line in enumerate(values):
        for x, value in enumerate(line):
            ax.text(
                x,
                y,
                f"{value}/9",
                ha="center",
                va="center",
                color="white" if value > 4 else "#10233f",
            )
    ax.set_title("Any business change: desktop attacks")
    save(fig, "browser-comparison")
    labels = ["CSP", "Interaction", "Fusion"]
    ab = list(summary["ablations"].values())
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, key, title, denominator in zip(
        axes,
        ["detected_attempts", "successful_attack_detections", "false_positives"],
        ["Detected attempts", "Detected successful attacks", "Normal controls flagged"],
        [ab[0]["attempts"], ab[0]["successful_attacks"], ab[0]["normal_controls"]],
        strict=True,
    ):
        values = [a[key] for a in ab]
        ax.bar(labels, values, color=["#2563eb", "#d95c37", "#10233f"])
        ax.set_title(f"{title}\nDenominator: {denominator}")
        ax.set_ylim(0, max(1, denominator) * 1.15)
        for x, value in enumerate(values):
            ax.text(x, value + denominator * 0.02, str(value), ha="center")
    save(fig, "channel-ablation")
    fig, ax = plt.subplots(figsize=(9, 4))
    ds = [
        [
            r["duration_s"]
            for r in rows
            if r["browser"] == b and r["kind"] == "attack" and r["viewport"] == "desktop"
        ]
        for b in ("chrome", "msedge", "firefox")
    ]
    ax.boxplot(ds, tick_labels=["Chrome", "Edge", "Firefox"], showfliers=False)
    ax.set(
        ylabel="End-to-end audit duration (seconds)",
        title="Includes launch, waits, clicks and evidence; not site latency overhead",
    )
    save(fig, "audit-duration")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    merged, provenance, replaced = {}, [], []
    for source in SOURCES:
        directory = ROOT / source
        rows = load(directory / "results.json")
        check_csv(directory / "results.csv", rows)
        provenance.append(
            dict(
                source=source,
                rows=len(rows),
                sha256=hashlib.sha256((directory / "results.json").read_bytes()).hexdigest(),
            )
        )
        assert len({r["case_id"] for r in rows}) == len(rows)
        for row in rows:
            key = row["case_id"]
            if key in merged:
                configuration_fix = source == "artifacts/final-origin-controls" and row[
                    "profile"
                ] in {"xfo-csp-conflict", "csp-partner-allowlist-attacker"}
                assert row["ok"] is True and (merged[key]["ok"] is False or configuration_fix), key
                replaced.append(
                    {
                        "case_id": key,
                        "reason": (
                            "explicit HTTPS attacker source added"
                            if configuration_fix
                            else "frame-busting top navigation classified"
                        ),
                    }
                )
            merged[key] = {**row, "evidence_dir": f"{source}/evidence/{key}"}
    profiles = yaml.safe_load((ROOT / "config/defense.yaml").read_text(encoding="utf-8"))[
        "profiles"
    ]
    assert set(merged) == expected_ids(profiles), set(merged) ^ expected_ids(profiles)
    rows = list(merged.values())
    assert len({r["run_id"] for r in rows}) == len(rows)
    pictures = sum(validate(row) for row in rows)
    summary = stats(rows)
    for name, value in [
        ("results.json", rows),
        ("summary.json", summary),
        (
            "provenance.json",
            dict(
                inputs=provenance,
                replaced_cases=replaced,
                generated_at=datetime.now(UTC).isoformat(),
            ),
        ),
        (
            "verification.json",
            dict(
                passed=True,
                cases=len(rows),
                screenshots=pictures,
                checks=[
                    "complete unique matrix",
                    "source JSON/CSV equivalence",
                    "retained failed runs and explicit replacements",
                    "evidence and browser versions",
                    "business deltas",
                    "raw signal rule recomputation",
                    "run and path isolation",
                ],
            ),
        ),
    ]:
        (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    with (OUT / "results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = list(dict.fromkeys(k for row in rows for k in row))
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()}
            for row in rows
        )
    figures(rows, summary)
    (DELIVERY / "data").mkdir(parents=True, exist_ok=True)
    for name in ("summary.json", "verification.json", "provenance.json", "results.csv"):
        (DELIVERY / "data" / name).write_bytes((OUT / name).read_bytes())
    business = [["配置", "单击转账 / 实验数"]] + [
        [p, f"{summary['profile_stats'][p]['overlay_transfers']}/9"]
        for p in ("none", "confirm-token", "confirm-reconfirm", "reauth", "business-hardened")
    ]
    partner = [["配置", "框架允许", "组件功能"]] + [
        [p, f"{d['allowed']}/{d['n']}", f"{d['functional']}/{d['n']}"]
        for p, d in summary["legitimate"].items()
    ]
    browsers = [["浏览器", "操作触发", "有效实验"]] + [
        [b, str(d["actions"]), str(d["n"])] for b, d in summary["browsers"].items()
    ]
    ab = list(summary["ablations"].values())
    facts = {
        "rows": len(rows),
        "profiles": len(profiles),
        "businessTable": business,
        "partnerTable": partner,
        "browserTable": browsers,
        "ablationChart": {
            "categories": ["CSP", "交互", "融合"],
            "series": [
                {
                    "name": "检测到的尝试",
                    "values": [a["detected_attempts"] for a in ab],
                    "fill": "#2563EB",
                },
                {"name": "全部有效攻击尝试", "values": [ab[0]["attempts"]] * 3, "fill": "#D5DDE8"},
            ],
        },
    }
    (DELIVERY / "data/facts.json").write_text(
        json.dumps(facts, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
