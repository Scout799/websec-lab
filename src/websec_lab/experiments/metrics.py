"""Metric computation for the M9 experiment pipeline.

Formulas follow PROJECT_TASKS T0907–T0911; every metric carries its
numerator/denominator so report claims stay auditable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ExperimentRow:
    case_id: str
    kind: str
    profile: str
    scenario: str
    viewport: str
    repeat: int
    static_framing: str | None = None
    dynamic_framing: str | None = None
    attack_triggered: bool | None = None
    agree: bool | None = None
    static_flagged_vulnerable: bool | None = None
    partner_embed_loaded: bool | None = None
    duration_s: float | None = None
    ok: bool = True
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "profile": self.profile,
            "scenario": self.scenario,
            "viewport": self.viewport,
            "repeat": self.repeat,
            "static_framing": self.static_framing,
            "dynamic_framing": self.dynamic_framing,
            "attack_triggered": self.attack_triggered,
            "agree": self.agree,
            "static_flagged_vulnerable": self.static_flagged_vulnerable,
            "partner_embed_loaded": self.partner_embed_loaded,
            "duration_s": self.duration_s,
            "ok": self.ok,
            "detail": self.detail,
        }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def compute_metrics(rows: list[ExperimentRow]) -> dict[str, object]:
    attack_rows = [row for row in rows if row.kind == "attack" and row.ok]
    legit_rows = [row for row in rows if row.kind == "legit" and row.ok]
    observed_attacks = [row for row in attack_rows if row.attack_triggered is not None]
    observed_frames = [row for row in attack_rows if row.dynamic_framing in {"allowed", "blocked"}]
    compared_rows = [row for row in attack_rows if row.agree is not None]

    triggered = sum(1 for row in attack_rows if row.attack_triggered is True)
    dynamic_blocked = sum(1 for row in attack_rows if row.dynamic_framing == "blocked")
    agree_count = sum(1 for row in attack_rows if row.agree is True)

    # T0911: treat "static predicts vulnerable (allowed)" as the detector
    # and "attack actually triggered" as ground truth.
    true_positive = sum(
        1
        for row in attack_rows
        if row.static_flagged_vulnerable is True and row.attack_triggered is True
    )
    false_positive = sum(
        1
        for row in attack_rows
        if row.static_flagged_vulnerable is True and row.attack_triggered is False
    )
    false_negative = sum(
        1
        for row in attack_rows
        if row.static_flagged_vulnerable is False and row.attack_triggered is True
    )
    true_negative = sum(
        1
        for row in attack_rows
        if row.static_flagged_vulnerable is False and row.attack_triggered is False
    )

    allowlist_legit = [row for row in legit_rows if row.profile == "csp-partner-allowlist"]
    denyall_legit = [row for row in legit_rows if row.profile != "csp-partner-allowlist"]

    durations = [row.duration_s for row in rows if row.duration_s is not None]

    per_profile: dict[str, dict[str, object]] = {}
    for profile in dict.fromkeys(row.profile for row in attack_rows):
        profile_rows = [row for row in attack_rows if row.profile == profile]
        per_profile[profile] = {
            "cases": len(profile_rows),
            "attack_triggered": sum(1 for row in profile_rows if row.attack_triggered is True),
            "dynamic_blocked": sum(1 for row in profile_rows if row.dynamic_framing == "blocked"),
        }

    return {
        "totals": {
            "rows": len(rows),
            "ok_rows": sum(1 for row in rows if row.ok),
            "attack_rows": len(attack_rows),
            "legit_rows": len(legit_rows),
            "observed_attacks": len(observed_attacks),
            "observed_frames": len(observed_frames),
            "compared_rows": len(compared_rows),
        },
        # T0907 attack success rate
        "attack_success_rate": _rate(triggered, len(observed_attacks)),
        # T0908 illegal-embed block rate
        "illegal_embed_block_rate": _rate(dynamic_blocked, len(observed_frames)),
        # T0909 legitimate embed pass rate (allowlist profiles only)
        "legit_embed_pass_rate": _rate(
            sum(1 for row in allowlist_legit if row.partner_embed_loaded is True),
            len(allowlist_legit),
        ),
        "legit_broken_under_deny_all": _rate(
            sum(1 for row in denyall_legit if row.partner_embed_loaded is False),
            len(denyall_legit),
        ),
        # T0910 static/dynamic consistency
        "static_dynamic_consistency": _rate(agree_count, len(compared_rows)),
        # T0911 detection quality of the static analyzer
        "detection": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "true_negative": true_negative,
            "detection_rate": _rate(true_positive, true_positive + false_negative),
            "false_alarm_rate": _rate(false_positive, false_positive + true_negative),
            "miss_rate": _rate(false_negative, true_positive + false_negative),
        },
        # T0912 timing
        "timing": {
            "avg_case_seconds": (round(sum(durations) / len(durations), 2) if durations else None),
            "total_seconds": round(sum(durations), 2) if durations else None,
        },
        "per_profile": per_profile,
    }
