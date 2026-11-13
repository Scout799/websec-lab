"""Unit tests for the M9 experiment matrix and metrics."""

from pathlib import Path

import pytest
import yaml

from websec_lab.experiments import (
    ExperimentRow,
    compute_metrics,
    load_experiment_spec,
)


def _spec(tmp_path: Path, **overrides: object) -> Path:
    payload = {
        "target_path": "/lab/quick-transfer",
        "profiles": ["none", "xfo-deny"],
        "scenarios": ["overlay"],
        "viewports": ["desktop"],
        "repeats": 2,
        "include_legit": True,
    }
    payload.update(overrides)
    path = tmp_path / "experiments.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_spec_expansion_counts(tmp_path: Path) -> None:
    spec = load_experiment_spec(_spec(tmp_path))

    cases = spec.expand()

    attack = [case for case in cases if case.kind == "attack"]
    legit = [case for case in cases if case.kind == "legit"]
    assert len(attack) == 2 * 1 * 2  # profiles × viewports × repeats
    assert len(legit) == 2 * 2  # two legit profiles × repeats
    assert len({case.case_id for case in cases}) == len(cases)


def test_spec_expansion_without_legit(tmp_path: Path) -> None:
    spec = load_experiment_spec(_spec(tmp_path, include_legit=False))
    assert all(case.kind == "attack" for case in spec.expand())


def test_spec_validation(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="profiles"):
        load_experiment_spec(_spec(tmp_path, profiles=[]))
    with pytest.raises(Exception, match="repeats"):
        load_experiment_spec(_spec(tmp_path, repeats=0))
    with pytest.raises(Exception, match="does not exist"):
        load_experiment_spec(tmp_path / "missing.yaml")


def test_metrics_formulas() -> None:
    rows = [
        # profile, static, dynamic, triggered
        ExperimentRow(
            "a",
            "attack",
            "none",
            "overlay",
            "desktop",
            1,
            static_framing="allowed",
            dynamic_framing="allowed",
            attack_triggered=True,
            agree=True,
            static_flagged_vulnerable=True,
        ),
        ExperimentRow(
            "b",
            "attack",
            "xfo-deny",
            "overlay",
            "desktop",
            1,
            static_framing="blocked",
            dynamic_framing="blocked",
            attack_triggered=False,
            agree=True,
            static_flagged_vulnerable=False,
        ),
        ExperimentRow(
            "c",
            "attack",
            "confirm-reconfirm",
            "overlay",
            "desktop",
            1,
            static_framing="allowed",
            dynamic_framing="allowed",
            attack_triggered=False,
            agree=True,
            static_flagged_vulnerable=True,
        ),
        ExperimentRow(
            "d",
            "legit",
            "csp-partner-allowlist",
            "partner-embed",
            "desktop",
            1,
            partner_embed_loaded=True,
        ),
        ExperimentRow(
            "e", "legit", "xfo-deny", "partner-embed", "desktop", 1, partner_embed_loaded=False
        ),
    ]

    metrics = compute_metrics(rows)

    assert metrics["totals"]["attack_rows"] == 3
    assert metrics["attack_success_rate"] == round(1 / 3, 4)
    assert metrics["illegal_embed_block_rate"] == round(1 / 3, 4)
    assert metrics["static_dynamic_consistency"] == 1.0
    assert metrics["legit_embed_pass_rate"] == 1.0
    assert metrics["legit_broken_under_deny_all"] == 1.0

    detection = metrics["detection"]
    # Detector says vulnerable for rows a & c; ground truth only a.
    assert detection["true_positive"] == 1
    assert detection["false_positive"] == 1
    assert detection["false_negative"] == 0
    assert detection["true_negative"] == 1
    assert detection["detection_rate"] == 1.0
    assert detection["false_alarm_rate"] == 0.5


def test_metrics_per_profile_aggregation() -> None:
    rows = [
        ExperimentRow(
            "a",
            "attack",
            "none",
            "overlay",
            "desktop",
            1,
            static_framing="allowed",
            dynamic_framing="allowed",
            attack_triggered=True,
            agree=True,
            static_flagged_vulnerable=True,
        ),
        ExperimentRow(
            "b",
            "attack",
            "none",
            "overlay",
            "desktop",
            2,
            static_framing="allowed",
            dynamic_framing="allowed",
            attack_triggered=True,
            agree=True,
            static_flagged_vulnerable=True,
        ),
        ExperimentRow(
            "c",
            "attack",
            "confirm-token",
            "overlay",
            "desktop",
            1,
            static_framing="allowed",
            dynamic_framing="allowed",
            attack_triggered=True,
            agree=True,
            static_flagged_vulnerable=True,
        ),
    ]

    metrics = compute_metrics(rows)

    assert metrics["per_profile"]["none"] == {
        "cases": 2,
        "attack_triggered": 2,
        "dynamic_blocked": 0,
    }
    assert metrics["per_profile"]["confirm-token"]["cases"] == 1


def test_charts_render_svg(tmp_path: Path) -> None:
    from websec_lab.experiments.charts import (
        attack_outcome_chart,
        metric_cards_chart,
        write_chart,
    )

    per_profile = {
        "none": {"cases": 1, "attack_triggered": 1, "dynamic_blocked": 0},
        "xfo-deny": {"cases": 1, "attack_triggered": 0, "dynamic_blocked": 1},
        "confirm-reconfirm": {"cases": 1, "attack_triggered": 0, "dynamic_blocked": 0},
    }
    svg = attack_outcome_chart(per_profile, total_cases=3)
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    write_chart(svg, tmp_path / "chart.svg")
    assert (tmp_path / "chart.svg").exists()

    cards = metric_cards_chart({"attack_success_rate": 0.5, "detection": {"detection_rate": 1.0}})
    assert "50.0%" in cards and "100.0%" in cards


def test_unknown_results_are_excluded_from_rate_denominators() -> None:
    rows = [
        ExperimentRow(
            "unknown",
            "attack",
            "none",
            "overlay",
            "desktop",
            1,
            dynamic_framing="unknown",
            attack_triggered=None,
            agree=None,
        ),
        ExperimentRow(
            "known",
            "attack",
            "xfo-deny",
            "overlay",
            "desktop",
            1,
            dynamic_framing="blocked",
            attack_triggered=False,
            agree=True,
        ),
        ExperimentRow("failed", "attack", "none", "overlay", "desktop", 1, ok=False),
    ]
    metrics = compute_metrics(rows)
    assert metrics["totals"]["rows"] == 3
    assert metrics["totals"]["observed_attacks"] == 1
    assert metrics["totals"]["observed_frames"] == 1
    assert metrics["totals"]["compared_rows"] == 1
    assert metrics["attack_success_rate"] == 0.0
    assert metrics["illegal_embed_block_rate"] == 1.0
    assert metrics["static_dynamic_consistency"] == 1.0


def test_empty_evidence_rates_remain_unknown() -> None:
    row = ExperimentRow("unknown", "attack", "none", "overlay", "desktop", 1)
    metrics = compute_metrics([row])
    assert metrics["attack_success_rate"] is None
    assert metrics["illegal_embed_block_rate"] is None
    assert metrics["static_dynamic_consistency"] is None
