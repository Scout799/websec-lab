"""Experiment matrix expansion for the M9 pipeline.

A small YAML spec (see ``config/experiments.yaml``) expands into the full
cross product of defense profiles × scenarios × viewports × repeats, plus
optional legitimate-embedding cases, each executed by :mod:`runner`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from websec_lab.config import repository_root

DEFAULT_SPEC_PATH = repository_root() / "config" / "experiments.yaml"

VALID_KINDS = ("attack", "legit")


class ExperimentSpecError(ValueError):
    """Raised when the experiment spec is invalid."""


@dataclass(frozen=True, slots=True)
class ExperimentCase:
    case_id: str
    kind: str  # "attack" (dynamic click audit) | "legit" (partner embed check)
    profile: str
    scenario: str
    viewport: str
    repeat: int

    def as_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "profile": self.profile,
            "scenario": self.scenario,
            "viewport": self.viewport,
            "repeat": self.repeat,
        }


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    target_path: str
    profiles: tuple[str, ...]
    scenarios: tuple[str, ...]
    viewports: tuple[str, ...]
    repeats: int
    include_legit: bool
    source_path: Path
    notes: tuple[str, ...] = field(default_factory=tuple)

    def expand(self) -> list[ExperimentCase]:
        cases: list[ExperimentCase] = []
        for profile in self.profiles:
            for viewport in self.viewports:
                for repeat in range(1, self.repeats + 1):
                    for scenario in self.scenarios:
                        cases.append(
                            ExperimentCase(
                                case_id=f"atk-{profile}-{scenario}-{viewport}-{repeat}",
                                kind="attack",
                                profile=profile,
                                scenario=scenario,
                                viewport=viewport,
                                repeat=repeat,
                            )
                        )
        if self.include_legit:
            for repeat in range(1, self.repeats + 1):
                cases.append(
                    ExperimentCase(
                        case_id=f"legit-csp-partner-allowlist-{repeat}",
                        kind="legit",
                        profile="csp-partner-allowlist",
                        scenario="partner-embed",
                        viewport="desktop",
                        repeat=repeat,
                    )
                )
                cases.append(
                    ExperimentCase(
                        case_id=f"legit-xfo-deny-{repeat}",
                        kind="legit",
                        profile="xfo-deny",
                        scenario="partner-embed",
                        viewport="desktop",
                        repeat=repeat,
                    )
                )
        return cases


def _require_str_list(raw: Any, section: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw or not all(isinstance(i, str) for i in raw):
        raise ExperimentSpecError(f"spec section {section!r} must be a non-empty string list")
    return tuple(raw)


def load_experiment_spec(path: str | Path | None = None) -> ExperimentSpec:
    source = Path(path) if path is not None else DEFAULT_SPEC_PATH
    source = source.resolve()
    if not source.is_file():
        raise ExperimentSpecError(f"experiment spec does not exist: {source}")

    with source.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ExperimentSpecError("experiment spec root must be a mapping")

    repeats = raw.get("repeats", 1)
    if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
        raise ExperimentSpecError("spec 'repeats' must be a positive integer")

    scenarios = _require_str_list(raw.get("scenarios", ["overlay"]), "scenarios")
    if not set(scenarios) <= {"overlay", "clip", "multistep"}:
        raise ExperimentSpecError("scenarios must be overlay, clip or multistep")
    return ExperimentSpec(
        target_path=str(raw.get("target_path", "/lab/quick-transfer")),
        profiles=_require_str_list(raw.get("profiles"), "profiles"),
        scenarios=scenarios,
        viewports=_require_str_list(raw.get("viewports", ["desktop"]), "viewports"),
        repeats=repeats,
        include_legit=bool(raw.get("include_legit", True)),
        source_path=source,
        notes=tuple(str(item) for item in raw.get("notes", [])),
    )
