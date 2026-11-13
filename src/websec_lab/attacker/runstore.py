"""Run registry for attacker scenarios with an append-only JSONL journal.

The in-memory structures serve the results API during a lab session;
the journal under ``artifacts/attacker/`` preserves the evidence for
post-run analysis and the M9 experiment pipeline.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path

MAX_EVENTS_PER_RUN = 200
MAX_RUNS_IN_MEMORY = 500
MAX_EVENT_JSON_LENGTH = 4096


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class RunStore:
    """Thread-safe storage for scenario runs and browser-side events."""

    def __init__(self, journal_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._runs: OrderedDict[str, dict[str, object]] = OrderedDict()
        self._journal_path = journal_path
        if journal_path is not None:
            journal_path.parent.mkdir(parents=True, exist_ok=True)

    def _journal(self, record: dict[str, object]) -> None:
        if self._journal_path is None:
            return
        try:
            with self._journal_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, default=str))
                handle.write("\n")
        except OSError:
            # Journaling is best-effort evidence collection, never fatal.
            pass

    def create_run(
        self,
        scenario_id: str,
        params: dict[str, object],
        run_id: str | None = None,
    ) -> dict[str, object]:
        resolved_run_id = run_id or uuid.uuid4().hex[:12]
        run: dict[str, object] = {
            "run_id": resolved_run_id,
            "scenario": scenario_id,
            "params": dict(params),
            "created_at": _utc_now(),
            "events": [],
        }
        with self._lock:
            self._runs[resolved_run_id] = run
            while len(self._runs) > MAX_RUNS_IN_MEMORY:
                self._runs.popitem(last=False)
            self._journal(
                {
                    "kind": "run",
                    "run_id": resolved_run_id,
                    "scenario": scenario_id,
                    "params": dict(params),
                    "created_at": run["created_at"],
                }
            )
        return self.get_run(resolved_run_id) or run

    def add_event(self, run_id: str, event: dict[str, object]) -> dict[str, object] | None:
        if len(json.dumps(event, ensure_ascii=False, default=str)) > MAX_EVENT_JSON_LENGTH:
            raise ValueError("event payload too large")
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            events = run["events"]
            assert isinstance(events, list)
            if len(events) >= MAX_EVENTS_PER_RUN:
                return run
            events.append(event)
            self._journal({"kind": "event", "run_id": run_id, "event": event})
            return run

    def get_run(self, run_id: str) -> dict[str, object] | None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            snapshot = dict(run)
            snapshot["params"] = dict(run["params"])  # type: ignore[arg-type]
            snapshot["events"] = list(run["events"])  # type: ignore[arg-type]
            return snapshot

    def list_runs(self, limit: int = 20) -> list[dict[str, object]]:
        with self._lock:
            runs = list(self._runs.values())[-limit:]
        snapshots = []
        for run in reversed(runs):
            snapshot = dict(run)
            events = run["events"]
            assert isinstance(events, list)
            snapshot["events"] = len(events)
            snapshots.append(snapshot)
        return snapshots


def sanitize_event(payload: object) -> dict[str, object]:
    """Keep only scalar JSON fields so browser reports stay predictable."""

    if not isinstance(payload, dict):
        raise ValueError("event payload must be a JSON object")
    event_type = payload.get("type")
    if not isinstance(event_type, str) or not (1 <= len(event_type) <= 40):
        raise ValueError("event requires a string 'type' field")

    sanitized: dict[str, object] = {"type": event_type, "reported_at": _utc_now()}
    for key, value in payload.items():
        if key in {"type", "reported_at"}:
            continue
        if isinstance(value, str | int | float | bool) or value is None:
            sanitized[str(key)[:40]] = value
    return sanitized
