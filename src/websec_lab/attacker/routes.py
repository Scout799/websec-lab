"""Routes for the local-only attacker application."""

from __future__ import annotations

import hmac

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
)

from websec_lab.attacker.runstore import RunStore, sanitize_event
from websec_lab.attacker.scenarios import (
    ScenarioParamError,
    get_scenario,
    parse_run_params,
    sorted_scenarios,
)

attacker_blueprint = Blueprint("attacker", __name__)


def _run_store() -> RunStore:
    store = current_app.extensions.get("websec_attacker_runs")
    if not isinstance(store, RunStore):
        abort(503, description="run store unavailable")
    return store


def _require_report_token() -> None:
    if not current_app.config.get("LAB_LOCAL_ONLY", False):
        abort(404)
    supplied = request.headers.get("X-Websec-Test-Token", "")
    expected = str(current_app.config["ATTACKER_REPORT_TOKEN"])
    if not hmac.compare_digest(supplied, expected):
        abort(403)


@attacker_blueprint.get("/")
def index():  # type: ignore[no-untyped-def]
    store = _run_store()
    return render_template(
        "attacker/index.html",
        scenarios=sorted_scenarios(),
        recent_runs=store.list_runs(10),
    )


@attacker_blueprint.get("/scenarios/<scenario_id>")
def scenario_detail(scenario_id: str):  # type: ignore[no-untyped-def]
    try:
        scenario = get_scenario(scenario_id)
    except ScenarioParamError:
        abort(404)
    params = parse_run_params(scenario, {}, current_app.config["ATTACKER_VICTIM_ORIGINS"])
    return render_template(
        "attacker/scenario_detail.html",
        scenario=scenario,
        preview=params,
        origins=current_app.config["ATTACKER_VICTIM_ORIGINS"],
    )


@attacker_blueprint.get("/scenarios/<scenario_id>/run")
def scenario_run(scenario_id: str):  # type: ignore[no-untyped-def]
    try:
        scenario = get_scenario(scenario_id)
    except ScenarioParamError:
        abort(404)
    try:
        params = parse_run_params(
            scenario, request.args, current_app.config["ATTACKER_VICTIM_ORIGINS"]
        )
    except ScenarioParamError as exc:
        return jsonify({"error": "invalid_scenario_params", "detail": str(exc)}), 400

    run = _run_store().create_run(scenario.scenario_id, params.as_dict())
    return render_template(
        scenario.template,
        scenario=scenario,
        params=params,
        run=run,
        report_token=str(current_app.config["ATTACKER_REPORT_TOKEN"]),
    )


@attacker_blueprint.post("/api/runs/<run_id>/events")
def append_event(run_id: str):  # type: ignore[no-untyped-def]
    _require_report_token()
    try:
        event = sanitize_event(request.get_json(silent=True))
    except ValueError as exc:
        return jsonify({"error": "invalid_event", "detail": str(exc)}), 400

    run = _run_store().add_event(run_id, event)
    if run is None:
        abort(404)
    events = run["events"]
    assert isinstance(events, list)
    return jsonify({"status": "ok", "run_id": run_id, "event_count": len(events)})


@attacker_blueprint.get("/api/runs")
def list_runs():  # type: ignore[no-untyped-def]
    limit = request.args.get("limit", 20, type=int) or 20
    limit = max(1, min(limit, 100))
    return jsonify({"runs": _run_store().list_runs(limit)})


@attacker_blueprint.get("/api/runs/<run_id>")
def run_detail(run_id: str):  # type: ignore[no-untyped-def]
    run = _run_store().get_run(run_id)
    if run is None:
        abort(404)
    return jsonify(run)


@attacker_blueprint.get("/healthz")
def healthz():  # type: ignore[no-untyped-def]
    from websec_lab import __version__

    return jsonify({"status": "ok", "service": "attacker", "version": __version__})


@attacker_blueprint.get("/readyz")
def readyz():  # type: ignore[no-untyped-def]
    return jsonify(
        {
            "status": "ready",
            "service": "attacker",
            "local_only": current_app.config["LAB_LOCAL_ONLY"],
            "victim_origins": current_app.config["ATTACKER_VICTIM_ORIGINS"],
        }
    )
