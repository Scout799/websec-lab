"""Local, explicit two-window timing experiment; no external target parameter."""

from flask import Blueprint, abort, current_app, render_template, request

from websec_lab.victim.telemetry import RUN_PATTERN

window_blueprint = Blueprint("window_lab", __name__)


@window_blueprint.get("/window-lab")
def window_lab():
    run = request.args.get("lab_run", "")
    if not current_app.config.get("LAB_LOCAL_ONLY"):
        abort(404)
    if run and not RUN_PATTERN.fullmatch(run):
        abort(400)
    origin = current_app.config["ATTACKER_VICTIM_ORIGINS"][0]
    return render_template(
        "attacker/window_lab.html", target=f"{origin}/lab/quick-transfer?lab_run={run}"
    )


@window_blueprint.get("/window-decoy")
def window_decoy():
    if not current_app.config.get("LAB_LOCAL_ONLY"):
        abort(404)
    return render_template("attacker/window_decoy.html")
