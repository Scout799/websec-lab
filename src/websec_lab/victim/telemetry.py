"""Two independent browser-signal channels, scoped to synthetic local runs."""

from __future__ import annotations

import hmac
import re
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, current_app, jsonify, request

telemetry_blueprint = Blueprint("telemetry", __name__, url_prefix="/telemetry")
RUN_PATTERN = re.compile(r"^[a-f0-9]{32}$")
EVENT_TYPES = {"focus", "blur", "visibilitychange", "pointerdown", "click", "load"}


class SignalStore:
    def __init__(self):
        self._events = deque(maxlen=20_000)
        self._lock = threading.Lock()

    def append(self, run: str, channel: str, payload: dict):
        with self._lock:
            self._events.append(
                {"run_id": run, "channel": channel, "received_at": time.time(), **payload}
            )

    def read(self, run: str) -> list[dict]:
        with self._lock:
            return [dict(event) for event in self._events if event["run_id"] == run]


def correlate(events: list[dict]) -> dict:
    """Rules use observable signals, never attack labels or business ground truth."""
    csp = [e for e in events if e["channel"] == "csp" and e.get("directive") == "frame-ancestors"]
    interaction = []
    for event in events:
        if event["channel"] != "interaction" or event.get("type") != "click":
            continue
        if not event.get("trusted") or not event.get("sensitive"):
            continue
        if event.get("in_frame") or 0 <= event.get("since_focus_ms", -1) < 300:
            interaction.append(event)
    pairs = [
        {
            "path": click["path"],
            "distance_ms": round(abs(report["received_at"] - click["received_at"]) * 1000),
        }
        for report in csp
        for click in interaction
        if report["path"] == click["path"]
        and abs(report["received_at"] - click["received_at"]) <= 2
    ]
    return {
        "csp_detected": bool(csp),
        "interaction_detected": bool(interaction),
        "fused_detected": bool(csp or interaction),
        "risk": "high" if interaction else "medium" if csp else "none",
        "csp_count": len(csp),
        "suspicious_click_count": len(interaction),
        "correlated_pairs": pairs,
        "event_count": len(events),
        "rule_version": "1.0",
        "focus_threshold_ms": 300,
        "join_window_ms": 2000,
    }


def _run() -> str:
    run = request.args.get("run_id", "")
    if not RUN_PATTERN.fullmatch(run):
        abort(400, description="run_id must be 32 lowercase hexadecimal characters")
    return run


@telemetry_blueprint.before_request
def guard():
    if not current_app.config.get("LAB_LOCAL_ONLY"):
        abort(404)
    if request.content_length and request.content_length > 24_000:
        abort(413)


@telemetry_blueprint.post("/csp")
def csp_report():
    run = _run()
    body = request.get_json(force=True, silent=True)
    reports = body if isinstance(body, list) else [body]
    for report in reports[:20]:
        if not isinstance(report, dict):
            abort(400)
        data = report.get("csp-report", report.get("body", report))
        if not isinstance(data, dict):
            abort(400)
        current_app.extensions["signal_store"].append(
            run,
            "csp",
            {
                "path": urlsplit(str(data.get("document-uri", data.get("documentURL", "")))).path[
                    :200
                ],
                "directive": str(
                    data.get("effective-directive", data.get("effectiveDirective", ""))
                )[:80],
                "disposition": str(data.get("disposition", "enforce"))[:30],
            },
        )
    return "", 204


@telemetry_blueprint.post("/events")
def interaction_report():
    run = _run()
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("type") not in EVENT_TYPES:
        abort(400)
    try:
        payload = {
            "type": data["type"],
            "path": str(data.get("path", ""))[:200],
            "element": str(data.get("element", ""))[:80],
            "client_time": float(data.get("client_time", 0)),
            "since_focus_ms": float(data.get("since_focus_ms", -1)),
            "in_frame": data.get("in_frame") is True,
            "trusted": data.get("trusted") is True,
            "sensitive": data.get("sensitive") is True,
            "visible": data.get("visible") is True,
        }
    except (ValueError, TypeError):
        abort(400)
    current_app.extensions["signal_store"].append(run, "interaction", payload)
    return "", 204


@telemetry_blueprint.get("/runs/<run>")
def run_signals(run: str):
    if not hmac.compare_digest(
        request.headers.get("X-Websec-Test-Token", ""), str(current_app.config["TEST_API_TOKEN"])
    ):
        abort(403)
    events = current_app.extensions["signal_store"].read(run)
    return jsonify({"events": events, "analysis": correlate(events)})


@telemetry_blueprint.get("/client.js")
def client_script():
    return Response(CLIENT_SCRIPT, mimetype="application/javascript")


CLIENT_SCRIPT = r"""(() => {
  const candidate = new URLSearchParams(location.search).get('lab_run');
  if (candidate && /^[a-f0-9]{32}$/.test(candidate)) sessionStorage.setItem('lab_run', candidate);
  const run = sessionStorage.getItem('lab_run');
  if (!run) return;
  let focusedAt = -1;
  const send = event => {
    if ((event.type === 'focus' || event.type === 'blur') && event.target !== window) return;
    if (event.type === 'focus') focusedAt = performance.now();
    const target = event.target?.closest?.('button,input[type=submit],a.button');
    const payload = {
      type: event.type, path: location.pathname, element: target?.id || target?.name || '',
      client_time: Date.now(), since_focus_ms: focusedAt < 0 ? -1 : performance.now() - focusedAt,
      in_frame: self !== top, trusted: event.isTrusted,
      visible: document.visibilityState === 'visible',
      sensitive: !!target && location.pathname.startsWith('/lab/quick-')
    };
    fetch('/telemetry/events?run_id=' + run, {method:'POST', keepalive:true,
      headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)}).catch(() => {});
  };
  for (const type of ['focus','blur']) window.addEventListener(type, send, true);
  for (const type of ['visibilitychange','pointerdown','click']) {
    document.addEventListener(type, send, true);
  }
  window.addEventListener('load', send);
})();"""
