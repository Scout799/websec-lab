"""Analyzer API routes for the auditor service (M6)."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from websec_lab.auditor.analyzer import analyze_response
from websec_lab.auditor.fetch import FetchError, fetch_response
from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.rules import RULES

analyzer_blueprint = Blueprint("analyzer", __name__, url_prefix="/api")

MAX_RAW_HEADERS = 50
MAX_ANCESTORS = 5


@analyzer_blueprint.get("/rules")
def list_rules():  # type: ignore[no-untyped-def]
    return jsonify(
        {
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "severity": rule.severity,
                    "title": rule.title,
                    "description": rule.description,
                    "remediation": rule.remediation,
                }
                for rule in RULES.values()
            ]
        }
    )


@analyzer_blueprint.get("/analyze")
def analyze_url():  # type: ignore[no-untyped-def]
    """Fetch a local target and analyze its real framing headers."""

    url = request.args.get("url", "").strip()
    ancestors = [value for value in request.args.getlist("ancestor") if value.strip()]
    matrix_origins = [value for value in request.args.getlist("matrix") if value.strip()] or None
    if not url:
        return jsonify({"error": "missing_url", "detail": "query parameter 'url' is required"}), 400
    if len(ancestors) > MAX_ANCESTORS:
        return jsonify({"error": "too_many_ancestors"}), 400

    try:
        fetched = fetch_response(url)
    except FetchError as exc:
        return jsonify({"error": "fetch_failed", "detail": str(exc)}), 400

    result = analyze_response(
        headers=fetched.headers,
        set_cookies=fetched.set_cookies,
        target_url=url,
        ancestors=ancestors[:MAX_ANCESTORS],
        matrix_origins=matrix_origins,
        redirect_chain=fetched.redirect_chain,
        final_url=fetched.final_url,
    )
    return jsonify({"fetch": {"status_code": fetched.status_code}, **result.as_dict()})


@analyzer_blueprint.post("/analyze")
def analyze_raw():  # type: ignore[no-untyped-def]
    """Analyze recorded headers without fetching anything (corpus / M8 mode)."""

    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    raw_headers = payload.get("headers") or {}
    if not url:
        return jsonify({"error": "missing_url", "detail": "field 'url' is required"}), 400
    if not isinstance(raw_headers, dict) or len(raw_headers) > MAX_RAW_HEADERS:
        return (
            jsonify({"error": "invalid_headers", "detail": "'headers' must be a small mapping"}),
            400,
        )

    ancestors = payload.get("ancestors") or []
    if not isinstance(ancestors, list) or len(ancestors) > MAX_ANCESTORS:
        return jsonify({"error": "invalid_ancestors"}), 400
    matrix_origins = payload.get("matrix") or None

    try:
        result = analyze_response(
            headers=HeaderMap(raw_headers),
            set_cookies=tuple(str(item) for item in payload.get("set_cookies") or []),
            target_url=url,
            ancestors=[str(origin) for origin in ancestors],
            matrix_origins=matrix_origins,
        )
    except ValueError as exc:
        return jsonify({"error": "invalid_input", "detail": str(exc)}), 400
    return jsonify(result.as_dict())
