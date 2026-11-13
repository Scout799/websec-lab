"""Probe harness pages served by the auditor (T0704/T0705/T0710).

The harness gives the dynamic auditor a real local origin from which the
target can be embedded: ``variant=visible`` reproduces a plain embed (the
S1-style probe), ``variant=overlay`` reproduces the transparent centered
overlay used to verify whether a coordinate click changes victim state
(the S2-style attack). Only local lab targets may be embedded.
"""

from __future__ import annotations

from urllib.parse import urlparse

from flask import Blueprint, abort, render_template, request

probe_blueprint = Blueprint("probe_harness", __name__, url_prefix="/probe")

ALLOWED_VARIANTS = ("visible", "overlay", "clip")


def _require_local_target(target: str) -> None:
    from websec_lab.auditor.fetch import is_local_target

    if not target or not is_local_target(target):
        abort(400, description="target must be a local lab URL")


@probe_blueprint.get("/embed")
def embed():  # type: ignore[no-untyped-def]
    target = request.args.get("target", "").strip()
    _require_local_target(target)

    variant = request.args.get("variant", "visible").strip()
    if variant not in ALLOWED_VARIANTS:
        abort(400, description=f"variant must be one of {', '.join(ALLOWED_VARIANTS)}")

    decoy = (request.args.get("decoy", "立即领取") or "立即领取").strip()[:60]
    opacity = request.args.get("opacity", 0.0, type=float)
    if opacity is None:
        opacity = 0.0
    opacity = max(0.0, min(opacity, 1.0))

    iframe_w = max(200, min(request.args.get("iframe_w", 340, type=int) or 340, 1600))
    iframe_h = max(150, min(request.args.get("iframe_h", 360, type=int) or 360, 1200))

    parsed = urlparse(target)
    host = parsed.hostname or "unknown"
    return render_template(
        "auditor/probe_embed.html",
        variant=variant,
        target=target,
        target_host=host,
        decoy=decoy,
        opacity=opacity,
        iframe_w=iframe_w,
        iframe_h=iframe_h,
    )
