"""Locate the concrete page elements a clickjacking attack would hijack.

The requirement asks the audit to point at *where* the attack happens, not just
whether the page can be framed. This module walks the live page in the browser,
picks the interactive elements a victim could be tricked into pressing, and
returns their selector, on-screen box and business risk so the report can say
"the hijack lands here".
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

MAX_POINTS = 12

# Ranking shared by the scanner and the report.
RISK_ORDER = {"high": 0, "medium": 1, "low": 2}

SCAN_SCRIPT = r"""() => {
  const visible = (el) => {
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return (
      rect.width > 0 && rect.height > 0 &&
      style.visibility !== "hidden" &&
      style.display !== "none" &&
      Number(style.opacity) !== 0
    );
  };
  const selector = (el) => {
    if (el.id) return "#" + el.id;
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 4) {
      let part = node.tagName.toLowerCase();
      if (node.classList.length) {
        part += "." + Array.from(node.classList).slice(0, 2).join(".");
      }
      const parent = node.parentElement;
      if (parent) {
        const same = Array.from(parent.children).filter((c) => c.tagName === node.tagName);
        part += ":nth-of-type(" + (same.indexOf(node) + 1) + ")";
      }
      parts.unshift(part);
      node = parent;
    }
    return parts.join(" > ");
  };
  const SENSITIVE =
    /pay|transfer|confirm|delete|remove|submit|buy|save|send|grant|authorize|授权|转账|确认|删除|提交|支付|领取|确定/;
  const nodes = document.querySelectorAll(
    "button, a[href], input[type=submit], input[type=button], [role=button], [onclick]"
  );
  const points = [];
  for (const el of nodes) {
    if (!visible(el)) continue;
    const rect = el.getBoundingClientRect();
    const text = (el.innerText || el.value || el.getAttribute("aria-label") || "")
      .trim()
      .replace(/\s+/g, " ")
      .slice(0, 60);
    if (!text) continue;
    const submits = el.tagName === "INPUT" ? el.type === "submit" : el.form != null;
    points.push({
      selector: selector(el),
      tag: el.tagName.toLowerCase(),
      text: text,
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      submits_form: submits,
      risk: SENSITIVE.test(text) ? "high" : submits ? "medium" : "low",
    });
  }
  points.sort((a, b) => {
    const rank = { high: 0, medium: 1, low: 2 };
    return rank[a.risk] - rank[b.risk] || a.y - b.y;
  });
  return points.slice(0, 20);
}"""

HIGHLIGHT_SCRIPT = r"""(points) => {
  const box = document.createElement("div");
  box.id = "__hijack_points_overlay";
  box.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147483647";
  points.forEach((point, index) => {
    const frame = document.createElement("div");
    frame.style.cssText = [
      "position:fixed",
      "left:" + point.x + "px",
      "top:" + point.y + "px",
      "width:" + point.width + "px",
      "height:" + point.height + "px",
      "border:2px solid #e2606b",
      "border-radius:6px",
      "box-shadow:0 0 0 9999px rgba(0,0,0,0.05)",
    ].join(";");
    const label = document.createElement("span");
    label.textContent = String(index + 1);
    label.style.cssText = [
      "position:absolute",
      "top:-11px",
      "left:-11px",
      "min-width:20px",
      "height:20px",
      "border-radius:10px",
      "background:#e2606b",
      "color:#fff",
      "font:600 12px/20px sans-serif",
      "text-align:center",
    ].join(";");
    frame.appendChild(label);
    box.appendChild(frame);
  });
  document.body.appendChild(box);
}"""

CLEAR_HIGHLIGHT_SCRIPT = r"""() => {
  const node = document.getElementById("__hijack_points_overlay");
  if (node) node.remove();
}"""


def scan_hijackable_elements(page: Any, limit: int = MAX_POINTS) -> list[dict[str, Any]]:
    """Return the interactive elements on the current page, risk-sorted."""

    try:
        points = page.evaluate(SCAN_SCRIPT)
    except Exception:  # pragma: no cover - page gone or script blocked
        return []
    if not isinstance(points, list):
        return []
    return [point for point in points if isinstance(point, dict)][:limit]


def capture_highlighted_points(page: Any, points: list[dict[str, Any]], path: Any) -> bool:
    """Draw numbered boxes over the points, screenshot, then clean up."""

    if not points:
        return False
    try:
        page.evaluate(HIGHLIGHT_SCRIPT, points)
        page.screenshot(path=str(path), full_page=False)
        return True
    except Exception:  # pragma: no cover - best effort evidence
        return False
    finally:
        with suppress(Exception):
            page.evaluate(CLEAR_HIGHLIGHT_SCRIPT)
