"""Evidence collection for dynamic audits (T0706/T0707/T0708/T0711/T0712/T0715).

One collector attaches console / page-error / CSP-violation / network
listeners to the audit page, keeps bounded in-memory logs, writes every
screenshot into the run's evidence directory, and preserves the failure
scene (screenshot + HTML snapshot + console dump) when a step raises.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from playwright.sync_api import Page

CONSOLE_LOG_LIMIT = 400
NETWORK_LOG_LIMIT = 300
CSP_MARKERS = (
    "Content Security Policy",
    "violates the following Content Security Policy",
    "ContentSecurityPolicy",
)


@dataclass(slots=True)
class ConsoleEntry:
    timestamp: float
    type: str
    text: str

    def as_dict(self) -> dict[str, object]:
        return {"timestamp": self.timestamp, "type": self.type, "text": self.text}


@dataclass(slots=True)
class NetworkEntry:
    timestamp: float
    method: str
    url: str
    status: int | None
    resource_type: str

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "resource_type": self.resource_type,
        }


@dataclass(slots=True)
class EvidenceCollector:
    """Bounded listeners plus evidence files under one run directory."""

    page: Page
    evidence_dir: Path
    console: list[ConsoleEntry] = field(default_factory=list)
    network: list[NetworkEntry] = field(default_factory=list)
    csp_violations: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    documents: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # Playwright's sync API caches handler wrappers as attributes on the
        # callable, so hand it plain closures instead of bound methods of a
        # slots dataclass.
        self.page.on("console", lambda message: self._on_console(message))
        self.page.on("pageerror", lambda error: self._on_page_error(error))
        self.page.on("response", lambda response: self._on_response(response))

    # ---- listeners -------------------------------------------------------

    def _on_console(self, message) -> None:  # type: ignore[no-untyped-def]
        entry = ConsoleEntry(timestamp=time.time(), type=message.type, text=message.text[:500])
        if len(self.console) < CONSOLE_LOG_LIMIT:
            self.console.append(entry)
        if any(marker in message.text for marker in CSP_MARKERS):
            self.csp_violations.append(message.text[:500])

    def _on_page_error(self, error: Exception) -> None:
        self.page_errors.append(str(error)[:500])

    def _on_response(self, response) -> None:  # type: ignore[no-untyped-def]
        request = response.request
        if len(self.network) >= NETWORK_LOG_LIMIT:
            return
        try:
            resource_type = request.resource_type
        except Exception:  # pragma: no cover - defensive against closed requests
            resource_type = "unknown"
        self.network.append(
            NetworkEntry(
                timestamp=time.time(),
                method=request.method,
                url=response.url,
                status=response.status,
                resource_type=resource_type,
            )
        )
        if resource_type == "document":
            headers: dict[str, list[str]] = {}
            for item in response.headers_array():
                headers.setdefault(item["name"].lower(), []).append(item["value"])
            self.documents.append(
                {"url": response.url, "status": response.status, "headers": headers}
            )

    # ---- evidence writers --------------------------------------------------

    def screenshot(self, name: str) -> str:
        path = self.evidence_dir / f"{name}.png"
        self.page.screenshot(path=str(path), full_page=True)
        self.files.append(path.name)
        return str(path)

    def snapshot_html(self, name: str = "failure_page") -> str:
        path = self.evidence_dir / f"{name}.html"
        path.write_text(self.page.content(), encoding="utf-8")
        self.files.append(path.name)
        return str(path)

    def dump_logs(self) -> None:
        console_path = self.evidence_dir / "console_log.json"
        console_path.write_text(
            json.dumps([entry.as_dict() for entry in self.console], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        network_path = self.evidence_dir / "network_log.json"
        network_path.write_text(
            json.dumps([entry.as_dict() for entry in self.network], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.files.extend([console_path.name, network_path.name])

    def save_storage_state(self, name: str = "storage_state.json") -> str:
        path = self.evidence_dir / name
        self.page.context.storage_state(path=str(path))
        self.files.append(path.name)
        return str(path)

    # ---- failure-scene preservation (T0715) --------------------------------

    def preserve_failure(self, step: str, error: Exception) -> str:
        """Capture screenshot + HTML + a dedicated console dump for a failed step."""

        prefix = f"failure_{step}"
        shot = self.evidence_dir / f"{prefix}.png"
        try:
            self.page.screenshot(path=str(shot), full_page=True)
            self.files.append(shot.name)
        except Exception:  # pragma: no cover - page may already be gone
            shot = None  # type: ignore[assignment]
        try:
            html_path = self.evidence_dir / f"{prefix}.html"
            html_path.write_text(self.page.content(), encoding="utf-8")
            self.files.append(html_path.name)
        except Exception:  # pragma: no cover
            pass
        report = self.evidence_dir / f"{prefix}_report.json"
        report.write_text(
            json.dumps(
                {
                    "step": step,
                    "error": repr(error),
                    "url": self.page.url,
                    "console_tail": [entry.as_dict() for entry in self.console[-30:]],
                    "page_errors": self.page_errors[-10:],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        self.files.append(report.name)
        return str(report)


def framing_block_markers(console_texts: list[str]) -> list[str]:
    """Which mechanisms blocked framing, judging from console evidence.

    Report-Only policies log violations with CSP wording too ("...
    violates the following report-only Content Security Policy
    directive ...") even though nothing is blocked, so those messages
    must not count as blocking evidence.
    """

    enforcing_texts = [
        text
        for text in console_texts
        if "report-only" not in text.lower() and "report only" not in text.lower()
    ]
    blocked_by: list[str] = []
    if any(
        "x-frame-options" in text.lower()
        and ("refused" in text.lower() or "denied" in text.lower())
        for text in enforcing_texts
    ):
        blocked_by.append("xfo")
    if any(
        "frame-ancestors" in text.lower()
        and any(word in text.lower() for word in ("violat", "blocked", "refused"))
        for text in enforcing_texts
    ):
        blocked_by.append("csp")
    return blocked_by
