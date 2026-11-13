"""Browser and context lifecycle management for dynamic audits (T0702/T0713/T0714).

The session resolves a browser channel (chrome / msedge / firefox) against
locally installed executables, applies desktop or mobile viewport profiles,
and always tears the browser down cleanly. Failure sites are captured by the
evidence collector, not here.
"""

from __future__ import annotations

import json
import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

from websec_lab.browser import discover_browsers
from websec_lab.transport import LAB_HOSTS

DESKTOP_VIEWPORT = {"width": 1280, "height": 900}
MOBILE_VIEWPORT = {
    "width": 390,
    "height": 844,
    "device_scale_factor": 3,
    "is_mobile": True,
    "has_touch": True,
    "user_agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ),
}

VIEWPORT_PROFILES = {"desktop": DESKTOP_VIEWPORT, "mobile": MOBILE_VIEWPORT}
SUPPORTED_CHANNELS = ("chrome", "msedge", "firefox")


class BrowserSessionError(RuntimeError):
    """Raised when the requested browser channel is unavailable."""


@dataclass(slots=True)
class _ResolvedBrowser:
    engine: str  # "chromium" | "firefox"
    executable: str | None
    display_name: str

    def describe(self) -> dict[str, object]:
        return {
            "engine": self.engine,
            "executable": self.executable,
            "name": self.display_name,
        }


def resolve_browser(channel: str) -> _ResolvedBrowser:
    if channel not in SUPPORTED_CHANNELS:
        raise BrowserSessionError(
            f"Unsupported browser channel {channel!r}; choose from {', '.join(SUPPORTED_CHANNELS)}"
        )

    if channel == "firefox":
        installed = [item for item in discover_browsers() if item.channel == "firefox"]
        if not installed:
            raise BrowserSessionError("No local Firefox installation found (channel=firefox)")
        return _ResolvedBrowser("firefox", str(installed[0].executable_path), installed[0].name)

    installed = [item for item in discover_browsers() if item.channel == channel]
    if not installed:
        raise BrowserSessionError(f"No local Chromium-family browser found for channel {channel!r}")
    return _ResolvedBrowser("chromium", str(installed[0].executable_path), installed[0].name)


class BrowserSession:
    """Owns playwright, one browser, one context and one page (T0702)."""

    def __init__(
        self,
        channel: str = "chrome",
        viewport_profile: str = "desktop",
        headless: bool = True,
        record_video_dir: Path | None = None,
        trace_enabled: bool = False,
        storage_state: Path | None = None,
        https_lab: bool = False,
    ) -> None:
        """Create a session.

        ``trace_enabled`` records a Playwright trace (no extra binaries
        needed); ``record_video_dir`` additionally records a video, which
        requires the ffmpeg binary Playwright ships separately.
        """
        if viewport_profile not in VIEWPORT_PROFILES:
            raise BrowserSessionError(
                f"Unknown viewport profile {viewport_profile!r}; "
                f"choose from {', '.join(VIEWPORT_PROFILES)}"
            )
        self.channel = channel
        self.viewport_profile = viewport_profile
        self.headless = headless
        self.record_video_dir = record_video_dir
        self.trace_enabled = trace_enabled
        self.storage_state = storage_state
        self.https_lab = https_lab
        self.resolved = resolve_browser(channel)
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._profile_directory: TemporaryDirectory | None = None

    @property
    def version(self) -> str:
        return self._browser.version if self._browser is not None else "unavailable"

    @property
    def page(self) -> Page:
        if self._page is None:
            raise BrowserSessionError("BrowserSession not started")
        return self._page

    @property
    def context(self) -> BrowserContext:
        if self._context is None:
            raise BrowserSessionError("BrowserSession not started")
        return self._context

    def viewport_description(self) -> dict[str, object]:
        profile = dict(VIEWPORT_PROFILES[self.viewport_profile])
        return {"profile": self.viewport_profile, **profile}

    def __enter__(self) -> BrowserSession:
        try:
            self.start()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def start(self) -> None:
        self._playwright = sync_playwright().start()
        engine = getattr(self._playwright, self.resolved.engine)
        launch_kwargs: dict[str, object] = {
            "headless": self.headless,
        }
        if self.resolved.executable:
            launch_kwargs["executable_path"] = self.resolved.executable
        if self.https_lab:
            from websec_lab.https_lab import browser_arguments

            if self.resolved.engine == "chromium":
                launch_kwargs["args"] = browser_arguments()
            else:
                launch_kwargs["firefox_user_prefs"] = {
                    "network.dns.localDomains": ",".join(LAB_HOSTS),
                    "network.proxy.type": 0,
                    "security.enterprise_roots.enabled": True,
                    "network.cookie.cookieBehavior": 0,
                }
        profile = VIEWPORT_PROFILES[self.viewport_profile]
        context_kwargs: dict[str, object] = {
            "viewport": {"width": profile["width"], "height": profile["height"]},
        }
        for optional in ("device_scale_factor", "is_mobile", "has_touch", "user_agent"):
            if optional in profile:
                context_kwargs[optional] = profile[optional]
        if self.record_video_dir is not None:
            self.record_video_dir.mkdir(parents=True, exist_ok=True)
            context_kwargs["record_video_dir"] = str(self.record_video_dir)
            context_kwargs["record_video_size"] = {
                "width": profile["width"],
                "height": profile["height"],
            }
        if self.storage_state is not None:
            context_kwargs["storage_state"] = str(self.storage_state)
        if self.https_lab and self.resolved.engine == "chromium" and os.name != "nt":
            # Linux Chromium's incognito preferences can override target CDP
            # settings. Use an owned regular profile, as in the SameSite suite.
            self._profile_directory = TemporaryDirectory(prefix="websec-browser-")
            user_dir = Path(self._profile_directory.name)
            preferences = user_dir / "Default/Preferences"
            preferences.parent.mkdir()
            preferences.write_text(
                json.dumps(
                    {"profile": {"cookie_controls_mode": 0, "block_third_party_cookies": False}}
                ),
                encoding="utf-8",
            )
            context_kwargs.pop("storage_state", None)
            self._context = engine.launch_persistent_context(
                str(user_dir), **launch_kwargs, **context_kwargs
            )
            self._browser = self._context.browser
            if self.storage_state is not None:
                self._context.set_storage_state(self.storage_state)
            self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
        else:
            self._browser = engine.launch(**launch_kwargs)  # type: ignore[union-attr]
            self._context = self._browser.new_context(**context_kwargs)
            self._page = self._context.new_page()
        if self.https_lab and self.resolved.engine == "chromium":
            # Explicit allow setting in this isolated audit context; the
            # separate SameSite matrix varies third-party-cookie restrictions.
            cdp = self._context.new_cdp_session(self._page)
            cdp.send("Network.enable")
            cdp.send(
                "Network.setCookieControls",
                {
                    "enableThirdPartyCookieRestriction": False,
                    "disableThirdPartyCookieMetadata": True,
                    "disableThirdPartyCookieHeuristics": True,
                },
            )
        if self.trace_enabled:
            self._context.tracing.start(screenshots=True, snapshots=True, sources=True)

    def close(self) -> None:
        # The trace itself is stopped by the runner so it can point at a file
        # inside the evidence directory; teardown here is best-effort.
        with suppress(Exception):
            if self._context is not None:
                self._context.close()
        with suppress(Exception):
            if self._browser is not None:
                self._browser.close()
        with suppress(Exception):
            if self._playwright is not None:
                self._playwright.stop()
        with suppress(Exception):
            if self._profile_directory is not None:
                self._profile_directory.cleanup()
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        self._profile_directory = None

    def stop_tracing(self, output_path: Path) -> None:
        if self._context is not None and self.trace_enabled:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self._context.tracing.stop(path=str(output_path))
