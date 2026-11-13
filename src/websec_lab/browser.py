"""Discover locally installed browsers for Playwright fallback launches."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BrowserInstallation:
    """A browser executable available to the local lab."""

    name: str
    channel: str
    executable_path: Path
    source: str

    def as_dict(self) -> dict[str, str]:
        payload = asdict(self)
        payload["executable_path"] = str(self.executable_path)
        return payload


def _candidate_browsers(
    environment: Mapping[str, str], *, ambient: bool = True
) -> list[BrowserInstallation]:
    candidates: list[BrowserInstallation] = []

    explicit = (
        ("Google Chrome", "chrome", "WEBSEC_CHROME_PATH"),
        ("Microsoft Edge", "msedge", "WEBSEC_EDGE_PATH"),
        ("Mozilla Firefox", "firefox", "WEBSEC_FIREFOX_PATH"),
    )
    for name, channel, variable in explicit:
        if value := environment.get(variable):
            candidates.append(BrowserInstallation(name, channel, Path(value), variable))

    program_files = environment.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = environment.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local_app_data = environment.get("LOCALAPPDATA")

    candidates.extend(
        [
            BrowserInstallation(
                "Google Chrome",
                "chrome",
                Path(program_files) / "Google/Chrome/Application/chrome.exe",
                "windows-default",
            ),
            BrowserInstallation(
                "Google Chrome",
                "chrome",
                Path(program_files_x86) / "Google/Chrome/Application/chrome.exe",
                "windows-default",
            ),
            BrowserInstallation(
                "Microsoft Edge",
                "msedge",
                Path(program_files_x86) / "Microsoft/Edge/Application/msedge.exe",
                "windows-default",
            ),
            BrowserInstallation(
                "Microsoft Edge",
                "msedge",
                Path(program_files) / "Microsoft/Edge/Application/msedge.exe",
                "windows-default",
            ),
            BrowserInstallation(
                "Mozilla Firefox",
                "firefox",
                Path(program_files) / "Mozilla Firefox/firefox.exe",
                "windows-default",
            ),
        ]
    )
    if local_app_data:
        candidates.append(
            BrowserInstallation(
                "Google Chrome",
                "chrome",
                Path(local_app_data) / "Google/Chrome/Application/chrome.exe",
                "windows-user",
            )
        )
    cache_root = Path(
        environment.get("PLAYWRIGHT_BROWSERS_PATH")
        or (
            str(Path(local_app_data) / "ms-playwright")
            if local_app_data
            else str(Path.home() / ".cache/ms-playwright")
        )
    )
    cache_enabled = ambient or "PLAYWRIGHT_BROWSERS_PATH" in environment or bool(local_app_data)
    for directory in sorted(cache_root.glob("firefox-*") if cache_enabled else [], reverse=True):
        executable = directory / "firefox" / ("firefox.exe" if os.name == "nt" else "firefox")
        if executable.is_file():
            candidates.append(
                BrowserInstallation("Playwright Firefox", "firefox", executable, "playwright-cache")
            )
            break
    if os.name != "nt" and ambient:
        import shutil

        for binary, channel in (("chromium", "chrome"), ("google-chrome", "chrome")):
            if found := shutil.which(binary):
                candidates.append(BrowserInstallation(binary, channel, Path(found), "system-path"))
        for directory in sorted(cache_root.glob("chromium-*"), reverse=True):
            for suffix in ("chrome-linux/chrome", "chrome-linux64/chrome"):
                executable = directory / suffix
                if executable.is_file():
                    candidates.append(
                        BrowserInstallation(
                            "Playwright Chromium", "chrome", executable, "playwright-cache"
                        )
                    )
    return candidates


def discover_browsers(environment: Mapping[str, str] | None = None) -> list[BrowserInstallation]:
    """Return unique browser executables that exist on the current machine."""

    resolved_environment = os.environ if environment is None else environment
    discovered: list[BrowserInstallation] = []
    seen_paths: set[Path] = set()

    for candidate in _candidate_browsers(resolved_environment, ambient=environment is None):
        path = candidate.executable_path.resolve()
        if path.is_file() and path not in seen_paths:
            discovered.append(
                BrowserInstallation(
                    candidate.name,
                    candidate.channel,
                    path,
                    candidate.source,
                )
            )
            seen_paths.add(path)
    return discovered
