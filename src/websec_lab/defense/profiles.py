"""Defense profile loading and validation for the M5 defense matrix.

A defense profile bundles frame headers, cookie attributes, business
confirmation rules and the frame-busting baseline into one named
configuration that can be selected with a single environment variable
(``WEBSEC_DEFENSE_PROFILE``) or app factory override
(``DEFENSE_PROFILE``), so defense combinations can be swapped without
touching business code.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from websec_lab.config import repository_root

VALID_SAMESITE = ("Strict", "Lax", "None")
VALID_CONFIRM_MODES = ("none", "reconfirm")
VALID_CSP_KEYWORDS = ("self", "none")
VALID_FRAME_BUSTING = ("off", "navigate", "hide")

# Special source token expanded at app-startup to the configured partner
# origins (public origin plus loopback variants) — see expand_partner_origins.
PARTNER_SOURCE_TOKEN = "partner"

HEADER_KEYS = {
    "xfo",
    "xfo_extra",
    "csp_frame_ancestors",
    "csp_report_only",
    "csp_extra_raw",
    "coop",
}
COOKIE_KEYS = {"samesite", "secure", "httponly"}
BUSINESS_KEYS = {"confirm_mode", "one_time_token", "reauth_ttl_seconds"}


class DefenseConfigError(ValueError):
    """Raised when the defense configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class DefenseProfile:
    """One validated defense combination."""

    name: str
    description: str
    xfo: str | None = None
    xfo_extra: tuple[str, ...] = ()
    csp_frame_ancestors: str | list[str] | None = None
    csp_report_only: bool = False
    csp_extra_raw: tuple[str, ...] = ()
    coop: str | None = None
    cookie_samesite: str = "Lax"
    cookie_secure: bool = False
    cookie_httponly: bool = True
    confirm_mode: str = "none"
    one_time_token: bool = False
    reauth_ttl_seconds: int | None = None
    frame_busting: str = "off"

    def csp_header_value(self) -> str | None:
        """Serialize the frame-ancestors directive for this profile."""

        if self.csp_frame_ancestors is None:
            return None
        if isinstance(self.csp_frame_ancestors, str):
            if self.csp_frame_ancestors == "*":
                return "frame-ancestors *"
            return f"frame-ancestors '{self.csp_frame_ancestors}'"

        def render(source: str) -> str:
            # Only CSP keywords are quoted; plain sources (origins, hosts,
            # wildcards) must appear unquoted.
            if source in VALID_CSP_KEYWORDS:
                return f"'{source}'"
            return source

        return "frame-ancestors " + " ".join(render(source) for source in self.csp_frame_ancestors)

    def csp_header_name(self) -> str:
        return (
            "Content-Security-Policy-Report-Only"
            if self.csp_report_only
            else "Content-Security-Policy"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "xfo": self.xfo,
            "xfo_extra": list(self.xfo_extra),
            "csp_frame_ancestors": self.csp_frame_ancestors,
            "csp_report_only": self.csp_report_only,
            "csp_extra_raw": list(self.csp_extra_raw),
            "coop": self.coop,
            "cookie_samesite": self.cookie_samesite,
            "cookie_secure": self.cookie_secure,
            "cookie_httponly": self.cookie_httponly,
            "confirm_mode": self.confirm_mode,
            "one_time_token": self.one_time_token,
            "reauth_ttl_seconds": self.reauth_ttl_seconds,
            "frame_busting": self.frame_busting,
        }


@dataclass(frozen=True, slots=True)
class DefenseSettings:
    """All known profiles plus the default selection."""

    profiles: dict[str, DefenseProfile]
    default_profile: str
    source_path: Path

    def profile(self, name: str | None) -> DefenseProfile:
        resolved = name or self.default_profile
        try:
            return self.profiles[resolved]
        except KeyError as exc:
            available = ", ".join(sorted(self.profiles))
            raise DefenseConfigError(
                f"Unknown defense profile {resolved!r}. Available: {available}"
            ) from exc

    def active_name(self, environment: Mapping[str, str] | None = None) -> str:
        env = os.environ if environment is None else environment
        return env.get("WEBSEC_DEFENSE_PROFILE") or self.default_profile

    def active_profile(self, environment: Mapping[str, str] | None = None) -> DefenseProfile:
        return self.profile(self.active_name(environment))


def default_defense_path() -> Path:
    configured = os.getenv("WEBSEC_DEFENSE_CONFIG")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else repository_root() / path
    return repository_root() / "config" / "defense.yaml"


def _require_mapping(data: Any, section: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise DefenseConfigError(f"Defense section {section!r} must be a mapping")
    return data


def _parse_headers(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    headers = _require_mapping(raw or {}, "headers")
    unknown = set(headers) - HEADER_KEYS
    if unknown:
        raise DefenseConfigError(
            f"Unknown headers keys: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(HEADER_KEYS))}"
        )
    parsed: dict[str, Any] = {}

    xfo = headers.get("xfo")
    if xfo is not None and (not isinstance(xfo, str) or not xfo.strip()):
        raise DefenseConfigError("headers.xfo must be a non-empty string or null")
    parsed["xfo"] = xfo.strip() if isinstance(xfo, str) else None

    xfo_extra = headers.get("xfo_extra") or []
    if not isinstance(xfo_extra, list) or not all(
        isinstance(item, str) and item.strip() for item in xfo_extra
    ):
        raise DefenseConfigError("headers.xfo_extra must be a list of non-empty strings")
    parsed["xfo_extra"] = tuple(item.strip() for item in xfo_extra)

    csp = headers.get("csp_frame_ancestors")
    if csp is not None:
        if isinstance(csp, str):
            if csp.strip() not in ("none", "self"):
                raise DefenseConfigError(
                    "headers.csp_frame_ancestors string must be 'none' or 'self'"
                )
        elif isinstance(csp, list):
            if not csp or not all(isinstance(item, str) and item.strip() for item in csp):
                raise DefenseConfigError(
                    "headers.csp_frame_ancestors list must contain non-empty sources"
                )
            csp = [item.strip() for item in csp]
        else:
            raise DefenseConfigError(
                "headers.csp_frame_ancestors must be null, 'none', 'self' or a source list"
            )
    parsed["csp_frame_ancestors"] = csp

    report_only = headers.get("csp_report_only", False)
    if not isinstance(report_only, bool):
        raise DefenseConfigError("headers.csp_report_only must be a boolean")
    parsed["csp_report_only"] = report_only

    csp_extra = headers.get("csp_extra_raw") or []
    if not isinstance(csp_extra, list) or not all(
        isinstance(item, str) and item.strip() for item in csp_extra
    ):
        raise DefenseConfigError("headers.csp_extra_raw must be a list of policy strings")
    parsed["csp_extra_raw"] = tuple(item.strip() for item in csp_extra)

    coop = headers.get("coop")
    if coop is not None and (not isinstance(coop, str) or not coop.strip()):
        raise DefenseConfigError("headers.coop must be a non-empty string or null")
    parsed["coop"] = coop.strip() if isinstance(coop, str) else None
    return parsed


def _parse_cookie(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    cookie = _require_mapping(raw or {}, "cookie")
    unknown = set(cookie) - COOKIE_KEYS
    if unknown:
        raise DefenseConfigError(
            f"Unknown cookie keys: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(COOKIE_KEYS))}"
        )
    samesite = cookie.get("samesite", "Lax")
    if samesite not in VALID_SAMESITE:
        allowed = ", ".join(VALID_SAMESITE)
        raise DefenseConfigError(f"cookie.samesite must be one of: {allowed}")
    secure = cookie.get("secure", False)
    httponly = cookie.get("httponly", True)
    if not isinstance(secure, bool) or not isinstance(httponly, bool):
        raise DefenseConfigError("cookie.secure and cookie.httponly must be booleans")
    return {
        "cookie_samesite": samesite,
        "cookie_secure": secure,
        "cookie_httponly": httponly,
    }


def _parse_business(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    business = _require_mapping(raw or {}, "business")
    unknown = set(business) - BUSINESS_KEYS
    if unknown:
        raise DefenseConfigError(
            f"Unknown business keys: {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(BUSINESS_KEYS))}"
        )
    confirm_mode = business.get("confirm_mode", "none")
    if confirm_mode not in VALID_CONFIRM_MODES:
        allowed = ", ".join(VALID_CONFIRM_MODES)
        raise DefenseConfigError(f"business.confirm_mode must be one of: {allowed}")

    one_time_token = business.get("one_time_token", False)
    if not isinstance(one_time_token, bool):
        raise DefenseConfigError("business.one_time_token must be a boolean")

    reauth_ttl = business.get("reauth_ttl_seconds")
    if reauth_ttl is not None and (
        not isinstance(reauth_ttl, int) or isinstance(reauth_ttl, bool) or reauth_ttl < 0
    ):
        raise DefenseConfigError(
            "business.reauth_ttl_seconds must be a non-negative integer or null"
        )
    return {
        "confirm_mode": confirm_mode,
        "one_time_token": one_time_token,
        "reauth_ttl_seconds": reauth_ttl,
    }


def load_defense_settings(path: str | Path | None = None) -> DefenseSettings:
    """Load, validate and normalize the defense profile matrix."""

    source = Path(path) if path is not None else default_defense_path()
    source = source.resolve()
    if not source.is_file():
        raise DefenseConfigError(f"Defense configuration does not exist: {source}")

    with source.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    root = _require_mapping(raw, "root")

    default_profile = str(root.get("default_profile", "")).strip()
    profiles_raw = _require_mapping(root.get("profiles"), "profiles")
    if not profiles_raw:
        raise DefenseConfigError("Defense configuration declares no profiles")
    if default_profile not in profiles_raw:
        raise DefenseConfigError(f"default_profile {default_profile!r} is not defined in profiles")

    profiles: dict[str, DefenseProfile] = {}
    for name, body in profiles_raw.items():
        item = _require_mapping(body, f"profiles.{name}")
        frame_busting = item.get("frame_busting", "off")
        if frame_busting not in VALID_FRAME_BUSTING:
            allowed = ", ".join(VALID_FRAME_BUSTING)
            raise DefenseConfigError(f"profiles.{name}.frame_busting must be one of: {allowed}")
        merged: dict[str, Any] = {"name": str(name)}
        merged["description"] = str(item.get("description", "")).strip()
        merged.update(_parse_headers(item.get("headers")))
        merged.update(_parse_cookie(item.get("cookie")))
        merged.update(_parse_business(item.get("business")))
        merged["frame_busting"] = frame_busting
        profiles[str(name)] = DefenseProfile(**merged)

    return DefenseSettings(
        profiles=profiles,
        default_profile=default_profile,
        source_path=source,
    )


def resolve_active_profile(
    override: str | None = None,
    path: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> DefenseProfile:
    """Resolve the profile to apply: explicit override > env var > default."""

    settings = load_defense_settings(path)
    return settings.profile(override or settings.active_name(environment))


def expand_partner_origins(profile: DefenseProfile, partner_origins: list[str]) -> DefenseProfile:
    """Replace the ``partner`` source token with concrete partner origins.

    This is the T0507 wiring: defense.yaml stays environment-agnostic
    while the victim serves a CSP allowlist derived from lab.yaml.
    """

    sources = profile.csp_frame_ancestors
    if not isinstance(sources, list) or PARTNER_SOURCE_TOKEN not in sources:
        return profile
    expanded = [source for source in sources if source != PARTNER_SOURCE_TOKEN]
    for origin in partner_origins:
        if origin not in expanded:
            expanded.append(origin)
    return replace(profile, csp_frame_ancestors=expanded)
