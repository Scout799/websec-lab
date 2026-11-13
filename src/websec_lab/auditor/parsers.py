"""Parsers for X-Frame-Options, CSP frame-ancestors and Set-Cookie (T0603/T0604/T0609)."""

from __future__ import annotations

from dataclasses import dataclass, field

from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.origins import Origin, matches_frame_ancestor_source

VALID_XFO_VALUES = ("deny", "sameorigin")


# ---------------------------------------------------------------------------
# X-Frame-Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class XfoPolicy:
    """Parsed X-Frame-Options state used for evaluation and rule firing."""

    values: tuple[str, ...]  # normalized, original order preserved
    duplicates: bool = False
    obsolete_allow_from: bool = False  # ALLOW-FROM: ignored by modern browsers
    invalid_values: tuple[str, ...] = ()

    @property
    def effective_value(self) -> str | None:
        """The value modern browsers act on: first well-formed value, else None.

        Browsers disagree on duplicate handling; the analyzer uses the first
        value and flags the ambiguity as its own rule.
        """

        for value in self.values:
            if value.lower() in VALID_XFO_VALUES:
                return value.lower()
        return None

    def as_dict(self) -> dict[str, object]:
        return {
            "values": list(self.values),
            "duplicates": self.duplicates,
            "obsolete_allow_from": self.obsolete_allow_from,
            "invalid_values": list(self.invalid_values),
            "effective_value": self.effective_value,
        }


def parse_xfo(headers: HeaderMap) -> XfoPolicy | None:
    raw_values = headers.getlist("x-frame-options")
    if not raw_values:
        return None

    normalized = [value.strip() for value in raw_values]
    invalid = [
        value
        for value in normalized
        if value.lower() not in VALID_XFO_VALUES and not value.upper().startswith("ALLOW-FROM")
    ]
    return XfoPolicy(
        values=tuple(normalized),
        duplicates=len(normalized) > 1,
        obsolete_allow_from=any(value.upper().startswith("ALLOW-FROM") for value in normalized),
        invalid_values=tuple(invalid),
    )


# ---------------------------------------------------------------------------
# CSP frame-ancestors
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CspPolicy:
    """One Content-Security-Policy header reduced to its frame-ancestors part."""

    raw: str
    has_frame_ancestors: bool
    sources: tuple[str, ...] = ()
    allows_none: bool = False
    malformed: bool = False

    def allows(self, ancestor: Origin, target: Origin) -> bool:
        if not self.has_frame_ancestors:
            return True
        if self.allows_none or not self.sources:
            return False
        return any(
            matches_frame_ancestor_source(source, ancestor, target) for source in self.sources
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "has_frame_ancestors": self.has_frame_ancestors,
            "sources": list(self.sources),
            "allows_none": self.allows_none,
            "malformed": self.malformed,
        }


@dataclass(frozen=True, slots=True)
class CspAnalysis:
    """All enforcing and report-only CSP policies found on a response."""

    enforcing: tuple[CspPolicy, ...] = ()
    report_only: tuple[CspPolicy, ...] = ()

    @property
    def has_enforcing_frame_ancestors(self) -> bool:
        return any(policy.has_frame_ancestors for policy in self.enforcing)

    def allows(self, ancestor: Origin, target: Origin) -> bool:
        """Multiple policies intersect: every enforcing policy must allow."""

        return all(policy.allows(ancestor, target) for policy in self.enforcing)

    def as_dict(self) -> dict[str, object]:
        return {
            "enforcing": [policy.as_dict() for policy in self.enforcing],
            "report_only": [policy.as_dict() for policy in self.report_only],
        }


def _parse_policy(raw: str) -> CspPolicy:
    directives: dict[str, list[str]] = {}
    malformed = False
    for directive in raw.split(";"):
        tokens = directive.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        values = tokens[1:]
        if name in directives:
            # A duplicated directive is ignored per CSP; remember it as malformed.
            malformed = True
            continue
        directives[name] = values

    fa_values = directives.get("frame-ancestors")
    if fa_values is None:
        return CspPolicy(raw=raw, has_frame_ancestors=False, malformed=malformed)

    allows_none = "'none'" in fa_values
    sources = tuple(value for value in fa_values if value != "'none'")
    if allows_none and sources:
        # A mixed 'none' is a configuration mistake, but browsers ignore that
        # keyword and still match the other source expressions (CSP3 6.7.2.7).
        return CspPolicy(
            raw=raw,
            has_frame_ancestors=True,
            sources=sources,
            allows_none=False,
            malformed=True,
        )
    return CspPolicy(
        raw=raw,
        has_frame_ancestors=True,
        sources=sources,
        allows_none=allows_none,
        malformed=malformed,
    )


def parse_csp(headers: HeaderMap) -> CspAnalysis:
    enforcing = tuple(_parse_policy(raw) for raw in headers.getlist("content-security-policy"))
    report_only = tuple(
        _parse_policy(raw) for raw in headers.getlist("content-security-policy-report-only")
    )
    return CspAnalysis(enforcing=enforcing, report_only=report_only)


# ---------------------------------------------------------------------------
# Set-Cookie
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CookiePolicy:
    """Security-relevant attributes of one Set-Cookie header."""

    name: str
    same_site: str | None
    secure: bool
    http_only: bool
    raw: str

    @property
    def same_site_none_without_secure(self) -> bool:
        return self.same_site == "None" and not self.secure

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "same_site": self.same_site,
            "secure": self.secure,
            "http_only": self.http_only,
            "raw": self.raw,
        }


def parse_set_cookies(raw_cookies: list[str] | tuple[str, ...]) -> list[CookiePolicy]:
    parsed: list[CookiePolicy] = []
    for raw in raw_cookies:
        parts = [part.strip() for part in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0]
        same_site: str | None = None
        secure = False
        http_only = False
        for attribute in parts[1:]:
            key = attribute.split("=", 1)[0].strip()
            value = attribute.split("=", 1)[1].strip() if "=" in attribute else ""
            if key.lower() == "samesite" and value:
                normalized = value.capitalize()
                same_site = normalized if normalized in ("Strict", "Lax", "None") else value
            elif key.lower() == "secure":
                secure = True
            elif key.lower() == "httponly":
                http_only = True
        parsed.append(
            CookiePolicy(
                name=name,
                same_site=same_site,
                secure=secure,
                http_only=http_only,
                raw=raw,
            )
        )
    return parsed


@dataclass(frozen=True, slots=True)
class ParsedHeaders:
    """Everything the analyzer needs, extracted from one normalized response."""

    xfo: XfoPolicy | None
    csp: CspAnalysis
    cookies: list[CookiePolicy] = field(default_factory=list)

    @classmethod
    def from_headers(cls, headers: HeaderMap, set_cookies: tuple[str, ...] = ()) -> ParsedHeaders:
        return cls(
            xfo=parse_xfo(headers),
            csp=parse_csp(headers),
            cookies=parse_set_cookies(set_cookies),
        )
