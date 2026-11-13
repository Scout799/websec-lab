"""Origin parsing and CSP source-expression matching (T0605).

The lab only uses ``*.test`` hosts and loopback addresses, so site
(registrable-domain) computation uses a last-two-labels approximation
instead of the full Public Suffix List; the limitation is documented
where the helper is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


@dataclass(frozen=True, slots=True)
class Origin:
    """An http(s) origin: scheme, host and effective port."""

    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def same_origin(self, other: Origin) -> bool:
        return (self.scheme, self.host, self.port) == (other.scheme, other.host, other.port)

    def same_site(self, other: Origin) -> bool:
        return self.scheme == other.scheme and registrable_domain(self.host) == registrable_domain(
            other.host
        )


def parse_origin(url: str) -> Origin:
    """Parse an absolute http(s) URL into an Origin, filling default ports."""

    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Not an absolute http(s) URL: {url!r}")
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    return Origin(scheme=parts.scheme, host=parts.hostname.lower(), port=port)


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 by keeping the last two labels.

    Sufficient for ``victim.test`` / ``partner.test`` style lab hosts;
    a full Public Suffix List is unnecessary for this project.
    """

    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def _source_host_matches(source_host: str, host: str) -> bool:
    if source_host == "*":
        return True
    if source_host.startswith("*."):
        suffix = source_host[2:].lower()
        return host.endswith("." + suffix)
    return source_host.lower() == host


def matches_frame_ancestor_source(source: str, ancestor: Origin, target: Origin) -> bool:
    """Whether one parsed frame-ancestors source expression matches an ancestor."""

    token = source.strip()
    if token in ("'self'", "'src'"):
        return ancestor.same_origin(target)
    if token == "'none'":
        return False
    if token == "*":
        return True
    if token.endswith(":") and "://" not in token:
        # Scheme-source such as ``https:``.
        return ancestor.scheme == token[:-1].lower()

    # Host-source: [scheme://]host[:port][/path|/path-prefix]
    rest = token
    scheme: str | None = None
    if "://" in rest:
        scheme, _, rest = rest.partition("://")
        scheme = scheme.lower()
    path: str | None = None
    if "/" in rest:
        rest, _, path = rest.partition("/")

    port: str | None = None
    if rest.count(":") == 1:
        host_part, _, port = rest.partition(":")
    else:
        host_part = rest

    if not _source_host_matches(host_part, ancestor.host):
        return False
    if scheme is not None and scheme != ancestor.scheme:
        return False
    # Only an explicit :* matches arbitrary ports. An omitted port uses the
    # default for the ancestor's scheme, not the protected page's port.
    if not port:
        return ancestor.port == DEFAULT_PORTS[ancestor.scheme]
    if port == "*":
        return True
    return port.isdigit() and int(port) == ancestor.port
