"""Local-guarded HTTP fetching with redirect-chain recording (T0601)."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

from websec_lab.auditor.headers import HeaderMap
from websec_lab.transport import local_get

FETCH_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 10
USER_AGENT = "WebSec-Lab-Auditor/0.1 (local lab only)"


class FetchError(ValueError):
    """Raised when a target cannot be fetched within the lab's safety rules."""


def is_local_target(url: str) -> bool:
    """Only loopback and ``*.test`` hosts may be analyzed (threat model)."""

    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1") or host.endswith(".test") or host == "test"


@dataclass(frozen=True, slots=True)
class FetchedResponse:
    """Normalized final response plus the full redirect chain."""

    requested_url: str
    final_url: str
    status_code: int
    headers: HeaderMap
    set_cookies: tuple[str, ...]
    redirect_chain: tuple[str, ...] = field(default_factory=tuple)


def fetch_response(url: str) -> FetchedResponse:
    """Fetch a local target, following redirects manually to record the chain."""

    if not is_local_target(url):
        raise FetchError(
            "Refusing non-local target: the lab only analyzes loopback or *.test origins"
        )

    chain: list[str] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = local_get(
                current,
                timeout=FETCH_TIMEOUT_SECONDS,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            raise FetchError(f"Target request failed: {current}: {exc}") from exc
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                raise FetchError(f"Redirect without Location header at {current}")
            current = _resolve_url(current, location)
            chain.append(current)
            continue

        raw_headers = response.raw.headers
        header_map: dict[str, list[str]] = {}
        for name in raw_headers:
            header_map[name.lower()] = raw_headers.getlist(name)
        return FetchedResponse(
            requested_url=url,
            final_url=current,
            status_code=response.status_code,
            headers=HeaderMap(header_map),
            set_cookies=tuple(response.raw.headers.getlist("Set-Cookie")),
            redirect_chain=tuple(chain),
        )

    raise FetchError(f"Too many redirects (>{MAX_REDIRECTS}) starting at {url}")


def _resolve_url(base: str, location: str) -> str:
    target = urljoin(base, location)
    if not is_local_target(target):
        raise FetchError(f"Redirect leaves the local lab scope: {target}")
    return target
