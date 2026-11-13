"""HTTP response-header normalization (T0602).

Header names are lowercased, values keep their list order so duplicate
headers (an important error-configuration class) survive normalization,
and comma-joined values sent by some clients are split back apart.
"""

from __future__ import annotations

from collections.abc import Mapping

COMMA_SPLIT_HEADERS = {"x-frame-options", "content-security-policy"}


class HeaderMap:
    """Case-insensitive multi-value header view."""

    def __init__(self, data: Mapping[str, list[str] | str] | None = None) -> None:
        self._data: dict[str, list[str]] = {}
        for raw_name, raw_values in (data or {}).items():
            name = raw_name.strip().lower()
            values = [raw_values] if isinstance(raw_values, str) else list(raw_values)
            if name in COMMA_SPLIT_HEADERS:
                expanded = [part.strip() for value in values for part in str(value).split(",")]
            else:
                expanded = [str(value).strip() for value in values]
            self._data.setdefault(name, []).extend(value for value in expanded if value)

    def getlist(self, name: str) -> list[str]:
        return list(self._data.get(name.strip().lower(), []))

    def first(self, name: str) -> str | None:
        values = self.getlist(name)
        return values[0] if values else None

    def has(self, name: str) -> bool:
        return bool(self._data.get(name.strip().lower()))

    def as_dict(self) -> dict[str, list[str]]:
        return {name: list(values) for name, values in self._data.items()}
