"""Configuration loading and validation for the local lab."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigurationError(ValueError):
    """Raised when the lab configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Network and descriptive settings for one lab service."""

    name: str
    display_name: str
    host: str
    port: int
    public_origin: str
    purpose: str


@dataclass(frozen=True, slots=True)
class LabSettings:
    """Validated project configuration."""

    project_name: str
    environment: str
    local_only: bool
    services: dict[str, ServiceConfig]
    database_path: Path
    artifact_dir: Path
    log_dir: Path
    source_path: Path
    trusted_proxy: bool = False

    def service(self, name: str) -> ServiceConfig:
        try:
            return self.services[name]
        except KeyError as exc:
            available = ", ".join(sorted(self.services))
            raise ConfigurationError(
                f"Unknown service {name!r}. Available services: {available}"
            ) from exc


def repository_root() -> Path:
    """Return the repository root for an editable or source checkout."""
    if configured := os.getenv("WEBSEC_PROJECT_ROOT"):
        return Path(configured).resolve()
    source = Path(__file__).resolve().parents[2]
    if (source / "config/lab.yaml").is_file():
        return source
    if (Path.cwd() / "config/lab.yaml").is_file():
        return Path.cwd()
    raise ConfigurationError("Run from the project checkout or set WEBSEC_PROJECT_ROOT")


def default_config_path() -> Path:
    configured = os.getenv("WEBSEC_CONFIG")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else repository_root() / path
    return repository_root() / "config" / "lab.yaml"


def _require_mapping(data: Any, section: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ConfigurationError(f"Configuration section {section!r} must be a mapping")
    return data


def load_settings(path: str | Path | None = None) -> LabSettings:
    """Load, validate, and normalize the lab configuration."""

    source = Path(path) if path is not None else default_config_path()
    source = source.resolve()
    if not source.is_file():
        raise ConfigurationError(f"Configuration file does not exist: {source}")

    with source.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)

    root = _require_mapping(raw, "root")
    project = _require_mapping(root.get("project"), "project")
    service_items = _require_mapping(root.get("services"), "services")
    storage = _require_mapping(root.get("storage"), "storage")
    if not isinstance(root.get("trusted_proxy", False), bool):
        raise ConfigurationError("trusted_proxy must be a boolean")

    services: dict[str, ServiceConfig] = {}
    ports: set[int] = set()
    for name, raw_service in service_items.items():
        item = _require_mapping(raw_service, f"services.{name}")
        try:
            port = int(item["port"])
            service = ServiceConfig(
                name=str(name),
                display_name=str(item["display_name"]),
                host=str(item["host"]),
                port=port,
                public_origin=str(item["public_origin"]),
                purpose=str(item["purpose"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid service configuration for {name!r}") from exc

        if not 1 <= port <= 65535:
            raise ConfigurationError(f"Port for service {name!r} is out of range: {port}")
        if port in ports:
            raise ConfigurationError(f"Duplicate service port: {port}")
        ports.add(port)
        services[service.name] = service

    required_services = {"victim", "attacker", "partner", "auditor"}
    missing = required_services.difference(services)
    if missing:
        raise ConfigurationError(f"Missing required services: {', '.join(sorted(missing))}")

    repo = repository_root()

    def storage_path(key: str) -> Path:
        try:
            value = Path(str(storage[key]))
        except KeyError as exc:
            raise ConfigurationError(f"Missing storage setting: {key}") from exc
        return value if value.is_absolute() else repo / value

    return LabSettings(
        project_name=str(project.get("name", "WebSec Clickjacking Lab")),
        environment=os.getenv("WEBSEC_ENV", str(project.get("environment", "development"))),
        local_only=bool(project.get("local_only", True)),
        services=services,
        database_path=storage_path("database_path"),
        artifact_dir=storage_path("artifact_dir"),
        log_dir=storage_path("log_dir"),
        source_path=source,
        trusted_proxy=bool(root.get("trusted_proxy", False)),
    )
