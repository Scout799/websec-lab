from pathlib import Path

import pytest

from websec_lab.config import ConfigurationError, load_settings


def test_default_configuration_contains_required_services() -> None:
    settings = load_settings()

    assert set(settings.services) == {"victim", "attacker", "partner", "auditor"}
    assert settings.local_only is True
    assert settings.database_path.is_absolute()


def test_service_lookup_reports_available_names() -> None:
    settings = load_settings()

    with pytest.raises(ConfigurationError, match="Available services"):
        settings.service("unknown")


def test_duplicate_ports_are_rejected(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yaml"
    config.write_text(
        """
project:
  name: test
  environment: test
  local_only: true
services:
  victim: &service
    display_name: victim
    host: 127.0.0.1
    port: 5100
    public_origin: http://victim.test:5100
    purpose: test
  attacker:
    <<: *service
    display_name: attacker
  partner:
    <<: *service
    display_name: partner
    port: 5300
  auditor:
    <<: *service
    display_name: auditor
    port: 5400
storage:
  database_path: data/test.sqlite3
  artifact_dir: artifacts
  log_dir: logs
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="Duplicate service port"):
        load_settings(config)


def test_missing_configuration_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_settings(tmp_path / "missing.yaml")


def test_non_mapping_root_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "invalid-root.yaml"
    config.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="root"):
        load_settings(config)
