from pathlib import Path

import pytest
import yaml

from websec_lab.defense import (
    DefenseConfigError,
    load_defense_settings,
    resolve_active_profile,
)

EXPECTED_PROFILES = {
    "none",
    "xfo-deny",
    "xfo-sameorigin",
    "csp-none",
    "csp-self",
    "csp-partner-allowlist",
    "csp-partner-allowlist-attacker",
    "xfo-csp-consistent",
    "xfo-csp-conflict",
    "broken-duplicate-xfo",
    "broken-invalid-xfo",
    "broken-wide-csp",
    "broken-duplicate-csp",
    "csp-report-only",
    "samesite-strict",
    "samesite-none",
    "cookie-hardened",
    "confirm-reconfirm",
    "confirm-token",
    "reauth",
    "business-hardened",
    "frame-busting",
    "frame-busting-hidden",
    "coop-same-origin",
}


def test_all_documented_profiles_load() -> None:
    settings = load_defense_settings()

    assert settings.default_profile == "none"
    assert set(settings.profiles) >= EXPECTED_PROFILES
    assert all(profile.description for profile in settings.profiles.values())


def test_unknown_profile_name_is_rejected() -> None:
    settings = load_defense_settings()
    with pytest.raises(DefenseConfigError, match="Unknown defense profile"):
        settings.profile("fort-knox")


def test_env_var_selects_active_profile() -> None:
    settings = load_defense_settings()
    environment = {"WEBSEC_DEFENSE_PROFILE": "xfo-deny"}

    assert settings.active_name(environment) == "xfo-deny"
    assert settings.active_profile(environment).xfo == "DENY"
    assert settings.active_name({}) == "none"


def test_explicit_override_beats_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBSEC_DEFENSE_PROFILE", "xfo-deny")

    resolved = resolve_active_profile(override="csp-self")

    assert resolved.name == "csp-self"


def test_env_var_without_override_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEBSEC_DEFENSE_PROFILE", "csp-none")

    assert resolve_active_profile().name == "csp-none"


def test_csp_header_serialization() -> None:
    settings = load_defense_settings()

    assert settings.profile("csp-none").csp_header_value() == "frame-ancestors 'none'"
    assert settings.profile("csp-self").csp_header_value() == "frame-ancestors 'self'"
    assert settings.profile("broken-wide-csp").csp_header_value() == "frame-ancestors *"
    assert settings.profile("none").csp_header_value() is None
    # The `partner` token stays literal in the profile; the victim factory
    # expands it into concrete origins at startup (T0507).
    assert (
        settings.profile("csp-partner-allowlist").csp_header_value()
        == "frame-ancestors 'self' partner"
    )


def test_partner_token_expansion() -> None:
    from websec_lab.defense import expand_partner_origins

    settings = load_defense_settings()
    profile = settings.profile("csp-partner-allowlist")

    expanded = expand_partner_origins(
        profile, ["http://partner.test:5300", "http://127.0.0.1:5300"]
    )

    assert expanded.csp_frame_ancestors == [
        "self",
        "http://partner.test:5300",
        "http://127.0.0.1:5300",
    ]
    assert (
        expanded.csp_header_value()
        == "frame-ancestors 'self' http://partner.test:5300 http://127.0.0.1:5300"
    )

    # Profiles without the token pass through untouched.
    untouched = expand_partner_origins(settings.profile("csp-self"), ["http://p.test"])
    assert untouched is settings.profile("csp-self")


def test_report_only_changes_header_name() -> None:
    settings = load_defense_settings()
    enforcing = settings.profile("csp-none")
    reporting = settings.profile("csp-report-only")

    assert enforcing.csp_header_name() == "Content-Security-Policy"
    assert reporting.csp_header_name() == "Content-Security-Policy-Report-Only"


def _write_config(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "defense-broken.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DefenseConfigError, match="does not exist"):
        load_defense_settings(tmp_path / "missing.yaml")


@pytest.mark.parametrize(
    ("section", "mutate", "match"),
    [
        ("cookie", {"samesite": "Always"}, "samesite"),
        ("cookie", {"secure": "yes"}, "secure"),
        ("business", {"confirm_mode": "triple"}, "confirm_mode"),
        ("business", {"reauth_ttl_seconds": -5}, "reauth_ttl_seconds"),
        ("headers", {"csp_frame_ancestors": "everyone"}, "csp_frame_ancestors"),
        ("headers", {"csp_report_only": "yes"}, "csp_report_only"),
        ("headers", {"guardian_angle": True}, "Unknown headers keys"),
    ],
)
def test_invalid_profile_fields_are_rejected(
    tmp_path: Path, section: str, mutate: dict, match: str
) -> None:
    sections: dict[str, dict] = {"headers": {}, "cookie": {}, "business": {}}
    sections[section] = {**sections[section], **mutate}
    raw = {"default_profile": "none", "profiles": {"none": sections}}
    path = _write_config(tmp_path, raw)
    with pytest.raises(DefenseConfigError, match=match):
        load_defense_settings(path)


def test_misplaced_keys_are_rejected(tmp_path: Path) -> None:
    # A cookie knob placed in the business section must not silently pass.
    raw = {
        "default_profile": "none",
        "profiles": {"none": {"headers": {}, "cookie": {}, "business": {"samesite": "Strict"}}},
    }
    path = _write_config(tmp_path, raw)
    with pytest.raises(DefenseConfigError, match="Unknown business keys"):
        load_defense_settings(path)


def test_invalid_frame_busting_mode_is_rejected(tmp_path: Path) -> None:
    raw = {
        "default_profile": "none",
        "profiles": {
            "none": {"headers": {}, "cookie": {}, "business": {}, "frame_busting": "sometimes"}
        },
    }
    path = _write_config(tmp_path, raw)
    with pytest.raises(DefenseConfigError, match="frame_busting"):
        load_defense_settings(path)


def test_default_profile_must_exist(tmp_path: Path) -> None:
    raw = {"default_profile": "ghost", "profiles": {"none": {"headers": {}}}}
    path = _write_config(tmp_path, raw)
    with pytest.raises(DefenseConfigError, match="default_profile"):
        load_defense_settings(path)


def test_empty_sources_list_is_rejected(tmp_path: Path) -> None:
    raw = {
        "default_profile": "none",
        "profiles": {
            "none": {
                "headers": {"csp_frame_ancestors": []},
                "cookie": {},
                "business": {},
            }
        },
    }
    path = _write_config(tmp_path, raw)
    with pytest.raises(DefenseConfigError, match="csp_frame_ancestors"):
        load_defense_settings(path)


def test_as_dict_snapshot_includes_all_knobs() -> None:
    profile = load_defense_settings().profile("business-hardened")
    snapshot = profile.as_dict()

    assert snapshot["name"] == "business-hardened"
    assert snapshot["confirm_mode"] == "reconfirm"
    assert snapshot["one_time_token"] is True
    assert snapshot["reauth_ttl_seconds"] == 300
    assert snapshot["cookie_samesite"] == "Lax"
    assert snapshot["xfo"] is None
