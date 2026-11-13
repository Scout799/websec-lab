"""Defense matrix for the victim application (M5)."""

from websec_lab.defense.profiles import (
    DefenseConfigError,
    DefenseProfile,
    DefenseSettings,
    default_defense_path,
    expand_partner_origins,
    load_defense_settings,
    resolve_active_profile,
)

__all__ = [
    "DefenseConfigError",
    "DefenseProfile",
    "DefenseSettings",
    "default_defense_path",
    "expand_partner_origins",
    "load_defense_settings",
    "resolve_active_profile",
]
