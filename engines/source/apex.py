"""
BIFROST SDK — Apex Legends Specific Offsets & Patterns
Apex uses a heavily modified Source 1 engine (r5 branch) with EAC protection.

Key differences from standard Source:
  - No ClientClass linked list (classes are registered differently)
  - Entity list is a flat array, not a linked structure
  - Bone matrix accessible via CBaseAnimating + studiohdr
  - Glow is handled via highlight system, not GlowObjectManager
"""

from __future__ import annotations

from dataclasses import dataclass


# Apex Legends AOB patterns (Season 24+ — update per patch)
# These scan r5apex.exe
APEX_PATTERNS = {
    # Entity list base pointer
    "entity_list": "4C 8B 05 ?? ?? ?? ?? 4D 85 C0 74 ?? 49 8B 08",

    # Local player pointer
    "local_player": "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 39 98",

    # ViewRender (view matrix)
    "view_render": "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 48 8D 4C 24",

    # Level name string
    "level_name": "48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 44 24 ?? C7 44 24",

    # Glow/Highlight context
    "highlight_settings": "48 8B 0D ?? ?? ?? ?? 45 33 C0 33 D2 E8 ?? ?? ?? ?? 48 8B",

    # Name list (player name array)
    "name_list": "48 8D 05 ?? ?? ?? ?? 48 03 C1 0F B7 48",

    # Global vars (tick, frametime)
    "global_vars": "48 8B 05 ?? ?? ?? ?? F3 0F 10 48 ?? F3 0F 59",
}


@dataclass
class ApexPlayer:
    """Player entity offsets for Apex Legends."""
    OFFSETS = {
        # CBaseEntity
        "flags": 0x0098,
        "velocity": 0x0140,
        "origin": 0x017C,  # m_vecAbsOrigin
        "view_angles": 0x2564,

        # CBaseAnimating
        "bone_array": 0x0E98,
        "studio_hdr": 0x1100,

        # CPlayer
        "team_id": 0x0338,
        "health": 0x0328,
        "max_health": 0x0470,
        "shields": 0x01A0,
        "max_shields": 0x01A4,
        "life_state": 0x0680,
        "bleed_out_state": 0x2788,
        "last_visible_time": 0x19B0,
        "name_index": 0x0480,

        # View
        "camera_origin": 0x1F48,
        "camera_angles": 0x1F54,
        "fov": 0x1700,
        "target_fov": 0x1704,
        "zoom_fov": 0x16E0,

        # Combat
        "last_aimed_at_time": 0x19C0,
        "latest_primary_weapon_index": 0x1944,
        "active_weapon_handle": 0x1964,
    }


@dataclass
class ApexWeapon:
    """Weapon entity offsets."""
    OFFSETS = {
        "weapon_name_index": 0x17A8,
        "projectile_speed": 0x1EBC,
        "projectile_gravity": 0x1EC0,
        "ammo_in_clip": 0x1644,
        "zoom_fov": 0x1700,
        "is_semi_auto": 0x1C99,
        "bullet_drop": 0x1EC4,
        "weapon_owner": 0x1604,
    }


@dataclass
class ApexGlow:
    """Highlight/glow system offsets."""
    OFFSETS = {
        "highlight_function_bits": 0x2C0,
        "highlight_server_context_id": 0x298,
        "current_highlight": 0x2E0,
        "highlight_visibility_type": 0x278,
        "highlight_set_params": 0x01D0,
    }


# Bone indices for common models (Legend-specific)
APEX_BONES = {
    "head": 8,
    "neck": 7,
    "upper_chest": 5,
    "lower_chest": 4,
    "stomach": 3,
    "pelvis": 0,
    "left_shoulder": 11,
    "left_elbow": 12,
    "left_hand": 13,
    "right_shoulder": 35,
    "right_elbow": 36,
    "right_hand": 37,
    "left_thigh": 63,
    "left_knee": 64,
    "left_foot": 65,
    "right_thigh": 57,
    "right_knee": 58,
    "right_foot": 59,
}


# Entity list constants
ENTITY_LIST_SIZE = 65536
ENTITY_STRIDE = 0x20  # Each entry in the entity list is 32 bytes apart
