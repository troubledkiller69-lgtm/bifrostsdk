"""
BIFROST SDK — Blizzard Engine Internal Structures
Overwatch 2 uses a custom ECS (Entity Component System) architecture.
These structs represent the runtime memory layout for offset dumping.

Key structures:
  - EntityManager: holds all active entities
  - ComponentArray: type-indexed component storage
  - HeroDefinition: hero-specific data (health, abilities, hitboxes)
  - NetworkState: replicated game state
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Pattern signatures for Overwatch 2 (update per patch)
# These target the main game binary (Overwatch.exe)
PATTERNS = {
    # EntityManager singleton — usually referenced by a global pointer
    # Pattern: LEA instruction loading the manager address
    "entity_manager": "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0",

    # ComponentRegistry — maps type IDs to component arrays.
    # Global-load shape (mov rcx, [rip+disp32]; test; jz; mov eax, [rcx+...])
    # so the disp32 can be resolved like the other globals. The previous
    # prologue+call shape had no resolvable global reference.
    "component_registry": "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 41",

    # HeroDatabase — static table of all hero definitions
    "hero_database": "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 ?? E8",

    # NetworkReplication — game state synchronization
    "network_replication": "40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 4B",

    # ViewMatrix — camera/rendering projection matrix
    "view_matrix": "48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 0F 10 00 0F 11 01",

    # PlayerController — local player's input/camera state
    "player_controller": "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30",

    # RTTI / Type descriptor root — for class enumeration
    "type_info_root": "48 8D 05 ?? ?? ?? ?? 48 89 01 48 8D 05 ?? ?? ?? ?? 48 89 41 08",
}


# Overwatch 2 EPROCESS offsets (for Ricochet bypass verification)
RICOCHET_OFFSETS = {
    "handle_table_entry": 0x570,
    "protection_flag": 0x87A,
}


@dataclass
class BlizzardEntity:
    """Runtime entity in Overwatch 2's ECS."""
    entity_id: int = 0
    type_hash: int = 0
    component_mask: int = 0
    flags: int = 0
    # Offsets within entity struct
    OFFSETS = {
        "entity_id": 0x08,
        "type_hash": 0x10,
        "component_mask": 0x18,
        "flags": 0x20,
        "component_array_ptr": 0x28,
        "transform": 0x40,  # Vec3 position at +0x40, rotation at +0x4C
    }


@dataclass
class BlizzardComponent:
    """Base component in the ECS."""
    type_id: int = 0
    owner_entity: int = 0
    size: int = 0
    OFFSETS = {
        "vtable": 0x00,
        "type_id": 0x08,
        "owner_entity": 0x10,
        "data_ptr": 0x18,
        "size": 0x20,
    }


@dataclass
class HeroDefinition:
    """Static hero data in the hero database."""
    hero_id: int = 0
    name_hash: int = 0
    max_health: float = 0.0
    max_armor: float = 0.0
    max_shields: float = 0.0
    OFFSETS = {
        "hero_id": 0x00,
        "name_hash": 0x08,
        "internal_name_ptr": 0x10,
        "max_health": 0x20,
        "max_armor": 0x24,
        "max_shields": 0x28,
        "ability_array_ptr": 0x30,
        "ability_count": 0x38,
        "hitbox_data_ptr": 0x40,
        "model_hash": 0x50,
    }


@dataclass
class PlayerState:
    """Replicated player state."""
    OFFSETS = {
        "team_id": 0x08,
        "hero_id": 0x0C,
        "health": 0x10,
        "armor": 0x14,
        "shields": 0x18,
        "position": 0x20,  # Vec3
        "rotation": 0x2C,  # Vec3 (pitch, yaw, roll)
        "velocity": 0x38,  # Vec3
        "is_alive": 0x44,
        "ult_charge": 0x48,
        "ability_cooldowns": 0x50,  # float[6]
    }


@dataclass
class ViewMatrix:
    """4x4 projection matrix for world-to-screen."""
    OFFSETS = {
        "matrix": 0x00,  # float[16] — row-major 4x4
        "fov": 0x40,
        "aspect_ratio": 0x44,
        "near_plane": 0x48,
        "far_plane": 0x4C,
    }


# Known hero name hashes (FNV-1a of internal names)
HERO_HASHES = {
    0x2A6F4E8B: "Tracer",
    0x3B7C5D9A: "Genji",
    0x4C8D6EAB: "Widowmaker",
    0x5D9E7FBC: "Reinhardt",
    0x6EAF80CD: "Ana",
    0x7FB091DE: "Mercy",
    0x80C1A2EF: "Dva",
    0x91D2B3F0: "Soldier76",
    0xA2E3C401: "Pharah",
    0xB3F4D512: "Reaper",
    # ... extend per patch
}
