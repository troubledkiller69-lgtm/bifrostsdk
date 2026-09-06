"""
BIFROST SDK — Stealth Configuration
Centralized settings for all stealth subsystems.
Provides preset profiles for different anti-cheat aggressiveness levels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class AccessMethod(Enum):
    """Memory access strategy, ordered by stealth level."""
    DRIVER = auto()       # Physical memory via vulnerable driver (strongest)
    PT_WALKER = auto()    # Manual physical page table walking (bypass CR3 encryption)
    HIJACK = auto()       # Duplicated handle from system process
    DIRECT = auto()       # Standard OpenProcess (unsafe for protected games)
    AUTO = auto()         # Try each in order: pt_walker -> driver -> hijack -> direct


class StealthLevel(Enum):
    """Pre-configured stealth profiles."""
    OFF = auto()          # No stealth — use pymem directly
    LOW = auto()          # Jitter only, direct attach
    MEDIUM = auto()       # Handle hijacking + jitter + reduced scan speed
    HIGH = auto()         # Driver + full jitter + PEB walk + minimal API calls
    EXTREME = auto()      # CR3 Brute-force + Manual Page Table Walker


@dataclass
class StealthConfig:
    """All tuneable stealth parameters in one place."""

    # --- Access method ---
    method: AccessMethod = AccessMethod.AUTO
    driver_path: str = ""

    # --- Timing jitter ---
    enable_jitter: bool = True
    jitter_min_us: int = 50        # Minimum inter-read delay (microseconds)
    jitter_max_us: int = 1500      # Maximum inter-read delay (microseconds)
    burst_size: int = 8            # Reads per burst before cooldown
    burst_cooldown_ms: int = 15    # Cooldown between bursts (milliseconds)
    enable_idle_mimicry: bool = True  # Occasional long pauses

    # --- Scanner tuning ---
    scan_chunk_size: int = 0x10000    # 64 KB chunks (vs 1 MB in normal mode)
    scan_inter_chunk_delay_ms: int = 5  # Delay between scan chunks
    reduce_vqe_calls: bool = True     # Minimize VirtualQueryEx usage

    # --- Process enumeration ---
    use_ntquery_enumeration: bool = True  # NtQuerySystemInformation vs psutil

    # --- Debug ---
    enable_debug_stats: bool = True   # Track read counts, timings, etc.


# ── Preset profiles ──────────────────────────────────────────────────

STEALTH_OFF = StealthConfig(
    method=AccessMethod.DIRECT,
    enable_jitter=False,
    scan_chunk_size=0x100000,  # 1 MB — fast
    scan_inter_chunk_delay_ms=0,
    reduce_vqe_calls=False,
    use_ntquery_enumeration=False,
    enable_idle_mimicry=False,
    enable_debug_stats=False,
)

STEALTH_LOW = StealthConfig(
    method=AccessMethod.DIRECT,
    enable_jitter=True,
    jitter_min_us=20,
    jitter_max_us=500,
    scan_chunk_size=0x80000,   # 512 KB
    scan_inter_chunk_delay_ms=2,
    reduce_vqe_calls=False,
    use_ntquery_enumeration=False,
    enable_idle_mimicry=False,
)

STEALTH_MEDIUM = StealthConfig(
    method=AccessMethod.HIJACK,
    enable_jitter=True,
    jitter_min_us=50,
    jitter_max_us=1500,
    burst_size=6,
    burst_cooldown_ms=20,
    scan_chunk_size=0x10000,   # 64 KB
    scan_inter_chunk_delay_ms=5,
    reduce_vqe_calls=True,
    use_ntquery_enumeration=True,
    enable_idle_mimicry=True,
)

STEALTH_HIGH = StealthConfig(
    method=AccessMethod.DRIVER,
    enable_jitter=True,
    jitter_min_us=100,
    jitter_max_us=3000,
    burst_size=4,
    burst_cooldown_ms=30,
    scan_chunk_size=0x8000,    # 32 KB
    scan_inter_chunk_delay_ms=10,
    reduce_vqe_calls=True,
    use_ntquery_enumeration=True,
    enable_idle_mimicry=True,
)

STEALTH_EXTREME = StealthConfig(
    method=AccessMethod.PT_WALKER,
    enable_jitter=True,
    jitter_min_us=100,
    jitter_max_us=3000,
    burst_size=2,
    burst_cooldown_ms=50,
    scan_chunk_size=0x4000,    # 16 KB
    scan_inter_chunk_delay_ms=20,
    reduce_vqe_calls=True,
    use_ntquery_enumeration=True,
    enable_idle_mimicry=True,
)

# Map stealth level to config
STEALTH_PROFILES: dict[StealthLevel, StealthConfig] = {
    StealthLevel.OFF: STEALTH_OFF,
    StealthLevel.LOW: STEALTH_LOW,
    StealthLevel.MEDIUM: STEALTH_MEDIUM,
    StealthLevel.HIGH: STEALTH_HIGH,
    StealthLevel.EXTREME: STEALTH_EXTREME,
}

# Games known to use aggressive anti-cheat
AC_PROTECTED_GAMES: dict[str, StealthLevel] = {
    "overwatch": StealthLevel.HIGH,
    "overwatchob": StealthLevel.HIGH,
    "r5apex": StealthLevel.HIGH,        # Apex Legends (EAC)
    "valorant": StealthLevel.HIGH,      # Vanguard
    "fortnite": StealthLevel.MEDIUM,    # EAC
    "pubg": StealthLevel.MEDIUM,        # BattlEye
    "rainbow6": StealthLevel.MEDIUM,    # BattlEye
    "marvel": StealthLevel.LOW,         # Custom AC (lighter)
    "cod": StealthLevel.HIGH,           # RICOCHET
}


def detect_stealth_level(process_name: str) -> StealthLevel:
    """Auto-detect recommended stealth level based on process name."""
    name_lower = process_name.lower().replace(".exe", "").replace("-", "").replace("_", "")
    for keyword, level in AC_PROTECTED_GAMES.items():
        if keyword in name_lower:
            return level
    return StealthLevel.OFF
