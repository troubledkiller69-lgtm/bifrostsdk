"""
BIFROST SDK — Stealth Memory Subsystem
Kernel-backed memory access that bypasses usermode AC hooks.
"""

from .config import (
    AccessMethod, StealthLevel, StealthConfig,
    STEALTH_OFF, STEALTH_LOW, STEALTH_MEDIUM, STEALTH_HIGH,
    STEALTH_PROFILES, detect_stealth_level,
)
from .reader import StealthReader
from .driver import DriverInterface
from .handle import HandleHijacker
from .timing import JitteredReader, AdaptiveJitter, TimingStats

__all__ = [
    "AccessMethod", "StealthLevel", "StealthConfig",
    "STEALTH_OFF", "STEALTH_LOW", "STEALTH_MEDIUM", "STEALTH_HIGH",
    "STEALTH_PROFILES", "detect_stealth_level",
    "StealthReader", "DriverInterface", "HandleHijacker",
    "JitteredReader", "AdaptiveJitter", "TimingStats",
]
