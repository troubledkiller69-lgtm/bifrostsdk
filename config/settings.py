"""
BIFROST SDK — Configuration & Settings
Global settings and engine profile management.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class AppSettings:
    """Global application settings."""
    # Output
    output_dir: str = "output"
    generate_headers: bool = True
    generate_json: bool = True

    # Scanning
    max_scan_results: int = 50
    scan_timeout_seconds: int = 30

    # UE5 specific
    ue5_profile: str = "default"
    ue5_custom_gnames_pattern: str = ""
    ue5_custom_gobjects_pattern: str = ""

    # Unity specific
    unity_game_dir: str = ""  # for IL2CPP metadata file location

    # Stealth
    stealth_mode: str = "auto"  # "auto", "driver", "hijack", "direct"
    stealth_driver_path: str = ""
    stealth_jitter_enabled: bool = True
    stealth_jitter_min_us: int = 50
    stealth_jitter_max_us: int = 1500

    # UI
    theme: str = "dark"
    show_log: bool = True
    
    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
    
    @classmethod
    def load(cls, path: str) -> "AppSettings":
        if not os.path.exists(path):
            return cls()
        try:
            with open(path, "r") as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except Exception:
            return cls()


# Default settings path
DEFAULT_SETTINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config",
    "settings.json",
)
