"""
BIFROST SDK — Access transport configuration.

Each AccessMethod is a single, explicit transport for reaching a target
process's memory. There is deliberately NO auto ladder: the direct
transport is the only one verifiable without kernel machinery, and
kernel transports (DRIVER, CR3) map a vulnerable driver — they can BSOD
or trip AV, so nothing ever falls back into them. Choosing them is an
explicit, informed act.

Every transport self-tests at connect time (open -> probe read -> verify)
and reports the exact step that failed instead of a generic "all access
methods failed" message.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AccessMethod(Enum):
    DIRECT = "direct"   # OpenProcess + ReadProcessMemory (userspace, verified)
    HIJACK = "hijack"   # duplicated handle from a system process (userspace)
    DRIVER = "driver"   # mapped vulnerable driver, physical reads via CR3
    CR3 = "cr3"         # driver + manual page-table walk (CR3 bypass)

    @property
    def label(self) -> str:
        return {
            AccessMethod.DIRECT: "Direct Attach",
            AccessMethod.HIJACK: "Handle Hijack",
            AccessMethod.DRIVER: "Kernel Driver (Physical)",
            AccessMethod.CR3: "PT Walker (Physical CR3)",
        }[self]

    def requires_kernel(self) -> bool:
        """True for transports that map a vulnerable driver."""
        return self in (AccessMethod.DRIVER, AccessMethod.CR3)


@dataclass
class StealthConfig:
    """Configuration for ONE memory-access transport.

    scan_chunk_size / scan_inter_chunk_delay_ms are read by engines.base
    (scanner pacing); the jitter knobs by StealthReader; use_ntquery_
    enumeration by PID resolution. engines.base compares dumper configs
    against STEALTH_OFF for equality, so keep this a plain dataclass.
    """
    method: AccessMethod = AccessMethod.DIRECT
    driver_path: str | None = None

    # Read-traffic shaping (applied when the transport is active)
    enable_jitter: bool = False
    jitter_min_us: int = 50
    jitter_max_us: int = 1500
    burst_size: int = 8
    burst_cooldown_ms: int = 15
    enable_idle_mimicry: bool = False

    # Scanner pacing consumed by engines/base -> PatternScanner
    scan_chunk_size: int = 0x10000
    scan_inter_chunk_delay_ms: int = 5

    # PID resolution strategy (default: psutil snapshot)
    use_ntquery_enumeration: bool = False


# engines/base defaults dumpers to this and treats it as "no stealth":
# a dumper whose config equals STEALTH_OFF gets an unscanned, full-speed
# PatternScanner. Must stay a plain default instance.
STEALTH_OFF = StealthConfig()
