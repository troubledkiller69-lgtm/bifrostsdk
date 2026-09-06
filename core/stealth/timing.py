"""
BIFROST SDK — Timing Obfuscation
Randomizes memory read patterns to avoid detection via timing analysis.

Anti-cheats profile suspicious access patterns:
  - Sequential reads at regular intervals (bot-like)
  - Burst reads followed by idle (typical cheat scan pattern)
  - Reads that correlate with game tick rate

This module adds controlled jitter and batching to break those signatures.
"""

from __future__ import annotations

import random
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class TimingStats:
    """Real-time statistics for the debug panel."""
    total_reads: int = 0
    total_bytes: int = 0
    failed_reads: int = 0
    total_delay_s: float = 0.0
    burst_count: int = 0
    idle_mimicry_triggers: int = 0
    session_start: float = 0.0

    @property
    def avg_delay_us(self) -> float:
        if self.total_reads <= 1:
            return 0
        return (self.total_delay_s / (self.total_reads - 1)) * 1_000_000

    @property
    def reads_per_second(self) -> float:
        elapsed = time.perf_counter() - self.session_start
        if elapsed <= 0:
            return 0
        return self.total_reads / elapsed

    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self.session_start

    def to_dict(self) -> dict:
        return {
            "total_reads": self.total_reads,
            "total_bytes": self.total_bytes,
            "failed_reads": self.failed_reads,
            "reads_per_second": round(self.reads_per_second, 1),
            "avg_delay_us": round(self.avg_delay_us, 1),
            "burst_count": self.burst_count,
            "idle_mimicry_triggers": self.idle_mimicry_triggers,
            "elapsed_s": round(self.elapsed, 2),
        }


class JitteredReader:
    """
    Wraps a read function and applies timing obfuscation.

    Strategies:
      - Gaussian jitter between reads
      - Batch coalescing (combine nearby reads into one)
      - Randomized read order for scan operations
      - Idle mimicry (occasional long pauses that look like normal system activity)
    """

    def __init__(
        self,
        read_fn: Callable[[int, int], bytes],
        *,
        min_delay_us: int = 50,
        max_delay_us: int = 2000,
        burst_size: int = 8,
        burst_cooldown_ms: int = 15,
        enable_idle_mimicry: bool = True,
    ):
        self._read = read_fn
        self._min_delay = min_delay_us / 1_000_000
        self._max_delay = max_delay_us / 1_000_000
        self._burst_size = burst_size
        self._burst_cooldown = burst_cooldown_ms / 1000
        self._idle_mimicry = enable_idle_mimicry

        self._read_count = 0
        self._last_read_time = 0.0
        self._session_start = time.perf_counter()

        # Stats tracking
        self.stats = TimingStats(session_start=self._session_start)

    def read(self, addr: int, size: int) -> bytes:
        """Perform a jittered read."""
        self._apply_jitter()
        self._read_count += 1
        try:
            data = self._read(addr, size)
            self.stats.total_reads += 1
            self.stats.total_bytes += len(data)
            self._last_read_time = time.perf_counter()
            return data
        except Exception:
            self.stats.failed_reads += 1
            raise

    def read_batch(self, requests: list[tuple[int, int]]) -> list[bytes]:
        """
        Read multiple addresses with randomized ordering.
        Returns results in the ORIGINAL request order.
        """
        # Shuffle read order to break sequential patterns
        indexed = list(enumerate(requests))
        random.shuffle(indexed)

        results = [b""] * len(requests)

        for batch_idx, (orig_idx, (addr, size)) in enumerate(indexed):
            # Apply burst logic
            if batch_idx > 0 and batch_idx % self._burst_size == 0:
                self._burst_pause()
            else:
                self._apply_jitter()

            try:
                results[orig_idx] = self._read(addr, size)
                self.stats.total_reads += 1
                self.stats.total_bytes += len(results[orig_idx])
            except Exception:
                self.stats.failed_reads += 1
                results[orig_idx] = b"\x00" * size

            self._read_count += 1
            self._last_read_time = time.perf_counter()

        return results

    def _apply_jitter(self):
        """Add randomized delay between reads."""
        if self._read_count == 0:
            return

        # Gaussian distribution centered between min and max
        center = (self._min_delay + self._max_delay) / 2
        sigma = (self._max_delay - self._min_delay) / 4
        delay = max(self._min_delay, random.gauss(center, sigma))
        delay = min(delay, self._max_delay * 2)  # cap outliers

        # Occasional idle mimicry — simulate "normal" system pauses
        if self._idle_mimicry and random.random() < 0.02:
            delay += random.uniform(0.005, 0.05)  # 5-50ms "natural" pause
            self.stats.idle_mimicry_triggers += 1

        if delay > 0:
            self.stats.total_delay_s += delay
            self._spin_wait(delay)

    def _burst_pause(self):
        """Longer pause between bursts of reads."""
        jittered_cooldown = self._burst_cooldown * random.uniform(0.7, 1.5)

        if self._idle_mimicry and random.random() < 0.1:
            jittered_cooldown += random.uniform(0.01, 0.1)
            self.stats.idle_mimicry_triggers += 1

        self.stats.total_delay_s += jittered_cooldown
        self.stats.burst_count += 1
        self._spin_wait(jittered_cooldown)

    @staticmethod
    def _spin_wait(seconds: float):
        """
        High-precision wait using hybrid sleep+spin.
        time.sleep() has ~15ms granularity on Windows which is too coarse
        for sub-millisecond delays, but pure spin wastes 100% CPU.
        Strategy: sleep for the bulk of the wait, spin only the final 1ms.
        """
        if seconds <= 0:
            return
        SPIN_THRESHOLD = 0.001  # 1ms — spin only the last millisecond
        if seconds > SPIN_THRESHOLD:
            # Sleep for the bulk, leaving 1ms margin for the spin finish
            time.sleep(seconds - SPIN_THRESHOLD)
        # Spin-wait the remaining sub-millisecond for precision
        end = time.perf_counter() + min(seconds, SPIN_THRESHOLD)
        while time.perf_counter() < end:
            pass

    def get_stats(self) -> dict:
        """Return current timing statistics as a dict for the debug panel."""
        return self.stats.to_dict()

    @property
    def reads_per_second(self) -> float:
        return self.stats.reads_per_second


class AdaptiveJitter(JitteredReader):
    """
    Self-adjusting jitter that adapts based on game framerate.
    Aligns reads to frame boundaries so they blend with normal
    memory access patterns.
    """

    def __init__(
        self,
        read_fn: Callable[[int, int], bytes],
        target_fps: int = 60,
        **kwargs,
    ):
        super().__init__(read_fn, **kwargs)
        self._frame_time = 1.0 / target_fps
        self._frame_counter = 0

    def sync_to_frame(self):
        """
        Call this once per game frame to sync read timing.
        Reads performed between sync calls get distributed
        across the frame interval.
        """
        self._frame_counter += 1
        # Jitter reads to land mid-frame where they're less suspicious
        offset = random.uniform(0.2, 0.8) * self._frame_time
        self._spin_wait(offset)
