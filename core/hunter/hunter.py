"""
BIFROST SDK - Vulnerable Driver Hunter
Scrapes the LOLDrivers API and scores drivers for physical memory R/W primitives.
Cross-references against the local drivers_list.json catalog.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Scoring weights for driver capabilities
# ---------------------------------------------------------------------------
SCORE_PHYSICAL_RW = 100      # Physical memory read/write — highest value
SCORE_MSR_RW = 60            # MSR read/write — useful for KASLR bypass
SCORE_PORT_IO = 40           # I/O port access — useful but less critical
SCORE_PROCESS_KILL = 20      # Can terminate processes — bonus
SCORE_BYOVD_TAG = 30         # Tagged as BYOVD in LOLDrivers
SCORE_KNOWN_SUPPORTED = 200  # Already in our drivers_list.json as supported

# Keywords to match in tags and commands
PHYS_KEYWORDS = [
    "physical memory", "physmem", "MmMapIoSpace", "physical read",
    "physical write", "memory read", "memory write", "arbitrary memory",
    "ring0 memcpy",
]
MSR_KEYWORDS = ["msr", "rdmsr", "wrmsr", "model specific register"]
PORT_KEYWORDS = ["port i/o", "i/o port", "io port", "in/out"]


class DriverHunter:
    """Searches LOLDrivers for vulnerable signed drivers suitable for BIFROST."""

    API_URL = "https://www.loldrivers.io/api/drivers.json"

    def __init__(self):
        self._log_callback: Optional[Callable[[str], None]] = None
        self._local_catalog: Dict[str, Any] = {}
        self._load_local_catalog()

    def set_logger(self, callback: Callable[[str], None]) -> None:
        self._log_callback = callback

    def _log(self, msg: str) -> None:
        if self._log_callback:
            self._log_callback(msg)
        else:
            print(msg)

    # ------------------------------------------------------------------
    # Local catalog
    # ------------------------------------------------------------------

    def _load_local_catalog(self) -> None:
        """Load drivers_list.json to cross-reference hunt results."""
        catalog_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "drivers", "drivers_list.json"
        )
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for drv in data.get("drivers", []):
                # Index by filename (lowered) for fast lookup
                fname = drv.get("filename", "").lower()
                if fname:
                    self._local_catalog[fname] = drv
                # Also index by SHA256 hashes
                for h in drv.get("sha256", []):
                    if h:
                        self._local_catalog[h.lower()] = drv
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self._log(f"[!] Could not load local driver catalog: {e}")

    def _check_local(self, filename: str, sha256_list: List[str]) -> Optional[Dict[str, Any]]:
        """Check if a driver is already in our local catalog."""
        hit = self._local_catalog.get(filename.lower())
        if hit:
            return hit
        for h in sha256_list:
            hit = self._local_catalog.get(h.lower())
            if hit:
                return hit
        return None

    # ------------------------------------------------------------------
    # LOLDrivers API fetch
    # ------------------------------------------------------------------

    def fetch_driver_metadata(self) -> List[Dict[str, Any]]:
        """Fetch the full driver database from LOLDrivers API."""
        if requests is None:
            self._log("[-] 'requests' module not installed. Cannot fetch LOLDrivers API.")
            return []

        self._log("[*] Fetching driver database from LOLDrivers API...")
        try:
            response = requests.get(self.API_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            self._log(f"[+] Loaded metadata for {len(data)} drivers.")
            return data
        except Exception as e:
            self._log(f"[-] Failed to fetch LOLDrivers API: {e}")
            return []

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_driver(self, driver: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single LOLDrivers entry and return a scored result.
        Returns None-equivalent (score=0) for uninteresting drivers.
        """
        driver_id = driver.get("Id", "Unknown")
        tags = driver.get("Tags", [])
        commands = driver.get("Commands", {})
        category = driver.get("Category", "")

        # Flatten all text for keyword matching
        all_text = " ".join([
            str(tags), str(commands),
            str(driver.get("Description", "")),
            str(driver.get("MitreID", "")),
        ]).lower()

        score = 0
        capabilities: List[str] = []

        # Physical memory R/W — the most valuable capability
        if any(kw.lower() in all_text for kw in PHYS_KEYWORDS):
            score += SCORE_PHYSICAL_RW
            capabilities.append("Physical Memory R/W")

        # MSR access
        if any(kw.lower() in all_text for kw in MSR_KEYWORDS):
            score += SCORE_MSR_RW
            capabilities.append("MSR Read/Write")

        # Port I/O
        if any(kw.lower() in all_text for kw in PORT_KEYWORDS):
            score += SCORE_PORT_IO
            capabilities.append("Port I/O")

        # Process termination
        if "terminates processes" in all_text:
            score += SCORE_PROCESS_KILL
            capabilities.append("Process Termination")

        # BYOVD tag
        if "byovd" in all_text:
            score += SCORE_BYOVD_TAG
            capabilities.append("BYOVD Tagged")

        if score == 0:
            return {"score": 0}

        # Extract hashes
        sha256_list: List[str] = []
        samples = driver.get("KnownVulnerableSamples", [])
        if isinstance(samples, list):
            for sample in samples:
                if isinstance(sample, dict):
                    h = sample.get("SHA256", "") or sample.get("Sha256", "")
                    if h:
                        sha256_list.append(h)

        # Cross-reference with local catalog
        filename = str(driver.get("Filename", ""))
        local_match = self._check_local(filename, sha256_list)
        local_status = "unknown"
        if local_match:
            local_status = local_match.get("status", "candidate")
            if local_status == "supported":
                score += SCORE_KNOWN_SUPPORTED

        return {
            "id": driver_id,
            "filename": filename,
            "category": category,
            "tags": tags,
            "score": score,
            "capabilities": capabilities,
            "hashes": sha256_list[:5],  # Cap at 5 for display
            "local_status": local_status,
            "description": str(driver.get("Description", ""))[:200],
        }

    # ------------------------------------------------------------------
    # Hunt
    # ------------------------------------------------------------------

    def start_hunt(self, max_drivers: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch LOLDrivers, score each for BIFROST usefulness, return ranked results.
        """
        self._log(f"\n--- INITIATING DRIVER HUNT (scanning up to {max_drivers} entries) ---")

        all_drivers = self.fetch_driver_metadata()
        if not all_drivers:
            return []

        results: List[Dict[str, Any]] = []
        scanned = 0

        for driver in all_drivers:
            if scanned >= max_drivers:
                break

            # Only look at vulnerable drivers
            if driver.get("Category") != "vulnerable driver":
                continue

            scanned += 1
            if scanned % 25 == 0:
                self._log(f"[*] Scanning... ({scanned}/{max_drivers})")

            result = self._score_driver(driver)
            if result["score"] > 0:
                results.append(result)

                # Log high-value finds
                if result["score"] >= SCORE_PHYSICAL_RW:
                    status_tag = f" [{result['local_status'].upper()}]" if result["local_status"] != "unknown" else ""
                    self._log(
                        f"[+] FOUND: {result['filename'] or result['id']} "
                        f"(score={result['score']}) — {', '.join(result['capabilities'])}{status_tag}"
                    )

            # Small delay to be polite to the API
            time.sleep(0.02)

        # Sort by score descending
        results.sort(key=lambda r: r["score"], reverse=True)

        self._log(f"\n--- HUNT COMPLETE ---")
        self._log(f"[+] Scanned: {scanned} vulnerable drivers")
        self._log(f"[+] Interesting results: {len(results)}")
        if results:
            self._log(f"[+] Top 5:")
            for r in results[:5]:
                self._log(
                    f"    {r['filename'] or r['id']}: score={r['score']} "
                    f"caps=[{', '.join(r['capabilities'])}] status={r['local_status']}"
                )

        return results
