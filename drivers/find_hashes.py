"""
BIFROST SDK — Driver Hash Finder
Searches the LOLDrivers API for SHA256 hashes of all supported drivers.
"""

import json
import urllib.request


def find_driver(query: str) -> None:
    print(f"\nSearching for '{query}'...")
    try:
        url = "https://loldrivers.io/api/drivers.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

            found = False
            for item in data:
                filename = str(item.get("Filename", "")).lower()
                tags_str = str(item.get("Tags", "")).lower()
                if query.lower() in filename or query.lower() in tags_str:
                    found = True
                    print(f"  Match: {item.get('Filename', 'Unknown')}")
                    print(f"  Category: {item.get('Category', 'Unknown')}")
                    print(f"  Tags: {item.get('Tags', [])}")
                    samples = item.get("KnownVulnerableSamples", [])
                    if isinstance(samples, list):
                        print(f"  SHA256 hashes ({len(samples)} samples):")
                        for sample in samples:
                            if isinstance(sample, dict):
                                sha = sample.get("SHA256", "") or sample.get("Sha256", "")
                                if sha:
                                    print(f"    - {sha}")
                    print()

            if not found:
                print(f"  No matches found for '{query}'")
    except Exception as e:
        print(f"  Error: {e}")


if __name__ == "__main__":
    drivers = [
        "iqvw64e.sys",
        "RTCore64.sys",
        "dbutil_2_3.sys",
        "WDTKernel.sys",
        "CorsairLLAccess64.sys",
        "gdrv.sys",
    ]
    for drv in drivers:
        find_driver(drv)
