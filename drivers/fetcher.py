import os
import sys
import urllib.request
import zipfile
import shutil


def _log(msg: str):
    # stderr, never stdout — stdout is the JSON IPC channel when running
    # under api_server.py or the frozen api_server.exe.
    print(msg, file=sys.stderr)


class DriverFetcher:
    """
    Downloads known vulnerable drivers (BYOVD) at runtime if they are not
    already present in the drivers directory.
    """
    
    ZIP_URL = "https://github.com/magicsword-io/LOLDrivers/releases/latest/download/drivers.zip"
    
    TARGET_DRIVERS = [
        "iqvw64e.sys",
        "RTCore64.sys",
        "dbutil_2_3.sys",
        "WDTKernel.sys",
        "CorsairLLAccess64.sys",
        "gdrv.sys",
    ]

    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        os.makedirs(self.target_dir, exist_ok=True)

    def fetch_all(self, timeout: float = 30.0):
        """Download and extract all missing target drivers from LOLDrivers."""
        missing = [d for d in self.TARGET_DRIVERS if not os.path.exists(os.path.join(self.target_dir, d))]
        if not missing:
            _log("[Fetcher] All required drivers are already present.")
            return True

        _log(f"[Fetcher] Missing drivers: {missing}. Downloading from {self.ZIP_URL}...")
        zip_path = os.path.join(self.target_dir, "drivers.zip")
        
        try:
            req = urllib.request.Request(self.ZIP_URL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                with open(zip_path, "wb") as f:
                    f.write(response.read())
            
            _log("[Fetcher] Extracting drivers...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    filename = os.path.basename(file_info.filename)
                    if filename in missing:
                        source = zip_ref.open(file_info)
                        target = open(os.path.join(self.target_dir, filename), "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                        _log(f"[Fetcher] Extracted {filename}")
                        missing.remove(filename)
                        if not missing:
                            break
                            
            os.remove(zip_path)
            
            if missing:
                _log(f"[Fetcher] Warning: Could not find {missing} in the zip archive.")
                return False
            return True
            
        except Exception as e:
            _log(f"[Fetcher] Failed to download or extract: {e}")
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return False

if __name__ == "__main__":
    fetcher = DriverFetcher(os.path.dirname(os.path.abspath(__file__)))
    fetcher.fetch_all()
