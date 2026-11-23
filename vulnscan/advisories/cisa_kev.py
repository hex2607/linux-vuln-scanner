"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Integration.
Authoritative source for vulnerabilities that are confirmed to be actively exploited in the wild.
"""

import json
from typing import Dict, Optional, Any


class CisaKevSource:
    OFFICIAL_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, offline_mode: bool = False, local_seed_file: Optional[str] = None):
        self.offline_mode = offline_mode
        self.local_seed_file = local_seed_file
        self.catalog: Dict[str, Dict[str, Any]] = {}
        self.last_updated: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if self.local_seed_file:
            try:
                with open(self.local_seed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("cisa_kev", []):
                        cve = item.get("cveID") or item.get("cve_id")
                        if cve:
                            self.catalog[cve] = item
                self.last_updated = data.get("metadata", {}).get("cisa_updated_at")
            except Exception:
                pass

    def is_exploited(self, cve_id: str) -> bool:
        return cve_id in self.catalog

    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.catalog.get(cve_id)

    def update_live(self) -> int:
        """Downloads latest CISA KEV catalog feed. Returns count of entries."""
        import urllib.request
        from datetime import datetime, timezone
        req = urllib.request.Request(self.OFFICIAL_URL, headers={"User-Agent": "LinuxVulnScanner/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    count = 0
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cveID")
                        if cve:
                            self.catalog[cve] = item
                            count += 1
                    self.last_updated = datetime.now(timezone.utc).isoformat()
                    return count
        except Exception as e:
            raise RuntimeError(f"Failed to fetch live CISA KEV feed: {e}")
        return 0
