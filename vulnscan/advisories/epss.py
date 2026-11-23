"""
FIRST EPSS (Exploit Prediction Scoring System) Integration.
Provides empirical machine-learning probability of in-the-wild exploitation within 30 days.
"""

import json
from typing import Dict, Optional, Tuple


class EpssSource:
    API_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, offline_mode: bool = False, local_seed_file: Optional[str] = None):
        self.offline_mode = offline_mode
        self.local_seed_file = local_seed_file
        self.scores: Dict[str, Tuple[float, float]] = {}  # cve -> (epss_score, percentile)
        self.last_updated: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if self.local_seed_file:
            try:
                with open(self.local_seed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for cve, entry in data.get("epss_scores", {}).items():
                        score = float(entry.get("epss", 0.0))
                        pct = float(entry.get("percentile", 0.0))
                        self.scores[cve] = (score, pct)
                self.last_updated = data.get("metadata", {}).get("epss_updated_at")
            except Exception:
                pass

    def get_score(self, cve_id: str) -> Optional[float]:
        val = self.scores.get(cve_id)
        return val[0] if val else None

    def get_percentile(self, cve_id: str) -> Optional[float]:
        val = self.scores.get(cve_id)
        return val[1] if val else None

    def update_live(self, cves: Optional[list] = None) -> int:
        """Queries FIRST EPSS API for scores. Returns number of updated scores."""
        import urllib.request
        from datetime import datetime, timezone
        cve_query = ",".join(cves[:50]) if cves else "CVE-2023-44487,CVE-2021-3156,CVE-2023-4863,CVE-2023-38408"
        url = f"{self.API_URL}?cve={cve_query}"
        req = urllib.request.Request(url, headers={"User-Agent": "LinuxVulnScanner/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    count = 0
                    for item in data.get("data", []):
                        c = item.get("cve")
                        epss_val = float(item.get("epss", 0.0))
                        pct_val = float(item.get("percentile", 0.0))
                        if c:
                            self.scores[c] = (epss_val, pct_val)
                            count += 1
                    self.last_updated = datetime.now(timezone.utc).isoformat()
                    return count
        except Exception as e:
            raise RuntimeError(f"Failed to fetch live EPSS scores: {e}")
        return 0
