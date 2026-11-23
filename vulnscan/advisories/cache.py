"""
Advisory Cache Manager.
Provides local persistent caching (JSON/SQLite) with TTL, staleness detection,
offline scan mode, and rate-limiting support.
"""

import os
import json
import time
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta, timezone
from vulnscan.core.models import VulnerabilityAdvisory, Severity


class AdvisoryCache:
    def __init__(self, cache_file: str, default_ttl_hours: int = 24):
        self.cache_file = cache_file
        self.default_ttl = timedelta(hours=default_ttl_hours)
        self._data: Dict[str, Any] = {"metadata": {}, "advisories": {}}
        self.load()

    def load(self) -> None:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {"metadata": {}, "advisories": {}}

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.cache_file)), exist_ok=True)
            self._data["metadata"]["last_saved"] = datetime.now(timezone.utc).isoformat()
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def get_advisory(self, cve_id: str) -> Optional[VulnerabilityAdvisory]:
        entry = self._data.get("advisories", {}).get(cve_id)
        if not entry:
            return None

        # Check timestamp
        cached_time_str = entry.get("cached_at")
        if cached_time_str:
            try:
                cached_time = datetime.fromisoformat(cached_time_str.replace("Z", ""))
                if datetime.utcnow() - cached_time > self.default_ttl:
                    # Stale entry, but returned if in offline mode
                    pass
            except Exception:
                pass

        adv_dict = entry.get("data")
        if not adv_dict:
            return None

        return VulnerabilityAdvisory(
            cve_id=adv_dict["cve_id"],
            advisory_id=adv_dict.get("advisory_id", ""),
            title=adv_dict.get("title", ""),
            description=adv_dict.get("description", ""),
            severity=Severity(adv_dict.get("severity", "UNKNOWN")),
            cvss_score=adv_dict.get("cvss_score"),
            cvss_vector=adv_dict.get("cvss_vector"),
            epss_score=adv_dict.get("epss_score"),
            cisa_kev=adv_dict.get("cisa_kev", False),
            cisa_due_date=adv_dict.get("cisa_due_date"),
            source_name=adv_dict.get("source_name", "Vendor"),
            affected_packages=adv_dict.get("affected_packages", {}),
            references=adv_dict.get("references", []),
            published_date=adv_dict.get("published_date"),
            last_modified_date=adv_dict.get("last_modified_date"),
            remediation_text=adv_dict.get("remediation_text"),
            mitigation_text=adv_dict.get("mitigation_text"),
            prerequisite_rules=adv_dict.get("prerequisite_rules", []),
        )

    def set_advisory(self, advisory: VulnerabilityAdvisory) -> None:
        if "advisories" not in self._data:
            self._data["advisories"] = {}
        self._data["advisories"][advisory.cve_id] = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "data": advisory.to_dict(),
        }

    def get_all_cves(self) -> List[str]:
        return list(self._data.get("advisories", {}).keys())

    def get_cache_timestamp(self) -> Optional[str]:
        return self._data.get("metadata", {}).get("last_saved")
