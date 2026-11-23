"""
Advisory Manager.
Orchestrates multi-source vulnerability intelligence across vendor advisories
(RHEL/Rocky/Alma/Debian/Ubuntu), CISA KEV, and FIRST EPSS.
Enforces local caching, offline fallback, and freshness metadata.
"""

import os
from typing import Dict, List, Optional, Tuple
from vulnscan.core.models import VulnerabilityAdvisory, SystemInfo
from vulnscan.advisories.rhel_rocky import RhelRockySource
from vulnscan.advisories.ubuntu_debian import UbuntuDebianSource
from vulnscan.advisories.cisa_kev import CisaKevSource
from vulnscan.advisories.epss import EpssSource
from vulnscan.advisories.cache import AdvisoryCache


class AdvisoryManager:
    def __init__(
        self,
        cache_dir: Optional[str] = None,
        offline_mode: bool = False,
        seed_file: Optional[str] = None
    ):
        self.offline_mode = offline_mode
        if not cache_dir:
            cache_dir = os.path.expanduser("~/.cache/linux-vuln-scanner")
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_file = os.path.join(cache_dir, "advisories_cache.json")
        self.cache = AdvisoryCache(self.cache_file)

        # Default seed file location if not specified
        if not seed_file:
            pkg_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            default_seed = os.path.join(pkg_dir, "data", "sample_advisories.json")
            if os.path.exists(default_seed):
                seed_file = default_seed

        self.rhel_source = RhelRockySource(offline_mode=offline_mode, local_seed_file=seed_file)
        self.debian_source = UbuntuDebianSource(offline_mode=offline_mode, local_seed_file=seed_file)
        self.cisa_kev = CisaKevSource(offline_mode=offline_mode, local_seed_file=seed_file)
        self.epss = EpssSource(offline_mode=offline_mode, local_seed_file=seed_file)

    def get_source_timestamps(self) -> Dict[str, str]:
        timestamps: Dict[str, str] = {}
        if self.rhel_source.get_last_updated():
            timestamps["Rocky Linux / RHEL Errata"] = self.rhel_source.get_last_updated()
        if self.debian_source.get_last_updated():
            timestamps["Ubuntu / Debian Security Tracker"] = self.debian_source.get_last_updated()
        if self.cisa_kev.last_updated:
            timestamps["CISA KEV Catalog"] = self.cisa_kev.last_updated
        if self.epss.last_updated:
            timestamps["FIRST EPSS"] = self.epss.last_updated
        cache_ts = self.cache.get_cache_timestamp()
        if cache_ts:
            timestamps["Local Advisory Cache"] = cache_ts
        return timestamps

    def get_advisories_for_system(self, sys_info: SystemInfo) -> List[VulnerabilityAdvisory]:
        """
        Retrieves all relevant advisories for the targeted operating system.
        Augments each advisory with CISA KEV status and EPSS scores.
        """
        advisories: List[VulnerabilityAdvisory] = []
        if sys_info.os_family == "rhel":
            # Collect from RHEL/Rocky
            advisories = list(self.rhel_source._local_advisories.values())
        elif sys_info.os_family == "debian":
            advisories = list(self.debian_source._local_advisories.values())
        else:
            # Generic fallback: inspect both
            advisories = list(self.rhel_source._local_advisories.values()) + list(self.debian_source._local_advisories.values())

        # Enrich with KEV & EPSS
        for adv in advisories:
            if self.cisa_kev.is_exploited(adv.cve_id):
                adv.cisa_kev = True
                details = self.cisa_kev.get_details(adv.cve_id)
                if details and "dueDate" in details:
                    adv.cisa_due_date = details["dueDate"]

            epss_val = self.epss.get_score(adv.cve_id)
            if epss_val is not None:
                adv.epss_score = epss_val

            # Cache the enriched advisory
            self.cache.set_advisory(adv)

        self.cache.save()
        return advisories

    def update_database(self) -> Dict[str, Any]:
        """
        Fetches live feeds from CISA KEV, FIRST EPSS, and vendor APIs.
        Saves updated records to local cache.
        """
        stats: Dict[str, Any] = {"cisa_kev_updated": 0, "epss_updated": 0, "errors": []}
        
        # 1. Update CISA KEV
        try:
            count = self.cisa_kev.update_live()
            stats["cisa_kev_updated"] = count
        except Exception as e:
            stats["errors"].append(f"CISA KEV: {str(e)}")

        # 2. Update EPSS
        try:
            all_cves = list(self.rhel_source._local_advisories.keys()) + list(self.debian_source._local_advisories.keys())
            count = self.epss.update_live(all_cves)
            stats["epss_updated"] = count
        except Exception as e:
            stats["errors"].append(f"EPSS: {str(e)}")

        # 3. Save to cache
        for adv in self.rhel_source._local_advisories.values():
            if self.cisa_kev.is_exploited(adv.cve_id):
                adv.cisa_kev = True
            epss_val = self.epss.get_score(adv.cve_id)
            if epss_val is not None:
                adv.epss_score = epss_val
            self.cache.set_advisory(adv)

        self.cache.save()
        return stats
