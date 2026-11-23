"""
Ubuntu and Debian Security Advisory Source.
Integrates Ubuntu Security Notices (USN) and Debian Security Tracker advisories.
"""

import json
from typing import Dict, List, Optional
from vulnscan.core.models import VulnerabilityAdvisory, Severity
from vulnscan.advisories.base import VulnerabilitySource


class UbuntuDebianSource(VulnerabilitySource):
    def __init__(self, offline_mode: bool = False, local_seed_file: Optional[str] = None):
        self.offline_mode = offline_mode
        self.local_seed_file = local_seed_file
        self.last_updated: Optional[str] = None
        self._local_advisories: Dict[str, VulnerabilityAdvisory] = {}
        self._load_local_data()

    def _load_local_data(self) -> None:
        if self.local_seed_file:
            try:
                with open(self.local_seed_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("advisories", []):
                        sname = item.get("source_name", "")
                        if any(x in sname for x in ["Ubuntu", "Debian"]):
                            adv = VulnerabilityAdvisory(
                                cve_id=item["cve_id"],
                                advisory_id=item.get("advisory_id", ""),
                                title=item.get("title", ""),
                                description=item.get("description", ""),
                                severity=Severity(item.get("severity", "UNKNOWN")),
                                cvss_score=item.get("cvss_score"),
                                cvss_vector=item.get("cvss_vector"),
                                epss_score=item.get("epss_score"),
                                cisa_kev=item.get("cisa_kev", False),
                                source_name=sname or "Ubuntu Security Notices",
                                affected_packages=item.get("affected_packages", {}),
                                references=item.get("references", []),
                                published_date=item.get("published_date"),
                                remediation_text=item.get("remediation_text"),
                                mitigation_text=item.get("mitigation_text"),
                                prerequisite_rules=item.get("prerequisite_rules", []),
                                root_cause=item.get("root_cause"),
                                validation_steps=item.get("validation_steps", []),
                                safe_verification_procedure=item.get("safe_verification_procedure"),
                                operational_impact=item.get("operational_impact"),
                                compensating_controls=item.get("compensating_controls", []),
                                residual_risk=item.get("residual_risk"),
                            )
                            self._local_advisories[adv.cve_id] = adv
                self.last_updated = data.get("metadata", {}).get("updated_at")
            except Exception:
                pass

    def get_source_name(self) -> str:
        return "Ubuntu Security Notices / Debian Security Tracker"

    def get_last_updated(self) -> Optional[str]:
        return self.last_updated

    def fetch_cve(self, cve_id: str) -> Optional[VulnerabilityAdvisory]:
        return self._local_advisories.get(cve_id)

    def fetch_advisories_for_package(
        self, package_name: str, os_family: str, os_version: str
    ) -> List[VulnerabilityAdvisory]:
        results: List[VulnerabilityAdvisory] = []
        for adv in self._local_advisories.values():
            if package_name in adv.affected_packages:
                results.append(adv)
        return results
