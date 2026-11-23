"""
Red Hat and Rocky Linux Security Advisory Source.
Parses authoritative vendor advisories (RHSA, RLSA), errata definitions,
and backported package fixes for EL8 and EL9 distributions.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, List, Optional
from vulnscan.core.models import VulnerabilityAdvisory, Severity
from vulnscan.advisories.base import VulnerabilitySource


class RhelRockySource(VulnerabilitySource):
    BASE_URL_RH_API = "https://access.redhat.com/hydra/rest/securitydata"

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
                        if any(x in sname for x in ["Red Hat", "Rocky", "RHEL"]):
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
                                source_name=sname or "Rocky Linux",
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
        return "Rocky Linux / Red Hat Security Advisories (RLSA/RHSA)"

    def get_last_updated(self) -> Optional[str]:
        return self.last_updated

    def fetch_cve(self, cve_id: str) -> Optional[VulnerabilityAdvisory]:
        # Check local cache/seed first
        if cve_id in self._local_advisories:
            return self._local_advisories[cve_id]

        if self.offline_mode:
            return None

        # Attempt to query Red Hat Security Data API with timeout
        url = f"{self.BASE_URL_RH_API}/cve/{cve_id}.json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LinuxVulnScanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    # Map to VulnerabilityAdvisory
                    cvss3 = data.get("cvss3", {})
                    score = float(cvss3.get("cvss3_base_score", 0.0)) if cvss3.get("cvss3_base_score") else None
                    vector = cvss3.get("cvss3_scoring_vector")
                    sev = Severity.from_cvss(score)

                    affected_pkgs: Dict[str, Dict[str, str]] = {}
                    for pkg in data.get("package_state", []):
                        pname = pkg.get("package_name")
                        fix_state = pkg.get("fix_state")
                        if pname:
                            affected_pkgs[pname] = {"fix_state": fix_state}

                    adv = VulnerabilityAdvisory(
                        cve_id=cve_id,
                        advisory_id=f"RHSA-{cve_id}",
                        title=data.get("bugzilla", {}).get("description") or cve_id,
                        description=data.get("details", [""])[0] if data.get("details") else "",
                        severity=sev,
                        cvss_score=score,
                        cvss_vector=vector,
                        source_name="Red Hat Security Data",
                        affected_packages=affected_pkgs,
                        references=[f"https://access.redhat.com/security/cve/{cve_id}"]
                    )
                    return adv
        except Exception:
            pass

        return None

    def fetch_advisories_for_package(
        self, package_name: str, os_family: str, os_version: str
    ) -> List[VulnerabilityAdvisory]:
        results: List[VulnerabilityAdvisory] = []
        for adv in self._local_advisories.values():
            if package_name in adv.affected_packages:
                results.append(adv)
        return results
