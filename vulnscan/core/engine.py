"""
Scan Engine Orchestrator.
Coordinates the end-to-end scanning pipeline:
System Inventory -> Advisory Matching -> Applicability Evaluation -> Multi-Factor Risk Prioritization -> ScanReport.
"""

import time
from datetime import datetime, timezone
from typing import List, Optional, Callable, Tuple
from vulnscan import __version__
from vulnscan.core.models import (
    ScanReport, ScanSummary, AssessmentFinding, AssessmentStatus, Severity, VulnerabilityAdvisory, ReportBranding
)
from vulnscan.inventory.collector import InventoryCollector, SystemInventory
from vulnscan.advisories.manager import AdvisoryManager
from vulnscan.core.rules import ApplicabilityEngine
from vulnscan.core.risk import RiskPrioritizer


class ScanEngine:
    def __init__(
        self,
        command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None,
        offline_mode: bool = False,
        seed_advisories_file: Optional[str] = None
    ):
        self.collector = InventoryCollector(command_runner)
        self.advisory_manager = AdvisoryManager(offline_mode=offline_mode, seed_file=seed_advisories_file)
        self.offline_mode = offline_mode

    def run_scan(
        self,
        prebuilt_inventory: Optional[SystemInventory] = None,
        target_cves: Optional[List[str]] = None,
        depth: str = "standard",
        branding: Optional[ReportBranding] = None
    ) -> ScanReport:
        """
        Executes a complete assessment run.
        Can assess the live host or evaluate a prebuilt/remote inventory.
        If target_cves is provided, filters assessment strictly to the requested CVEs.
        """
        start_time = time.time()
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Gather System Inventory
        if prebuilt_inventory:
            inventory = prebuilt_inventory
        else:
            inventory = self.collector.collect(depth=depth)

        # 2. Retrieve authoritative advisories
        advisories = self.advisory_manager.get_advisories_for_system(inventory.system_info)
        source_timestamps = self.advisory_manager.get_source_timestamps()

        # Filter by targeted CVE(s) if specified
        clean_target_cves = set()
        if target_cves:
            for item in target_cves:
                for sub in item.split(","):
                    c_clean = sub.strip().upper()
                    if c_clean:
                        if not c_clean.startswith("CVE-") and not c_clean.startswith("GHSA-"):
                            c_clean = f"CVE-{c_clean}"
                        clean_target_cves.add(c_clean)

        if clean_target_cves:
            advisories = [adv for adv in advisories if adv.cve_id.upper() in clean_target_cves]

            # If online and some requested CVEs are missing from local advisories, attempt on-the-fly fetch
            found_ids = {adv.cve_id.upper() for adv in advisories}
            missing_cves = clean_target_cves - found_ids
            if missing_cves and not self.offline_mode:
                try:
                    from vulnscan.advisories.updater import AdvisoryUpdater
                    target_os = inventory.system_info.platform_id or "el9"
                    for m_cve in sorted(missing_cves):
                        try:
                            online_data = AdvisoryUpdater.fetch_online_cve_data(m_cve, target_os=target_os)
                            adv_dict = AdvisoryUpdater.synthesize_advisory(m_cve, online_data, target_os=target_os)
                            sname = adv_dict.get("source_name") or "Vendor Security Advisory"
                            adv = VulnerabilityAdvisory(
                                cve_id=adv_dict["cve_id"],
                                advisory_id=adv_dict.get("advisory_id", ""),
                                title=adv_dict.get("title", ""),
                                description=adv_dict.get("description", ""),
                                severity=Severity(adv_dict.get("severity", "UNKNOWN")),
                                cvss_score=adv_dict.get("cvss_score"),
                                cvss_vector=adv_dict.get("cvss_vector"),
                                epss_score=adv_dict.get("epss_score"),
                                cisa_kev=adv_dict.get("cisa_kev", False),
                                source_name=sname,
                                affected_packages=adv_dict.get("affected_packages", {}),
                                references=adv_dict.get("references", []),
                                published_date=adv_dict.get("published_date"),
                                remediation_text=adv_dict.get("remediation_text"),
                                mitigation_text=adv_dict.get("mitigation_text"),
                                prerequisite_rules=adv_dict.get("prerequisite_rules", []),
                                root_cause=adv_dict.get("root_cause"),
                                validation_steps=adv_dict.get("validation_steps", []),
                                safe_verification_procedure=adv_dict.get("safe_verification_procedure"),
                                operational_impact=adv_dict.get("operational_impact"),
                                compensating_controls=adv_dict.get("compensating_controls", []),
                                residual_risk=adv_dict.get("residual_risk"),
                            )
                            advisories.append(adv)
                        except Exception:
                            pass
                except ImportError:
                    pass

        # 3. Evaluate Applicability for each advisory
        applicability_engine = ApplicabilityEngine(inventory)
        raw_findings: List[AssessmentFinding] = []
        for adv in advisories:
            finding = applicability_engine.evaluate_cve(adv)
            raw_findings.append(finding)

        # 4. Multi-Factor Risk Prioritization
        prioritized_findings = RiskPrioritizer.prioritize_findings(raw_findings)

        # 5. Compute Scan Summary Metrics
        duration = round(time.time() - start_time, 2)
        summary = ScanSummary(
            total_cves_evaluated=len(prioritized_findings),
            affected_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.AFFECTED),
            potentially_affected_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.POTENTIALLY_AFFECTED),
            not_affected_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.NOT_AFFECTED),
            mitigated_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.MITIGATED),
            fixed_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.FIXED),
            unable_to_determine_count=sum(1 for f in prioritized_findings if f.status == AssessmentStatus.UNABLE_TO_DETERMINE),
            critical_count=sum(1 for f in prioritized_findings if f.severity == Severity.CRITICAL and f.status in [AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED]),
            high_count=sum(1 for f in prioritized_findings if f.severity == Severity.HIGH and f.status in [AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED]),
            medium_count=sum(1 for f in prioritized_findings if f.severity == Severity.MEDIUM and f.status in [AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED]),
            low_count=sum(1 for f in prioritized_findings if f.severity == Severity.LOW and f.status in [AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED]),
            cisa_kev_count=sum(1 for f in prioritized_findings if f.cisa_kev and f.status in [AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED]),
            duration_seconds=duration,
        )

        limitations = [
            "Assessment is based on authoritative local and vendor advisories available at scan time.",
            "Ephemeral or containerized processes spawned after the inventory collection window are not reflected.",
            "Non-standard binaries without version banners or metadata may require manual binary signature analysis.",
        ]
        if clean_target_cves:
            limitations.append(f"Scoped Scan: Filtered strictly to target CVE(s): {', '.join(sorted(clean_target_cves))}.")
            unresolved = clean_target_cves - {adv.cve_id.upper() for adv in advisories}
            if unresolved:
                limitations.append(f"Target CVE(s) not found in active advisory database: {', '.join(sorted(unresolved))}. Run 'fetch-cve --cve <id>' to ingest.")
        if self.offline_mode:
            limitations.append("Scan ran in Offline Mode; live API lookups for newly published 0-day advisories were skipped.")

        return ScanReport(
            scanner_version=__version__,
            scan_timestamp=scan_timestamp,
            system_info=inventory.system_info,
            summary=summary,
            findings=prioritized_findings,
            packages=inventory.packages,
            runtimes=inventory.runtimes,
            services=inventory.services,
            configurations=inventory.configurations,
            limitations=limitations,
            data_source_timestamps=source_timestamps,
            is_offline_mode=self.offline_mode,
            branding=branding,
        )
