"""
Multi-Factor Risk Prioritization Engine.
Calculates risk priority scores (1 to 100) combining CVSS severity, FIRST EPSS probability,
CISA KEV active exploitation, verified applicability status, and running service exposure.
Ranks findings in compliance with Section 8 requirements.
"""

from typing import List
from vulnscan.core.models import AssessmentFinding, AssessmentStatus, Severity


class RiskPrioritizer:
    @classmethod
    def calculate_priority_score(cls, finding: AssessmentFinding) -> float:
        """
        Computes composite risk priority score from 0.0 to 100.0.
        Factors:
          - CVSS Score (0 - 10) -> base weight 35
          - EPSS Score (0.0 - 1.0) -> weight 25
          - CISA KEV (Known Exploited) -> 20 points bonus
          - Applicability Status Multiplier:
              * Affected: 1.0
              * Potentially affected: 0.6
              * Mitigated: 0.2
              * Fixed: 0.05
              * Not affected: 0.0
              * Unable to determine: 0.4
          - Active Service Exposure Bonus -> 10 points
        """
        # Status multiplier
        status_multipliers = {
            AssessmentStatus.AFFECTED: 1.0,
            AssessmentStatus.POTENTIALLY_AFFECTED: 0.6,
            AssessmentStatus.MITIGATED: 0.2,
            AssessmentStatus.FIXED: 0.05,
            AssessmentStatus.NOT_AFFECTED: 0.0,
            AssessmentStatus.UNABLE_TO_DETERMINE: 0.4,
        }
        multiplier = status_multipliers.get(finding.status, 0.5)

        # CVSS component (max 35)
        cvss = finding.cvss_score if finding.cvss_score is not None else 5.0
        cvss_component = (cvss / 10.0) * 35.0

        # EPSS component (max 25)
        epss = finding.epss_score if finding.epss_score is not None else 0.05
        epss_component = min(epss * 35.0, 25.0)

        # CISA KEV component (20 points)
        cisa_component = 20.0 if finding.cisa_kev else 0.0

        # Service exposure component (10 points if service restart required or active)
        exposure_component = 10.0 if finding.requires_service_restart and finding.status == AssessmentStatus.AFFECTED else 0.0

        raw_score = (cvss_component + epss_component + cisa_component + exposure_component)
        final_score = round(raw_score * multiplier, 1)
        return min(max(final_score, 0.0), 100.0)

    @classmethod
    def prioritize_findings(cls, findings: List[AssessmentFinding]) -> List[AssessmentFinding]:
        """
        Sorts findings according to Section 8 priority hierarchy:
        1. Critical vulnerabilities with confirmed applicability and known exploitation (KEV)
        2. Critical vulnerabilities with confirmed applicability
        3. High vulnerabilities with confirmed applicability
        4. Vulnerabilities with known exploitation and uncertain applicability
        5. Remaining confirmed vulnerabilities
        6. Potentially affected vulnerabilities requiring additional investigation
        7. Mitigated vulnerabilities
        8. Fixed vulnerabilities
        9. Not affected vulnerabilities
        """
        for f in findings:
            f.risk_priority_score = cls.calculate_priority_score(f)

        def sorting_key(f: AssessmentFinding) -> tuple:
            # Stage 1: Tier assignment (lower is higher priority)
            tier = 9
            if f.status == AssessmentStatus.AFFECTED:
                if f.cisa_kev and f.severity == Severity.CRITICAL:
                    tier = 1
                elif f.severity == Severity.CRITICAL:
                    tier = 2
                elif f.severity == Severity.HIGH:
                    tier = 3
                else:
                    tier = 5
            elif f.cisa_kev and f.status == AssessmentStatus.POTENTIALLY_AFFECTED:
                tier = 4
            elif f.status == AssessmentStatus.POTENTIALLY_AFFECTED:
                tier = 6
            elif f.status == AssessmentStatus.MITIGATED:
                tier = 7
            elif f.status == AssessmentStatus.FIXED:
                tier = 8
            elif f.status == AssessmentStatus.NOT_AFFECTED:
                tier = 10

            # Primary: tier ascending, Secondary: risk_priority_score descending
            return (tier, -f.risk_priority_score, -(f.cvss_score or 0.0))

        sorted_findings = sorted(findings, key=sorting_key)

        # Assign priority rank (1, 2, 3...)
        for idx, finding in enumerate(sorted_findings, 1):
            finding.priority_rank = idx

        return sorted_findings
