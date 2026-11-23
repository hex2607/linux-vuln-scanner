"""
JSON and CSV Report Generators.
Produces standardized machine-readable outputs for automation, SIEM, and ticketing ingestion.
"""

import csv
import json
from vulnscan.core.models import ScanReport


class JsonReporter:
    @classmethod
    def generate(cls, report: ScanReport, output_file: str) -> str:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        return output_file


class CsvReporter:
    @classmethod
    def generate(cls, report: ScanReport, output_file: str) -> str:
        headers = [
            "Priority Rank",
            "CVE ID",
            "Advisory ID",
            "Component",
            "Installed Version",
            "Vendor Fixed Version",
            "Severity",
            "CVSS Base Score",
            "EPSS Score",
            "CISA KEV",
            "Assessment Status",
            "Contextual Risk Rating",
            "Remediation Priority",
            "Risk Priority Score",
            "Confidence",
            "Root Cause",
            "Applicability Reason",
            "Remediation",
            "Remediation Command",
            "Verification Command",
            "Operational Impact",
            "Compensating Controls",
            "Residual Risk"
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for item in report.findings:
                writer.writerow([
                    item.priority_rank,
                    item.cve_id,
                    item.advisory_id,
                    item.component,
                    item.installed_version,
                    item.fixed_version or "N/A",
                    item.severity.value,
                    item.cvss_score or "N/A",
                    f"{round(item.epss_score * 100, 2)}%" if item.epss_score is not None else "N/A",
                    "YES" if item.cisa_kev else "NO",
                    item.status.value,
                    item.contextual_risk_rating,
                    item.remediation_priority,
                    item.risk_priority_score,
                    item.confidence.value,
                    item.root_cause,
                    item.applicability_reason,
                    item.remediation,
                    item.remediation_cmd or "",
                    item.verification_cmd or "",
                    item.operational_impact,
                    " | ".join(item.compensating_controls),
                    item.residual_risk
                ])
        return output_file
