"""
Historical Scan Comparison & Diffing Engine.
Compares vulnerability assessment reports across time to track:
- Newly introduced vulnerabilities (NEW)
- Remediated / patched vulnerabilities (FIXED)
- Unresolved persistent vulnerabilities (PERSISTING)
- Configuration / status transitions (STATE CHANGED)
"""

import os
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from vulnscan.core.models import ScanReport, AssessmentFinding, AssessmentStatus


@dataclass
class FindingDiffItem:
    cve_id: str
    component: str
    previous_status: Optional[str]
    current_status: str
    severity: str
    cvss_score: Optional[float]
    title: str
    change_type: str  # "NEW", "FIXED", "PERSISTENT", "STATE_CHANGED"
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "component": self.component,
            "previous_status": self.previous_status,
            "current_status": self.current_status,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "change_type": self.change_type,
            "notes": self.notes,
        }


@dataclass
class ScanDiffResult:
    baseline_timestamp: str
    current_timestamp: str
    baseline_host: str
    current_host: str
    new_findings: List[FindingDiffItem] = field(default_factory=list)
    fixed_findings: List[FindingDiffItem] = field(default_factory=list)
    persistent_findings: List[FindingDiffItem] = field(default_factory=list)
    state_changed_findings: List[FindingDiffItem] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return len(self.new_findings)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed_findings)

    @property
    def total_persistent(self) -> int:
        return len(self.persistent_findings)

    @property
    def total_state_changed(self) -> int:
        return len(self.state_changed_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "diff_timestamp": datetime.now().isoformat(),
            "baseline": {
                "host": self.baseline_host,
                "timestamp": self.baseline_timestamp,
            },
            "current": {
                "host": self.current_host,
                "timestamp": self.current_timestamp,
            },
            "metrics": {
                "new_vulnerabilities": self.total_new,
                "fixed_remediated": self.total_fixed,
                "persistent_unresolved": self.total_persistent,
                "state_changed": self.total_state_changed,
            },
            "new_findings": [f.to_dict() for f in self.new_findings],
            "fixed_findings": [f.to_dict() for f in self.fixed_findings],
            "persistent_findings": [f.to_dict() for f in self.persistent_findings],
            "state_changed_findings": [f.to_dict() for f in self.state_changed_findings],
        }


class ScanDiffer:
    """Compares baseline vs current scan reports."""

    @classmethod
    def _extract_report_data(cls, report_input: Union[ScanReport, dict, str]) -> Dict[str, Any]:
        if isinstance(report_input, ScanReport):
            return report_input.to_dict()
        elif isinstance(report_input, dict):
            return report_input
        elif isinstance(report_input, str):
            if not os.path.exists(report_input):
                raise FileNotFoundError(f"Report file not found: {report_input}")
            with open(report_input, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            raise TypeError(f"Unsupported report input type: {type(report_input)}")

    @classmethod
    def compare(
        cls,
        baseline_input: Union[ScanReport, dict, str],
        current_input: Union[ScanReport, dict, str]
    ) -> ScanDiffResult:
        base_data = cls._extract_report_data(baseline_input)
        curr_data = cls._extract_report_data(current_input)

        base_host = base_data.get("system_info", {}).get("hostname", "Unknown")
        curr_host = curr_data.get("system_info", {}).get("hostname", "Unknown")
        base_ts = base_data.get("scan_timestamp", "N/A")
        curr_ts = curr_data.get("scan_timestamp", "N/A")

        base_findings: Dict[str, Dict[str, Any]] = {
            f["cve_id"]: f for f in base_data.get("findings", [])
        }
        curr_findings: Dict[str, Dict[str, Any]] = {
            f["cve_id"]: f for f in curr_data.get("findings", [])
        }

        diff = ScanDiffResult(
            baseline_timestamp=base_ts,
            current_timestamp=curr_ts,
            baseline_host=base_host,
            current_host=curr_host,
        )

        all_cve_ids = set(base_findings.keys()) | set(curr_findings.keys())

        for cve in sorted(all_cve_ids):
            in_base = cve in base_findings
            in_curr = cve in curr_findings

            b_item = base_findings.get(cve)
            c_item = curr_findings.get(cve)

            b_status = b_item.get("status") if b_item else None
            c_status = c_item.get("status") if c_item else "Remediated/Absent"

            comp = (c_item or b_item).get("component", "Unknown")
            sev = (c_item or b_item).get("severity", "UNKNOWN")
            cvss = (c_item or b_item).get("cvss_score")
            title = (c_item or b_item).get("title", "")

            # 1. NEW Vulnerability: Appears in current, wasn't in baseline
            if in_curr and not in_base:
                diff.new_findings.append(FindingDiffItem(
                    cve_id=cve,
                    component=comp,
                    previous_status=None,
                    current_status=c_status,
                    severity=sev,
                    cvss_score=cvss,
                    title=title,
                    change_type="NEW",
                    notes="Newly identified vulnerability not present in baseline scan."
                ))
            # 2. FIXED / Remediated: Was vulnerable in baseline, now fixed or removed
            elif in_base and not in_curr:
                diff.fixed_findings.append(FindingDiffItem(
                    cve_id=cve,
                    component=comp,
                    previous_status=b_status,
                    current_status=c_status,
                    severity=sev,
                    cvss_score=cvss,
                    title=title,
                    change_type="FIXED",
                    notes=f"Successfully remediated. Finding is absent in current scan."
                ))
            elif in_base and in_curr and b_status in ("Affected", "Potentially affected", "Unable to determine") and c_status == "Fixed":
                diff.fixed_findings.append(FindingDiffItem(
                    cve_id=cve,
                    component=comp,
                    previous_status=b_status,
                    current_status=c_status,
                    severity=sev,
                    cvss_score=cvss,
                    title=title,
                    change_type="FIXED",
                    notes=f"Successfully remediated. Status transitioned from '{b_status}' to '{c_status}'."
                ))
            # 3. STATE CHANGED: Still present, but configuration / applicability changed (e.g. Affected -> Mitigated)
            elif in_base and in_curr and b_status != c_status:
                diff.state_changed_findings.append(FindingDiffItem(
                    cve_id=cve,
                    component=comp,
                    previous_status=b_status,
                    current_status=c_status,
                    severity=sev,
                    cvss_score=cvss,
                    title=title,
                    change_type="STATE_CHANGED",
                    notes=f"Applicability state changed: '{b_status}' -> '{c_status}'."
                ))
            # 4. PERSISTENT: Remains in same status (e.g. Affected -> Affected or Fixed -> Fixed)
            elif in_base and in_curr:
                diff.persistent_findings.append(FindingDiffItem(
                    cve_id=cve,
                    component=comp,
                    previous_status=b_status,
                    current_status=c_status,
                    severity=sev,
                    cvss_score=cvss,
                    title=title,
                    change_type="PERSISTENT",
                    notes=f"Unchanged state '{c_status}' persists across assessment window."
                ))

        return diff

    @classmethod
    def print_diff_summary(cls, diff: ScanDiffResult) -> None:
        print("""
================================================================================
   📊  HISTORICAL VULNERABILITY SCAN COMPARISON & TREND DELTA
================================================================================
""")
        print(f"[*] Baseline Target : {diff.baseline_host} (Scanned: {diff.baseline_timestamp})")
        print(f"[*] Current Target  : {diff.current_host} (Scanned: {diff.current_timestamp})")
        print("-" * 80)
        print(f"  🟢 Successfully Remediated / FIXED : {diff.total_fixed}")
        print(f"  🔴 Newly Introduced Vulnerabilities: {diff.total_new}")
        print(f"  🟡 Applicability State Changed      : {diff.total_state_changed}")
        print(f"  ⚪ Persistent Unchanged Findings    : {diff.total_persistent}")
        print("-" * 80)

        if diff.fixed_findings:
            print("\n[+] RESOLVED & REMEDIATED VULNERABILITIES:")
            for f in diff.fixed_findings:
                print(f"    ✓ {f.cve_id:<18} {f.component:<14} [{f.previous_status} -> {f.current_status}]")

        if diff.new_findings:
            print("\n[!] NEW VULNERABILITIES IDENTIFIED:")
            for f in diff.new_findings:
                print(f"    + {f.cve_id:<18} {f.component:<14} [{f.current_status}] (Severity: {f.severity})")

        if diff.state_changed_findings:
            print("\n[*] STATE & APPLICABILITY TRANSITIONS:")
            for f in diff.state_changed_findings:
                print(f"    ~ {f.cve_id:<18} {f.component:<14} [{f.previous_status} -> {f.current_status}]")

        print("=" * 80)

    @classmethod
    def save_diff_json(cls, diff: ScanDiffResult, output_file: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(diff.to_dict(), f, indent=2)
        return output_file

    @classmethod
    def save_diff_html(cls, diff: ScanDiffResult, output_file: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        def render_rows(items: List[FindingDiffItem], color: str):
            if not items:
                return f'<tr><td colspan="5" style="text-align:center; padding:16px; color:#94a3b8;">No entries in this category.</td></tr>'
            rows = []
            for item in items:
                rows.append(f"""
                <tr>
                    <td><strong>{item.cve_id}</strong></td>
                    <td><code>{item.component}</code></td>
                    <td><span style="color:#94a3b8;">{item.previous_status or 'N/A'}</span> &rarr; <span style="font-weight:600; color:{color};">{item.current_status}</span></td>
                    <td>{item.severity}</td>
                    <td>{item.notes}</td>
                </tr>
                """)
            return "\n".join(rows)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Delta Report - {diff.current_host}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
        h1 {{ margin: 0 0 10px 0; font-size: 1.6rem; color: #38bdf8; }}
        .meta {{ color: #94a3b8; font-size: 0.85rem; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #1e293b; padding: 18px; border-radius: 10px; border: 1px solid #334155; text-align: center; }}
        .card-num {{ font-size: 2rem; font-weight: 700; margin-bottom: 4px; }}
        .card-lbl {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
        .sec {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 24px; border: 1px solid #334155; }}
        .sec-title {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 12px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ background: #0f172a; padding: 10px 14px; text-align: left; color: #cbd5e1; border-bottom: 2px solid #334155; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #334155; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Vulnerability Delta & Remediation Tracking Report</h1>
        <div class="meta">
            Target Host: <strong>{diff.current_host}</strong> | 
            Baseline Scan: <strong>{diff.baseline_timestamp}</strong> | 
            Current Scan: <strong>{diff.current_timestamp}</strong>
        </div>
    </div>

    <div class="cards">
        <div class="card" style="border-top: 4px solid #22c55e;">
            <div class="card-num" style="color: #22c55e;">{diff.total_fixed}</div>
            <div class="card-lbl">Resolved / Fixed</div>
        </div>
        <div class="card" style="border-top: 4px solid #ef4444;">
            <div class="card-num" style="color: #ef4444;">{diff.total_new}</div>
            <div class="card-lbl">Newly Introduced</div>
        </div>
        <div class="card" style="border-top: 4px solid #f59e0b;">
            <div class="card-num" style="color: #f59e0b;">{diff.total_state_changed}</div>
            <div class="card-lbl">State Changed</div>
        </div>
        <div class="card" style="border-top: 4px solid #64748b;">
            <div class="card-num" style="color: #94a3b8;">{diff.total_persistent}</div>
            <div class="card-lbl">Persistent Findings</div>
        </div>
    </div>

    <div class="sec">
        <div class="sec-title" style="color: #22c55e;">&check; Successfully Remediated / Fixed Vulnerabilities ({diff.total_fixed})</div>
        <table>
            <thead><tr><th>CVE ID</th><th>Component</th><th>Transition</th><th>Severity</th><th>Remediation Notes</th></tr></thead>
            <tbody>{render_rows(diff.fixed_findings, '#22c55e')}</tbody>
        </table>
    </div>

    <div class="sec">
        <div class="sec-title" style="color: #ef4444;">&plus; Newly Introduced Vulnerabilities ({diff.total_new})</div>
        <table>
            <thead><tr><th>CVE ID</th><th>Component</th><th>Transition</th><th>Severity</th><th>Audit Notes</th></tr></thead>
            <tbody>{render_rows(diff.new_findings, '#ef4444')}</tbody>
        </table>
    </div>

    <div class="sec">
        <div class="sec-title" style="color: #f59e0b;">&tilde; State & Applicability Transitions ({diff.total_state_changed})</div>
        <table>
            <thead><tr><th>CVE ID</th><th>Component</th><th>Transition</th><th>Severity</th><th>State Change Details</th></tr></thead>
            <tbody>{render_rows(diff.state_changed_findings, '#f59e0b')}</tbody>
        </table>
    </div>
</div>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        return output_file
