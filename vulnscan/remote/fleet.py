"""
Multi-Server Fleet Assessment and Consolidated Reporting.
Orchestrates parallel security assessments across multiple Linux servers
(e.g., AWS EC2 fleets or on-premise clusters) and generates consolidated posture reports.
"""

import os
import csv
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Tuple
import concurrent.futures

from vulnscan.core.models import ScanReport, AssessmentStatus, Severity
from vulnscan.core.engine import ScanEngine
from vulnscan.remote.ssh_runner import RemoteSSHRunner
from vulnscan.inventory.collector import InventoryCollector


@dataclass
class FleetTarget:
    host: str
    user: str = "root"
    port: int = 22
    key_file: Optional[str] = None
    alias: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    is_mock: bool = False
    mock_scenario: str = "default"


@dataclass
class HostScanResult:
    target: FleetTarget
    success: bool
    report: Optional[ScanReport] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class FleetReport:
    fleet_name: str
    assessment_timestamp: str
    total_targets: int
    successful_scans: int
    failed_scans: int
    compliance_score_pct: float
    host_results: List[HostScanResult] = field(default_factory=list)
    fleet_cve_matrix: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fleet_name": self.fleet_name,
            "assessment_timestamp": self.assessment_timestamp,
            "metrics": {
                "total_targets": self.total_targets,
                "successful_scans": self.successful_scans,
                "failed_scans": self.failed_scans,
                "compliance_score_pct": self.compliance_score_pct,
            },
            "fleet_cve_matrix": self.fleet_cve_matrix,
            "hosts": [
                {
                    "host": h.target.host,
                    "alias": h.target.alias or h.target.host,
                    "success": h.success,
                    "tags": h.target.tags,
                    "duration_seconds": h.duration_seconds,
                    "error": h.error_message,
                    "summary": h.report.summary.to_dict() if h.report else None,
                }
                for h in self.host_results
            ]
        }


class FleetScanner:
    """Manages concurrent assessment of multiple Linux servers."""

    @classmethod
    def parse_inventory_file(cls, file_path: str) -> List[FleetTarget]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Fleet inventory file not found: {file_path}")

        targets: List[FleetTarget] = []
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                items = data.get("servers", data) if isinstance(data, dict) else data
                for item in items:
                    targets.append(FleetTarget(
                        host=item["host"],
                        user=item.get("user", "root"),
                        port=int(item.get("port", 22)),
                        key_file=item.get("key_file"),
                        alias=item.get("alias"),
                        tags=item.get("tags", {}),
                        is_mock=item.get("is_mock", False),
                        mock_scenario=item.get("mock_scenario", "default"),
                    ))
        elif ext in (".yaml", ".yml"):
            try:
                import yaml
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    items = data.get("servers", data) if isinstance(data, dict) else data
                    for item in items:
                        targets.append(FleetTarget(
                            host=item["host"],
                            user=item.get("user", "root"),
                            port=int(item.get("port", 22)),
                            key_file=item.get("key_file"),
                            alias=item.get("alias"),
                            tags=item.get("tags", {}),
                            is_mock=item.get("is_mock", False),
                            mock_scenario=item.get("mock_scenario", "default"),
                        ))
            except ImportError:
                # Basic line parser if PyYAML is not installed
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Fallback simple line reading for servers: - host: x
                    lines = content.splitlines()
                    curr: Dict[str, Any] = {}
                    for l in lines:
                        strip = l.strip()
                        if strip.startswith("- host:") or strip.startswith("host:"):
                            if curr and "host" in curr:
                                targets.append(FleetTarget(**curr))
                                curr = {}
                            curr["host"] = strip.split(":", 1)[1].strip()
                        elif strip.startswith("user:"):
                            curr["user"] = strip.split(":", 1)[1].strip()
                        elif strip.startswith("port:"):
                            curr["port"] = int(strip.split(":", 1)[1].strip())
                        elif strip.startswith("alias:"):
                            curr["alias"] = strip.split(":", 1)[1].strip()
                        elif strip.startswith("key_file:"):
                            curr["key_file"] = strip.split(":", 1)[1].strip()
                    if curr and "host" in curr:
                        targets.append(FleetTarget(**curr))
        elif ext == ".csv":
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tags = {}
                    if "tags" in row and row["tags"]:
                        for t in row["tags"].split(";"):
                            if "=" in t:
                                k, v = t.split("=", 1)
                                tags[k.strip()] = v.strip()
                    targets.append(FleetTarget(
                        host=row["host"].strip(),
                        user=row.get("user", "root").strip(),
                        port=int(row.get("port", 22)),
                        key_file=row.get("key_file", "").strip() or None,
                        alias=row.get("alias", "").strip() or None,
                        tags=tags,
                        is_mock=row.get("is_mock", "").lower() in ("true", "1", "yes"),
                        mock_scenario=row.get("mock_scenario", "default").strip(),
                    ))
        else:
            raise ValueError(f"Unsupported inventory file extension '{ext}'. Use .json, .yaml, or .csv")

        return targets

    @classmethod
    def scan_target(
        cls,
        target: FleetTarget,
        offline_mode: bool = True,
        target_cves: Optional[List[str]] = None,
        depth: str = "standard"
    ) -> HostScanResult:
        start_t = time.time()
        alias = target.alias or target.host

        try:
            if target.is_mock or target.host.startswith("mock-") or target.host == "local-profile":
                engine = ScanEngine(offline_mode=True)
                if target.mock_scenario == "mitigated":
                    inv = InventoryCollector.create_rocky9_reference_inventory(nginx_http2_enabled=False)
                elif target.mock_scenario == "patched":
                    inv = InventoryCollector.create_rocky9_reference_inventory(
                        nginx_release="14.el9_2.3", java_version="17.0.9", java_release="1.el9"
                    )
                else:
                    inv = InventoryCollector.create_rocky9_reference_inventory()
                report = engine.run_scan(prebuilt_inventory=inv, target_cves=target_cves, depth=depth)
            else:
                ssh_runner = RemoteSSHRunner(
                    host=target.host,
                    user=target.user,
                    port=target.port,
                    key_file=target.key_file
                )
                engine = ScanEngine(command_runner=ssh_runner.run_command, offline_mode=offline_mode)
                report = engine.run_scan(target_cves=target_cves, depth=depth)

            report.system_info.hostname = alias
            duration = round(time.time() - start_t, 2)
            return HostScanResult(target=target, success=True, report=report, duration_seconds=duration)
        except Exception as e:
            duration = round(time.time() - start_t, 2)
            return HostScanResult(target=target, success=False, error_message=str(e), duration_seconds=duration)

    @classmethod
    def run_fleet_scan(
        cls,
        targets: List[FleetTarget],
        concurrency: int = 5,
        offline_mode: bool = True,
        target_cves: Optional[List[str]] = None,
        fleet_name: str = "Production Fleet Assessment",
        depth: str = "standard"
    ) -> FleetReport:
        results: List[HostScanResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_target = {
                executor.submit(cls.scan_target, t, offline_mode, target_cves, depth): t
                for t in targets
            }
            for future in concurrent.futures.as_completed(future_to_target):
                res = future.result()
                results.append(res)

        # Sort results by alias or host name
        results.sort(key=lambda r: r.target.alias or r.target.host)

        successful = [r for r in results if r.success and r.report]
        failed = [r for r in results if not r.success]

        # Calculate fleet CVE matrix (CVE -> affected hosts)
        matrix: Dict[str, List[str]] = {}
        clean_hosts_count = 0

        for r in successful:
            rep = r.report
            host_name = r.target.alias or r.target.host
            is_clean = True
            for f in rep.findings:
                if f.status in (AssessmentStatus.AFFECTED, AssessmentStatus.POTENTIALLY_AFFECTED):
                    is_clean = False
                    if f.cve_id not in matrix:
                        matrix[f.cve_id] = []
                    matrix[f.cve_id].append(host_name)
            if is_clean:
                clean_hosts_count += 1

        compliance = round((clean_hosts_count / len(successful) * 100), 1) if successful else 0.0

        return FleetReport(
            fleet_name=fleet_name,
            assessment_timestamp=datetime.now(timezone.utc).isoformat(),
            total_targets=len(targets),
            successful_scans=len(successful),
            failed_scans=len(failed),
            compliance_score_pct=compliance,
            host_results=results,
            fleet_cve_matrix=matrix,
        )

    @classmethod
    def print_fleet_summary(cls, report: FleetReport) -> None:
        print("""
================================================================================
   🌐  FLEET VULNERABILITY ASSESSMENT CONSOLIDATED REPORT
================================================================================
""")
        print(f"[*] Fleet Name           : {report.fleet_name}")
        print(f"[*] Assessment Timestamp : {report.assessment_timestamp}")
        print(f"[*] Total Targets Scanned: {report.total_targets} ({report.successful_scans} succeeded, {report.failed_scans} failed)")
        print(f"[*] Fleet Patch Compliance: {report.compliance_score_pct}% of hosts clean")
        print("-" * 80)
        print(f"{'Target Host / Alias':<28} {'OS':<16} {'Status':<12} {'Affected':<10} {'Mitigated':<10} {'Fixed':<8}")
        print("-" * 80)

        for hr in report.host_results:
            name = (hr.target.alias or hr.target.host)[:26]
            if hr.success and hr.report:
                sys_desc = f"{hr.report.system_info.os_name} {hr.report.system_info.os_version}"[:15]
                s = hr.report.summary
                status_str = "OK" if s.affected_count == 0 else "VULNERABLE"
                print(f"{name:<28} {sys_desc:<16} {status_str:<12} {s.affected_count:<10} {s.mitigated_count:<10} {s.fixed_count:<8}")
            else:
                err_msg = (hr.error_message or "Scan Failed")[:20]
                print(f"{name:<28} {'N/A':<16} {'FAILED':<12} {'-':<10} {'-':<10} {err_msg}")

        print("=" * 80)
        if report.fleet_cve_matrix:
            print("\n[!] FLEET-WIDE AFFECTED CVE BREAKDOWN:")
            for cve, hosts in sorted(report.fleet_cve_matrix.items()):
                print(f"    • {cve:<18} -> Affects {len(hosts)} host(s): {', '.join(hosts[:4])}{'...' if len(hosts) > 4 else ''}")
        print("=" * 80)

    @classmethod
    def save_fleet_reports(cls, report: FleetReport, output_dir: str, base_name: Optional[str] = None) -> List[str]:
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        prefix = base_name or f"fleet-report-{ts}"

        paths = []
        # 1. JSON
        json_path = os.path.join(output_dir, f"{prefix}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        paths.append(json_path)

        # 2. CSV
        csv_path = os.path.join(output_dir, f"{prefix}.csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Alias", "Scan_Status", "OS", "Kernel", "Affected", "Potentially_Affected", "Mitigated", "Fixed", "Duration_Sec", "Error"])
            for hr in report.host_results:
                if hr.success and hr.report:
                    s = hr.report.summary
                    sys_info = hr.report.system_info
                    writer.writerow([
                        hr.target.host, hr.target.alias or hr.target.host, "Success",
                        f"{sys_info.os_name} {sys_info.os_version}", sys_info.kernel_version,
                        s.affected_count, s.potentially_affected_count, s.mitigated_count, s.fixed_count,
                        hr.duration_seconds, ""
                    ])
                else:
                    writer.writerow([hr.target.host, hr.target.alias or hr.target.host, "Failed", "N/A", "N/A", 0, 0, 0, 0, hr.duration_seconds, hr.error_message])
        paths.append(csv_path)

        # 3. HTML Dashboard
        html_path = os.path.join(output_dir, f"{prefix}.html")
        html_content = cls._generate_fleet_html(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        paths.append(html_path)

        return paths

    @classmethod
    def _generate_fleet_html(cls, report: FleetReport) -> str:
        rows = []
        for hr in report.host_results:
            name = hr.target.alias or hr.target.host
            if hr.success and hr.report:
                s = hr.report.summary
                sys_info = hr.report.system_info
                st_color = "#22c55e" if s.affected_count == 0 else "#ef4444"
                st_text = "CLEAN" if s.affected_count == 0 else f"{s.affected_count} AFFECTED"
                tag_str = ", ".join(f"{k}={v}" for k, v in hr.target.tags.items()) if hr.target.tags else "None"
                rows.append(f"""
                <tr>
                    <td><strong>{name}</strong><br><small style="color:#94a3b8;">{hr.target.host}</small></td>
                    <td>{sys_info.os_name} {sys_info.os_version} ({sys_info.architecture})</td>
                    <td><span style="background:{st_color}22; color:{st_color}; padding:4px 8px; border-radius:4px; font-weight:600;">{st_text}</span></td>
                    <td><strong style="color:#ef4444;">{s.affected_count}</strong></td>
                    <td><strong style="color:#f59e0b;">{s.mitigated_count}</strong></td>
                    <td><strong style="color:#22c55e;">{s.fixed_count}</strong></td>
                    <td><small>{tag_str}</small></td>
                    <td>{hr.duration_seconds}s</td>
                </tr>
                """)
            else:
                rows.append(f"""
                <tr>
                    <td><strong>{name}</strong><br><small style="color:#94a3b8;">{hr.target.host}</small></td>
                    <td>N/A</td>
                    <td><span style="background:#ef444422; color:#ef4444; padding:4px 8px; border-radius:4px; font-weight:600;">FAILED</span></td>
                    <td>-</td><td>-</td><td>-</td>
                    <td colspan="2" style="color:#f87171;"><small>{hr.error_message}</small></td>
                </tr>
                """)

        matrix_items = []
        for cve, hosts in sorted(report.fleet_cve_matrix.items()):
            matrix_items.append(f"""
            <div style="background:#1e293b; padding:12px 16px; border-radius:8px; margin-bottom:8px; border:1px solid #334155;">
                <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                    <strong style="color:#38bdf8;">{cve}</strong>
                    <span style="color:#ef4444; font-weight:600;">{len(hosts)} Host(s) Affected</span>
                </div>
                <div style="color:#94a3b8; font-size:0.85rem;">Affected Targets: {', '.join(hosts)}</div>
            </div>
            """)

        matrix_html = "\n".join(matrix_items) if matrix_items else "<div style='color:#22c55e; padding:12px;'>No critical or affected vulnerabilities across fleet!</div>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{report.fleet_name} - Consolidated Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
        h1 {{ margin: 0 0 10px 0; font-size: 1.6rem; color: #38bdf8; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #1e293b; padding: 18px; border-radius: 10px; border: 1px solid #334155; text-align: center; }}
        .card-num {{ font-size: 2.2rem; font-weight: 700; margin-bottom: 4px; }}
        .card-lbl {{ font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; }}
        .sec {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 24px; border: 1px solid #334155; }}
        .sec-title {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 14px; color: #f1f5f9; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ background: #0f172a; padding: 10px 14px; text-align: left; color: #cbd5e1; border-bottom: 2px solid #334155; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #334155; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>{report.fleet_name}</h1>
        <div style="color: #94a3b8; font-size: 0.85rem;">
            Assessment Window: <strong>{report.assessment_timestamp}</strong> | Consolidated Fleet Assessment
        </div>
    </div>

    <div class="cards">
        <div class="card" style="border-top: 4px solid #38bdf8;">
            <div class="card-num" style="color: #38bdf8;">{report.total_targets}</div>
            <div class="card-lbl">Total Servers Assessed</div>
        </div>
        <div class="card" style="border-top: 4px solid #22c55e;">
            <div class="card-num" style="color: #22c55e;">{report.compliance_score_pct}%</div>
            <div class="card-lbl">Fleet Compliance Rate</div>
        </div>
        <div class="card" style="border-top: 4px solid #ef4444;">
            <div class="card-num" style="color: #ef4444;">{len(report.fleet_cve_matrix)}</div>
            <div class="card-lbl">Distinct Active CVEs</div>
        </div>
        <div class="card" style="border-top: 4px solid #f59e0b;">
            <div class="card-num" style="color: #f59e0b;">{report.failed_scans}</div>
            <div class="card-lbl">Unreachable / Failed Hosts</div>
        </div>
    </div>

    <div class="sec">
        <div class="sec-title">Fleet Servers Summary Table</div>
        <table>
            <thead>
                <tr>
                    <th>Host / Alias</th>
                    <th>Operating System</th>
                    <th>Posture</th>
                    <th>Affected</th>
                    <th>Mitigated</th>
                    <th>Fixed</th>
                    <th>Tags</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>

    <div class="sec">
        <div class="sec-title">Fleet-Wide CVE Exposure Heat Matrix</div>
        {matrix_html}
    </div>
</div>
</body>
</html>
"""
