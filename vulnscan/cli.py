"""
Command Line Interface (CLI) for Linux Vulnerability Scanner.
Provides command-line subcommands for local scanning, remote SSH assessment,
multi-format report generation, database updates, and dashboard hosting.
"""

import os
import sys
import argparse
import json
from datetime import datetime, timezone
from typing import Optional, List
from vulnscan import __version__
from vulnscan.core.models import ReportBranding
from vulnscan.core.engine import ScanEngine
from vulnscan.core.history import ScanDiffer
from vulnscan.core.config import ConfigLoader
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.reporting.html_reporter import HtmlReporter
from vulnscan.reporting.pdf_reporter import PdfReporter
from vulnscan.reporting.json_reporter import JsonReporter, CsvReporter
from vulnscan.remote.ssh_runner import RemoteSSHRunner
from vulnscan.remote.fleet import FleetScanner
from vulnscan.ui.web_server import run_web_server


def print_banner():
    print("""
================================================================================
   🛡️  LINUX VULNERABILITY SCANNER & SECURITY ASSESSMENT TOOL  v1.0.0
   Authoritative Multi-Source CVE & Applicability Assessment Engine
================================================================================
""")


def print_summary_table(report):
    sys = report.system_info
    sum_obj = report.summary
    print(f"[*] Target Host: {sys.hostname} | OS: {sys.os_name} {sys.os_version} ({sys.architecture})")
    print(f"[*] Kernel: {sys.kernel_version} | Cloud: {sys.cloud_provider or 'N/A'}")
    print(f"[*] Total Packages Audited: {len(report.packages)} | Services: {len(report.services)}")
    print(f"[*] Assessment Duration: {sum_obj.duration_seconds}s | Offline Mode: {report.is_offline_mode}")
    print("-" * 80)
    print(f"  Confirmed AFFECTED       : {sum_obj.affected_count}")
    print(f"  POTENTIALLY AFFECTED     : {sum_obj.potentially_affected_count}")
    print(f"  MITIGATED by Config      : {sum_obj.mitigated_count}")
    print(f"  Vendor FIXED / Patched   : {sum_obj.fixed_count}")
    print(f"  NOT AFFECTED             : {sum_obj.not_affected_count}")
    print(f"  CISA Known Exploited     : {sum_obj.cisa_kev_count}")
    print("-" * 80)
    print(f"{'Rank':<5} {'CVE ID':<18} {'Component':<16} {'Severity':<10} {'Status':<22} {'Risk Score':<10}")
    print("-" * 80)
    for f in report.findings:
        print(f"#{f.priority_rank:<4} {f.cve_id:<18} {f.component[:15]:<16} {f.severity.value:<10} {f.status.value:<22} {f.risk_priority_score:<10}")
    print("=" * 80)


def save_reports(
    report,
    output_dir: str,
    formats: str,
    report_name: Optional[str] = None,
    host_alias: Optional[str] = None
) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    fmt_list = [f.strip().lower() for f in formats.split(",")]

    try:
        ts_clean = report.scan_timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        time_part = dt.strftime("%Y%m%d-%H%M%S")
    except Exception:
        time_part = datetime.now().strftime("%Y%m%d-%H%M%S")

    if host_alias:
        clean_alias = host_alias.replace("/", "_").replace(":", "_").replace(" ", "_")
        base_name = f"{clean_alias}-{time_part}"
    elif report_name:
        clean_name = report_name.replace("/", "_").replace(":", "_")
        if "{timestamp}" in clean_name:
            base_name = clean_name.replace("{timestamp}", time_part)
        elif any(clean_name.endswith(f".{fmt}") for fmt in ["html", "pdf", "json", "csv"]):
            base_name = os.path.splitext(clean_name)[0]
        else:
            base_name = f"{clean_name}-{time_part}"
    else:
        host = report.system_info.hostname.replace("/", "_").replace(":", "_").replace(" ", "_")
        base_name = f"{host}-{time_part}"

    paths = []
    if "json" in fmt_list:
        p = os.path.join(output_dir, f"{base_name}.json")
        JsonReporter.generate(report, p)
        paths.append(p)
    if "csv" in fmt_list:
        p = os.path.join(output_dir, f"{base_name}.csv")
        CsvReporter.generate(report, p)
        paths.append(p)
    if "html" in fmt_list:
        p = os.path.join(output_dir, f"{base_name}.html")
        HtmlReporter.generate(report, p)
        paths.append(p)
    if "pdf" in fmt_list:
        p = os.path.join(output_dir, f"{base_name}.pdf")
        PdfReporter.generate(report, p)
        paths.append(p)

    print(f"[+] Assessment reports successfully generated in '{output_dir}':")
    for p in paths:
        print(f"    - {p}")
    return paths


def str_to_bool(v):
    if isinstance(v, bool):
        return v
    if str(v).lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif str(v).lower() in ("no", "false", "f", "n", "0"):
        return False
    raise argparse.ArgumentTypeError(f"Boolean value expected, got '{v}'. Use true or false.")


def resolve_offline(args) -> bool:
    if getattr(args, "online", False):
        return False
    off_mode = getattr(args, "offline_mode", None)
    if off_mode is not None:
        return str_to_bool(off_mode)
    off = getattr(args, "offline", None)
    if off is not None:
        return str_to_bool(off)
    return True


def handle_scan_local(args):
    print_banner()
    offline_mode = resolve_offline(args)
    engine = ScanEngine(offline_mode=offline_mode)
    prebuilt_inv = None

    if args.profile == "rocky9":
        print("[*] Running assessment using Rocky Linux 9.6 Reference Profile...")
        if args.scenario == "mitigated_nginx":
            prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(nginx_http2_enabled=False)
        elif args.scenario == "mitigated_openjdk":
            prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(jvm_disable_base64_intrinsics=True)
        elif args.scenario == "non_avx512":
            prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(cpu_has_avx512_vbmi=False)
        elif args.scenario == "patched":
            prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(
                nginx_release="14.el9_2.3", java_version="17.0.9", java_release="1.el9"
            )
        else:
            prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory()

    target_cves = None
    if getattr(args, "cve", None):
        target_cves = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
        print(f"[*] Scoped Scan: Targeting specific CVE(s): {', '.join(target_cves)}")

    cfg = ConfigLoader.load(getattr(args, "config", None))
    branding = ConfigLoader.get_branding(cfg, {
        "company": getattr(args, "company", None),
        "assessor": getattr(args, "assessor", None),
        "classification": getattr(args, "classification", None),
    })
    depth = getattr(args, "depth", "standard")
    if depth == "standard" and "scanner" in cfg and "depth" in cfg["scanner"]:
        depth = cfg["scanner"]["depth"]

    out_dir = getattr(args, "output_dir", "./reports")
    if out_dir == "./reports" and "reporting" in cfg and "output_dir" in cfg["reporting"]:
        out_dir = cfg["reporting"]["output_dir"]

    fmts = getattr(args, "format", "html,pdf,json,csv")
    if fmts == "html,pdf,json,csv" and "reporting" in cfg and "default_formats" in cfg["reporting"]:
        fmts = ConfigLoader.get_formats(cfg)

    report = engine.run_scan(prebuilt_inventory=prebuilt_inv, target_cves=target_cves, depth=depth, branding=branding)
    alias = getattr(args, "host_alias", None)
    if alias:
        report.system_info.hostname = alias
    print_summary_table(report)
    save_reports(report, out_dir, fmts, getattr(args, "report_name", None), host_alias=alias)


def handle_scan_remote(args):
    print_banner()
    offline_mode = resolve_offline(args)
    print(f"[*] Initiating non-destructive read-only SSH scan against {args.user}@{args.host}:{args.port} (Offline Mode: {offline_mode})...")
    ssh_runner = RemoteSSHRunner(
        host=args.host, user=args.user, port=args.port, key_file=args.key_file
    )
    engine = ScanEngine(command_runner=ssh_runner.run_command, offline_mode=offline_mode)

    target_cves = None
    if getattr(args, "cve", None):
        target_cves = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
        print(f"[*] Scoped Scan: Targeting specific CVE(s): {', '.join(target_cves)}")

    cfg = ConfigLoader.load(getattr(args, "config", None))
    branding = ConfigLoader.get_branding(cfg, {
        "company": getattr(args, "company", None),
        "assessor": getattr(args, "assessor", None),
        "classification": getattr(args, "classification", None),
    })
    depth = getattr(args, "depth", "standard")
    if depth == "standard" and "scanner" in cfg and "depth" in cfg["scanner"]:
        depth = cfg["scanner"]["depth"]

    out_dir = getattr(args, "output_dir", "./reports")
    if out_dir == "./reports" and "reporting" in cfg and "output_dir" in cfg["reporting"]:
        out_dir = cfg["reporting"]["output_dir"]

    fmts = getattr(args, "format", "html,pdf,json,csv")
    if fmts == "html,pdf,json,csv" and "reporting" in cfg and "default_formats" in cfg["reporting"]:
        fmts = ConfigLoader.get_formats(cfg)

    report = engine.run_scan(target_cves=target_cves, depth=depth, branding=branding)
    alias = getattr(args, "host_alias", None)
    if alias:
        report.system_info.hostname = alias
    print_summary_table(report)
    save_reports(report, out_dir, fmts, getattr(args, "report_name", None), host_alias=alias)


def handle_update_db(args):
    print_banner()
    print("[*] Updating advisory database from authoritative vendor and threat feeds...")
    from vulnscan.advisories.manager import AdvisoryManager
    mgr = AdvisoryManager(offline_mode=False)
    try:
        stats = mgr.update_database()
        print(f"[+] CISA KEV Catalog: {stats.get('cisa_kev_updated', 0)} entries synchronized")
        print(f"[+] FIRST EPSS Scores: {stats.get('epss_updated', 0)} scores updated")
        if stats.get("errors"):
            print("[!] Warnings during live synchronization:")
            for err in stats["errors"]:
                print(f"    - {err}")
        print(f"[+] Advisory database successfully updated: {mgr.cache_file}")
    except Exception as e:
        print(f"[-] Database update error: {e}")


def handle_fetch_cve(args):
    from vulnscan.advisories.updater import AdvisoryUpdater
    cve_list = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
    if not cve_list:
        print("[-] No valid CVE ID provided.")
        return

    file_path = args.file
    if not file_path:
        pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_path = os.path.join(pkg_dir, "data", "sample_advisories.json")

    print_banner()
    print(f"[*] Ingesting CVE Advisories for target OS release: {args.target_os}")
    print(f"[*] Target database: {file_path}")
    print("-" * 80)

    success = 0
    for cve in cve_list:
        if not cve.startswith("CVE-"):
            cve = f"CVE-{cve}"
        print(f"[*] Processing {cve}...")
        online_data = {}
        if not args.offline:
            print("    -> Querying Red Hat Security Data API...")
            print("    -> Querying FIRST EPSS Intelligence API...")
            print("    -> Checking CISA KEV Known Exploited Catalog...")
            online_data = AdvisoryUpdater.fetch_online_cve_data(cve, target_os=args.target_os)

        advisory_entry = AdvisoryUpdater.synthesize_advisory(
            cve_id=cve,
            data=online_data,
            component_override=args.component,
            fixed_version_override=args.fixed_version,
            title_override=args.title,
            severity_override=args.severity,
            cvss_score_override=args.cvss,
            target_os=args.target_os,
        )

        comp = list(advisory_entry["affected_packages"].keys())[0]
        fix_v = advisory_entry["affected_packages"][comp]["fixed_version"]
        print(f"    [+] {cve}: {advisory_entry['title'][:60]}")
        print(f"    [+] Package: {comp} | Fixed Version: {fix_v} | Severity: {advisory_entry['severity']} (CVSS: {advisory_entry['cvss_score']})")
        if advisory_entry.get("cisa_kev"):
            print("    [!] ALERT: Confirmed in CISA KEV Catalog (Actively Exploited In-The-Wild)")

        ok, msg = AdvisoryUpdater.save_to_advisory_file(advisory_entry, file_path)
        if ok:
            print(f"    [+] {msg}")
            success += 1
        else:
            print(f"    [-] Error: {msg}")

    print("=" * 80)
    print(f"[+] Completed: Ingested {success}/{len(cve_list)} advisories into database.")


def handle_diff(args):
    print_banner()
    print("[*] Historical Vulnerability Scan Comparison & Delta Analysis")
    print(f"[*] Baseline Report: {args.baseline}")
    print(f"[*] Current Report : {args.current}")
    print("-" * 80)

    try:
        diff = ScanDiffer.compare(args.baseline, args.current)
    except Exception as e:
        print(f"[-] Error loading or parsing reports: {e}")
        return

    ScanDiffer.print_diff_summary(diff)
    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_out = os.path.join(args.output_dir, f"scan-diff-{ts}")
    json_path = ScanDiffer.save_diff_json(diff, f"{base_out}.json")
    html_path = ScanDiffer.save_diff_html(diff, f"{base_out}.html")
    print(f"[+] Diff Reports generated in '{args.output_dir}':")
    print(f"    - {json_path}")
    print(f"    - {html_path}")


def handle_scan_fleet(args):
    print_banner()
    offline_mode = resolve_offline(args)
    try:
        targets = FleetScanner.parse_inventory_file(args.fleet_file)
    except Exception as e:
        print(f"[-] Error reading fleet inventory '{args.fleet_file}': {e}")
        return

    print(f"[*] Loaded {len(targets)} server target(s) from '{args.fleet_file}'")
    print(f"[*] Starting concurrent fleet assessment (Concurrency: {args.concurrency}, Depth: {args.depth}, Offline Mode: {offline_mode})...")

    target_cves = None
    if getattr(args, "cve", None):
        target_cves = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
        print(f"[*] Scoped Scan: Targeting specific CVE(s): {', '.join(target_cves)}")

    fleet_name = getattr(args, "fleet_name", None) or "Fleet Security Assessment"
    report = FleetScanner.run_fleet_scan(
        targets=targets,
        concurrency=args.concurrency,
        offline_mode=offline_mode,
        target_cves=target_cves,
        fleet_name=fleet_name,
        depth=args.depth,
    )
    FleetScanner.print_fleet_summary(report)
    paths = FleetScanner.save_fleet_reports(report, args.output_dir, getattr(args, "report_name", None))
    print(f"[+] Consolidated Fleet Reports generated in '{args.output_dir}':")
    for p in paths:
        print(f"    - {p}")


def handle_serve(args):
    print_banner()
    initial_report = None
    if args.preload_profile == "rocky9":
        engine = ScanEngine(offline_mode=True)
        inv = InventoryCollector.create_rocky9_reference_inventory()
        initial_report = engine.run_scan(prebuilt_inventory=inv)
    run_web_server(port=args.port, host=args.host, initial_report=initial_report, output_dir=args.output_dir)


def handle_report(args):
    print_banner()
    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}")
        sys.exit(1)
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[+] Loaded report from {args.input}. Generating formatted outputs...")
    # Generate based on JSON file


def main():
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Linux Vulnerability Scanner and Security Assessment Tool"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", default=None, help="Path to YAML configuration file (default: ./config.yaml)")
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # scan local
    p_local = subparsers.add_parser("scan-local", help="Scan the current machine or run reference profile")
    p_local.add_argument("--cve", default=None, help="Scan only for specific CVE ID(s) (comma-separated, e.g. 'CVE-2021-3156' or 'CVE-2021-3156,CVE-2023-44487')")
    p_local.add_argument("--depth", choices=["basic", "standard", "deep"], default="standard", help="Inventory scan depth ('basic', 'standard', 'deep')")
    p_local.add_argument("--output-dir", default="./reports", help="Directory to store reports")
    p_local.add_argument("--format", default="html,pdf,json,csv", help="Comma-separated formats (html,pdf,json,csv)")
    p_local.add_argument("--host-alias", "--target-name", dest="host_alias", default=None, help="Custom host name/alias to use in report name and headers (e.g. 'new-server')")
    p_local.add_argument("--report-name", default=None, help="Custom report base filename (default: <host>-<timestamp>)")
    p_local.add_argument("--company", default=None, help="Company / Organization name for report branding")
    p_local.add_argument("--assessor", default=None, help="Lead Assessor or team name for report branding")
    p_local.add_argument("--classification", default="CONFIDENTIAL", help="Report classification header (e.g. 'CONFIDENTIAL', 'RESTRICTED')")
    p_local.add_argument("--offline", nargs="?", const=True, default=True, help="Run in offline mode (true/false, default: true)")
    p_local.add_argument("--offline-mode", nargs="?", const=True, default=None, help="Alias for --offline")
    p_local.add_argument("--online", action="store_true", help="Perform live queries to external vendor APIs")
    p_local.add_argument("--profile", choices=["rocky9", "live"], default="live", help="Evaluation profile ('live' or 'rocky9')")
    p_local.add_argument("--scenario", choices=["default", "mitigated_nginx", "mitigated_openjdk", "non_avx512", "patched"], default="default", help="Scenario for rocky9 profile")
    p_local.set_defaults(func=handle_scan_local)

    # scan remote
    p_remote = subparsers.add_parser("scan-remote", help="Assess a remote Linux host over SSH (read-only)")
    p_remote.add_argument("--host", required=True, help="Remote server IP or hostname")
    p_remote.add_argument("--cve", default=None, help="Scan only for specific CVE ID(s) (comma-separated, e.g. 'CVE-2021-3156' or 'CVE-2021-3156,CVE-2023-44487')")
    p_remote.add_argument("--depth", choices=["basic", "standard", "deep"], default="standard", help="Inventory scan depth ('basic', 'standard', 'deep')")
    p_remote.add_argument("--user", default="root", help="SSH username (default: root)")
    p_remote.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p_remote.add_argument("--key-file", help="Path to SSH private key file")
    p_remote.add_argument("--output-dir", default="./reports", help="Directory to store reports")
    p_remote.add_argument("--format", default="html,pdf,json,csv", help="Comma-separated formats")
    p_remote.add_argument("--host-alias", "--target-name", dest="host_alias", default=None, help="Custom host name/alias to use in report name and headers (e.g. 'new-server')")
    p_remote.add_argument("--report-name", default=None, help="Custom report base filename (default: <host>-<timestamp>)")
    p_remote.add_argument("--company", default=None, help="Company / Organization name for report branding")
    p_remote.add_argument("--assessor", default=None, help="Lead Assessor or team name for report branding")
    p_remote.add_argument("--classification", default="CONFIDENTIAL", help="Report classification header (e.g. 'CONFIDENTIAL', 'RESTRICTED')")
    p_remote.add_argument("--offline", nargs="?", const=True, default=True, help="Run in offline mode (true/false, default: true)")
    p_remote.add_argument("--offline-mode", nargs="?", const=True, default=None, help="Alias for --offline")
    p_remote.add_argument("--online", action="store_true", help="Perform live queries to external vendor APIs")
    p_remote.set_defaults(func=handle_scan_remote)

    # scan fleet (multi-server)
    p_fleet = subparsers.add_parser("scan-fleet", help="Assess multiple Linux servers concurrently from an inventory file")
    p_fleet.add_argument("--fleet-file", "-f", required=True, help="Path to fleet inventory file (.json, .yaml, or .csv)")
    p_fleet.add_argument("--concurrency", type=int, default=5, help="Number of concurrent host assessment threads (default: 5)")
    p_fleet.add_argument("--cve", default=None, help="Target specific CVE ID(s) across fleet (comma-separated)")
    p_fleet.add_argument("--depth", choices=["basic", "standard", "deep"], default="standard", help="Inventory scan depth ('basic', 'standard', 'deep')")
    p_fleet.add_argument("--fleet-name", default="Fleet Security Assessment", help="Descriptive name of the server fleet")
    p_fleet.add_argument("--output-dir", default="./reports", help="Directory to store consolidated fleet reports")
    p_fleet.add_argument("--report-name", default=None, help="Custom base filename for fleet reports")
    p_fleet.add_argument("--offline", nargs="?", const=True, default=True, help="Run in offline mode (true/false, default: true)")
    p_fleet.add_argument("--offline-mode", nargs="?", const=True, default=None, help="Alias for --offline")
    p_fleet.add_argument("--online", action="store_true", help="Perform live queries to external vendor APIs")
    p_fleet.set_defaults(func=handle_scan_fleet)

    # diff (historical comparison)
    p_diff = subparsers.add_parser("diff", help="Compare two scan JSON reports to identify new, fixed, and persistent findings")
    p_diff.add_argument("--baseline", "-b", required=True, help="Path to baseline assessment JSON report")
    p_diff.add_argument("--current", "-c", required=True, help="Path to current assessment JSON report")
    p_diff.add_argument("--output-dir", default="./reports", help="Directory to save diff delta reports")
    p_diff.set_defaults(func=handle_diff)

    # update-db
    p_update = subparsers.add_parser("update-db", help="Update local advisory cache from vendor and threat sources")
    p_update.set_defaults(func=handle_update_db)

    # fetch-cve
    p_fetch = subparsers.add_parser("fetch-cve", help="Fetch CVE details online and update advisory database")
    p_fetch.add_argument("--cve", "-c", required=True, help="One or more CVE IDs (comma-separated, e.g. 'CVE-2023-38408')")
    p_fetch.add_argument("--target-os", default="el9", help="Target OS release identifier (default: 'el9')")
    p_fetch.add_argument("--file", "-f", default=None, help="Path to advisory JSON file to update (default: data/sample_advisories.json)")
    p_fetch.add_argument("--component", "--pkg", dest="component", default=None, help="Override affected component/package name")
    p_fetch.add_argument("--fixed-version", default=None, help="Override fixed EVR package version")
    p_fetch.add_argument("--title", default=None, help="Override vulnerability title")
    p_fetch.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None, help="Override severity")
    p_fetch.add_argument("--cvss", type=float, default=None, help="Override CVSS v3 score")
    p_fetch.add_argument("--offline", action="store_true", help="Skip online network fetch and generate template")
    p_fetch.set_defaults(func=handle_fetch_cve)

    # serve web UI
    p_serve = subparsers.add_parser("serve", help="Launch interactive Web Dashboard")
    p_serve.add_argument("--port", type=int, default=8080, help="Web server port (default: 8080)")
    p_serve.add_argument("--host", default="0.0.0.0", help="Web server bind host (default: 0.0.0.0)")
    p_serve.add_argument("--output-dir", default="./reports", help="Directory to store reports")
    p_serve.add_argument("--preload-profile", choices=["none", "rocky9"], default="rocky9", help="Preload Rocky 9.6 profile")
    p_serve.set_defaults(func=handle_serve)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
