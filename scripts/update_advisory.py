#!/usr/bin/env python3
"""
Advisory Auto-Updater Script.
Fetches vulnerability intelligence for specific CVE IDs from online authoritative sources
(Red Hat Security Data API, CISA KEV, FIRST EPSS) and automatically updates the
advisory JSON database (data/sample_advisories.json) with complete Section A-G findings.

Usage:
  python3 scripts/update_advisory.py --cve CVE-2023-38408
  python3 scripts/update_advisory.py --cve CVE-2024-6387 --target-os el9
  python3 scripts/update_advisory.py --cve CVE-2023-38408,CVE-2024-6387
  python3 scripts/update_advisory.py --cve CVE-2023-99999 --component openssl --fixed-version 3.0.7-24.el9
"""

import os
import sys
import argparse

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from vulnscan.advisories.updater import AdvisoryUpdater


def main():
    parser = argparse.ArgumentParser(
        description="Fetch CVE details from authoritative online feeds and update the advisory database."
    )
    parser.add_argument(
        "--cve", "-c", required=True,
        help="One or more CVE IDs (comma-separated, e.g. 'CVE-2023-38408' or 'CVE-2023-38408,CVE-2024-6387')"
    )
    parser.add_argument(
        "--target-os", default="el9",
        help="Target operating system release identifier (e.g. 'el9', 'el8', default: 'el9')"
    )
    parser.add_argument(
        "--file", "-f", default=os.path.join(PROJECT_ROOT, "data", "sample_advisories.json"),
        help="Path to advisories JSON file to update (default: data/sample_advisories.json)"
    )
    parser.add_argument(
        "--component", "--pkg", dest="component", default=None,
        help="Override affected package/component name (e.g. 'openssh', 'sudo', 'nginx')"
    )
    parser.add_argument(
        "--fixed-version", default=None,
        help="Override fixed EVR package version (e.g. '8.7p1-30.el9_2')"
    )
    parser.add_argument(
        "--title", default=None,
        help="Override vulnerability title"
    )
    parser.add_argument(
        "--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
        help="Override severity rating"
    )
    parser.add_argument(
        "--cvss", type=float, default=None,
        help="Override CVSS v3.1 score (e.g. 9.8)"
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Skip online network lookups and build advisory using provided arguments"
    )

    args = parser.parse_args()

    cve_list = [c.strip().upper() for c in args.cve.split(",") if c.strip()]
    if not cve_list:
        print("[-] No valid CVE ID provided.")
        sys.exit(1)

    print("=" * 78)
    print("   🛡️  VULNERABILITY ADVISORY INGESTION & AUTO-UPDATER")
    print(f"   Target Database : {args.file}")
    print(f"   Target Release  : {args.target_os}")
    print(f"   Mode            : {'Offline Template' if args.offline else 'Live API Fetch (Red Hat, CISA, EPSS)'}")
    print("=" * 78)

    success_count = 0
    for cve in cve_list:
        if not cve.startswith("CVE-"):
            cve = f"CVE-{cve}"

        print(f"\n[*] Processing {cve}...")

        online_data = {}
        if not args.offline:
            print("    -> Querying Red Hat Security Data API...")
            print("    -> Querying FIRST EPSS Intelligence API...")
            print("    -> Checking CISA KEV Known Exploited Catalog...")
            online_data = AdvisoryUpdater.fetch_online_cve_data(cve, target_os=args.target_os)

            if online_data.get("title") and online_data["title"] != f"Security Vulnerability {cve}":
                print(f"    [+] Successfully fetched metadata: {online_data['title'][:65]}")
            else:
                print("    [!] Live query returned minimal metadata (offline fallback applied).")

            if online_data.get("cisa_kev"):
                print("    [!] ALERT: Confirmed in CISA KEV Catalog (Actively Exploited In-The-Wild)")

            if online_data.get("epss_score") is not None:
                epss_pct = round(online_data["epss_score"] * 100, 2)
                print(f"    [+] EPSS Exploit Probability: {epss_pct}%")

        # Synthesize full 7-section structured assessment advisory
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
        print(f"    [+] Component: {comp} | Fixed Version: {fix_v} | Severity: {advisory_entry['severity']} (CVSS: {advisory_entry['cvss_score']})")

        # Save to JSON file
        ok, msg = AdvisoryUpdater.save_to_advisory_file(advisory_entry, args.file)
        if ok:
            print(f"    [+] {msg}")
            success_count += 1
        else:
            print(f"    [-] Error saving advisory: {msg}")

    print("\n" + "=" * 78)
    print(f"[+] Completed: Successfully ingested {success_count}/{len(cve_list)} advisories.")
    print("=" * 78)


if __name__ == "__main__":
    main()
