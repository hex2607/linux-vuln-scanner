"""
Unit tests for Historical Scan Comparison & Diffing Engine.
"""

import os
import unittest
from vulnscan.core.engine import ScanEngine
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.core.history import ScanDiffer, ScanDiffResult


class TestScanHistoryDiff(unittest.TestCase):
    def setUp(self):
        self.engine = ScanEngine(offline_mode=True)

    def test_compare_baseline_and_current_reports(self):
        # Baseline: Unpatched NGINX (HTTP/2 enabled -> Vulnerable) and sudo unpatched
        base_inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=True,
            nginx_running=True
        )
        base_report = self.engine.run_scan(prebuilt_inventory=base_inv)

        # Current: NGINX patched to 14.el9_2.3 (Fixed!)
        curr_inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.3",
            nginx_http2_enabled=True,
            nginx_running=True
        )
        curr_report = self.engine.run_scan(prebuilt_inventory=curr_inv)

        diff = ScanDiffer.compare(base_report, curr_report)
        self.assertIsInstance(diff, ScanDiffResult)
        
        # Verify NGINX CVEs were marked as FIXED in delta
        fixed_cves = [f.cve_id for f in diff.fixed_findings]
        self.assertIn("CVE-2026-123633", fixed_cves)
        self.assertIn("CVE-2023-44487", fixed_cves)

        # Verify sudo (already fixed in both) is persistent
        persistent_cves = [f.cve_id for f in diff.persistent_findings]
        self.assertIn("CVE-2021-3156", persistent_cves)

        # Test dictionary serialization
        diff_dict = diff.to_dict()
        self.assertIn("metrics", diff_dict)
        self.assertGreaterEqual(diff_dict["metrics"]["fixed_remediated"], 2)

    def test_state_change_transition(self):
        # Baseline: NGINX vulnerable (HTTP/2 enabled)
        base_inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=True,
            nginx_running=True
        )
        base_report = self.engine.run_scan(prebuilt_inventory=base_inv)

        # Current: NGINX mitigated via config (HTTP/2 disabled)
        curr_inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=False,
            nginx_running=True
        )
        curr_report = self.engine.run_scan(prebuilt_inventory=curr_inv)

        diff = ScanDiffer.compare(base_report, curr_report)
        state_changed_cves = [f.cve_id for f in diff.state_changed_findings]
        self.assertIn("CVE-2026-123633", state_changed_cves)

    def test_save_diff_exports(self):
        inv = InventoryCollector.create_rocky9_reference_inventory()
        report = self.engine.run_scan(prebuilt_inventory=inv)
        diff = ScanDiffer.compare(report, report)

        out_json = "/tmp/test_diff_export.json"
        out_html = "/tmp/test_diff_export.html"
        ScanDiffer.save_diff_json(diff, out_json)
        ScanDiffer.save_diff_html(diff, out_html)

        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_html))
        self.assertGreater(os.path.getsize(out_html), 1000)


if __name__ == "__main__":
    unittest.main()
