"""
Unit tests for Multi-Server Fleet Assessment.
"""

import os
import json
import tempfile
import unittest
from vulnscan.remote.fleet import FleetScanner, FleetTarget, FleetReport


class TestFleetScanner(unittest.TestCase):
    def test_parse_json_inventory(self):
        inv_data = {
            "servers": [
                {"host": "mock-web01", "alias": "web-prod-01", "is_mock": True, "mock_scenario": "default", "tags": {"env": "prod"}},
                {"host": "mock-web02", "alias": "web-prod-02", "is_mock": True, "mock_scenario": "patched", "tags": {"env": "prod"}},
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(inv_data, f)
            temp_path = f.name

        try:
            targets = FleetScanner.parse_inventory_file(temp_path)
            self.assertEqual(len(targets), 2)
            self.assertEqual(targets[0].alias, "web-prod-01")
            self.assertEqual(targets[1].mock_scenario, "patched")
            self.assertTrue(targets[0].is_mock)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_run_fleet_scan_mock_aggregation(self):
        targets = [
            FleetTarget(host="mock-web01", alias="web-01", is_mock=True, mock_scenario="default"),
            FleetTarget(host="mock-web02", alias="web-02", is_mock=True, mock_scenario="patched"),
        ]
        fleet_rep = FleetScanner.run_fleet_scan(targets, concurrency=2, offline_mode=True)

        self.assertIsInstance(fleet_rep, FleetReport)
        self.assertEqual(fleet_rep.total_targets, 2)
        self.assertEqual(fleet_rep.successful_scans, 2)
        self.assertEqual(fleet_rep.failed_scans, 0)
        # web-02 is fully patched, web-01 has affected findings -> compliance should be 50.0%
        self.assertEqual(fleet_rep.compliance_score_pct, 50.0)
        self.assertIn("CVE-2023-44487", fleet_rep.fleet_cve_matrix)
        self.assertIn("web-01", fleet_rep.fleet_cve_matrix["CVE-2023-44487"])

    def test_save_fleet_reports(self):
        targets = [
            FleetTarget(host="mock-web01", alias="web-01", is_mock=True, mock_scenario="default"),
        ]
        fleet_rep = FleetScanner.run_fleet_scan(targets, concurrency=1, offline_mode=True)
        out_dir = "/tmp/test_fleet_out"
        paths = FleetScanner.save_fleet_reports(fleet_rep, out_dir, "test-fleet")

        self.assertEqual(len(paths), 3)
        for p in paths:
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 100)


if __name__ == "__main__":
    unittest.main()
