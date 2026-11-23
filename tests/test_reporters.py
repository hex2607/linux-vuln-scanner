"""
Unit tests for report generation (HTML, PDF, JSON, CSV).
"""

import os
import unittest
import json
from vulnscan.core.engine import ScanEngine
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.reporting.html_reporter import HtmlReporter
from vulnscan.reporting.pdf_reporter import PdfReporter
from vulnscan.reporting.json_reporter import JsonReporter, CsvReporter


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.output_dir = "/tmp/vulnscan_test_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        engine = ScanEngine(offline_mode=True)
        inv = InventoryCollector.create_rocky9_reference_inventory()
        self.report = engine.run_scan(prebuilt_inventory=inv)

    def test_json_reporter(self):
        json_path = os.path.join(self.output_dir, "test_report.json")
        JsonReporter.generate(self.report, json_path)
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["system_info"]["hostname"], "rocky9-prod-web01.internal")
            self.assertEqual(data["summary"]["total_cves_evaluated"], len(self.report.findings))

    def test_csv_reporter(self):
        csv_path = os.path.join(self.output_dir, "test_report.csv")
        CsvReporter.generate(self.report, csv_path)
        self.assertTrue(os.path.exists(csv_path))
        with open(csv_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertTrue(len(lines) > 1) # Header + findings

    def test_html_reporter(self):
        html_path = os.path.join(self.output_dir, "test_report.html")
        HtmlReporter.generate(self.report, html_path)
        self.assertTrue(os.path.exists(html_path))
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("rocky9-prod-web01.internal", content)
            self.assertIn("CVE-2026-123633", content)
            self.assertIn("CVE-2026-114938", content)

    def test_pdf_reporter(self):
        import re
        pdf_path = os.path.join(self.output_dir, "test_report.pdf")
        PdfReporter.generate(self.report, pdf_path)
        self.assertTrue(os.path.exists(pdf_path))
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
            self.assertTrue(pdf_bytes.endswith(b"%%EOF\n") or b"%%EOF" in pdf_bytes)

        # Verify PDF formatting fixes: single footer per page, full classification badge, and no clipped context risk
        latin_text = pdf_bytes.decode("latin1", errors="ignore")
        page_streams = re.findall(r"stream\n(.*?)\nendstream", latin_text, re.DOTALL)
        self.assertGreaterEqual(len(page_streams), 2)
        for idx, stream in enumerate(page_streams):
            footer_matches = [line for line in stream.split("\n") if "Linux Vulnerability Assessment Report" in line or "STRICTLY FOR AUTHORIZED" in line]
            self.assertEqual(len(footer_matches), 1, f"Page {idx+1} should have exactly one footer line")

        # Page 1 checks
        p1 = page_streams[0]
        self.assertNotIn("INTERNAL USE ONL)", p1, "Header classification badge must not be cut off")
        self.assertNotIn("None (Patche)", p1, "Context risk rating must not be cut off to 'None (Patche'")

    def test_save_reports_naming_convention(self):
        from vulnscan.cli import save_reports
        # 1. Default naming: <host>-<timestamp>.<ext>
        paths = save_reports(self.report, self.output_dir, "json,csv,html,pdf")
        self.assertEqual(len(paths), 4)
        for p in paths:
            self.assertTrue(os.path.exists(p))
            fname = os.path.basename(p)
            self.assertTrue(fname.startswith("rocky9-prod-web01.internal-"))
            self.assertTrue(any(fname.endswith(ext) for ext in [".json", ".csv", ".html", ".pdf"]))

        # 2. Custom host alias: e.g. "new-server"
        alias_paths = save_reports(self.report, self.output_dir, "csv,html", host_alias="new-server")
        for p in alias_paths:
            self.assertTrue(os.path.exists(p))
            fname = os.path.basename(p)
            self.assertTrue(fname.startswith("new-server-"))

        # 3. Custom report name: e.g. "new-server"
        name_paths = save_reports(self.report, self.output_dir, "json", report_name="new-server")
        for p in name_paths:
            self.assertTrue(os.path.exists(p))
            fname = os.path.basename(p)
            self.assertTrue(fname.startswith("new-server-"))


if __name__ == "__main__":
    unittest.main()
