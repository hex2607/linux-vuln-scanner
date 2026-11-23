"""
Unit tests for Identification and Reporting Enhancements:
- Unmanaged / bundled process discovery
- Node.js runtime detection
- OpenSSH and sysctl security configuration analysis
- Report branding and classification headers
- Scan depth profiles (basic, standard, deep)
"""

import os
import unittest
from vulnscan.inventory.software_detector import SoftwareDetector
from vulnscan.inventory.config_analyzer import ConfigurationAnalyzer
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.core.models import ReportBranding
from vulnscan.core.engine import ScanEngine
from vulnscan.reporting.html_reporter import HtmlReporter
from vulnscan.reporting.pdf_reporter import PdfReporter


class TestEnhancements(unittest.TestCase):
    def test_detect_unmanaged_processes_mock(self):
        mock_ps = """PID USER COMMAND
100 root /usr/lib/systemd/systemd --switched-root --system --deserialize 31
2500 appuser /opt/custom-app/bin/microservice --port 8080
3100 nodeuser /home/nodeuser/app/server.js
4200 root /var/www/internal-api/api-daemon
"""
        runner = lambda cmd: (0, mock_ps, "") if "ps -eo" in cmd else (0, "", "")
        detector = SoftwareDetector(command_runner=runner)
        unmanaged = detector.detect_unmanaged_processes()

        self.assertEqual(len(unmanaged), 3)
        paths = [u.binary_path for u in unmanaged]
        self.assertIn("/opt/custom-app/bin/microservice", paths)
        self.assertIn("/home/nodeuser/app/server.js", paths)
        self.assertIn("/var/www/internal-api/api-daemon", paths)
        self.assertEqual(unmanaged[0].install_type, "standalone")

    def test_detect_nodejs_mock(self):
        runner = lambda cmd: (0, "v20.10.0\n", "") if "node --version" in cmd else (0, "/usr/local/bin/node", "")
        detector = SoftwareDetector(command_runner=runner)
        node = detector.detect_nodejs()

        self.assertIsNotNone(node)
        self.assertEqual(node.name, "nodejs")
        self.assertEqual(node.detected_version, "20.10.0")

    def test_analyze_sshd_config(self):
        mock_sshd_t = """
permitrootlogin prohibit-password
passwordauthentication no
logingracetime 120
maxauthtries 3
"""
        analyzer = ConfigurationAnalyzer()
        findings = analyzer.analyze_sshd(mock_output=mock_sshd_t)

        self.assertEqual(len(findings), 3)
        directives = {f.directive: f.value for f in findings}
        self.assertEqual(directives["LoginGraceTime"], "120")
        self.assertEqual(directives["PermitRootLogin"], "prohibit-password")
        self.assertEqual(directives["PasswordAuthentication"], "no")

    def test_analyze_sysctl_security(self):
        mock_sysctl = """
kernel.unprivileged_userns_clone = 0
net.ipv4.ip_forward = 0
fs.protected_regular = 2
kernel.kptr_restrict = 1
"""
        analyzer = ConfigurationAnalyzer()
        findings = analyzer.analyze_sysctl(mock_output=mock_sysctl)

        self.assertEqual(len(findings), 4)
        vals = {f.directive: f.value for f in findings}
        self.assertEqual(vals["kernel.unprivileged_userns_clone"], "0")
        self.assertEqual(vals["net.ipv4.ip_forward"], "0")

    def test_report_branding_in_html_and_pdf(self):
        engine = ScanEngine(offline_mode=True)
        inv = InventoryCollector.create_rocky9_reference_inventory()
        branding = ReportBranding(
            company_name="Acme Financial Infrastructure",
            assessor_name="SecOps Team Red",
            classification="STRICTLY CONFIDENTIAL"
        )
        report = engine.run_scan(prebuilt_inventory=inv, branding=branding)

        # Generate HTML
        html_out = "/tmp/test_branded_report.html"
        HtmlReporter.generate(report, html_out)
        with open(html_out, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("STRICTLY CONFIDENTIAL", html)
        self.assertIn("Acme Financial Infrastructure", html)
        self.assertIn("SecOps Team Red", html)

        # Generate PDF
        pdf_out = "/tmp/test_branded_report.pdf"
        PdfReporter.generate(report, pdf_out)
        self.assertTrue(os.path.exists(pdf_out))
        with open(pdf_out, "rb") as f:
            pdf_bytes = f.read()
        self.assertIn(b"STRICTLY CONFIDENTIAL", pdf_bytes)

    def test_scan_depth_basic_vs_deep(self):
        collector = InventoryCollector()
        inv_basic = collector.collect(depth="basic")
        self.assertEqual(len(inv_basic.services), 0)
        self.assertEqual(len(inv_basic.runtimes), 0)
        self.assertEqual(len(inv_basic.configurations), 0)

    def test_config_loader(self):
        from vulnscan.core.config import ConfigLoader
        # Test loading config.example.yaml
        cfg = ConfigLoader.load("config.example.yaml")
        self.assertIn("scanner", cfg)
        self.assertIn("branding", cfg)
        self.assertIn("audit_modules", cfg)
        self.assertEqual(cfg["branding"]["company_name"], "Enterprise Cloud Security")
        self.assertEqual(cfg["scanner"]["depth"], "standard")

        # Test branding extraction
        branding = ConfigLoader.get_branding(cfg, {"company": "Custom Corp"})
        self.assertEqual(branding.company_name, "Custom Corp")
        self.assertEqual(branding.assessor_name, "Security Assessment Team")


if __name__ == "__main__":
    unittest.main()
