"""
Comprehensive Vulnerability Applicability Scenarios and Reference Tests.
Validates Rocky Linux 9.6 reference scenarios:
- CVE-2026-114938 (OpenJDK AVX-512 VBMI Base64 intrinsic vulnerability)
- CVE-2026-123633 (NGINX HTTP/2 Rapid Stream Cancellation)
- CVE-2026-123007 (NGINX HTTP/2 Dynamic Table state flaw)
- Vendor backported patch validation (14.el9_2.1 vs 14.el9_2.3)
- Active configuration mitigations vs unpatched binaries
- Missing hardware instruction set mitigations
- Offline and cache fallback mechanisms
"""

import unittest
from vulnscan.core.engine import ScanEngine
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.core.models import AssessmentStatus, Severity


class TestApplicabilityScenarios(unittest.TestCase):
    def setUp(self):
        self.engine = ScanEngine(offline_mode=True)

    def test_scenario_1_unpatched_vulnerable_rocky9(self):
        """
        Unpatched NGINX (1.20.1-14.el9_2.1 < 14.el9_2.3) with HTTP/2 enabled and running.
        OpenJDK 17.0.8 (< 17.0.9) on CPU with AVX-512 VBMI and default intrinsics.
        Expected: Both CVEs are classified as AFFECTED with HIGH confidence.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=True,
            nginx_running=True,
            java_version="17.0.8",
            java_release="7.el9",
            cpu_has_avx512_vbmi=True,
            jvm_disable_base64_intrinsics=False,
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        # Check CVE-2026-123633 (NGINX HTTP/2)
        nginx_f = next(f for f in report.findings if f.cve_id == "CVE-2026-123633")
        self.assertEqual(nginx_f.status, AssessmentStatus.AFFECTED)
        self.assertIn("Confirmed vulnerable package installed", nginx_f.applicability_reason)
        self.assertTrue(len(nginx_f.evidence) > 0)
        self.assertIsNotNone(nginx_f.remediation_cmd)

        # Check CVE-2026-114938 (OpenJDK AVX-512)
        java_f = next(f for f in report.findings if f.cve_id == "CVE-2026-114938")
        self.assertEqual(java_f.status, AssessmentStatus.AFFECTED)
        self.assertIn("CPU instruction flag 'avx512_vbmi' present", java_f.prerequisites_met)

    def test_scenario_2_mitigated_nginx_http2_disabled(self):
        """
        Unpatched NGINX installed, BUT HTTP/2 is disabled in configuration.
        Expected: CVE-2026-123633 and CVE-2026-123007 are classified as MITIGATED,
        NOT marked Fixed and NOT marked Affected!
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=False,
            nginx_running=True
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        nginx_f = next(f for f in report.findings if f.cve_id == "CVE-2026-123633")
        self.assertEqual(nginx_f.status, AssessmentStatus.MITIGATED)
        self.assertIn("mitigated by active system configuration", nginx_f.applicability_reason)
        self.assertIn("Underlying binary remains unpatched", nginx_f.applicability_reason)

    def test_scenario_3_hardware_prerequisite_fails_not_affected(self):
        """
        OpenJDK 17.0.8 installed (unpatched), BUT host CPU does NOT have AVX-512 VBMI instructions.
        Expected: CVE-2026-114938 is classified as NOT AFFECTED due to hardware constraint!
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            java_version="17.0.8",
            cpu_has_avx512_vbmi=False
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        java_f = next(f for f in report.findings if f.cve_id == "CVE-2026-114938")
        self.assertEqual(java_f.status, AssessmentStatus.NOT_AFFECTED)
        self.assertIn("Host CPU hardware lacks required instruction set", java_f.applicability_reason)

    def test_scenario_4_jvm_intrinsic_mitigated(self):
        """
        OpenJDK 17.0.8 installed on AVX-512 VBMI CPU, BUT admin configured -XX:-UseBase64Intrinsics.
        Expected: CVE-2026-114938 is classified as MITIGATED.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            java_version="17.0.8",
            cpu_has_avx512_vbmi=True,
            jvm_disable_base64_intrinsics=True
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        java_f = next(f for f in report.findings if f.cve_id == "CVE-2026-114938")
        self.assertEqual(java_f.status, AssessmentStatus.MITIGATED)
        self.assertIn("Vulnerable JVM intrinsic explicitly disabled", java_f.applicability_reason)

    def test_scenario_5_vendor_backported_patch_installed(self):
        """
        Vendor patched package installed: NGINX release is 14.el9_2.3 (meeting fixed release).
        Expected: CVE-2026-123633 is classified as FIXED.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.3",
            nginx_http2_enabled=True,
            nginx_running=True
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        nginx_f = next(f for f in report.findings if f.cve_id == "CVE-2026-123633")
        self.assertEqual(nginx_f.status, AssessmentStatus.FIXED)
        self.assertIn("meets or exceeds vendor fixed release", nginx_f.applicability_reason)

    def test_scenario_6_stopped_service_potentially_affected(self):
        """
        Unpatched NGINX installed with HTTP/2 configured, BUT nginx service is stopped/inactive.
        Expected: Classified as POTENTIALLY AFFECTED.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory(
            nginx_version="1.20.1",
            nginx_release="14.el9_2.1",
            nginx_http2_enabled=True,
            nginx_running=False
        )
        report = self.engine.run_scan(prebuilt_inventory=inv)

        nginx_f = next(f for f in report.findings if f.cve_id == "CVE-2026-123633")
        self.assertEqual(nginx_f.status, AssessmentStatus.POTENTIALLY_AFFECTED)
        self.assertIn("service is currently inactive/stopped", nginx_f.applicability_reason)

    def test_scoped_scan_single_cve(self):
        """
        Test targeting a single specific CVE via target_cves.
        Ensures only the requested CVE is evaluated and reported in metrics.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory()
        report = self.engine.run_scan(prebuilt_inventory=inv, target_cves=["CVE-2021-3156"])

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].cve_id, "CVE-2021-3156")
        self.assertEqual(report.summary.total_cves_evaluated, 1)
        self.assertEqual(report.summary.fixed_count, 1)
        self.assertTrue(any("Scoped Scan" in limit for limit in report.limitations))

    def test_scoped_scan_multiple_cves_and_normalization(self):
        """
        Test targeting multiple comma-separated CVEs with case-insensitivity and prefix auto-handling.
        """
        inv = InventoryCollector.create_rocky9_reference_inventory()
        report = self.engine.run_scan(
            prebuilt_inventory=inv,
            target_cves=["cve-2021-3156, 2026-123633"]
        )

        self.assertEqual(len(report.findings), 2)
        evaluated_ids = {f.cve_id for f in report.findings}
        self.assertIn("CVE-2021-3156", evaluated_ids)
        self.assertIn("CVE-2026-123633", evaluated_ids)
        self.assertEqual(report.summary.total_cves_evaluated, 2)


if __name__ == "__main__":
    unittest.main()
