"""
Unit tests for AdvisoryUpdater and CVE ingestion logic.
"""

import os
import json
import tempfile
import unittest
from vulnscan.advisories.updater import AdvisoryUpdater


class TestAdvisoryUpdater(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.advisory_file = os.path.join(self.temp_dir.name, "test_advisories.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_synthesize_advisory(self):
        adv = AdvisoryUpdater.synthesize_advisory(
            cve_id="CVE-2023-38408",
            data={
                "title": "OpenSSH PKCS#11 Remote Code Execution",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.6210,
                "cisa_kev": True,
            },
            component_override="openssh",
            fixed_version_override="8.7p1-30.el9_2",
            target_os="el9",
        )
        self.assertEqual(adv["cve_id"], "CVE-2023-38408")
        self.assertEqual(adv["severity"], "CRITICAL")
        self.assertEqual(adv["cvss_score"], 9.8)
        self.assertTrue(adv["cisa_kev"])
        self.assertIn("openssh", adv["affected_packages"])
        self.assertEqual(adv["affected_packages"]["openssh"]["fixed_version"], "8.7p1-30.el9_2")
        self.assertTrue(len(adv["validation_steps"]) >= 2)
        self.assertIn("rpm -q openssh", adv["validation_steps"][0]["command"])
        self.assertIn("dnf upgrade -y openssh", adv["remediation_cmd"])

    def test_save_and_update_advisory_file(self):
        adv = AdvisoryUpdater.synthesize_advisory(
            cve_id="CVE-2023-38408",
            component_override="openssh",
            fixed_version_override="8.7p1-30.el9_2",
            target_os="el9",
        )
        # 1. Save new advisory
        ok, msg = AdvisoryUpdater.save_to_advisory_file(adv, self.advisory_file)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(self.advisory_file))

        with open(self.advisory_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(len(data["advisories"]), 1)
            self.assertEqual(data["advisories"][0]["cve_id"], "CVE-2023-38408")

        # 2. Update existing advisory
        adv_updated = AdvisoryUpdater.synthesize_advisory(
            cve_id="CVE-2023-38408",
            component_override="openssh",
            fixed_version_override="8.7p1-30.el9_4", # updated fixed version
            target_os="el9",
        )
        ok2, msg2 = AdvisoryUpdater.save_to_advisory_file(adv_updated, self.advisory_file)
        self.assertTrue(ok2)

        with open(self.advisory_file, "r", encoding="utf-8") as f:
            data2 = json.load(f)
            self.assertEqual(len(data2["advisories"]), 1) # Still 1 advisory (updated, not duplicated)
            self.assertEqual(data2["advisories"][0]["affected_packages"]["openssh"]["fixed_version"], "8.7p1-30.el9_4")


if __name__ == "__main__":
    unittest.main()
