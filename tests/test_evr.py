"""
Unit tests for RPM and Debian version comparison algorithms.
"""

import unittest
from vulnscan.core.evr import rpmvercmp, compare_rpm_evr, debvercmp, parse_rpm_nevra


class TestEVRComparison(unittest.TestCase):
    def test_rpmvercmp_basic(self):
        self.assertEqual(rpmvercmp("1.0", "1.0"), 0)
        self.assertEqual(rpmvercmp("1.1", "1.0"), 1)
        self.assertEqual(rpmvercmp("1.0", "1.1"), -1)
        self.assertEqual(rpmvercmp("2.0.1", "2.0.0"), 1)
        self.assertEqual(rpmvercmp("1.20.1", "1.20.1"), 0)

    def test_rpmvercmp_tildes(self):
        # Tilde sorts before anything else
        self.assertEqual(rpmvercmp("1.0~rc1", "1.0"), -1)
        self.assertEqual(rpmvercmp("1.0", "1.0~rc1"), 1)
        self.assertEqual(rpmvercmp("1.0~rc1", "1.0~rc2"), -1)

    def test_rpmvercmp_carets(self):
        # Caret sorts after empty, but before any non-empty
        self.assertEqual(rpmvercmp("1.0^git1", "1.0"), 1)
        self.assertEqual(rpmvercmp("1.0^git1", "1.0.1"), -1)

    def test_compare_rpm_evr_vendor_releases(self):
        # Rocky / RHEL backport release comparison:
        # 1.20.1-14.el9_2.1 vs 1.20.1-14.el9_2.3 (fixed)
        self.assertEqual(compare_rpm_evr("0", "1.20.1", "14.el9_2.1", "0", "1.20.1", "14.el9_2.3"), -1)
        self.assertEqual(compare_rpm_evr("0", "1.20.1", "14.el9_2.3", "0", "1.20.1", "14.el9_2.1"), 1)
        self.assertEqual(compare_rpm_evr("0", "1.20.1", "14.el9_2.3", "0", "1.20.1", "14.el9_2.3"), 0)

    def test_compare_rpm_evr_epochs(self):
        # Epoch dominance: epoch 1 version 1.0 is greater than epoch 0 version 2.0
        self.assertEqual(compare_rpm_evr("1", "1.0", "1", "0", "2.0", "1"), 1)
        self.assertEqual(compare_rpm_evr("0", "2.0", "1", "1", "1.0", "1"), -1)

    def test_parse_rpm_nevra(self):
        name, epoch, ver, rel, arch = parse_rpm_nevra("nginx-1:1.20.1-14.el9_2.1.x86_64")
        self.assertEqual(name, "nginx")
        self.assertEqual(epoch, "1")
        self.assertEqual(ver, "1.20.1")
        self.assertEqual(rel, "14.el9_2.1")
        self.assertEqual(arch, "x86_64")

    def test_debvercmp(self):
        self.assertEqual(debvercmp("1:2.4.52-1ubuntu4.7", "1:2.4.52-1ubuntu4.6"), 1)
        self.assertEqual(debvercmp("1:2.4.52-1ubuntu4.6", "1:2.4.52-1ubuntu4.7"), -1)
        self.assertEqual(debvercmp("2.4.52", "2.4.52"), 0)
        self.assertEqual(debvercmp("2.4.52~beta1", "2.4.52"), -1)


if __name__ == "__main__":
    unittest.main()
