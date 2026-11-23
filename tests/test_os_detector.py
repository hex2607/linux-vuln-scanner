"""
Unit tests for OS and hardware environment detection.
"""

import unittest
from vulnscan.inventory.os_detector import OSDetector
from vulnscan.inventory.cpu_analyzer import CpuAnalyzer
from vulnscan.core.models import PackageManagerType


class TestOSDetector(unittest.TestCase):
    def test_rocky9_detection(self):
        sample_os_release = """NAME="Rocky Linux"
VERSION="9.6 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.6"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:9::baseos"
HOME_URL="https://rockylinux.org/"
BUG_REPORT_URL="https://bugs.rockylinux.org/"
SUPPORT_END="2032-05-31"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-9"
ROCKY_SUPPORT_PRODUCT_VERSION="9.6"
"""
        sample_uname = "Linux rocky9-prod 5.14.0-503.14.1.el9_6.x86_64 #1 SMP PREEMPT_DYNAMIC x86_64"
        detector = OSDetector()
        sys_info = detector.detect(mock_os_release=sample_os_release, mock_uname=sample_uname)

        self.assertEqual(sys_info.os_name, "Rocky Linux")
        self.assertEqual(sys_info.os_version, "9.6")
        self.assertEqual(sys_info.os_family, "rhel")
        self.assertEqual(sys_info.package_manager, PackageManagerType.RPM)
        self.assertEqual(sys_info.architecture, "x86_64")
        self.assertEqual(sys_info.platform_id, "platform:el9")

    def test_ubuntu_detection(self):
        sample_os_release = """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
"""
        sample_uname = "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP x86_64"
        detector = OSDetector()
        sys_info = detector.detect(mock_os_release=sample_os_release, mock_uname=sample_uname)

        self.assertEqual(sys_info.os_name, "Ubuntu")
        self.assertEqual(sys_info.os_version, "22.04")
        self.assertEqual(sys_info.os_family, "debian")
        self.assertEqual(sys_info.package_manager, PackageManagerType.DPKG)

    def test_cpu_analyzer_avx512(self):
        sample_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 106
model name	: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.80GHz
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc avx avx2 avx512f avx512dq avx512cd avx512bw avx512vl avx512_vbmi aes
"""
        analyzer = CpuAnalyzer()
        caps = analyzer.analyze(mock_cpuinfo=sample_cpuinfo)
        self.assertTrue(caps.has_avx512)
        self.assertTrue(caps.has_avx512_vbmi)
        self.assertTrue(caps.has_aes_ni)


if __name__ == "__main__":
    unittest.main()
