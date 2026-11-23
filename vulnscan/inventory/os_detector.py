"""
OS and Environment Detector.
Authoritatively determines Linux distribution, version, kernel, architecture,
virtualization, and cloud hosting environment using /etc/os-release, uname, and DMI data.
"""

import os
import re
import platform
from typing import Dict, Optional, Tuple, Callable
from vulnscan.core.models import SystemInfo, PackageManagerType, CpuCapabilities


class OSDetector:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        """
        command_runner is a function (cmd) -> (exit_code, stdout, stderr).
        If None, runs locally via subprocess or direct filesystem reads.
        """
        self.runner = command_runner

    def _run_cmd(self, cmd: str) -> str:
        if self.runner:
            code, out, _ = self.runner(cmd)
            return out.strip() if code == 0 else ""
        try:
            import subprocess
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return res.stdout.strip() if res.returncode == 0 else ""
        except Exception:
            return ""

    def _read_file(self, path: str) -> str:
        if self.runner:
            return self._run_cmd(f"cat {path} 2>/dev/null")
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    def parse_os_release(self, content: str) -> Dict[str, str]:
        """Parses /etc/os-release standard key=value format."""
        data: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip().strip('"').strip("'")
        return data

    def detect_cloud_provider(self) -> Optional[str]:
        """Detects if system is hosted on AWS EC2 or other cloud providers."""
        # 1. AWS EC2 DMI check
        sys_vendor = self._read_file("/sys/class/dmi/id/sys_vendor").lower()
        product_name = self._read_file("/sys/class/dmi/id/product_name").lower()
        bios_version = self._read_file("/sys/class/dmi/id/bios_version").lower()

        if "amazon" in sys_vendor or "amazon" in product_name or "amazon" in bios_version:
            return "AWS EC2"

        # Check /sys/hypervisor/uuid (on Xen/KVM EC2 instances starts with 'ec2')
        uuid = self._read_file("/sys/hypervisor/uuid").lower()
        if uuid.startswith("ec2"):
            return "AWS EC2"

        # Check dmidecode if available
        dmi = self._run_cmd("dmidecode -s system-product-name 2>/dev/null").lower()
        if "ec2" in dmi or "amazon" in dmi:
            return "AWS EC2"
        if "google" in sys_vendor or "google" in product_name:
            return "Google Cloud Platform"
        if "microsoft" in sys_vendor or "azure" in product_name:
            return "Microsoft Azure"

        return "On-Premise / Other"

    def detect_virtualization(self) -> Optional[str]:
        virt = self._run_cmd("systemd-detect-virt 2>/dev/null")
        if virt:
            return virt
        hypervisor = self._read_file("/sys/hypervisor/type")
        if hypervisor:
            return hypervisor.strip()
        return "bare-metal / undetected"

    def detect(self, mock_os_release: Optional[str] = None, mock_uname: Optional[str] = None) -> SystemInfo:
        """Collects authoritative OS information."""
        os_release_content = mock_os_release or self._read_file("/etc/os-release")
        os_info = self.parse_os_release(os_release_content)

        # OS Identification
        os_name = os_info.get("NAME") or os_info.get("ID") or "Linux"
        os_version = os_info.get("VERSION_ID") or os_info.get("VERSION") or "Unknown"
        os_id = os_info.get("ID", "").lower()
        os_id_like = os_info.get("ID_LIKE", "").lower()
        os_codename = os_info.get("VERSION_CODENAME") or None
        platform_id = os_info.get("PLATFORM_ID") or None

        # Determine OS Family
        if "rhel" in os_id or "rocky" in os_id or "almalinux" in os_id or "centos" in os_id or "fedora" in os_id or "amzn" in os_id or "rhel" in os_id_like:
            os_family = "rhel"
            pkg_mgr = PackageManagerType.RPM
        elif "debian" in os_id or "ubuntu" in os_id or "debian" in os_id_like or "ubuntu" in os_id_like:
            os_family = "debian"
            pkg_mgr = PackageManagerType.DPKG
        else:
            os_family = "generic_linux"
            pkg_mgr = PackageManagerType.UNKNOWN

        # Kernel & Architecture
        if mock_uname:
            parts = mock_uname.split()
            kernel_version = parts[2] if len(parts) > 2 else "Unknown"
            architecture = parts[-1] if len(parts) > 4 else "x86_64"
            hostname = parts[1] if len(parts) > 1 else "localhost"
        else:
            kernel_version = self._run_cmd("uname -r") or platform.release() or "Unknown"
            architecture = self._run_cmd("uname -m") or platform.machine() or "x86_64"
            hostname = self._run_cmd("hostname") or platform.node() or "localhost"

        # Uptime
        uptime_sec = None
        uptime_raw = self._read_file("/proc/uptime")
        if uptime_raw:
            try:
                uptime_sec = float(uptime_raw.split()[0])
            except (ValueError, IndexError):
                pass

        # Memory total
        mem_mb = None
        meminfo = self._read_file("/proc/meminfo")
        if meminfo:
            match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
            if match:
                mem_mb = int(match.group(1)) // 1024

        cloud_env = self.detect_cloud_provider()
        virt_env = self.detect_virtualization()

        return SystemInfo(
            hostname=hostname,
            os_name=os_name,
            os_version=os_version,
            os_family=os_family,
            os_codename=os_codename,
            platform_id=platform_id,
            kernel_version=kernel_version,
            architecture=architecture,
            package_manager=pkg_mgr,
            uptime_seconds=uptime_sec,
            virtualization=virt_env,
            cloud_provider=cloud_env,
            memory_total_mb=mem_mb,
        )
