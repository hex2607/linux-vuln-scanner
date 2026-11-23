"""
System Inventory Collector Orchestrator.
Coordinates the collection of OS identity, CPU capabilities, packages,
software runtimes, systemd services, listening sockets, and configurations.
Supports both live execution and simulated profiles for testing.
"""

from typing import Dict, List, Optional, Tuple, Callable
from vulnscan.core.models import (
    SystemInfo, Package, SoftwareRuntime, ServiceInfo,
    ListeningPort, ConfigurationFinding, PackageManagerType, CpuCapabilities
)
from vulnscan.inventory.os_detector import OSDetector
from vulnscan.inventory.cpu_analyzer import CpuAnalyzer
from vulnscan.inventory.package_collector import PackageCollector
from vulnscan.inventory.software_detector import SoftwareDetector
from vulnscan.inventory.service_collector import ServiceCollector
from vulnscan.inventory.config_analyzer import ConfigurationAnalyzer


class SystemInventory:
    def __init__(
        self,
        system_info: SystemInfo,
        packages: List[Package],
        runtimes: List[SoftwareRuntime],
        services: List[ServiceInfo],
        ports: List[ListeningPort],
        configurations: List[ConfigurationFinding]
    ):
        self.system_info = system_info
        self.packages = packages
        self.runtimes = runtimes
        self.services = services
        self.ports = ports
        self.configurations = configurations
        self._pkg_map: Dict[str, Package] = {p.name: p for p in packages}
        self._service_map: Dict[str, ServiceInfo] = {s.name: s for s in services}

    def get_package(self, name: str) -> Optional[Package]:
        return self._pkg_map.get(name)

    def get_service(self, name: str) -> Optional[ServiceInfo]:
        return self._service_map.get(name)

    def is_service_running(self, name: str) -> bool:
        srv = self.get_service(name)
        return srv.is_running if srv else False

    def get_config(self, service: str, directive: str) -> Optional[ConfigurationFinding]:
        for c in self.configurations:
            if c.service_name.lower() == service.lower() and c.directive.lower() == directive.lower():
                return c
        return None


class InventoryCollector:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        self.runner = command_runner
        self.os_detector = OSDetector(command_runner)
        self.cpu_analyzer = CpuAnalyzer(command_runner)
        self.package_collector = PackageCollector(command_runner)
        self.software_detector = SoftwareDetector(command_runner)
        self.service_collector = ServiceCollector(command_runner)
        self.config_analyzer = ConfigurationAnalyzer(command_runner)

    def collect(self, depth: str = "standard") -> SystemInventory:
        """
        Executes live inventory collection according to specified scan depth:
        - 'basic': OS, CPU, packages, and listening ports only.
        - 'standard' (default): basic + running services + standard runtime and config analysis.
        - 'deep': standard + unmanaged processes crawl + OpenSSH config + sysctl security audit.
        """
        sys_info = self.os_detector.detect()
        sys_info.cpu = self.cpu_analyzer.analyze()
        packages = self.package_collector.collect(sys_info.package_manager)
        ports = self.service_collector.collect_listening_ports()

        if depth == "basic":
            services = []
            runtimes = []
            configs = []
        else:
            include_deep = (depth == "deep")
            services = self.service_collector.collect_services()
            runtimes = self.software_detector.detect_all(include_deep=include_deep)
            configs = self.config_analyzer.analyze_all(include_deep=include_deep)

        return SystemInventory(
            system_info=sys_info,
            packages=packages,
            runtimes=runtimes,
            services=services,
            ports=ports,
            configurations=configs
        )

    @classmethod
    def create_rocky9_reference_inventory(
        cls,
        nginx_version: str = "1.20.1",
        nginx_release: str = "14.el9_2.1",
        nginx_http2_enabled: bool = True,
        nginx_running: bool = True,
        java_version: str = "17.0.8",
        java_release: str = "7.el9",
        cpu_has_avx512_vbmi: bool = True,
        jvm_disable_base64_intrinsics: bool = False,
    ) -> SystemInventory:
        """
        Creates an authoritative Rocky Linux 9.6 reference inventory for initial validation.
        Matches the primary reference environment specified in Section 17.
        """
        cpu = CpuCapabilities(
            vendor_id="GenuineIntel",
            model_name="Intel(R) Xeon(R) Platinum 8375C CPU @ 2.80GHz",
            architecture="x86_64",
            cpu_count=4,
            flags=["fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep",
                   "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "mmx", "fxsr", "sse",
                   "sse2", "ss", "ht", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc",
                   "avx", "avx2", "avx512f", "avx512dq", "avx512cd", "avx512bw", "avx512vl",
                   "avx512_vnni"] + (["avx512_vbmi"] if cpu_has_avx512_vbmi else []) + ["aes"],
            has_avx512=True,
            has_avx512_vbmi=cpu_has_avx512_vbmi,
            has_aes_ni=True,
        )

        sys_info = SystemInfo(
            hostname="rocky9-prod-web01.internal",
            os_name="Rocky Linux",
            os_version="9.6",
            os_family="rhel",
            os_codename="Blue Onyx",
            platform_id="platform:el9",
            kernel_version="5.14.0-503.14.1.el9_6.x86_64",
            architecture="x86_64",
            package_manager=PackageManagerType.RPM,
            uptime_seconds=345600.0,
            virtualization="kvm",
            cloud_provider="AWS EC2",
            cpu=cpu,
            memory_total_mb=15920
        )

        packages = [
            Package(name="kernel", version="5.14.0", release="503.14.1.el9_6", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="systemd", version="252", release="46.el9_6", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="openssl", version="3.2.2", release="6.el9_6", epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="openssl-libs", version="3.2.2", release="6.el9_6", epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="nginx", version=nginx_version, release=nginx_release, epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="nginx-core", version=nginx_version, release=nginx_release, epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="java-17-openjdk", version=java_version, release=java_release, epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="java-17-openjdk-headless", version=java_version, release=java_release, epoch="1", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="glibc", version="2.34", release="125.el9_6", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="curl", version="7.76.1", release="31.el9_6", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="sudo", version="1.9.5p2", release="14.el9", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
            Package(name="python3", version="3.9.21", release="1.el9_6", epoch="0", arch="x86_64", vendor="Rocky Enterprise Software Foundation"),
        ]

        runtimes = [
            SoftwareRuntime(name="nginx", detected_version=nginx_version, binary_path="/usr/sbin/nginx", install_type="system", metadata={"has_http_v2_module": True}),
            SoftwareRuntime(name="openjdk", detected_version=f"{java_version}+{java_release}", binary_path="/usr/lib/jvm/java-17-openjdk/bin/java", install_type="system"),
            SoftwareRuntime(name="openssl", detected_version="3.2.2", binary_path="/usr/bin/openssl", install_type="system"),
            SoftwareRuntime(name="python3", detected_version="3.9.21", binary_path="/usr/bin/python3", install_type="system")
        ]

        services = [
            ServiceInfo(name="nginx", load_state="loaded", active_state="active" if nginx_running else "inactive", sub_state="running" if nginx_running else "dead", exec_path="/usr/sbin/nginx", pid=1120 if nginx_running else None, listening_ports=[80, 443] if nginx_running else []),
            ServiceInfo(name="sshd", load_state="loaded", active_state="active", sub_state="running", exec_path="/usr/sbin/sshd", pid=840, listening_ports=[22]),
            ServiceInfo(name="systemd-journald", load_state="loaded", active_state="active", sub_state="running", exec_path="/usr/lib/systemd/systemd-journald", pid=560)
        ]

        ports = [
            ListeningPort(protocol="tcp", local_address="0.0.0.0", local_port=22, process_name="sshd", pid=840),
        ]
        if nginx_running:
            ports.extend([
                ListeningPort(protocol="tcp", local_address="0.0.0.0", local_port=80, process_name="nginx", pid=1120),
                ListeningPort(protocol="tcp", local_address="0.0.0.0", local_port=443, process_name="nginx", pid=1120),
            ])

        configs = [
            ConfigurationFinding(
                service_name="nginx",
                config_file="/etc/nginx/nginx.conf",
                directive="http2",
                value="enabled" if nginx_http2_enabled else "disabled",
                security_relevance="HTTP/2 listener configuration on port 443 ssl",
                raw_snippet="listen 443 ssl http2;" if nginx_http2_enabled else "listen 443 ssl;"
            ),
            ConfigurationFinding(
                service_name="java",
                config_file="jvm_arguments",
                directive="-XX:-UseBase64Intrinsics",
                value="disabled" if jvm_disable_base64_intrinsics else "default_enabled",
                security_relevance="JVM Base64 AVX-512 intrinsic status",
                raw_snippet="-XX:-UseBase64Intrinsics" if jvm_disable_base64_intrinsics else "default intrinsic settings"
            )
        ]

        return SystemInventory(
            system_info=sys_info,
            packages=packages,
            runtimes=runtimes,
            services=services,
            ports=ports,
            configurations=configs
        )
