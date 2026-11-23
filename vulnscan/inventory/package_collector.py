"""
Package Inventory Collector.
Gathers installed RPM and Debian package lists with exact epochs, versions, releases,
vendors, architectures, and queries distribution-specific security update advisories.
"""

from typing import List, Dict, Optional, Tuple, Callable
from vulnscan.core.models import Package, PackageManagerType


class PackageCollector:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        self.runner = command_runner

    def _run_cmd(self, cmd: str) -> str:
        if self.runner:
            code, out, _ = self.runner(cmd)
            return out if code == 0 else ""
        try:
            import subprocess
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    def collect_rpm(self, mock_output: Optional[str] = None) -> List[Package]:
        """
        Gathers RPM packages using format:
        %{NAME}|%{VERSION}|%{RELEASE}|%{EPOCH}|%{ARCH}|%{VENDOR}|%{SOURCERPM}
        """
        output = mock_output
        if output is None:
            cmd = 'rpm -qa --qf "%{NAME}|%{VERSION}|%{RELEASE}|%{EPOCH}|%{ARCH}|%{VENDOR}|%{SOURCERPM}\\n"'
            output = self._run_cmd(cmd)

        packages: List[Package] = []
        if not output:
            return packages

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 7:
                name, ver, rel, epoch, arch, vendor, sourcerpm = parts[:7]
                epoch_val = "0" if epoch == "(none)" or not epoch else epoch
                packages.append(Package(
                    name=name,
                    version=ver,
                    release=rel,
                    epoch=epoch_val,
                    arch=arch,
                    vendor=vendor if vendor != "(none)" else "",
                    source_rpm=sourcerpm if sourcerpm != "(none)" else None,
                    status="installed"
                ))
            elif len(parts) >= 3:
                name = parts[0]
                ver = parts[1]
                rel = parts[2] if len(parts) > 2 else ""
                packages.append(Package(name=name, version=ver, release=rel))

        return packages

    def collect_dpkg(self, mock_output: Optional[str] = None) -> List[Package]:
        """
        Gathers Debian packages using format:
        ${Package}|${Version}|${Architecture}|${Status}
        """
        output = mock_output
        if output is None:
            cmd = "dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Status}\\n'"
            output = self._run_cmd(cmd)

        packages: List[Package] = []
        if not output:
            return packages

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                pkg_name, ver_str, arch, status = parts[:4]
                # Only keep installed packages
                if "installed" in status:
                    epoch = "0"
                    version = ver_str
                    release = ""
                    if ":" in ver_str:
                        epoch, rest = ver_str.split(":", 1)
                    else:
                        rest = ver_str
                    if "-" in rest:
                        version, release = rest.rsplit("-", 1)
                    else:
                        version = rest

                    packages.append(Package(
                        name=pkg_name,
                        version=version,
                        release=release,
                        epoch=epoch,
                        arch=arch,
                        vendor="Debian/Ubuntu",
                        status=status,
                    ))

        return packages

    def check_dnf_security_updates(self) -> Dict[str, str]:
        """
        Queries DNF for available security updates.
        Returns mapping of package_name -> advisory_id/info.
        """
        updates: Dict[str, str] = {}
        cmd = "dnf updateinfo list --security -q 2>/dev/null"
        out = self._run_cmd(cmd)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # Typical line: RHSA-2023:5468 Important/Sec. nginx-1:1.20.1-14.el9_2.3.x86_64
            parts = line.split()
            if len(parts) >= 3:
                adv_id = parts[0]
                pkg_nevra = parts[-1]
                pkg_name = pkg_nevra.split("-")[0]
                updates[pkg_name] = adv_id
        return updates

    def collect(self, pkg_mgr: PackageManagerType, mock_output: Optional[str] = None) -> List[Package]:
        if pkg_mgr == PackageManagerType.RPM:
            return self.collect_rpm(mock_output)
        elif pkg_mgr == PackageManagerType.DPKG:
            return self.collect_dpkg(mock_output)
        return []
